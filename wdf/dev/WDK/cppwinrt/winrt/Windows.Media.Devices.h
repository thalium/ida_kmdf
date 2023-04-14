// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Media.Capture.2.h"
#include "winrt/impl/Windows.Media.Devices.Core.2.h"
#include "winrt/impl/Windows.Media.MediaProperties.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Media.Devices.2.h"
#include "winrt/Windows.Media.h"

namespace winrt::impl {

template <typename D> Windows::Media::Devices::AdvancedPhotoMode consume_Windows_Media_Devices_IAdvancedPhotoCaptureSettings<D>::Mode() const
{
    Windows::Media::Devices::AdvancedPhotoMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedPhotoCaptureSettings)->get_Mode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IAdvancedPhotoCaptureSettings<D>::Mode(Windows::Media::Devices::AdvancedPhotoMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedPhotoCaptureSettings)->put_Mode(get_abi(value)));
}

template <typename D> bool consume_Windows_Media_Devices_IAdvancedPhotoControl<D>::Supported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedPhotoControl)->get_Supported(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::AdvancedPhotoMode> consume_Windows_Media_Devices_IAdvancedPhotoControl<D>::SupportedModes() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::AdvancedPhotoMode> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedPhotoControl)->get_SupportedModes(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::AdvancedPhotoMode consume_Windows_Media_Devices_IAdvancedPhotoControl<D>::Mode() const
{
    Windows::Media::Devices::AdvancedPhotoMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedPhotoControl)->get_Mode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IAdvancedPhotoControl<D>::Configure(Windows::Media::Devices::AdvancedPhotoCaptureSettings const& settings) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedPhotoControl)->Configure(get_abi(settings)));
}

template <typename D> void consume_Windows_Media_Devices_IAdvancedVideoCaptureDeviceController<D>::SetDeviceProperty(param::hstring const& propertyId, Windows::Foundation::IInspectable const& propertyValue) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedVideoCaptureDeviceController)->SetDeviceProperty(get_abi(propertyId), get_abi(propertyValue)));
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Media_Devices_IAdvancedVideoCaptureDeviceController<D>::GetDeviceProperty(param::hstring const& propertyId) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedVideoCaptureDeviceController)->GetDeviceProperty(get_abi(propertyId), put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> Windows::Media::Devices::LowLagPhotoSequenceControl consume_Windows_Media_Devices_IAdvancedVideoCaptureDeviceController2<D>::LowLagPhotoSequence() const
{
    Windows::Media::Devices::LowLagPhotoSequenceControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedVideoCaptureDeviceController2)->get_LowLagPhotoSequence(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::LowLagPhotoControl consume_Windows_Media_Devices_IAdvancedVideoCaptureDeviceController2<D>::LowLagPhoto() const
{
    Windows::Media::Devices::LowLagPhotoControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedVideoCaptureDeviceController2)->get_LowLagPhoto(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::SceneModeControl consume_Windows_Media_Devices_IAdvancedVideoCaptureDeviceController2<D>::SceneModeControl() const
{
    Windows::Media::Devices::SceneModeControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedVideoCaptureDeviceController2)->get_SceneModeControl(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::TorchControl consume_Windows_Media_Devices_IAdvancedVideoCaptureDeviceController2<D>::TorchControl() const
{
    Windows::Media::Devices::TorchControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedVideoCaptureDeviceController2)->get_TorchControl(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::FlashControl consume_Windows_Media_Devices_IAdvancedVideoCaptureDeviceController2<D>::FlashControl() const
{
    Windows::Media::Devices::FlashControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedVideoCaptureDeviceController2)->get_FlashControl(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::WhiteBalanceControl consume_Windows_Media_Devices_IAdvancedVideoCaptureDeviceController2<D>::WhiteBalanceControl() const
{
    Windows::Media::Devices::WhiteBalanceControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedVideoCaptureDeviceController2)->get_WhiteBalanceControl(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::ExposureControl consume_Windows_Media_Devices_IAdvancedVideoCaptureDeviceController2<D>::ExposureControl() const
{
    Windows::Media::Devices::ExposureControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedVideoCaptureDeviceController2)->get_ExposureControl(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::FocusControl consume_Windows_Media_Devices_IAdvancedVideoCaptureDeviceController2<D>::FocusControl() const
{
    Windows::Media::Devices::FocusControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedVideoCaptureDeviceController2)->get_FocusControl(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::ExposureCompensationControl consume_Windows_Media_Devices_IAdvancedVideoCaptureDeviceController2<D>::ExposureCompensationControl() const
{
    Windows::Media::Devices::ExposureCompensationControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedVideoCaptureDeviceController2)->get_ExposureCompensationControl(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::IsoSpeedControl consume_Windows_Media_Devices_IAdvancedVideoCaptureDeviceController2<D>::IsoSpeedControl() const
{
    Windows::Media::Devices::IsoSpeedControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedVideoCaptureDeviceController2)->get_IsoSpeedControl(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::RegionsOfInterestControl consume_Windows_Media_Devices_IAdvancedVideoCaptureDeviceController2<D>::RegionsOfInterestControl() const
{
    Windows::Media::Devices::RegionsOfInterestControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedVideoCaptureDeviceController2)->get_RegionsOfInterestControl(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::CaptureUse consume_Windows_Media_Devices_IAdvancedVideoCaptureDeviceController2<D>::PrimaryUse() const
{
    Windows::Media::Devices::CaptureUse value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedVideoCaptureDeviceController2)->get_PrimaryUse(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IAdvancedVideoCaptureDeviceController2<D>::PrimaryUse(Windows::Media::Devices::CaptureUse const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedVideoCaptureDeviceController2)->put_PrimaryUse(get_abi(value)));
}

template <typename D> Windows::Media::Devices::Core::VariablePhotoSequenceController consume_Windows_Media_Devices_IAdvancedVideoCaptureDeviceController3<D>::VariablePhotoSequenceController() const
{
    Windows::Media::Devices::Core::VariablePhotoSequenceController value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedVideoCaptureDeviceController3)->get_VariablePhotoSequenceController(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::PhotoConfirmationControl consume_Windows_Media_Devices_IAdvancedVideoCaptureDeviceController3<D>::PhotoConfirmationControl() const
{
    Windows::Media::Devices::PhotoConfirmationControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedVideoCaptureDeviceController3)->get_PhotoConfirmationControl(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::ZoomControl consume_Windows_Media_Devices_IAdvancedVideoCaptureDeviceController3<D>::ZoomControl() const
{
    Windows::Media::Devices::ZoomControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedVideoCaptureDeviceController3)->get_ZoomControl(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::ExposurePriorityVideoControl consume_Windows_Media_Devices_IAdvancedVideoCaptureDeviceController4<D>::ExposurePriorityVideoControl() const
{
    Windows::Media::Devices::ExposurePriorityVideoControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedVideoCaptureDeviceController4)->get_ExposurePriorityVideoControl(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::MediaCaptureOptimization consume_Windows_Media_Devices_IAdvancedVideoCaptureDeviceController4<D>::DesiredOptimization() const
{
    Windows::Media::Devices::MediaCaptureOptimization value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedVideoCaptureDeviceController4)->get_DesiredOptimization(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IAdvancedVideoCaptureDeviceController4<D>::DesiredOptimization(Windows::Media::Devices::MediaCaptureOptimization const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedVideoCaptureDeviceController4)->put_DesiredOptimization(get_abi(value)));
}

template <typename D> Windows::Media::Devices::HdrVideoControl consume_Windows_Media_Devices_IAdvancedVideoCaptureDeviceController4<D>::HdrVideoControl() const
{
    Windows::Media::Devices::HdrVideoControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedVideoCaptureDeviceController4)->get_HdrVideoControl(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::OpticalImageStabilizationControl consume_Windows_Media_Devices_IAdvancedVideoCaptureDeviceController4<D>::OpticalImageStabilizationControl() const
{
    Windows::Media::Devices::OpticalImageStabilizationControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedVideoCaptureDeviceController4)->get_OpticalImageStabilizationControl(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::AdvancedPhotoControl consume_Windows_Media_Devices_IAdvancedVideoCaptureDeviceController4<D>::AdvancedPhotoControl() const
{
    Windows::Media::Devices::AdvancedPhotoControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedVideoCaptureDeviceController4)->get_AdvancedPhotoControl(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Devices_IAdvancedVideoCaptureDeviceController5<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedVideoCaptureDeviceController5)->get_Id(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::VideoDeviceControllerGetDevicePropertyResult consume_Windows_Media_Devices_IAdvancedVideoCaptureDeviceController5<D>::GetDevicePropertyById(param::hstring const& propertyId, optional<uint32_t> const& maxPropertyValueSize) const
{
    Windows::Media::Devices::VideoDeviceControllerGetDevicePropertyResult value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedVideoCaptureDeviceController5)->GetDevicePropertyById(get_abi(propertyId), get_abi(maxPropertyValueSize), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::VideoDeviceControllerSetDevicePropertyStatus consume_Windows_Media_Devices_IAdvancedVideoCaptureDeviceController5<D>::SetDevicePropertyById(param::hstring const& propertyId, Windows::Foundation::IInspectable const& propertyValue) const
{
    Windows::Media::Devices::VideoDeviceControllerSetDevicePropertyStatus value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedVideoCaptureDeviceController5)->SetDevicePropertyById(get_abi(propertyId), get_abi(propertyValue), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::VideoDeviceControllerGetDevicePropertyResult consume_Windows_Media_Devices_IAdvancedVideoCaptureDeviceController5<D>::GetDevicePropertyByExtendedId(array_view<uint8_t const> extendedPropertyId, optional<uint32_t> const& maxPropertyValueSize) const
{
    Windows::Media::Devices::VideoDeviceControllerGetDevicePropertyResult value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedVideoCaptureDeviceController5)->GetDevicePropertyByExtendedId(extendedPropertyId.size(), get_abi(extendedPropertyId), get_abi(maxPropertyValueSize), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::VideoDeviceControllerSetDevicePropertyStatus consume_Windows_Media_Devices_IAdvancedVideoCaptureDeviceController5<D>::SetDevicePropertyByExtendedId(array_view<uint8_t const> extendedPropertyId, array_view<uint8_t const> propertyValue) const
{
    Windows::Media::Devices::VideoDeviceControllerSetDevicePropertyStatus value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedVideoCaptureDeviceController5)->SetDevicePropertyByExtendedId(extendedPropertyId.size(), get_abi(extendedPropertyId), propertyValue.size(), get_abi(propertyValue), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::VideoTemporalDenoisingControl consume_Windows_Media_Devices_IAdvancedVideoCaptureDeviceController6<D>::VideoTemporalDenoisingControl() const
{
    Windows::Media::Devices::VideoTemporalDenoisingControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedVideoCaptureDeviceController6)->get_VideoTemporalDenoisingControl(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::InfraredTorchControl consume_Windows_Media_Devices_IAdvancedVideoCaptureDeviceController7<D>::InfraredTorchControl() const
{
    Windows::Media::Devices::InfraredTorchControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAdvancedVideoCaptureDeviceController7)->get_InfraredTorchControl(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IAudioDeviceController<D>::Muted(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAudioDeviceController)->put_Muted(value));
}

template <typename D> bool consume_Windows_Media_Devices_IAudioDeviceController<D>::Muted() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAudioDeviceController)->get_Muted(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IAudioDeviceController<D>::VolumePercent(float value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAudioDeviceController)->put_VolumePercent(value));
}

template <typename D> float consume_Windows_Media_Devices_IAudioDeviceController<D>::VolumePercent() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAudioDeviceController)->get_VolumePercent(&value));
    return value;
}

template <typename D> hstring consume_Windows_Media_Devices_IAudioDeviceModule<D>::ClassId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAudioDeviceModule)->get_ClassId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Devices_IAudioDeviceModule<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAudioDeviceModule)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Devices_IAudioDeviceModule<D>::InstanceId() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAudioDeviceModule)->get_InstanceId(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Devices_IAudioDeviceModule<D>::MajorVersion() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAudioDeviceModule)->get_MajorVersion(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Devices_IAudioDeviceModule<D>::MinorVersion() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAudioDeviceModule)->get_MinorVersion(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Devices::ModuleCommandResult> consume_Windows_Media_Devices_IAudioDeviceModule<D>::SendCommandAsync(Windows::Storage::Streams::IBuffer const& Command) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Devices::ModuleCommandResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAudioDeviceModule)->SendCommandAsync(get_abi(Command), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Media::Devices::AudioDeviceModule consume_Windows_Media_Devices_IAudioDeviceModuleNotificationEventArgs<D>::Module() const
{
    Windows::Media::Devices::AudioDeviceModule value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAudioDeviceModuleNotificationEventArgs)->get_Module(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Media_Devices_IAudioDeviceModuleNotificationEventArgs<D>::NotificationData() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAudioDeviceModuleNotificationEventArgs)->get_NotificationData(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Devices_IAudioDeviceModulesManager<D>::ModuleNotificationReceived(Windows::Foundation::TypedEventHandler<Windows::Media::Devices::AudioDeviceModulesManager, Windows::Media::Devices::AudioDeviceModuleNotificationEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAudioDeviceModulesManager)->add_ModuleNotificationReceived(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Devices_IAudioDeviceModulesManager<D>::ModuleNotificationReceived_revoker consume_Windows_Media_Devices_IAudioDeviceModulesManager<D>::ModuleNotificationReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Devices::AudioDeviceModulesManager, Windows::Media::Devices::AudioDeviceModuleNotificationEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ModuleNotificationReceived_revoker>(this, ModuleNotificationReceived(handler));
}

template <typename D> void consume_Windows_Media_Devices_IAudioDeviceModulesManager<D>::ModuleNotificationReceived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Devices::IAudioDeviceModulesManager)->remove_ModuleNotificationReceived(get_abi(token)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::AudioDeviceModule> consume_Windows_Media_Devices_IAudioDeviceModulesManager<D>::FindAllById(param::hstring const& moduleId) const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::AudioDeviceModule> modules{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAudioDeviceModulesManager)->FindAllById(get_abi(moduleId), put_abi(modules)));
    return modules;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::AudioDeviceModule> consume_Windows_Media_Devices_IAudioDeviceModulesManager<D>::FindAll() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::AudioDeviceModule> modules{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAudioDeviceModulesManager)->FindAll(put_abi(modules)));
    return modules;
}

template <typename D> Windows::Media::Devices::AudioDeviceModulesManager consume_Windows_Media_Devices_IAudioDeviceModulesManagerFactory<D>::Create(param::hstring const& deviceId) const
{
    Windows::Media::Devices::AudioDeviceModulesManager result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IAudioDeviceModulesManagerFactory)->Create(get_abi(deviceId), put_abi(result)));
    return result;
}

template <typename D> uint64_t consume_Windows_Media_Devices_ICallControl<D>::IndicateNewIncomingCall(bool enableRinger, param::hstring const& callerId) const
{
    uint64_t callToken{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ICallControl)->IndicateNewIncomingCall(enableRinger, get_abi(callerId), &callToken));
    return callToken;
}

template <typename D> uint64_t consume_Windows_Media_Devices_ICallControl<D>::IndicateNewOutgoingCall() const
{
    uint64_t callToken{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ICallControl)->IndicateNewOutgoingCall(&callToken));
    return callToken;
}

template <typename D> void consume_Windows_Media_Devices_ICallControl<D>::IndicateActiveCall(uint64_t callToken) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ICallControl)->IndicateActiveCall(callToken));
}

template <typename D> void consume_Windows_Media_Devices_ICallControl<D>::EndCall(uint64_t callToken) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ICallControl)->EndCall(callToken));
}

template <typename D> bool consume_Windows_Media_Devices_ICallControl<D>::HasRinger() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ICallControl)->get_HasRinger(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Devices_ICallControl<D>::AnswerRequested(Windows::Media::Devices::CallControlEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ICallControl)->add_AnswerRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Devices_ICallControl<D>::AnswerRequested_revoker consume_Windows_Media_Devices_ICallControl<D>::AnswerRequested(auto_revoke_t, Windows::Media::Devices::CallControlEventHandler const& handler) const
{
    return impl::make_event_revoker<D, AnswerRequested_revoker>(this, AnswerRequested(handler));
}

template <typename D> void consume_Windows_Media_Devices_ICallControl<D>::AnswerRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Devices::ICallControl)->remove_AnswerRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Devices_ICallControl<D>::HangUpRequested(Windows::Media::Devices::CallControlEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ICallControl)->add_HangUpRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Devices_ICallControl<D>::HangUpRequested_revoker consume_Windows_Media_Devices_ICallControl<D>::HangUpRequested(auto_revoke_t, Windows::Media::Devices::CallControlEventHandler const& handler) const
{
    return impl::make_event_revoker<D, HangUpRequested_revoker>(this, HangUpRequested(handler));
}

template <typename D> void consume_Windows_Media_Devices_ICallControl<D>::HangUpRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Devices::ICallControl)->remove_HangUpRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Devices_ICallControl<D>::DialRequested(Windows::Media::Devices::DialRequestedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ICallControl)->add_DialRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Devices_ICallControl<D>::DialRequested_revoker consume_Windows_Media_Devices_ICallControl<D>::DialRequested(auto_revoke_t, Windows::Media::Devices::DialRequestedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, DialRequested_revoker>(this, DialRequested(handler));
}

template <typename D> void consume_Windows_Media_Devices_ICallControl<D>::DialRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Devices::ICallControl)->remove_DialRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Devices_ICallControl<D>::RedialRequested(Windows::Media::Devices::RedialRequestedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ICallControl)->add_RedialRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Devices_ICallControl<D>::RedialRequested_revoker consume_Windows_Media_Devices_ICallControl<D>::RedialRequested(auto_revoke_t, Windows::Media::Devices::RedialRequestedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, RedialRequested_revoker>(this, RedialRequested(handler));
}

template <typename D> void consume_Windows_Media_Devices_ICallControl<D>::RedialRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Devices::ICallControl)->remove_RedialRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Devices_ICallControl<D>::KeypadPressed(Windows::Media::Devices::KeypadPressedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ICallControl)->add_KeypadPressed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Devices_ICallControl<D>::KeypadPressed_revoker consume_Windows_Media_Devices_ICallControl<D>::KeypadPressed(auto_revoke_t, Windows::Media::Devices::KeypadPressedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, KeypadPressed_revoker>(this, KeypadPressed(handler));
}

template <typename D> void consume_Windows_Media_Devices_ICallControl<D>::KeypadPressed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Devices::ICallControl)->remove_KeypadPressed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Devices_ICallControl<D>::AudioTransferRequested(Windows::Media::Devices::CallControlEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ICallControl)->add_AudioTransferRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Devices_ICallControl<D>::AudioTransferRequested_revoker consume_Windows_Media_Devices_ICallControl<D>::AudioTransferRequested(auto_revoke_t, Windows::Media::Devices::CallControlEventHandler const& handler) const
{
    return impl::make_event_revoker<D, AudioTransferRequested_revoker>(this, AudioTransferRequested(handler));
}

template <typename D> void consume_Windows_Media_Devices_ICallControl<D>::AudioTransferRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Devices::ICallControl)->remove_AudioTransferRequested(get_abi(token)));
}

template <typename D> Windows::Media::Devices::CallControl consume_Windows_Media_Devices_ICallControlStatics<D>::GetDefault() const
{
    Windows::Media::Devices::CallControl callControl{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ICallControlStatics)->GetDefault(put_abi(callControl)));
    return callControl;
}

template <typename D> Windows::Media::Devices::CallControl consume_Windows_Media_Devices_ICallControlStatics<D>::FromId(param::hstring const& deviceId) const
{
    Windows::Media::Devices::CallControl callControl{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ICallControlStatics)->FromId(get_abi(deviceId), put_abi(callControl)));
    return callControl;
}

template <typename D> hstring consume_Windows_Media_Devices_IDefaultAudioDeviceChangedEventArgs<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IDefaultAudioDeviceChangedEventArgs)->get_Id(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::AudioDeviceRole consume_Windows_Media_Devices_IDefaultAudioDeviceChangedEventArgs<D>::Role() const
{
    Windows::Media::Devices::AudioDeviceRole value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IDefaultAudioDeviceChangedEventArgs)->get_Role(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IDialRequestedEventArgs<D>::Handled() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IDialRequestedEventArgs)->Handled());
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Media_Devices_IDialRequestedEventArgs<D>::Contact() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IDialRequestedEventArgs)->get_Contact(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Devices_IExposureCompensationControl<D>::Supported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IExposureCompensationControl)->get_Supported(&value));
    return value;
}

template <typename D> float consume_Windows_Media_Devices_IExposureCompensationControl<D>::Min() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IExposureCompensationControl)->get_Min(&value));
    return value;
}

template <typename D> float consume_Windows_Media_Devices_IExposureCompensationControl<D>::Max() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IExposureCompensationControl)->get_Max(&value));
    return value;
}

template <typename D> float consume_Windows_Media_Devices_IExposureCompensationControl<D>::Step() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IExposureCompensationControl)->get_Step(&value));
    return value;
}

template <typename D> float consume_Windows_Media_Devices_IExposureCompensationControl<D>::Value() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IExposureCompensationControl)->get_Value(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Devices_IExposureCompensationControl<D>::SetValueAsync(float value) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IExposureCompensationControl)->SetValueAsync(value, put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> bool consume_Windows_Media_Devices_IExposureControl<D>::Supported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IExposureControl)->get_Supported(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Devices_IExposureControl<D>::Auto() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IExposureControl)->get_Auto(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Devices_IExposureControl<D>::SetAutoAsync(bool value) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IExposureControl)->SetAutoAsync(value, put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Devices_IExposureControl<D>::Min() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IExposureControl)->get_Min(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Devices_IExposureControl<D>::Max() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IExposureControl)->get_Max(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Devices_IExposureControl<D>::Step() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IExposureControl)->get_Step(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Devices_IExposureControl<D>::Value() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IExposureControl)->get_Value(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Devices_IExposureControl<D>::SetValueAsync(Windows::Foundation::TimeSpan const& shutterDuration) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IExposureControl)->SetValueAsync(get_abi(shutterDuration), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> bool consume_Windows_Media_Devices_IExposurePriorityVideoControl<D>::Supported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IExposurePriorityVideoControl)->get_Supported(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Devices_IExposurePriorityVideoControl<D>::Enabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IExposurePriorityVideoControl)->get_Enabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IExposurePriorityVideoControl<D>::Enabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IExposurePriorityVideoControl)->put_Enabled(value));
}

template <typename D> bool consume_Windows_Media_Devices_IFlashControl<D>::Supported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFlashControl)->get_Supported(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Devices_IFlashControl<D>::PowerSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFlashControl)->get_PowerSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Devices_IFlashControl<D>::RedEyeReductionSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFlashControl)->get_RedEyeReductionSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Devices_IFlashControl<D>::Enabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFlashControl)->get_Enabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IFlashControl<D>::Enabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFlashControl)->put_Enabled(value));
}

template <typename D> bool consume_Windows_Media_Devices_IFlashControl<D>::Auto() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFlashControl)->get_Auto(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IFlashControl<D>::Auto(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFlashControl)->put_Auto(value));
}

template <typename D> bool consume_Windows_Media_Devices_IFlashControl<D>::RedEyeReduction() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFlashControl)->get_RedEyeReduction(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IFlashControl<D>::RedEyeReduction(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFlashControl)->put_RedEyeReduction(value));
}

template <typename D> float consume_Windows_Media_Devices_IFlashControl<D>::PowerPercent() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFlashControl)->get_PowerPercent(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IFlashControl<D>::PowerPercent(float value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFlashControl)->put_PowerPercent(value));
}

template <typename D> bool consume_Windows_Media_Devices_IFlashControl2<D>::AssistantLightSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFlashControl2)->get_AssistantLightSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Devices_IFlashControl2<D>::AssistantLightEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFlashControl2)->get_AssistantLightEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IFlashControl2<D>::AssistantLightEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFlashControl2)->put_AssistantLightEnabled(value));
}

template <typename D> bool consume_Windows_Media_Devices_IFocusControl<D>::Supported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFocusControl)->get_Supported(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::FocusPreset> consume_Windows_Media_Devices_IFocusControl<D>::SupportedPresets() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::FocusPreset> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFocusControl)->get_SupportedPresets(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::FocusPreset consume_Windows_Media_Devices_IFocusControl<D>::Preset() const
{
    Windows::Media::Devices::FocusPreset value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFocusControl)->get_Preset(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Devices_IFocusControl<D>::SetPresetAsync(Windows::Media::Devices::FocusPreset const& preset) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFocusControl)->SetPresetAsync(get_abi(preset), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Devices_IFocusControl<D>::SetPresetAsync(Windows::Media::Devices::FocusPreset const& preset, bool completeBeforeFocus) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFocusControl)->SetPresetWithCompletionOptionAsync(get_abi(preset), completeBeforeFocus, put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> uint32_t consume_Windows_Media_Devices_IFocusControl<D>::Min() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFocusControl)->get_Min(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Devices_IFocusControl<D>::Max() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFocusControl)->get_Max(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Devices_IFocusControl<D>::Step() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFocusControl)->get_Step(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Devices_IFocusControl<D>::Value() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFocusControl)->get_Value(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Devices_IFocusControl<D>::SetValueAsync(uint32_t focus) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFocusControl)->SetValueAsync(focus, put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Devices_IFocusControl<D>::FocusAsync() const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFocusControl)->FocusAsync(put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> bool consume_Windows_Media_Devices_IFocusControl2<D>::FocusChangedSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFocusControl2)->get_FocusChangedSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Devices_IFocusControl2<D>::WaitForFocusSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFocusControl2)->get_WaitForFocusSupported(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::FocusMode> consume_Windows_Media_Devices_IFocusControl2<D>::SupportedFocusModes() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::FocusMode> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFocusControl2)->get_SupportedFocusModes(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::ManualFocusDistance> consume_Windows_Media_Devices_IFocusControl2<D>::SupportedFocusDistances() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::ManualFocusDistance> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFocusControl2)->get_SupportedFocusDistances(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::AutoFocusRange> consume_Windows_Media_Devices_IFocusControl2<D>::SupportedFocusRanges() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::AutoFocusRange> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFocusControl2)->get_SupportedFocusRanges(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::FocusMode consume_Windows_Media_Devices_IFocusControl2<D>::Mode() const
{
    Windows::Media::Devices::FocusMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFocusControl2)->get_Mode(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::MediaCaptureFocusState consume_Windows_Media_Devices_IFocusControl2<D>::FocusState() const
{
    Windows::Media::Devices::MediaCaptureFocusState value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFocusControl2)->get_FocusState(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Devices_IFocusControl2<D>::UnlockAsync() const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFocusControl2)->UnlockAsync(put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Devices_IFocusControl2<D>::LockAsync() const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFocusControl2)->LockAsync(put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> void consume_Windows_Media_Devices_IFocusControl2<D>::Configure(Windows::Media::Devices::FocusSettings const& settings) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFocusControl2)->Configure(get_abi(settings)));
}

template <typename D> Windows::Media::Devices::FocusMode consume_Windows_Media_Devices_IFocusSettings<D>::Mode() const
{
    Windows::Media::Devices::FocusMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFocusSettings)->get_Mode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IFocusSettings<D>::Mode(Windows::Media::Devices::FocusMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFocusSettings)->put_Mode(get_abi(value)));
}

template <typename D> Windows::Media::Devices::AutoFocusRange consume_Windows_Media_Devices_IFocusSettings<D>::AutoFocusRange() const
{
    Windows::Media::Devices::AutoFocusRange value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFocusSettings)->get_AutoFocusRange(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IFocusSettings<D>::AutoFocusRange(Windows::Media::Devices::AutoFocusRange const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFocusSettings)->put_AutoFocusRange(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_Media_Devices_IFocusSettings<D>::Value() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFocusSettings)->get_Value(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IFocusSettings<D>::Value(optional<uint32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFocusSettings)->put_Value(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Media::Devices::ManualFocusDistance> consume_Windows_Media_Devices_IFocusSettings<D>::Distance() const
{
    Windows::Foundation::IReference<Windows::Media::Devices::ManualFocusDistance> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFocusSettings)->get_Distance(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IFocusSettings<D>::Distance(optional<Windows::Media::Devices::ManualFocusDistance> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFocusSettings)->put_Distance(get_abi(value)));
}

template <typename D> bool consume_Windows_Media_Devices_IFocusSettings<D>::WaitForFocus() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFocusSettings)->get_WaitForFocus(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IFocusSettings<D>::WaitForFocus(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFocusSettings)->put_WaitForFocus(value));
}

template <typename D> bool consume_Windows_Media_Devices_IFocusSettings<D>::DisableDriverFallback() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFocusSettings)->get_DisableDriverFallback(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IFocusSettings<D>::DisableDriverFallback(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IFocusSettings)->put_DisableDriverFallback(value));
}

template <typename D> bool consume_Windows_Media_Devices_IHdrVideoControl<D>::Supported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IHdrVideoControl)->get_Supported(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::HdrVideoMode> consume_Windows_Media_Devices_IHdrVideoControl<D>::SupportedModes() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::HdrVideoMode> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IHdrVideoControl)->get_SupportedModes(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::HdrVideoMode consume_Windows_Media_Devices_IHdrVideoControl<D>::Mode() const
{
    Windows::Media::Devices::HdrVideoMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IHdrVideoControl)->get_Mode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IHdrVideoControl<D>::Mode(Windows::Media::Devices::HdrVideoMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IHdrVideoControl)->put_Mode(get_abi(value)));
}

template <typename D> bool consume_Windows_Media_Devices_IInfraredTorchControl<D>::IsSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IInfraredTorchControl)->get_IsSupported(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::InfraredTorchMode> consume_Windows_Media_Devices_IInfraredTorchControl<D>::SupportedModes() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::InfraredTorchMode> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IInfraredTorchControl)->get_SupportedModes(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::InfraredTorchMode consume_Windows_Media_Devices_IInfraredTorchControl<D>::CurrentMode() const
{
    Windows::Media::Devices::InfraredTorchMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IInfraredTorchControl)->get_CurrentMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IInfraredTorchControl<D>::CurrentMode(Windows::Media::Devices::InfraredTorchMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IInfraredTorchControl)->put_CurrentMode(get_abi(value)));
}

template <typename D> int32_t consume_Windows_Media_Devices_IInfraredTorchControl<D>::MinPower() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IInfraredTorchControl)->get_MinPower(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Media_Devices_IInfraredTorchControl<D>::MaxPower() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IInfraredTorchControl)->get_MaxPower(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Media_Devices_IInfraredTorchControl<D>::PowerStep() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IInfraredTorchControl)->get_PowerStep(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Media_Devices_IInfraredTorchControl<D>::Power() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IInfraredTorchControl)->get_Power(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IInfraredTorchControl<D>::Power(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IInfraredTorchControl)->put_Power(value));
}

template <typename D> bool consume_Windows_Media_Devices_IIsoSpeedControl<D>::Supported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IIsoSpeedControl)->get_Supported(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::IsoSpeedPreset> consume_Windows_Media_Devices_IIsoSpeedControl<D>::SupportedPresets() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::IsoSpeedPreset> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IIsoSpeedControl)->get_SupportedPresets(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::IsoSpeedPreset consume_Windows_Media_Devices_IIsoSpeedControl<D>::Preset() const
{
    Windows::Media::Devices::IsoSpeedPreset value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IIsoSpeedControl)->get_Preset(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Devices_IIsoSpeedControl<D>::SetPresetAsync(Windows::Media::Devices::IsoSpeedPreset const& preset) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IIsoSpeedControl)->SetPresetAsync(get_abi(preset), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> uint32_t consume_Windows_Media_Devices_IIsoSpeedControl2<D>::Min() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IIsoSpeedControl2)->get_Min(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Devices_IIsoSpeedControl2<D>::Max() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IIsoSpeedControl2)->get_Max(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Devices_IIsoSpeedControl2<D>::Step() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IIsoSpeedControl2)->get_Step(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Devices_IIsoSpeedControl2<D>::Value() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IIsoSpeedControl2)->get_Value(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Devices_IIsoSpeedControl2<D>::SetValueAsync(uint32_t isoSpeed) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IIsoSpeedControl2)->SetValueAsync(isoSpeed, put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> bool consume_Windows_Media_Devices_IIsoSpeedControl2<D>::Auto() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IIsoSpeedControl2)->get_Auto(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Devices_IIsoSpeedControl2<D>::SetAutoAsync() const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IIsoSpeedControl2)->SetAutoAsync(put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Media::Devices::TelephonyKey consume_Windows_Media_Devices_IKeypadPressedEventArgs<D>::TelephonyKey() const
{
    Windows::Media::Devices::TelephonyKey telephonyKey{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IKeypadPressedEventArgs)->get_TelephonyKey(put_abi(telephonyKey)));
    return telephonyKey;
}

template <typename D> Windows::Media::MediaProperties::MediaRatio consume_Windows_Media_Devices_ILowLagPhotoControl<D>::GetHighestConcurrentFrameRate(Windows::Media::MediaProperties::IMediaEncodingProperties const& captureProperties) const
{
    Windows::Media::MediaProperties::MediaRatio value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ILowLagPhotoControl)->GetHighestConcurrentFrameRate(get_abi(captureProperties), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::MediaRatio consume_Windows_Media_Devices_ILowLagPhotoControl<D>::GetCurrentFrameRate() const
{
    Windows::Media::MediaProperties::MediaRatio value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ILowLagPhotoControl)->GetCurrentFrameRate(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Devices_ILowLagPhotoControl<D>::ThumbnailEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ILowLagPhotoControl)->get_ThumbnailEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_ILowLagPhotoControl<D>::ThumbnailEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ILowLagPhotoControl)->put_ThumbnailEnabled(value));
}

template <typename D> Windows::Media::MediaProperties::MediaThumbnailFormat consume_Windows_Media_Devices_ILowLagPhotoControl<D>::ThumbnailFormat() const
{
    Windows::Media::MediaProperties::MediaThumbnailFormat value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ILowLagPhotoControl)->get_ThumbnailFormat(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_ILowLagPhotoControl<D>::ThumbnailFormat(Windows::Media::MediaProperties::MediaThumbnailFormat const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ILowLagPhotoControl)->put_ThumbnailFormat(get_abi(value)));
}

template <typename D> uint32_t consume_Windows_Media_Devices_ILowLagPhotoControl<D>::DesiredThumbnailSize() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ILowLagPhotoControl)->get_DesiredThumbnailSize(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_ILowLagPhotoControl<D>::DesiredThumbnailSize(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ILowLagPhotoControl)->put_DesiredThumbnailSize(value));
}

template <typename D> uint32_t consume_Windows_Media_Devices_ILowLagPhotoControl<D>::HardwareAcceleratedThumbnailSupported() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ILowLagPhotoControl)->get_HardwareAcceleratedThumbnailSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Devices_ILowLagPhotoSequenceControl<D>::Supported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ILowLagPhotoSequenceControl)->get_Supported(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Devices_ILowLagPhotoSequenceControl<D>::MaxPastPhotos() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ILowLagPhotoSequenceControl)->get_MaxPastPhotos(&value));
    return value;
}

template <typename D> float consume_Windows_Media_Devices_ILowLagPhotoSequenceControl<D>::MaxPhotosPerSecond() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ILowLagPhotoSequenceControl)->get_MaxPhotosPerSecond(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Devices_ILowLagPhotoSequenceControl<D>::PastPhotoLimit() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ILowLagPhotoSequenceControl)->get_PastPhotoLimit(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_ILowLagPhotoSequenceControl<D>::PastPhotoLimit(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ILowLagPhotoSequenceControl)->put_PastPhotoLimit(value));
}

template <typename D> float consume_Windows_Media_Devices_ILowLagPhotoSequenceControl<D>::PhotosPerSecondLimit() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ILowLagPhotoSequenceControl)->get_PhotosPerSecondLimit(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_ILowLagPhotoSequenceControl<D>::PhotosPerSecondLimit(float value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ILowLagPhotoSequenceControl)->put_PhotosPerSecondLimit(value));
}

template <typename D> Windows::Media::MediaProperties::MediaRatio consume_Windows_Media_Devices_ILowLagPhotoSequenceControl<D>::GetHighestConcurrentFrameRate(Windows::Media::MediaProperties::IMediaEncodingProperties const& captureProperties) const
{
    Windows::Media::MediaProperties::MediaRatio value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ILowLagPhotoSequenceControl)->GetHighestConcurrentFrameRate(get_abi(captureProperties), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::MediaRatio consume_Windows_Media_Devices_ILowLagPhotoSequenceControl<D>::GetCurrentFrameRate() const
{
    Windows::Media::MediaProperties::MediaRatio value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ILowLagPhotoSequenceControl)->GetCurrentFrameRate(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Devices_ILowLagPhotoSequenceControl<D>::ThumbnailEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ILowLagPhotoSequenceControl)->get_ThumbnailEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_ILowLagPhotoSequenceControl<D>::ThumbnailEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ILowLagPhotoSequenceControl)->put_ThumbnailEnabled(value));
}

template <typename D> Windows::Media::MediaProperties::MediaThumbnailFormat consume_Windows_Media_Devices_ILowLagPhotoSequenceControl<D>::ThumbnailFormat() const
{
    Windows::Media::MediaProperties::MediaThumbnailFormat value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ILowLagPhotoSequenceControl)->get_ThumbnailFormat(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_ILowLagPhotoSequenceControl<D>::ThumbnailFormat(Windows::Media::MediaProperties::MediaThumbnailFormat const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ILowLagPhotoSequenceControl)->put_ThumbnailFormat(get_abi(value)));
}

template <typename D> uint32_t consume_Windows_Media_Devices_ILowLagPhotoSequenceControl<D>::DesiredThumbnailSize() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ILowLagPhotoSequenceControl)->get_DesiredThumbnailSize(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_ILowLagPhotoSequenceControl<D>::DesiredThumbnailSize(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ILowLagPhotoSequenceControl)->put_DesiredThumbnailSize(value));
}

template <typename D> uint32_t consume_Windows_Media_Devices_ILowLagPhotoSequenceControl<D>::HardwareAcceleratedThumbnailSupported() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ILowLagPhotoSequenceControl)->get_HardwareAcceleratedThumbnailSupported(&value));
    return value;
}

template <typename D> Windows::Media::Devices::MediaDeviceControlCapabilities consume_Windows_Media_Devices_IMediaDeviceControl<D>::Capabilities() const
{
    Windows::Media::Devices::MediaDeviceControlCapabilities value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IMediaDeviceControl)->get_Capabilities(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Devices_IMediaDeviceControl<D>::TryGetValue(double& value) const
{
    bool succeeded{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IMediaDeviceControl)->TryGetValue(&value, &succeeded));
    return succeeded;
}

template <typename D> bool consume_Windows_Media_Devices_IMediaDeviceControl<D>::TrySetValue(double value) const
{
    bool succeeded{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IMediaDeviceControl)->TrySetValue(value, &succeeded));
    return succeeded;
}

template <typename D> bool consume_Windows_Media_Devices_IMediaDeviceControl<D>::TryGetAuto(bool& value) const
{
    bool succeeded{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IMediaDeviceControl)->TryGetAuto(&value, &succeeded));
    return succeeded;
}

template <typename D> bool consume_Windows_Media_Devices_IMediaDeviceControl<D>::TrySetAuto(bool value) const
{
    bool succeeded{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IMediaDeviceControl)->TrySetAuto(value, &succeeded));
    return succeeded;
}

template <typename D> bool consume_Windows_Media_Devices_IMediaDeviceControlCapabilities<D>::Supported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IMediaDeviceControlCapabilities)->get_Supported(&value));
    return value;
}

template <typename D> double consume_Windows_Media_Devices_IMediaDeviceControlCapabilities<D>::Min() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IMediaDeviceControlCapabilities)->get_Min(&value));
    return value;
}

template <typename D> double consume_Windows_Media_Devices_IMediaDeviceControlCapabilities<D>::Max() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IMediaDeviceControlCapabilities)->get_Max(&value));
    return value;
}

template <typename D> double consume_Windows_Media_Devices_IMediaDeviceControlCapabilities<D>::Step() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IMediaDeviceControlCapabilities)->get_Step(&value));
    return value;
}

template <typename D> double consume_Windows_Media_Devices_IMediaDeviceControlCapabilities<D>::Default() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IMediaDeviceControlCapabilities)->get_Default(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Devices_IMediaDeviceControlCapabilities<D>::AutoModeSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IMediaDeviceControlCapabilities)->get_AutoModeSupported(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::MediaProperties::IMediaEncodingProperties> consume_Windows_Media_Devices_IMediaDeviceController<D>::GetAvailableMediaStreamProperties(Windows::Media::Capture::MediaStreamType const& mediaStreamType) const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::MediaProperties::IMediaEncodingProperties> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IMediaDeviceController)->GetAvailableMediaStreamProperties(get_abi(mediaStreamType), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::IMediaEncodingProperties consume_Windows_Media_Devices_IMediaDeviceController<D>::GetMediaStreamProperties(Windows::Media::Capture::MediaStreamType const& mediaStreamType) const
{
    Windows::Media::MediaProperties::IMediaEncodingProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IMediaDeviceController)->GetMediaStreamProperties(get_abi(mediaStreamType), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Devices_IMediaDeviceController<D>::SetMediaStreamPropertiesAsync(Windows::Media::Capture::MediaStreamType const& mediaStreamType, Windows::Media::MediaProperties::IMediaEncodingProperties const& mediaEncodingProperties) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IMediaDeviceController)->SetMediaStreamPropertiesAsync(get_abi(mediaStreamType), get_abi(mediaEncodingProperties), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> hstring consume_Windows_Media_Devices_IMediaDeviceStatics<D>::GetAudioCaptureSelector() const
{
    hstring selector{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IMediaDeviceStatics)->GetAudioCaptureSelector(put_abi(selector)));
    return selector;
}

template <typename D> hstring consume_Windows_Media_Devices_IMediaDeviceStatics<D>::GetAudioRenderSelector() const
{
    hstring selector{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IMediaDeviceStatics)->GetAudioRenderSelector(put_abi(selector)));
    return selector;
}

template <typename D> hstring consume_Windows_Media_Devices_IMediaDeviceStatics<D>::GetVideoCaptureSelector() const
{
    hstring selector{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IMediaDeviceStatics)->GetVideoCaptureSelector(put_abi(selector)));
    return selector;
}

template <typename D> hstring consume_Windows_Media_Devices_IMediaDeviceStatics<D>::GetDefaultAudioCaptureId(Windows::Media::Devices::AudioDeviceRole const& role) const
{
    hstring deviceId{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IMediaDeviceStatics)->GetDefaultAudioCaptureId(get_abi(role), put_abi(deviceId)));
    return deviceId;
}

template <typename D> hstring consume_Windows_Media_Devices_IMediaDeviceStatics<D>::GetDefaultAudioRenderId(Windows::Media::Devices::AudioDeviceRole const& role) const
{
    hstring deviceId{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IMediaDeviceStatics)->GetDefaultAudioRenderId(get_abi(role), put_abi(deviceId)));
    return deviceId;
}

template <typename D> winrt::event_token consume_Windows_Media_Devices_IMediaDeviceStatics<D>::DefaultAudioCaptureDeviceChanged(Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Media::Devices::DefaultAudioCaptureDeviceChangedEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IMediaDeviceStatics)->add_DefaultAudioCaptureDeviceChanged(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Media_Devices_IMediaDeviceStatics<D>::DefaultAudioCaptureDeviceChanged_revoker consume_Windows_Media_Devices_IMediaDeviceStatics<D>::DefaultAudioCaptureDeviceChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Media::Devices::DefaultAudioCaptureDeviceChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, DefaultAudioCaptureDeviceChanged_revoker>(this, DefaultAudioCaptureDeviceChanged(handler));
}

template <typename D> void consume_Windows_Media_Devices_IMediaDeviceStatics<D>::DefaultAudioCaptureDeviceChanged(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Devices::IMediaDeviceStatics)->remove_DefaultAudioCaptureDeviceChanged(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_Media_Devices_IMediaDeviceStatics<D>::DefaultAudioRenderDeviceChanged(Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Media::Devices::DefaultAudioRenderDeviceChangedEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IMediaDeviceStatics)->add_DefaultAudioRenderDeviceChanged(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Media_Devices_IMediaDeviceStatics<D>::DefaultAudioRenderDeviceChanged_revoker consume_Windows_Media_Devices_IMediaDeviceStatics<D>::DefaultAudioRenderDeviceChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Media::Devices::DefaultAudioRenderDeviceChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, DefaultAudioRenderDeviceChanged_revoker>(this, DefaultAudioRenderDeviceChanged(handler));
}

template <typename D> void consume_Windows_Media_Devices_IMediaDeviceStatics<D>::DefaultAudioRenderDeviceChanged(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Devices::IMediaDeviceStatics)->remove_DefaultAudioRenderDeviceChanged(get_abi(cookie)));
}

template <typename D> Windows::Media::Devices::SendCommandStatus consume_Windows_Media_Devices_IModuleCommandResult<D>::Status() const
{
    Windows::Media::Devices::SendCommandStatus value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IModuleCommandResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Media_Devices_IModuleCommandResult<D>::Result() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IModuleCommandResult)->get_Result(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Devices_IOpticalImageStabilizationControl<D>::Supported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IOpticalImageStabilizationControl)->get_Supported(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::OpticalImageStabilizationMode> consume_Windows_Media_Devices_IOpticalImageStabilizationControl<D>::SupportedModes() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::OpticalImageStabilizationMode> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IOpticalImageStabilizationControl)->get_SupportedModes(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::OpticalImageStabilizationMode consume_Windows_Media_Devices_IOpticalImageStabilizationControl<D>::Mode() const
{
    Windows::Media::Devices::OpticalImageStabilizationMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IOpticalImageStabilizationControl)->get_Mode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IOpticalImageStabilizationControl<D>::Mode(Windows::Media::Devices::OpticalImageStabilizationMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IOpticalImageStabilizationControl)->put_Mode(get_abi(value)));
}

template <typename D> bool consume_Windows_Media_Devices_IPhotoConfirmationControl<D>::Supported() const
{
    bool pbSupported{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IPhotoConfirmationControl)->get_Supported(&pbSupported));
    return pbSupported;
}

template <typename D> bool consume_Windows_Media_Devices_IPhotoConfirmationControl<D>::Enabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IPhotoConfirmationControl)->get_Enabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IPhotoConfirmationControl<D>::Enabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IPhotoConfirmationControl)->put_Enabled(value));
}

template <typename D> Windows::Media::MediaProperties::MediaPixelFormat consume_Windows_Media_Devices_IPhotoConfirmationControl<D>::PixelFormat() const
{
    Windows::Media::MediaProperties::MediaPixelFormat format{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IPhotoConfirmationControl)->get_PixelFormat(put_abi(format)));
    return format;
}

template <typename D> void consume_Windows_Media_Devices_IPhotoConfirmationControl<D>::PixelFormat(Windows::Media::MediaProperties::MediaPixelFormat const& format) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IPhotoConfirmationControl)->put_PixelFormat(get_abi(format)));
}

template <typename D> void consume_Windows_Media_Devices_IRedialRequestedEventArgs<D>::Handled() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IRedialRequestedEventArgs)->Handled());
}

template <typename D> bool consume_Windows_Media_Devices_IRegionOfInterest<D>::AutoFocusEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IRegionOfInterest)->get_AutoFocusEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IRegionOfInterest<D>::AutoFocusEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IRegionOfInterest)->put_AutoFocusEnabled(value));
}

template <typename D> bool consume_Windows_Media_Devices_IRegionOfInterest<D>::AutoWhiteBalanceEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IRegionOfInterest)->get_AutoWhiteBalanceEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IRegionOfInterest<D>::AutoWhiteBalanceEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IRegionOfInterest)->put_AutoWhiteBalanceEnabled(value));
}

template <typename D> bool consume_Windows_Media_Devices_IRegionOfInterest<D>::AutoExposureEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IRegionOfInterest)->get_AutoExposureEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IRegionOfInterest<D>::AutoExposureEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IRegionOfInterest)->put_AutoExposureEnabled(value));
}

template <typename D> Windows::Foundation::Rect consume_Windows_Media_Devices_IRegionOfInterest<D>::Bounds() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IRegionOfInterest)->get_Bounds(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IRegionOfInterest<D>::Bounds(Windows::Foundation::Rect const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IRegionOfInterest)->put_Bounds(get_abi(value)));
}

template <typename D> Windows::Media::Devices::RegionOfInterestType consume_Windows_Media_Devices_IRegionOfInterest2<D>::Type() const
{
    Windows::Media::Devices::RegionOfInterestType value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IRegionOfInterest2)->get_Type(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IRegionOfInterest2<D>::Type(Windows::Media::Devices::RegionOfInterestType const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IRegionOfInterest2)->put_Type(get_abi(value)));
}

template <typename D> bool consume_Windows_Media_Devices_IRegionOfInterest2<D>::BoundsNormalized() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IRegionOfInterest2)->get_BoundsNormalized(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IRegionOfInterest2<D>::BoundsNormalized(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IRegionOfInterest2)->put_BoundsNormalized(value));
}

template <typename D> uint32_t consume_Windows_Media_Devices_IRegionOfInterest2<D>::Weight() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IRegionOfInterest2)->get_Weight(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IRegionOfInterest2<D>::Weight(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IRegionOfInterest2)->put_Weight(value));
}

template <typename D> uint32_t consume_Windows_Media_Devices_IRegionsOfInterestControl<D>::MaxRegions() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IRegionsOfInterestControl)->get_MaxRegions(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Devices_IRegionsOfInterestControl<D>::SetRegionsAsync(param::async_iterable<Windows::Media::Devices::RegionOfInterest> const& regions) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IRegionsOfInterestControl)->SetRegionsAsync(get_abi(regions), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Devices_IRegionsOfInterestControl<D>::SetRegionsAsync(param::async_iterable<Windows::Media::Devices::RegionOfInterest> const& regions, bool lockValues) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IRegionsOfInterestControl)->SetRegionsWithLockAsync(get_abi(regions), lockValues, put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Devices_IRegionsOfInterestControl<D>::ClearRegionsAsync() const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IRegionsOfInterestControl)->ClearRegionsAsync(put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> bool consume_Windows_Media_Devices_IRegionsOfInterestControl<D>::AutoFocusSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IRegionsOfInterestControl)->get_AutoFocusSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Devices_IRegionsOfInterestControl<D>::AutoWhiteBalanceSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IRegionsOfInterestControl)->get_AutoWhiteBalanceSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Devices_IRegionsOfInterestControl<D>::AutoExposureSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IRegionsOfInterestControl)->get_AutoExposureSupported(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::CaptureSceneMode> consume_Windows_Media_Devices_ISceneModeControl<D>::SupportedModes() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::CaptureSceneMode> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ISceneModeControl)->get_SupportedModes(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::CaptureSceneMode consume_Windows_Media_Devices_ISceneModeControl<D>::Value() const
{
    Windows::Media::Devices::CaptureSceneMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ISceneModeControl)->get_Value(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Devices_ISceneModeControl<D>::SetValueAsync(Windows::Media::Devices::CaptureSceneMode const& sceneMode) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ISceneModeControl)->SetValueAsync(get_abi(sceneMode), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> bool consume_Windows_Media_Devices_ITorchControl<D>::Supported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ITorchControl)->get_Supported(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Devices_ITorchControl<D>::PowerSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ITorchControl)->get_PowerSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Devices_ITorchControl<D>::Enabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ITorchControl)->get_Enabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_ITorchControl<D>::Enabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ITorchControl)->put_Enabled(value));
}

template <typename D> float consume_Windows_Media_Devices_ITorchControl<D>::PowerPercent() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ITorchControl)->get_PowerPercent(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_ITorchControl<D>::PowerPercent(float value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::ITorchControl)->put_PowerPercent(value));
}

template <typename D> Windows::Media::Devices::MediaDeviceControl consume_Windows_Media_Devices_IVideoDeviceController<D>::Brightness() const
{
    Windows::Media::Devices::MediaDeviceControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IVideoDeviceController)->get_Brightness(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::MediaDeviceControl consume_Windows_Media_Devices_IVideoDeviceController<D>::Contrast() const
{
    Windows::Media::Devices::MediaDeviceControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IVideoDeviceController)->get_Contrast(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::MediaDeviceControl consume_Windows_Media_Devices_IVideoDeviceController<D>::Hue() const
{
    Windows::Media::Devices::MediaDeviceControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IVideoDeviceController)->get_Hue(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::MediaDeviceControl consume_Windows_Media_Devices_IVideoDeviceController<D>::WhiteBalance() const
{
    Windows::Media::Devices::MediaDeviceControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IVideoDeviceController)->get_WhiteBalance(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::MediaDeviceControl consume_Windows_Media_Devices_IVideoDeviceController<D>::BacklightCompensation() const
{
    Windows::Media::Devices::MediaDeviceControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IVideoDeviceController)->get_BacklightCompensation(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::MediaDeviceControl consume_Windows_Media_Devices_IVideoDeviceController<D>::Pan() const
{
    Windows::Media::Devices::MediaDeviceControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IVideoDeviceController)->get_Pan(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::MediaDeviceControl consume_Windows_Media_Devices_IVideoDeviceController<D>::Tilt() const
{
    Windows::Media::Devices::MediaDeviceControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IVideoDeviceController)->get_Tilt(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::MediaDeviceControl consume_Windows_Media_Devices_IVideoDeviceController<D>::Zoom() const
{
    Windows::Media::Devices::MediaDeviceControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IVideoDeviceController)->get_Zoom(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::MediaDeviceControl consume_Windows_Media_Devices_IVideoDeviceController<D>::Roll() const
{
    Windows::Media::Devices::MediaDeviceControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IVideoDeviceController)->get_Roll(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::MediaDeviceControl consume_Windows_Media_Devices_IVideoDeviceController<D>::Exposure() const
{
    Windows::Media::Devices::MediaDeviceControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IVideoDeviceController)->get_Exposure(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::MediaDeviceControl consume_Windows_Media_Devices_IVideoDeviceController<D>::Focus() const
{
    Windows::Media::Devices::MediaDeviceControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IVideoDeviceController)->get_Focus(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Devices_IVideoDeviceController<D>::TrySetPowerlineFrequency(Windows::Media::Capture::PowerlineFrequency const& value) const
{
    bool succeeded{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IVideoDeviceController)->TrySetPowerlineFrequency(get_abi(value), &succeeded));
    return succeeded;
}

template <typename D> bool consume_Windows_Media_Devices_IVideoDeviceController<D>::TryGetPowerlineFrequency(Windows::Media::Capture::PowerlineFrequency& value) const
{
    bool succeeded{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IVideoDeviceController)->TryGetPowerlineFrequency(put_abi(value), &succeeded));
    return succeeded;
}

template <typename D> Windows::Media::Devices::VideoDeviceControllerGetDevicePropertyStatus consume_Windows_Media_Devices_IVideoDeviceControllerGetDevicePropertyResult<D>::Status() const
{
    Windows::Media::Devices::VideoDeviceControllerGetDevicePropertyStatus value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IVideoDeviceControllerGetDevicePropertyResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Media_Devices_IVideoDeviceControllerGetDevicePropertyResult<D>::Value() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IVideoDeviceControllerGetDevicePropertyResult)->get_Value(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Devices_IVideoTemporalDenoisingControl<D>::Supported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IVideoTemporalDenoisingControl)->get_Supported(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::VideoTemporalDenoisingMode> consume_Windows_Media_Devices_IVideoTemporalDenoisingControl<D>::SupportedModes() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::VideoTemporalDenoisingMode> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IVideoTemporalDenoisingControl)->get_SupportedModes(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::VideoTemporalDenoisingMode consume_Windows_Media_Devices_IVideoTemporalDenoisingControl<D>::Mode() const
{
    Windows::Media::Devices::VideoTemporalDenoisingMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IVideoTemporalDenoisingControl)->get_Mode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IVideoTemporalDenoisingControl<D>::Mode(Windows::Media::Devices::VideoTemporalDenoisingMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IVideoTemporalDenoisingControl)->put_Mode(get_abi(value)));
}

template <typename D> bool consume_Windows_Media_Devices_IWhiteBalanceControl<D>::Supported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IWhiteBalanceControl)->get_Supported(&value));
    return value;
}

template <typename D> Windows::Media::Devices::ColorTemperaturePreset consume_Windows_Media_Devices_IWhiteBalanceControl<D>::Preset() const
{
    Windows::Media::Devices::ColorTemperaturePreset value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IWhiteBalanceControl)->get_Preset(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Devices_IWhiteBalanceControl<D>::SetPresetAsync(Windows::Media::Devices::ColorTemperaturePreset const& preset) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IWhiteBalanceControl)->SetPresetAsync(get_abi(preset), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> uint32_t consume_Windows_Media_Devices_IWhiteBalanceControl<D>::Min() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IWhiteBalanceControl)->get_Min(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Devices_IWhiteBalanceControl<D>::Max() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IWhiteBalanceControl)->get_Max(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Devices_IWhiteBalanceControl<D>::Step() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IWhiteBalanceControl)->get_Step(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Devices_IWhiteBalanceControl<D>::Value() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IWhiteBalanceControl)->get_Value(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Devices_IWhiteBalanceControl<D>::SetValueAsync(uint32_t temperature) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IWhiteBalanceControl)->SetValueAsync(temperature, put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> bool consume_Windows_Media_Devices_IZoomControl<D>::Supported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IZoomControl)->get_Supported(&value));
    return value;
}

template <typename D> float consume_Windows_Media_Devices_IZoomControl<D>::Min() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IZoomControl)->get_Min(&value));
    return value;
}

template <typename D> float consume_Windows_Media_Devices_IZoomControl<D>::Max() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IZoomControl)->get_Max(&value));
    return value;
}

template <typename D> float consume_Windows_Media_Devices_IZoomControl<D>::Step() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IZoomControl)->get_Step(&value));
    return value;
}

template <typename D> float consume_Windows_Media_Devices_IZoomControl<D>::Value() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IZoomControl)->get_Value(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IZoomControl<D>::Value(float value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IZoomControl)->put_Value(value));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::ZoomTransitionMode> consume_Windows_Media_Devices_IZoomControl2<D>::SupportedModes() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::ZoomTransitionMode> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IZoomControl2)->get_SupportedModes(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::ZoomTransitionMode consume_Windows_Media_Devices_IZoomControl2<D>::Mode() const
{
    Windows::Media::Devices::ZoomTransitionMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IZoomControl2)->get_Mode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IZoomControl2<D>::Configure(Windows::Media::Devices::ZoomSettings const& settings) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IZoomControl2)->Configure(get_abi(settings)));
}

template <typename D> Windows::Media::Devices::ZoomTransitionMode consume_Windows_Media_Devices_IZoomSettings<D>::Mode() const
{
    Windows::Media::Devices::ZoomTransitionMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IZoomSettings)->get_Mode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IZoomSettings<D>::Mode(Windows::Media::Devices::ZoomTransitionMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IZoomSettings)->put_Mode(get_abi(value)));
}

template <typename D> float consume_Windows_Media_Devices_IZoomSettings<D>::Value() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IZoomSettings)->get_Value(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_IZoomSettings<D>::Value(float value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::IZoomSettings)->put_Value(value));
}

template <> struct delegate<Windows::Media::Devices::CallControlEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::Media::Devices::CallControlEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::Media::Devices::CallControlEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Media::Devices::CallControl const*>(&sender));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::Media::Devices::DialRequestedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::Media::Devices::DialRequestedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::Media::Devices::DialRequestedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Media::Devices::CallControl const*>(&sender), *reinterpret_cast<Windows::Media::Devices::DialRequestedEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::Media::Devices::KeypadPressedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::Media::Devices::KeypadPressedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::Media::Devices::KeypadPressedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Media::Devices::CallControl const*>(&sender), *reinterpret_cast<Windows::Media::Devices::KeypadPressedEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::Media::Devices::RedialRequestedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::Media::Devices::RedialRequestedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::Media::Devices::RedialRequestedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Media::Devices::CallControl const*>(&sender), *reinterpret_cast<Windows::Media::Devices::RedialRequestedEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <typename D>
struct produce<D, Windows::Media::Devices::IAdvancedPhotoCaptureSettings> : produce_base<D, Windows::Media::Devices::IAdvancedPhotoCaptureSettings>
{
    int32_t WINRT_CALL get_Mode(Windows::Media::Devices::AdvancedPhotoMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(Windows::Media::Devices::AdvancedPhotoMode));
            *value = detach_from<Windows::Media::Devices::AdvancedPhotoMode>(this->shim().Mode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Mode(Windows::Media::Devices::AdvancedPhotoMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(void), Windows::Media::Devices::AdvancedPhotoMode const&);
            this->shim().Mode(*reinterpret_cast<Windows::Media::Devices::AdvancedPhotoMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IAdvancedPhotoControl> : produce_base<D, Windows::Media::Devices::IAdvancedPhotoControl>
{
    int32_t WINRT_CALL get_Supported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Supported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Supported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedModes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedModes, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::AdvancedPhotoMode>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::AdvancedPhotoMode>>(this->shim().SupportedModes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Mode(Windows::Media::Devices::AdvancedPhotoMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(Windows::Media::Devices::AdvancedPhotoMode));
            *value = detach_from<Windows::Media::Devices::AdvancedPhotoMode>(this->shim().Mode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Configure(void* settings) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Configure, WINRT_WRAP(void), Windows::Media::Devices::AdvancedPhotoCaptureSettings const&);
            this->shim().Configure(*reinterpret_cast<Windows::Media::Devices::AdvancedPhotoCaptureSettings const*>(&settings));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IAdvancedVideoCaptureDeviceController> : produce_base<D, Windows::Media::Devices::IAdvancedVideoCaptureDeviceController>
{
    int32_t WINRT_CALL SetDeviceProperty(void* propertyId, void* propertyValue) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetDeviceProperty, WINRT_WRAP(void), hstring const&, Windows::Foundation::IInspectable const&);
            this->shim().SetDeviceProperty(*reinterpret_cast<hstring const*>(&propertyId), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&propertyValue));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceProperty(void* propertyId, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceProperty, WINRT_WRAP(Windows::Foundation::IInspectable), hstring const&);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().GetDeviceProperty(*reinterpret_cast<hstring const*>(&propertyId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IAdvancedVideoCaptureDeviceController2> : produce_base<D, Windows::Media::Devices::IAdvancedVideoCaptureDeviceController2>
{
    int32_t WINRT_CALL get_LowLagPhotoSequence(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LowLagPhotoSequence, WINRT_WRAP(Windows::Media::Devices::LowLagPhotoSequenceControl));
            *value = detach_from<Windows::Media::Devices::LowLagPhotoSequenceControl>(this->shim().LowLagPhotoSequence());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LowLagPhoto(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LowLagPhoto, WINRT_WRAP(Windows::Media::Devices::LowLagPhotoControl));
            *value = detach_from<Windows::Media::Devices::LowLagPhotoControl>(this->shim().LowLagPhoto());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SceneModeControl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SceneModeControl, WINRT_WRAP(Windows::Media::Devices::SceneModeControl));
            *value = detach_from<Windows::Media::Devices::SceneModeControl>(this->shim().SceneModeControl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TorchControl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TorchControl, WINRT_WRAP(Windows::Media::Devices::TorchControl));
            *value = detach_from<Windows::Media::Devices::TorchControl>(this->shim().TorchControl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FlashControl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FlashControl, WINRT_WRAP(Windows::Media::Devices::FlashControl));
            *value = detach_from<Windows::Media::Devices::FlashControl>(this->shim().FlashControl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WhiteBalanceControl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WhiteBalanceControl, WINRT_WRAP(Windows::Media::Devices::WhiteBalanceControl));
            *value = detach_from<Windows::Media::Devices::WhiteBalanceControl>(this->shim().WhiteBalanceControl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExposureControl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExposureControl, WINRT_WRAP(Windows::Media::Devices::ExposureControl));
            *value = detach_from<Windows::Media::Devices::ExposureControl>(this->shim().ExposureControl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FocusControl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusControl, WINRT_WRAP(Windows::Media::Devices::FocusControl));
            *value = detach_from<Windows::Media::Devices::FocusControl>(this->shim().FocusControl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExposureCompensationControl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExposureCompensationControl, WINRT_WRAP(Windows::Media::Devices::ExposureCompensationControl));
            *value = detach_from<Windows::Media::Devices::ExposureCompensationControl>(this->shim().ExposureCompensationControl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsoSpeedControl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsoSpeedControl, WINRT_WRAP(Windows::Media::Devices::IsoSpeedControl));
            *value = detach_from<Windows::Media::Devices::IsoSpeedControl>(this->shim().IsoSpeedControl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RegionsOfInterestControl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegionsOfInterestControl, WINRT_WRAP(Windows::Media::Devices::RegionsOfInterestControl));
            *value = detach_from<Windows::Media::Devices::RegionsOfInterestControl>(this->shim().RegionsOfInterestControl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PrimaryUse(Windows::Media::Devices::CaptureUse* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrimaryUse, WINRT_WRAP(Windows::Media::Devices::CaptureUse));
            *value = detach_from<Windows::Media::Devices::CaptureUse>(this->shim().PrimaryUse());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PrimaryUse(Windows::Media::Devices::CaptureUse value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrimaryUse, WINRT_WRAP(void), Windows::Media::Devices::CaptureUse const&);
            this->shim().PrimaryUse(*reinterpret_cast<Windows::Media::Devices::CaptureUse const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IAdvancedVideoCaptureDeviceController3> : produce_base<D, Windows::Media::Devices::IAdvancedVideoCaptureDeviceController3>
{
    int32_t WINRT_CALL get_VariablePhotoSequenceController(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VariablePhotoSequenceController, WINRT_WRAP(Windows::Media::Devices::Core::VariablePhotoSequenceController));
            *value = detach_from<Windows::Media::Devices::Core::VariablePhotoSequenceController>(this->shim().VariablePhotoSequenceController());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PhotoConfirmationControl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhotoConfirmationControl, WINRT_WRAP(Windows::Media::Devices::PhotoConfirmationControl));
            *value = detach_from<Windows::Media::Devices::PhotoConfirmationControl>(this->shim().PhotoConfirmationControl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ZoomControl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZoomControl, WINRT_WRAP(Windows::Media::Devices::ZoomControl));
            *value = detach_from<Windows::Media::Devices::ZoomControl>(this->shim().ZoomControl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IAdvancedVideoCaptureDeviceController4> : produce_base<D, Windows::Media::Devices::IAdvancedVideoCaptureDeviceController4>
{
    int32_t WINRT_CALL get_ExposurePriorityVideoControl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExposurePriorityVideoControl, WINRT_WRAP(Windows::Media::Devices::ExposurePriorityVideoControl));
            *value = detach_from<Windows::Media::Devices::ExposurePriorityVideoControl>(this->shim().ExposurePriorityVideoControl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DesiredOptimization(Windows::Media::Devices::MediaCaptureOptimization* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredOptimization, WINRT_WRAP(Windows::Media::Devices::MediaCaptureOptimization));
            *value = detach_from<Windows::Media::Devices::MediaCaptureOptimization>(this->shim().DesiredOptimization());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DesiredOptimization(Windows::Media::Devices::MediaCaptureOptimization value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredOptimization, WINRT_WRAP(void), Windows::Media::Devices::MediaCaptureOptimization const&);
            this->shim().DesiredOptimization(*reinterpret_cast<Windows::Media::Devices::MediaCaptureOptimization const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HdrVideoControl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HdrVideoControl, WINRT_WRAP(Windows::Media::Devices::HdrVideoControl));
            *value = detach_from<Windows::Media::Devices::HdrVideoControl>(this->shim().HdrVideoControl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OpticalImageStabilizationControl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpticalImageStabilizationControl, WINRT_WRAP(Windows::Media::Devices::OpticalImageStabilizationControl));
            *value = detach_from<Windows::Media::Devices::OpticalImageStabilizationControl>(this->shim().OpticalImageStabilizationControl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AdvancedPhotoControl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AdvancedPhotoControl, WINRT_WRAP(Windows::Media::Devices::AdvancedPhotoControl));
            *value = detach_from<Windows::Media::Devices::AdvancedPhotoControl>(this->shim().AdvancedPhotoControl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IAdvancedVideoCaptureDeviceController5> : produce_base<D, Windows::Media::Devices::IAdvancedVideoCaptureDeviceController5>
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

    int32_t WINRT_CALL GetDevicePropertyById(void* propertyId, void* maxPropertyValueSize, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDevicePropertyById, WINRT_WRAP(Windows::Media::Devices::VideoDeviceControllerGetDevicePropertyResult), hstring const&, Windows::Foundation::IReference<uint32_t> const&);
            *value = detach_from<Windows::Media::Devices::VideoDeviceControllerGetDevicePropertyResult>(this->shim().GetDevicePropertyById(*reinterpret_cast<hstring const*>(&propertyId), *reinterpret_cast<Windows::Foundation::IReference<uint32_t> const*>(&maxPropertyValueSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetDevicePropertyById(void* propertyId, void* propertyValue, Windows::Media::Devices::VideoDeviceControllerSetDevicePropertyStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetDevicePropertyById, WINRT_WRAP(Windows::Media::Devices::VideoDeviceControllerSetDevicePropertyStatus), hstring const&, Windows::Foundation::IInspectable const&);
            *value = detach_from<Windows::Media::Devices::VideoDeviceControllerSetDevicePropertyStatus>(this->shim().SetDevicePropertyById(*reinterpret_cast<hstring const*>(&propertyId), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&propertyValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDevicePropertyByExtendedId(uint32_t __extendedPropertyIdSize, uint8_t* extendedPropertyId, void* maxPropertyValueSize, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDevicePropertyByExtendedId, WINRT_WRAP(Windows::Media::Devices::VideoDeviceControllerGetDevicePropertyResult), array_view<uint8_t const>, Windows::Foundation::IReference<uint32_t> const&);
            *value = detach_from<Windows::Media::Devices::VideoDeviceControllerGetDevicePropertyResult>(this->shim().GetDevicePropertyByExtendedId(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(extendedPropertyId), reinterpret_cast<uint8_t const *>(extendedPropertyId) + __extendedPropertyIdSize), *reinterpret_cast<Windows::Foundation::IReference<uint32_t> const*>(&maxPropertyValueSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetDevicePropertyByExtendedId(uint32_t __extendedPropertyIdSize, uint8_t* extendedPropertyId, uint32_t __propertyValueSize, uint8_t* propertyValue, Windows::Media::Devices::VideoDeviceControllerSetDevicePropertyStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetDevicePropertyByExtendedId, WINRT_WRAP(Windows::Media::Devices::VideoDeviceControllerSetDevicePropertyStatus), array_view<uint8_t const>, array_view<uint8_t const>);
            *value = detach_from<Windows::Media::Devices::VideoDeviceControllerSetDevicePropertyStatus>(this->shim().SetDevicePropertyByExtendedId(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(extendedPropertyId), reinterpret_cast<uint8_t const *>(extendedPropertyId) + __extendedPropertyIdSize), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(propertyValue), reinterpret_cast<uint8_t const *>(propertyValue) + __propertyValueSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IAdvancedVideoCaptureDeviceController6> : produce_base<D, Windows::Media::Devices::IAdvancedVideoCaptureDeviceController6>
{
    int32_t WINRT_CALL get_VideoTemporalDenoisingControl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoTemporalDenoisingControl, WINRT_WRAP(Windows::Media::Devices::VideoTemporalDenoisingControl));
            *value = detach_from<Windows::Media::Devices::VideoTemporalDenoisingControl>(this->shim().VideoTemporalDenoisingControl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IAdvancedVideoCaptureDeviceController7> : produce_base<D, Windows::Media::Devices::IAdvancedVideoCaptureDeviceController7>
{
    int32_t WINRT_CALL get_InfraredTorchControl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InfraredTorchControl, WINRT_WRAP(Windows::Media::Devices::InfraredTorchControl));
            *value = detach_from<Windows::Media::Devices::InfraredTorchControl>(this->shim().InfraredTorchControl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IAudioDeviceController> : produce_base<D, Windows::Media::Devices::IAudioDeviceController>
{
    int32_t WINRT_CALL put_Muted(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Muted, WINRT_WRAP(void), bool);
            this->shim().Muted(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Muted(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Muted, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Muted());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_VolumePercent(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VolumePercent, WINRT_WRAP(void), float);
            this->shim().VolumePercent(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VolumePercent(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VolumePercent, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().VolumePercent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IAudioDeviceModule> : produce_base<D, Windows::Media::Devices::IAudioDeviceModule>
{
    int32_t WINRT_CALL get_ClassId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClassId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ClassId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InstanceId(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InstanceId, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().InstanceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MajorVersion(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MajorVersion, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MajorVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinorVersion(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinorVersion, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MinorVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SendCommandAsync(void* Command, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendCommandAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Devices::ModuleCommandResult>), Windows::Storage::Streams::IBuffer const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Devices::ModuleCommandResult>>(this->shim().SendCommandAsync(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&Command)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IAudioDeviceModuleNotificationEventArgs> : produce_base<D, Windows::Media::Devices::IAudioDeviceModuleNotificationEventArgs>
{
    int32_t WINRT_CALL get_Module(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Module, WINRT_WRAP(Windows::Media::Devices::AudioDeviceModule));
            *value = detach_from<Windows::Media::Devices::AudioDeviceModule>(this->shim().Module());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NotificationData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotificationData, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().NotificationData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IAudioDeviceModulesManager> : produce_base<D, Windows::Media::Devices::IAudioDeviceModulesManager>
{
    int32_t WINRT_CALL add_ModuleNotificationReceived(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ModuleNotificationReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Devices::AudioDeviceModulesManager, Windows::Media::Devices::AudioDeviceModuleNotificationEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ModuleNotificationReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Devices::AudioDeviceModulesManager, Windows::Media::Devices::AudioDeviceModuleNotificationEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ModuleNotificationReceived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ModuleNotificationReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ModuleNotificationReceived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL FindAllById(void* moduleId, void** modules) noexcept final
    {
        try
        {
            *modules = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAllById, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::AudioDeviceModule>), hstring const&);
            *modules = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::AudioDeviceModule>>(this->shim().FindAllById(*reinterpret_cast<hstring const*>(&moduleId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAll(void** modules) noexcept final
    {
        try
        {
            *modules = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAll, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::AudioDeviceModule>));
            *modules = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::AudioDeviceModule>>(this->shim().FindAll());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IAudioDeviceModulesManagerFactory> : produce_base<D, Windows::Media::Devices::IAudioDeviceModulesManagerFactory>
{
    int32_t WINRT_CALL Create(void* deviceId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Media::Devices::AudioDeviceModulesManager), hstring const&);
            *result = detach_from<Windows::Media::Devices::AudioDeviceModulesManager>(this->shim().Create(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::ICallControl> : produce_base<D, Windows::Media::Devices::ICallControl>
{
    int32_t WINRT_CALL IndicateNewIncomingCall(bool enableRinger, void* callerId, uint64_t* callToken) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IndicateNewIncomingCall, WINRT_WRAP(uint64_t), bool, hstring const&);
            *callToken = detach_from<uint64_t>(this->shim().IndicateNewIncomingCall(enableRinger, *reinterpret_cast<hstring const*>(&callerId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IndicateNewOutgoingCall(uint64_t* callToken) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IndicateNewOutgoingCall, WINRT_WRAP(uint64_t));
            *callToken = detach_from<uint64_t>(this->shim().IndicateNewOutgoingCall());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IndicateActiveCall(uint64_t callToken) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IndicateActiveCall, WINRT_WRAP(void), uint64_t);
            this->shim().IndicateActiveCall(callToken);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EndCall(uint64_t callToken) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndCall, WINRT_WRAP(void), uint64_t);
            this->shim().EndCall(callToken);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasRinger(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasRinger, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasRinger());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_AnswerRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AnswerRequested, WINRT_WRAP(winrt::event_token), Windows::Media::Devices::CallControlEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().AnswerRequested(*reinterpret_cast<Windows::Media::Devices::CallControlEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AnswerRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AnswerRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AnswerRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_HangUpRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HangUpRequested, WINRT_WRAP(winrt::event_token), Windows::Media::Devices::CallControlEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().HangUpRequested(*reinterpret_cast<Windows::Media::Devices::CallControlEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_HangUpRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(HangUpRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().HangUpRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_DialRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DialRequested, WINRT_WRAP(winrt::event_token), Windows::Media::Devices::DialRequestedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().DialRequested(*reinterpret_cast<Windows::Media::Devices::DialRequestedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DialRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DialRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DialRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_RedialRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RedialRequested, WINRT_WRAP(winrt::event_token), Windows::Media::Devices::RedialRequestedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().RedialRequested(*reinterpret_cast<Windows::Media::Devices::RedialRequestedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RedialRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RedialRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RedialRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_KeypadPressed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeypadPressed, WINRT_WRAP(winrt::event_token), Windows::Media::Devices::KeypadPressedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().KeypadPressed(*reinterpret_cast<Windows::Media::Devices::KeypadPressedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_KeypadPressed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(KeypadPressed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().KeypadPressed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_AudioTransferRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioTransferRequested, WINRT_WRAP(winrt::event_token), Windows::Media::Devices::CallControlEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().AudioTransferRequested(*reinterpret_cast<Windows::Media::Devices::CallControlEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AudioTransferRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AudioTransferRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AudioTransferRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::ICallControlStatics> : produce_base<D, Windows::Media::Devices::ICallControlStatics>
{
    int32_t WINRT_CALL GetDefault(void** callControl) noexcept final
    {
        try
        {
            *callControl = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Media::Devices::CallControl));
            *callControl = detach_from<Windows::Media::Devices::CallControl>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromId(void* deviceId, void** callControl) noexcept final
    {
        try
        {
            *callControl = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromId, WINRT_WRAP(Windows::Media::Devices::CallControl), hstring const&);
            *callControl = detach_from<Windows::Media::Devices::CallControl>(this->shim().FromId(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IDefaultAudioDeviceChangedEventArgs> : produce_base<D, Windows::Media::Devices::IDefaultAudioDeviceChangedEventArgs>
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

    int32_t WINRT_CALL get_Role(Windows::Media::Devices::AudioDeviceRole* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Role, WINRT_WRAP(Windows::Media::Devices::AudioDeviceRole));
            *value = detach_from<Windows::Media::Devices::AudioDeviceRole>(this->shim().Role());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IDialRequestedEventArgs> : produce_base<D, Windows::Media::Devices::IDialRequestedEventArgs>
{
    int32_t WINRT_CALL Handled() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(void));
            this->shim().Handled();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Contact(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Contact, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().Contact());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IExposureCompensationControl> : produce_base<D, Windows::Media::Devices::IExposureCompensationControl>
{
    int32_t WINRT_CALL get_Supported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Supported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Supported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Min(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Min, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Min());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Max(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Max, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Max());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Step(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Step, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Step());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Value(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetValueAsync(float value, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetValueAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), float);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetValueAsync(value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IExposureControl> : produce_base<D, Windows::Media::Devices::IExposureControl>
{
    int32_t WINRT_CALL get_Supported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Supported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Supported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Auto(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Auto, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Auto());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetAutoAsync(bool value, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetAutoAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), bool);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetAutoAsync(value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Min(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Min, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Min());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Max(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Max, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Max());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Step(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Step, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Step());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Value(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetValueAsync(Windows::Foundation::TimeSpan shutterDuration, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetValueAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Foundation::TimeSpan const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetValueAsync(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&shutterDuration)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IExposurePriorityVideoControl> : produce_base<D, Windows::Media::Devices::IExposurePriorityVideoControl>
{
    int32_t WINRT_CALL get_Supported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Supported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Supported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Enabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Enabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Enabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Enabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Enabled, WINRT_WRAP(void), bool);
            this->shim().Enabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IFlashControl> : produce_base<D, Windows::Media::Devices::IFlashControl>
{
    int32_t WINRT_CALL get_Supported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Supported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Supported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PowerSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PowerSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().PowerSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RedEyeReductionSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RedEyeReductionSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().RedEyeReductionSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Enabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Enabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Enabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Enabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Enabled, WINRT_WRAP(void), bool);
            this->shim().Enabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Auto(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Auto, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Auto());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Auto(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Auto, WINRT_WRAP(void), bool);
            this->shim().Auto(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RedEyeReduction(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RedEyeReduction, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().RedEyeReduction());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RedEyeReduction(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RedEyeReduction, WINRT_WRAP(void), bool);
            this->shim().RedEyeReduction(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PowerPercent(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PowerPercent, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().PowerPercent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PowerPercent(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PowerPercent, WINRT_WRAP(void), float);
            this->shim().PowerPercent(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IFlashControl2> : produce_base<D, Windows::Media::Devices::IFlashControl2>
{
    int32_t WINRT_CALL get_AssistantLightSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AssistantLightSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AssistantLightSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AssistantLightEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AssistantLightEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AssistantLightEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AssistantLightEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AssistantLightEnabled, WINRT_WRAP(void), bool);
            this->shim().AssistantLightEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IFocusControl> : produce_base<D, Windows::Media::Devices::IFocusControl>
{
    int32_t WINRT_CALL get_Supported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Supported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Supported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedPresets(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedPresets, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::FocusPreset>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::FocusPreset>>(this->shim().SupportedPresets());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Preset(Windows::Media::Devices::FocusPreset* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Preset, WINRT_WRAP(Windows::Media::Devices::FocusPreset));
            *value = detach_from<Windows::Media::Devices::FocusPreset>(this->shim().Preset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPresetAsync(Windows::Media::Devices::FocusPreset preset, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPresetAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Media::Devices::FocusPreset const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetPresetAsync(*reinterpret_cast<Windows::Media::Devices::FocusPreset const*>(&preset)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPresetWithCompletionOptionAsync(Windows::Media::Devices::FocusPreset preset, bool completeBeforeFocus, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPresetAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Media::Devices::FocusPreset const, bool);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetPresetAsync(*reinterpret_cast<Windows::Media::Devices::FocusPreset const*>(&preset), completeBeforeFocus));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Min(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Min, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Min());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Max(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Max, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Max());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Step(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Step, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Step());
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

    int32_t WINRT_CALL SetValueAsync(uint32_t focus, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetValueAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), uint32_t);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetValueAsync(focus));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FocusAsync(void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().FocusAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IFocusControl2> : produce_base<D, Windows::Media::Devices::IFocusControl2>
{
    int32_t WINRT_CALL get_FocusChangedSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusChangedSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().FocusChangedSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WaitForFocusSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WaitForFocusSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().WaitForFocusSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedFocusModes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedFocusModes, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::FocusMode>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::FocusMode>>(this->shim().SupportedFocusModes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedFocusDistances(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedFocusDistances, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::ManualFocusDistance>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::ManualFocusDistance>>(this->shim().SupportedFocusDistances());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedFocusRanges(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedFocusRanges, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::AutoFocusRange>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::AutoFocusRange>>(this->shim().SupportedFocusRanges());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Mode(Windows::Media::Devices::FocusMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(Windows::Media::Devices::FocusMode));
            *value = detach_from<Windows::Media::Devices::FocusMode>(this->shim().Mode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FocusState(Windows::Media::Devices::MediaCaptureFocusState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusState, WINRT_WRAP(Windows::Media::Devices::MediaCaptureFocusState));
            *value = detach_from<Windows::Media::Devices::MediaCaptureFocusState>(this->shim().FocusState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UnlockAsync(void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnlockAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().UnlockAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LockAsync(void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LockAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().LockAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Configure(void* settings) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Configure, WINRT_WRAP(void), Windows::Media::Devices::FocusSettings const&);
            this->shim().Configure(*reinterpret_cast<Windows::Media::Devices::FocusSettings const*>(&settings));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IFocusSettings> : produce_base<D, Windows::Media::Devices::IFocusSettings>
{
    int32_t WINRT_CALL get_Mode(Windows::Media::Devices::FocusMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(Windows::Media::Devices::FocusMode));
            *value = detach_from<Windows::Media::Devices::FocusMode>(this->shim().Mode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Mode(Windows::Media::Devices::FocusMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(void), Windows::Media::Devices::FocusMode const&);
            this->shim().Mode(*reinterpret_cast<Windows::Media::Devices::FocusMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AutoFocusRange(Windows::Media::Devices::AutoFocusRange* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoFocusRange, WINRT_WRAP(Windows::Media::Devices::AutoFocusRange));
            *value = detach_from<Windows::Media::Devices::AutoFocusRange>(this->shim().AutoFocusRange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AutoFocusRange(Windows::Media::Devices::AutoFocusRange value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoFocusRange, WINRT_WRAP(void), Windows::Media::Devices::AutoFocusRange const&);
            this->shim().AutoFocusRange(*reinterpret_cast<Windows::Media::Devices::AutoFocusRange const*>(&value));
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
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Value(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(void), Windows::Foundation::IReference<uint32_t> const&);
            this->shim().Value(*reinterpret_cast<Windows::Foundation::IReference<uint32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Distance(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Distance, WINRT_WRAP(Windows::Foundation::IReference<Windows::Media::Devices::ManualFocusDistance>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Media::Devices::ManualFocusDistance>>(this->shim().Distance());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Distance(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Distance, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Media::Devices::ManualFocusDistance> const&);
            this->shim().Distance(*reinterpret_cast<Windows::Foundation::IReference<Windows::Media::Devices::ManualFocusDistance> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WaitForFocus(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WaitForFocus, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().WaitForFocus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_WaitForFocus(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WaitForFocus, WINRT_WRAP(void), bool);
            this->shim().WaitForFocus(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisableDriverFallback(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisableDriverFallback, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().DisableDriverFallback());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DisableDriverFallback(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisableDriverFallback, WINRT_WRAP(void), bool);
            this->shim().DisableDriverFallback(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IHdrVideoControl> : produce_base<D, Windows::Media::Devices::IHdrVideoControl>
{
    int32_t WINRT_CALL get_Supported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Supported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Supported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedModes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedModes, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::HdrVideoMode>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::HdrVideoMode>>(this->shim().SupportedModes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Mode(Windows::Media::Devices::HdrVideoMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(Windows::Media::Devices::HdrVideoMode));
            *value = detach_from<Windows::Media::Devices::HdrVideoMode>(this->shim().Mode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Mode(Windows::Media::Devices::HdrVideoMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(void), Windows::Media::Devices::HdrVideoMode const&);
            this->shim().Mode(*reinterpret_cast<Windows::Media::Devices::HdrVideoMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IInfraredTorchControl> : produce_base<D, Windows::Media::Devices::IInfraredTorchControl>
{
    int32_t WINRT_CALL get_IsSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedModes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedModes, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::InfraredTorchMode>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::InfraredTorchMode>>(this->shim().SupportedModes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CurrentMode(Windows::Media::Devices::InfraredTorchMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentMode, WINRT_WRAP(Windows::Media::Devices::InfraredTorchMode));
            *value = detach_from<Windows::Media::Devices::InfraredTorchMode>(this->shim().CurrentMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CurrentMode(Windows::Media::Devices::InfraredTorchMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentMode, WINRT_WRAP(void), Windows::Media::Devices::InfraredTorchMode const&);
            this->shim().CurrentMode(*reinterpret_cast<Windows::Media::Devices::InfraredTorchMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinPower(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinPower, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().MinPower());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxPower(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxPower, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().MaxPower());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PowerStep(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PowerStep, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().PowerStep());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Power(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Power, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Power());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Power(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Power, WINRT_WRAP(void), int32_t);
            this->shim().Power(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IIsoSpeedControl> : produce_base<D, Windows::Media::Devices::IIsoSpeedControl>
{
    int32_t WINRT_CALL get_Supported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Supported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Supported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedPresets(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedPresets, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::IsoSpeedPreset>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::IsoSpeedPreset>>(this->shim().SupportedPresets());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Preset(Windows::Media::Devices::IsoSpeedPreset* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Preset, WINRT_WRAP(Windows::Media::Devices::IsoSpeedPreset));
            *value = detach_from<Windows::Media::Devices::IsoSpeedPreset>(this->shim().Preset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPresetAsync(Windows::Media::Devices::IsoSpeedPreset preset, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPresetAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Media::Devices::IsoSpeedPreset const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetPresetAsync(*reinterpret_cast<Windows::Media::Devices::IsoSpeedPreset const*>(&preset)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IIsoSpeedControl2> : produce_base<D, Windows::Media::Devices::IIsoSpeedControl2>
{
    int32_t WINRT_CALL get_Min(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Min, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Min());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Max(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Max, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Max());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Step(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Step, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Step());
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

    int32_t WINRT_CALL SetValueAsync(uint32_t isoSpeed, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetValueAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), uint32_t);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetValueAsync(isoSpeed));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Auto(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Auto, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Auto());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetAutoAsync(void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetAutoAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetAutoAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IKeypadPressedEventArgs> : produce_base<D, Windows::Media::Devices::IKeypadPressedEventArgs>
{
    int32_t WINRT_CALL get_TelephonyKey(Windows::Media::Devices::TelephonyKey* telephonyKey) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TelephonyKey, WINRT_WRAP(Windows::Media::Devices::TelephonyKey));
            *telephonyKey = detach_from<Windows::Media::Devices::TelephonyKey>(this->shim().TelephonyKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::ILowLagPhotoControl> : produce_base<D, Windows::Media::Devices::ILowLagPhotoControl>
{
    int32_t WINRT_CALL GetHighestConcurrentFrameRate(void* captureProperties, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetHighestConcurrentFrameRate, WINRT_WRAP(Windows::Media::MediaProperties::MediaRatio), Windows::Media::MediaProperties::IMediaEncodingProperties const&);
            *value = detach_from<Windows::Media::MediaProperties::MediaRatio>(this->shim().GetHighestConcurrentFrameRate(*reinterpret_cast<Windows::Media::MediaProperties::IMediaEncodingProperties const*>(&captureProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCurrentFrameRate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentFrameRate, WINRT_WRAP(Windows::Media::MediaProperties::MediaRatio));
            *value = detach_from<Windows::Media::MediaProperties::MediaRatio>(this->shim().GetCurrentFrameRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ThumbnailEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ThumbnailEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ThumbnailEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ThumbnailEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ThumbnailEnabled, WINRT_WRAP(void), bool);
            this->shim().ThumbnailEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ThumbnailFormat(Windows::Media::MediaProperties::MediaThumbnailFormat* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ThumbnailFormat, WINRT_WRAP(Windows::Media::MediaProperties::MediaThumbnailFormat));
            *value = detach_from<Windows::Media::MediaProperties::MediaThumbnailFormat>(this->shim().ThumbnailFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ThumbnailFormat(Windows::Media::MediaProperties::MediaThumbnailFormat value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ThumbnailFormat, WINRT_WRAP(void), Windows::Media::MediaProperties::MediaThumbnailFormat const&);
            this->shim().ThumbnailFormat(*reinterpret_cast<Windows::Media::MediaProperties::MediaThumbnailFormat const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DesiredThumbnailSize(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredThumbnailSize, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().DesiredThumbnailSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DesiredThumbnailSize(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredThumbnailSize, WINRT_WRAP(void), uint32_t);
            this->shim().DesiredThumbnailSize(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HardwareAcceleratedThumbnailSupported(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HardwareAcceleratedThumbnailSupported, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().HardwareAcceleratedThumbnailSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::ILowLagPhotoSequenceControl> : produce_base<D, Windows::Media::Devices::ILowLagPhotoSequenceControl>
{
    int32_t WINRT_CALL get_Supported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Supported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Supported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxPastPhotos(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxPastPhotos, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaxPastPhotos());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxPhotosPerSecond(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxPhotosPerSecond, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().MaxPhotosPerSecond());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PastPhotoLimit(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PastPhotoLimit, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().PastPhotoLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PastPhotoLimit(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PastPhotoLimit, WINRT_WRAP(void), uint32_t);
            this->shim().PastPhotoLimit(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PhotosPerSecondLimit(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhotosPerSecondLimit, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().PhotosPerSecondLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PhotosPerSecondLimit(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhotosPerSecondLimit, WINRT_WRAP(void), float);
            this->shim().PhotosPerSecondLimit(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetHighestConcurrentFrameRate(void* captureProperties, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetHighestConcurrentFrameRate, WINRT_WRAP(Windows::Media::MediaProperties::MediaRatio), Windows::Media::MediaProperties::IMediaEncodingProperties const&);
            *value = detach_from<Windows::Media::MediaProperties::MediaRatio>(this->shim().GetHighestConcurrentFrameRate(*reinterpret_cast<Windows::Media::MediaProperties::IMediaEncodingProperties const*>(&captureProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCurrentFrameRate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentFrameRate, WINRT_WRAP(Windows::Media::MediaProperties::MediaRatio));
            *value = detach_from<Windows::Media::MediaProperties::MediaRatio>(this->shim().GetCurrentFrameRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ThumbnailEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ThumbnailEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ThumbnailEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ThumbnailEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ThumbnailEnabled, WINRT_WRAP(void), bool);
            this->shim().ThumbnailEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ThumbnailFormat(Windows::Media::MediaProperties::MediaThumbnailFormat* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ThumbnailFormat, WINRT_WRAP(Windows::Media::MediaProperties::MediaThumbnailFormat));
            *value = detach_from<Windows::Media::MediaProperties::MediaThumbnailFormat>(this->shim().ThumbnailFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ThumbnailFormat(Windows::Media::MediaProperties::MediaThumbnailFormat value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ThumbnailFormat, WINRT_WRAP(void), Windows::Media::MediaProperties::MediaThumbnailFormat const&);
            this->shim().ThumbnailFormat(*reinterpret_cast<Windows::Media::MediaProperties::MediaThumbnailFormat const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DesiredThumbnailSize(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredThumbnailSize, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().DesiredThumbnailSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DesiredThumbnailSize(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredThumbnailSize, WINRT_WRAP(void), uint32_t);
            this->shim().DesiredThumbnailSize(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HardwareAcceleratedThumbnailSupported(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HardwareAcceleratedThumbnailSupported, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().HardwareAcceleratedThumbnailSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IMediaDeviceControl> : produce_base<D, Windows::Media::Devices::IMediaDeviceControl>
{
    int32_t WINRT_CALL get_Capabilities(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Capabilities, WINRT_WRAP(Windows::Media::Devices::MediaDeviceControlCapabilities));
            *value = detach_from<Windows::Media::Devices::MediaDeviceControlCapabilities>(this->shim().Capabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetValue(double* value, bool* succeeded) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetValue, WINRT_WRAP(bool), double&);
            *succeeded = detach_from<bool>(this->shim().TryGetValue(*value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySetValue(double value, bool* succeeded) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySetValue, WINRT_WRAP(bool), double);
            *succeeded = detach_from<bool>(this->shim().TrySetValue(value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetAuto(bool* value, bool* succeeded) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetAuto, WINRT_WRAP(bool), bool&);
            *succeeded = detach_from<bool>(this->shim().TryGetAuto(*value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySetAuto(bool value, bool* succeeded) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySetAuto, WINRT_WRAP(bool), bool);
            *succeeded = detach_from<bool>(this->shim().TrySetAuto(value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IMediaDeviceControlCapabilities> : produce_base<D, Windows::Media::Devices::IMediaDeviceControlCapabilities>
{
    int32_t WINRT_CALL get_Supported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Supported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Supported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Min(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Min, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Min());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Max(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Max, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Max());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Step(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Step, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Step());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Default(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Default, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Default());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AutoModeSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoModeSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AutoModeSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IMediaDeviceController> : produce_base<D, Windows::Media::Devices::IMediaDeviceController>
{
    int32_t WINRT_CALL GetAvailableMediaStreamProperties(Windows::Media::Capture::MediaStreamType mediaStreamType, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAvailableMediaStreamProperties, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::MediaProperties::IMediaEncodingProperties>), Windows::Media::Capture::MediaStreamType const&);
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::MediaProperties::IMediaEncodingProperties>>(this->shim().GetAvailableMediaStreamProperties(*reinterpret_cast<Windows::Media::Capture::MediaStreamType const*>(&mediaStreamType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetMediaStreamProperties(Windows::Media::Capture::MediaStreamType mediaStreamType, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetMediaStreamProperties, WINRT_WRAP(Windows::Media::MediaProperties::IMediaEncodingProperties), Windows::Media::Capture::MediaStreamType const&);
            *value = detach_from<Windows::Media::MediaProperties::IMediaEncodingProperties>(this->shim().GetMediaStreamProperties(*reinterpret_cast<Windows::Media::Capture::MediaStreamType const*>(&mediaStreamType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetMediaStreamPropertiesAsync(Windows::Media::Capture::MediaStreamType mediaStreamType, void* mediaEncodingProperties, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetMediaStreamPropertiesAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Media::Capture::MediaStreamType const, Windows::Media::MediaProperties::IMediaEncodingProperties const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetMediaStreamPropertiesAsync(*reinterpret_cast<Windows::Media::Capture::MediaStreamType const*>(&mediaStreamType), *reinterpret_cast<Windows::Media::MediaProperties::IMediaEncodingProperties const*>(&mediaEncodingProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IMediaDeviceStatics> : produce_base<D, Windows::Media::Devices::IMediaDeviceStatics>
{
    int32_t WINRT_CALL GetAudioCaptureSelector(void** selector) noexcept final
    {
        try
        {
            *selector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAudioCaptureSelector, WINRT_WRAP(hstring));
            *selector = detach_from<hstring>(this->shim().GetAudioCaptureSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAudioRenderSelector(void** selector) noexcept final
    {
        try
        {
            *selector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAudioRenderSelector, WINRT_WRAP(hstring));
            *selector = detach_from<hstring>(this->shim().GetAudioRenderSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetVideoCaptureSelector(void** selector) noexcept final
    {
        try
        {
            *selector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetVideoCaptureSelector, WINRT_WRAP(hstring));
            *selector = detach_from<hstring>(this->shim().GetVideoCaptureSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDefaultAudioCaptureId(Windows::Media::Devices::AudioDeviceRole role, void** deviceId) noexcept final
    {
        try
        {
            *deviceId = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefaultAudioCaptureId, WINRT_WRAP(hstring), Windows::Media::Devices::AudioDeviceRole const&);
            *deviceId = detach_from<hstring>(this->shim().GetDefaultAudioCaptureId(*reinterpret_cast<Windows::Media::Devices::AudioDeviceRole const*>(&role)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDefaultAudioRenderId(Windows::Media::Devices::AudioDeviceRole role, void** deviceId) noexcept final
    {
        try
        {
            *deviceId = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefaultAudioRenderId, WINRT_WRAP(hstring), Windows::Media::Devices::AudioDeviceRole const&);
            *deviceId = detach_from<hstring>(this->shim().GetDefaultAudioRenderId(*reinterpret_cast<Windows::Media::Devices::AudioDeviceRole const*>(&role)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_DefaultAudioCaptureDeviceChanged(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultAudioCaptureDeviceChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Media::Devices::DefaultAudioCaptureDeviceChangedEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().DefaultAudioCaptureDeviceChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Media::Devices::DefaultAudioCaptureDeviceChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DefaultAudioCaptureDeviceChanged(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DefaultAudioCaptureDeviceChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DefaultAudioCaptureDeviceChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_DefaultAudioRenderDeviceChanged(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultAudioRenderDeviceChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Media::Devices::DefaultAudioRenderDeviceChangedEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().DefaultAudioRenderDeviceChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Media::Devices::DefaultAudioRenderDeviceChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DefaultAudioRenderDeviceChanged(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DefaultAudioRenderDeviceChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DefaultAudioRenderDeviceChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IModuleCommandResult> : produce_base<D, Windows::Media::Devices::IModuleCommandResult>
{
    int32_t WINRT_CALL get_Status(Windows::Media::Devices::SendCommandStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Media::Devices::SendCommandStatus));
            *value = detach_from<Windows::Media::Devices::SendCommandStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Result(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Result, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().Result());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IOpticalImageStabilizationControl> : produce_base<D, Windows::Media::Devices::IOpticalImageStabilizationControl>
{
    int32_t WINRT_CALL get_Supported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Supported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Supported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedModes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedModes, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::OpticalImageStabilizationMode>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::OpticalImageStabilizationMode>>(this->shim().SupportedModes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Mode(Windows::Media::Devices::OpticalImageStabilizationMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(Windows::Media::Devices::OpticalImageStabilizationMode));
            *value = detach_from<Windows::Media::Devices::OpticalImageStabilizationMode>(this->shim().Mode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Mode(Windows::Media::Devices::OpticalImageStabilizationMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(void), Windows::Media::Devices::OpticalImageStabilizationMode const&);
            this->shim().Mode(*reinterpret_cast<Windows::Media::Devices::OpticalImageStabilizationMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IPhotoConfirmationControl> : produce_base<D, Windows::Media::Devices::IPhotoConfirmationControl>
{
    int32_t WINRT_CALL get_Supported(bool* pbSupported) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Supported, WINRT_WRAP(bool));
            *pbSupported = detach_from<bool>(this->shim().Supported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Enabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Enabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Enabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Enabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Enabled, WINRT_WRAP(void), bool);
            this->shim().Enabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PixelFormat(Windows::Media::MediaProperties::MediaPixelFormat* format) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PixelFormat, WINRT_WRAP(Windows::Media::MediaProperties::MediaPixelFormat));
            *format = detach_from<Windows::Media::MediaProperties::MediaPixelFormat>(this->shim().PixelFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PixelFormat(Windows::Media::MediaProperties::MediaPixelFormat format) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PixelFormat, WINRT_WRAP(void), Windows::Media::MediaProperties::MediaPixelFormat const&);
            this->shim().PixelFormat(*reinterpret_cast<Windows::Media::MediaProperties::MediaPixelFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IRedialRequestedEventArgs> : produce_base<D, Windows::Media::Devices::IRedialRequestedEventArgs>
{
    int32_t WINRT_CALL Handled() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(void));
            this->shim().Handled();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IRegionOfInterest> : produce_base<D, Windows::Media::Devices::IRegionOfInterest>
{
    int32_t WINRT_CALL get_AutoFocusEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoFocusEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AutoFocusEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AutoFocusEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoFocusEnabled, WINRT_WRAP(void), bool);
            this->shim().AutoFocusEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AutoWhiteBalanceEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoWhiteBalanceEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AutoWhiteBalanceEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AutoWhiteBalanceEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoWhiteBalanceEnabled, WINRT_WRAP(void), bool);
            this->shim().AutoWhiteBalanceEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AutoExposureEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoExposureEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AutoExposureEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AutoExposureEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoExposureEnabled, WINRT_WRAP(void), bool);
            this->shim().AutoExposureEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Bounds(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bounds, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().Bounds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Bounds(Windows::Foundation::Rect value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bounds, WINRT_WRAP(void), Windows::Foundation::Rect const&);
            this->shim().Bounds(*reinterpret_cast<Windows::Foundation::Rect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IRegionOfInterest2> : produce_base<D, Windows::Media::Devices::IRegionOfInterest2>
{
    int32_t WINRT_CALL get_Type(Windows::Media::Devices::RegionOfInterestType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(Windows::Media::Devices::RegionOfInterestType));
            *value = detach_from<Windows::Media::Devices::RegionOfInterestType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Type(Windows::Media::Devices::RegionOfInterestType value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(void), Windows::Media::Devices::RegionOfInterestType const&);
            this->shim().Type(*reinterpret_cast<Windows::Media::Devices::RegionOfInterestType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BoundsNormalized(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BoundsNormalized, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().BoundsNormalized());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BoundsNormalized(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BoundsNormalized, WINRT_WRAP(void), bool);
            this->shim().BoundsNormalized(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Weight(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Weight, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Weight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Weight(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Weight, WINRT_WRAP(void), uint32_t);
            this->shim().Weight(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IRegionsOfInterestControl> : produce_base<D, Windows::Media::Devices::IRegionsOfInterestControl>
{
    int32_t WINRT_CALL get_MaxRegions(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxRegions, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaxRegions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetRegionsAsync(void* regions, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetRegionsAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Foundation::Collections::IIterable<Windows::Media::Devices::RegionOfInterest> const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetRegionsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Media::Devices::RegionOfInterest> const*>(&regions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetRegionsWithLockAsync(void* regions, bool lockValues, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetRegionsAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Foundation::Collections::IIterable<Windows::Media::Devices::RegionOfInterest> const, bool);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetRegionsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Media::Devices::RegionOfInterest> const*>(&regions), lockValues));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClearRegionsAsync(void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClearRegionsAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ClearRegionsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AutoFocusSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoFocusSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AutoFocusSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AutoWhiteBalanceSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoWhiteBalanceSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AutoWhiteBalanceSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AutoExposureSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoExposureSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AutoExposureSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::ISceneModeControl> : produce_base<D, Windows::Media::Devices::ISceneModeControl>
{
    int32_t WINRT_CALL get_SupportedModes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedModes, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::CaptureSceneMode>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::CaptureSceneMode>>(this->shim().SupportedModes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Value(Windows::Media::Devices::CaptureSceneMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(Windows::Media::Devices::CaptureSceneMode));
            *value = detach_from<Windows::Media::Devices::CaptureSceneMode>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetValueAsync(Windows::Media::Devices::CaptureSceneMode sceneMode, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetValueAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Media::Devices::CaptureSceneMode const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetValueAsync(*reinterpret_cast<Windows::Media::Devices::CaptureSceneMode const*>(&sceneMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::ITorchControl> : produce_base<D, Windows::Media::Devices::ITorchControl>
{
    int32_t WINRT_CALL get_Supported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Supported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Supported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PowerSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PowerSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().PowerSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Enabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Enabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Enabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Enabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Enabled, WINRT_WRAP(void), bool);
            this->shim().Enabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PowerPercent(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PowerPercent, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().PowerPercent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PowerPercent(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PowerPercent, WINRT_WRAP(void), float);
            this->shim().PowerPercent(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IVideoDeviceController> : produce_base<D, Windows::Media::Devices::IVideoDeviceController>
{
    int32_t WINRT_CALL get_Brightness(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Brightness, WINRT_WRAP(Windows::Media::Devices::MediaDeviceControl));
            *value = detach_from<Windows::Media::Devices::MediaDeviceControl>(this->shim().Brightness());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Contrast(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Contrast, WINRT_WRAP(Windows::Media::Devices::MediaDeviceControl));
            *value = detach_from<Windows::Media::Devices::MediaDeviceControl>(this->shim().Contrast());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Hue(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Hue, WINRT_WRAP(Windows::Media::Devices::MediaDeviceControl));
            *value = detach_from<Windows::Media::Devices::MediaDeviceControl>(this->shim().Hue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WhiteBalance(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WhiteBalance, WINRT_WRAP(Windows::Media::Devices::MediaDeviceControl));
            *value = detach_from<Windows::Media::Devices::MediaDeviceControl>(this->shim().WhiteBalance());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BacklightCompensation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BacklightCompensation, WINRT_WRAP(Windows::Media::Devices::MediaDeviceControl));
            *value = detach_from<Windows::Media::Devices::MediaDeviceControl>(this->shim().BacklightCompensation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Pan(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pan, WINRT_WRAP(Windows::Media::Devices::MediaDeviceControl));
            *value = detach_from<Windows::Media::Devices::MediaDeviceControl>(this->shim().Pan());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Tilt(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tilt, WINRT_WRAP(Windows::Media::Devices::MediaDeviceControl));
            *value = detach_from<Windows::Media::Devices::MediaDeviceControl>(this->shim().Tilt());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Zoom(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Zoom, WINRT_WRAP(Windows::Media::Devices::MediaDeviceControl));
            *value = detach_from<Windows::Media::Devices::MediaDeviceControl>(this->shim().Zoom());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Roll(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Roll, WINRT_WRAP(Windows::Media::Devices::MediaDeviceControl));
            *value = detach_from<Windows::Media::Devices::MediaDeviceControl>(this->shim().Roll());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Exposure(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Exposure, WINRT_WRAP(Windows::Media::Devices::MediaDeviceControl));
            *value = detach_from<Windows::Media::Devices::MediaDeviceControl>(this->shim().Exposure());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Focus(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Focus, WINRT_WRAP(Windows::Media::Devices::MediaDeviceControl));
            *value = detach_from<Windows::Media::Devices::MediaDeviceControl>(this->shim().Focus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySetPowerlineFrequency(Windows::Media::Capture::PowerlineFrequency value, bool* succeeded) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySetPowerlineFrequency, WINRT_WRAP(bool), Windows::Media::Capture::PowerlineFrequency const&);
            *succeeded = detach_from<bool>(this->shim().TrySetPowerlineFrequency(*reinterpret_cast<Windows::Media::Capture::PowerlineFrequency const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetPowerlineFrequency(Windows::Media::Capture::PowerlineFrequency* value, bool* succeeded) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetPowerlineFrequency, WINRT_WRAP(bool), Windows::Media::Capture::PowerlineFrequency&);
            *succeeded = detach_from<bool>(this->shim().TryGetPowerlineFrequency(*reinterpret_cast<Windows::Media::Capture::PowerlineFrequency*>(value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IVideoDeviceControllerGetDevicePropertyResult> : produce_base<D, Windows::Media::Devices::IVideoDeviceControllerGetDevicePropertyResult>
{
    int32_t WINRT_CALL get_Status(Windows::Media::Devices::VideoDeviceControllerGetDevicePropertyStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Media::Devices::VideoDeviceControllerGetDevicePropertyStatus));
            *value = detach_from<Windows::Media::Devices::VideoDeviceControllerGetDevicePropertyStatus>(this->shim().Status());
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
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IVideoTemporalDenoisingControl> : produce_base<D, Windows::Media::Devices::IVideoTemporalDenoisingControl>
{
    int32_t WINRT_CALL get_Supported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Supported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Supported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedModes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedModes, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::VideoTemporalDenoisingMode>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::VideoTemporalDenoisingMode>>(this->shim().SupportedModes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Mode(Windows::Media::Devices::VideoTemporalDenoisingMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(Windows::Media::Devices::VideoTemporalDenoisingMode));
            *value = detach_from<Windows::Media::Devices::VideoTemporalDenoisingMode>(this->shim().Mode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Mode(Windows::Media::Devices::VideoTemporalDenoisingMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(void), Windows::Media::Devices::VideoTemporalDenoisingMode const&);
            this->shim().Mode(*reinterpret_cast<Windows::Media::Devices::VideoTemporalDenoisingMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IWhiteBalanceControl> : produce_base<D, Windows::Media::Devices::IWhiteBalanceControl>
{
    int32_t WINRT_CALL get_Supported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Supported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Supported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Preset(Windows::Media::Devices::ColorTemperaturePreset* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Preset, WINRT_WRAP(Windows::Media::Devices::ColorTemperaturePreset));
            *value = detach_from<Windows::Media::Devices::ColorTemperaturePreset>(this->shim().Preset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPresetAsync(Windows::Media::Devices::ColorTemperaturePreset preset, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPresetAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Media::Devices::ColorTemperaturePreset const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetPresetAsync(*reinterpret_cast<Windows::Media::Devices::ColorTemperaturePreset const*>(&preset)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Min(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Min, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Min());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Max(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Max, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Max());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Step(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Step, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Step());
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

    int32_t WINRT_CALL SetValueAsync(uint32_t temperature, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetValueAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), uint32_t);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetValueAsync(temperature));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IZoomControl> : produce_base<D, Windows::Media::Devices::IZoomControl>
{
    int32_t WINRT_CALL get_Supported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Supported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Supported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Min(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Min, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Min());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Max(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Max, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Max());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Step(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Step, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Step());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Value(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Value(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(void), float);
            this->shim().Value(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IZoomControl2> : produce_base<D, Windows::Media::Devices::IZoomControl2>
{
    int32_t WINRT_CALL get_SupportedModes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedModes, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::ZoomTransitionMode>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::ZoomTransitionMode>>(this->shim().SupportedModes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Mode(Windows::Media::Devices::ZoomTransitionMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(Windows::Media::Devices::ZoomTransitionMode));
            *value = detach_from<Windows::Media::Devices::ZoomTransitionMode>(this->shim().Mode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Configure(void* settings) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Configure, WINRT_WRAP(void), Windows::Media::Devices::ZoomSettings const&);
            this->shim().Configure(*reinterpret_cast<Windows::Media::Devices::ZoomSettings const*>(&settings));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::IZoomSettings> : produce_base<D, Windows::Media::Devices::IZoomSettings>
{
    int32_t WINRT_CALL get_Mode(Windows::Media::Devices::ZoomTransitionMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(Windows::Media::Devices::ZoomTransitionMode));
            *value = detach_from<Windows::Media::Devices::ZoomTransitionMode>(this->shim().Mode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Mode(Windows::Media::Devices::ZoomTransitionMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(void), Windows::Media::Devices::ZoomTransitionMode const&);
            this->shim().Mode(*reinterpret_cast<Windows::Media::Devices::ZoomTransitionMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Value(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Value(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(void), float);
            this->shim().Value(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Media::Devices {

inline AdvancedPhotoCaptureSettings::AdvancedPhotoCaptureSettings() :
    AdvancedPhotoCaptureSettings(impl::call_factory<AdvancedPhotoCaptureSettings>([](auto&& f) { return f.template ActivateInstance<AdvancedPhotoCaptureSettings>(); }))
{}

inline AudioDeviceModulesManager::AudioDeviceModulesManager(param::hstring const& deviceId) :
    AudioDeviceModulesManager(impl::call_factory<AudioDeviceModulesManager, Windows::Media::Devices::IAudioDeviceModulesManagerFactory>([&](auto&& f) { return f.Create(deviceId); }))
{}

inline Windows::Media::Devices::CallControl CallControl::GetDefault()
{
    return impl::call_factory<CallControl, Windows::Media::Devices::ICallControlStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline Windows::Media::Devices::CallControl CallControl::FromId(param::hstring const& deviceId)
{
    return impl::call_factory<CallControl, Windows::Media::Devices::ICallControlStatics>([&](auto&& f) { return f.FromId(deviceId); });
}

inline FocusSettings::FocusSettings() :
    FocusSettings(impl::call_factory<FocusSettings>([](auto&& f) { return f.template ActivateInstance<FocusSettings>(); }))
{}

inline hstring MediaDevice::GetAudioCaptureSelector()
{
    return impl::call_factory<MediaDevice, Windows::Media::Devices::IMediaDeviceStatics>([&](auto&& f) { return f.GetAudioCaptureSelector(); });
}

inline hstring MediaDevice::GetAudioRenderSelector()
{
    return impl::call_factory<MediaDevice, Windows::Media::Devices::IMediaDeviceStatics>([&](auto&& f) { return f.GetAudioRenderSelector(); });
}

inline hstring MediaDevice::GetVideoCaptureSelector()
{
    return impl::call_factory<MediaDevice, Windows::Media::Devices::IMediaDeviceStatics>([&](auto&& f) { return f.GetVideoCaptureSelector(); });
}

inline hstring MediaDevice::GetDefaultAudioCaptureId(Windows::Media::Devices::AudioDeviceRole const& role)
{
    return impl::call_factory<MediaDevice, Windows::Media::Devices::IMediaDeviceStatics>([&](auto&& f) { return f.GetDefaultAudioCaptureId(role); });
}

inline hstring MediaDevice::GetDefaultAudioRenderId(Windows::Media::Devices::AudioDeviceRole const& role)
{
    return impl::call_factory<MediaDevice, Windows::Media::Devices::IMediaDeviceStatics>([&](auto&& f) { return f.GetDefaultAudioRenderId(role); });
}

inline winrt::event_token MediaDevice::DefaultAudioCaptureDeviceChanged(Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Media::Devices::DefaultAudioCaptureDeviceChangedEventArgs> const& handler)
{
    return impl::call_factory<MediaDevice, Windows::Media::Devices::IMediaDeviceStatics>([&](auto&& f) { return f.DefaultAudioCaptureDeviceChanged(handler); });
}

inline MediaDevice::DefaultAudioCaptureDeviceChanged_revoker MediaDevice::DefaultAudioCaptureDeviceChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Media::Devices::DefaultAudioCaptureDeviceChangedEventArgs> const& handler)
{
    auto f = get_activation_factory<MediaDevice, Windows::Media::Devices::IMediaDeviceStatics>();
    return { f, f.DefaultAudioCaptureDeviceChanged(handler) };
}

inline void MediaDevice::DefaultAudioCaptureDeviceChanged(winrt::event_token const& cookie)
{
    impl::call_factory<MediaDevice, Windows::Media::Devices::IMediaDeviceStatics>([&](auto&& f) { return f.DefaultAudioCaptureDeviceChanged(cookie); });
}

inline winrt::event_token MediaDevice::DefaultAudioRenderDeviceChanged(Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Media::Devices::DefaultAudioRenderDeviceChangedEventArgs> const& handler)
{
    return impl::call_factory<MediaDevice, Windows::Media::Devices::IMediaDeviceStatics>([&](auto&& f) { return f.DefaultAudioRenderDeviceChanged(handler); });
}

inline MediaDevice::DefaultAudioRenderDeviceChanged_revoker MediaDevice::DefaultAudioRenderDeviceChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Media::Devices::DefaultAudioRenderDeviceChangedEventArgs> const& handler)
{
    auto f = get_activation_factory<MediaDevice, Windows::Media::Devices::IMediaDeviceStatics>();
    return { f, f.DefaultAudioRenderDeviceChanged(handler) };
}

inline void MediaDevice::DefaultAudioRenderDeviceChanged(winrt::event_token const& cookie)
{
    impl::call_factory<MediaDevice, Windows::Media::Devices::IMediaDeviceStatics>([&](auto&& f) { return f.DefaultAudioRenderDeviceChanged(cookie); });
}

inline RegionOfInterest::RegionOfInterest() :
    RegionOfInterest(impl::call_factory<RegionOfInterest>([](auto&& f) { return f.template ActivateInstance<RegionOfInterest>(); }))
{}

inline ZoomSettings::ZoomSettings() :
    ZoomSettings(impl::call_factory<ZoomSettings>([](auto&& f) { return f.template ActivateInstance<ZoomSettings>(); }))
{}

template <typename L> CallControlEventHandler::CallControlEventHandler(L handler) :
    CallControlEventHandler(impl::make_delegate<CallControlEventHandler>(std::forward<L>(handler)))
{}

template <typename F> CallControlEventHandler::CallControlEventHandler(F* handler) :
    CallControlEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> CallControlEventHandler::CallControlEventHandler(O* object, M method) :
    CallControlEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> CallControlEventHandler::CallControlEventHandler(com_ptr<O>&& object, M method) :
    CallControlEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> CallControlEventHandler::CallControlEventHandler(weak_ref<O>&& object, M method) :
    CallControlEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void CallControlEventHandler::operator()(Windows::Media::Devices::CallControl const& sender) const
{
    check_hresult((*(impl::abi_t<CallControlEventHandler>**)this)->Invoke(get_abi(sender)));
}

template <typename L> DialRequestedEventHandler::DialRequestedEventHandler(L handler) :
    DialRequestedEventHandler(impl::make_delegate<DialRequestedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> DialRequestedEventHandler::DialRequestedEventHandler(F* handler) :
    DialRequestedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> DialRequestedEventHandler::DialRequestedEventHandler(O* object, M method) :
    DialRequestedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> DialRequestedEventHandler::DialRequestedEventHandler(com_ptr<O>&& object, M method) :
    DialRequestedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> DialRequestedEventHandler::DialRequestedEventHandler(weak_ref<O>&& object, M method) :
    DialRequestedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void DialRequestedEventHandler::operator()(Windows::Media::Devices::CallControl const& sender, Windows::Media::Devices::DialRequestedEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<DialRequestedEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> KeypadPressedEventHandler::KeypadPressedEventHandler(L handler) :
    KeypadPressedEventHandler(impl::make_delegate<KeypadPressedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> KeypadPressedEventHandler::KeypadPressedEventHandler(F* handler) :
    KeypadPressedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> KeypadPressedEventHandler::KeypadPressedEventHandler(O* object, M method) :
    KeypadPressedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> KeypadPressedEventHandler::KeypadPressedEventHandler(com_ptr<O>&& object, M method) :
    KeypadPressedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> KeypadPressedEventHandler::KeypadPressedEventHandler(weak_ref<O>&& object, M method) :
    KeypadPressedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void KeypadPressedEventHandler::operator()(Windows::Media::Devices::CallControl const& sender, Windows::Media::Devices::KeypadPressedEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<KeypadPressedEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> RedialRequestedEventHandler::RedialRequestedEventHandler(L handler) :
    RedialRequestedEventHandler(impl::make_delegate<RedialRequestedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> RedialRequestedEventHandler::RedialRequestedEventHandler(F* handler) :
    RedialRequestedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> RedialRequestedEventHandler::RedialRequestedEventHandler(O* object, M method) :
    RedialRequestedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> RedialRequestedEventHandler::RedialRequestedEventHandler(com_ptr<O>&& object, M method) :
    RedialRequestedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> RedialRequestedEventHandler::RedialRequestedEventHandler(weak_ref<O>&& object, M method) :
    RedialRequestedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void RedialRequestedEventHandler::operator()(Windows::Media::Devices::CallControl const& sender, Windows::Media::Devices::RedialRequestedEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<RedialRequestedEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Media::Devices::IAdvancedPhotoCaptureSettings> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IAdvancedPhotoCaptureSettings> {};
template<> struct hash<winrt::Windows::Media::Devices::IAdvancedPhotoControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IAdvancedPhotoControl> {};
template<> struct hash<winrt::Windows::Media::Devices::IAdvancedVideoCaptureDeviceController> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IAdvancedVideoCaptureDeviceController> {};
template<> struct hash<winrt::Windows::Media::Devices::IAdvancedVideoCaptureDeviceController2> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IAdvancedVideoCaptureDeviceController2> {};
template<> struct hash<winrt::Windows::Media::Devices::IAdvancedVideoCaptureDeviceController3> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IAdvancedVideoCaptureDeviceController3> {};
template<> struct hash<winrt::Windows::Media::Devices::IAdvancedVideoCaptureDeviceController4> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IAdvancedVideoCaptureDeviceController4> {};
template<> struct hash<winrt::Windows::Media::Devices::IAdvancedVideoCaptureDeviceController5> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IAdvancedVideoCaptureDeviceController5> {};
template<> struct hash<winrt::Windows::Media::Devices::IAdvancedVideoCaptureDeviceController6> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IAdvancedVideoCaptureDeviceController6> {};
template<> struct hash<winrt::Windows::Media::Devices::IAdvancedVideoCaptureDeviceController7> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IAdvancedVideoCaptureDeviceController7> {};
template<> struct hash<winrt::Windows::Media::Devices::IAudioDeviceController> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IAudioDeviceController> {};
template<> struct hash<winrt::Windows::Media::Devices::IAudioDeviceModule> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IAudioDeviceModule> {};
template<> struct hash<winrt::Windows::Media::Devices::IAudioDeviceModuleNotificationEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IAudioDeviceModuleNotificationEventArgs> {};
template<> struct hash<winrt::Windows::Media::Devices::IAudioDeviceModulesManager> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IAudioDeviceModulesManager> {};
template<> struct hash<winrt::Windows::Media::Devices::IAudioDeviceModulesManagerFactory> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IAudioDeviceModulesManagerFactory> {};
template<> struct hash<winrt::Windows::Media::Devices::ICallControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::ICallControl> {};
template<> struct hash<winrt::Windows::Media::Devices::ICallControlStatics> : winrt::impl::hash_base<winrt::Windows::Media::Devices::ICallControlStatics> {};
template<> struct hash<winrt::Windows::Media::Devices::IDefaultAudioDeviceChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IDefaultAudioDeviceChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Devices::IDialRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IDialRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Devices::IExposureCompensationControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IExposureCompensationControl> {};
template<> struct hash<winrt::Windows::Media::Devices::IExposureControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IExposureControl> {};
template<> struct hash<winrt::Windows::Media::Devices::IExposurePriorityVideoControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IExposurePriorityVideoControl> {};
template<> struct hash<winrt::Windows::Media::Devices::IFlashControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IFlashControl> {};
template<> struct hash<winrt::Windows::Media::Devices::IFlashControl2> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IFlashControl2> {};
template<> struct hash<winrt::Windows::Media::Devices::IFocusControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IFocusControl> {};
template<> struct hash<winrt::Windows::Media::Devices::IFocusControl2> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IFocusControl2> {};
template<> struct hash<winrt::Windows::Media::Devices::IFocusSettings> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IFocusSettings> {};
template<> struct hash<winrt::Windows::Media::Devices::IHdrVideoControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IHdrVideoControl> {};
template<> struct hash<winrt::Windows::Media::Devices::IInfraredTorchControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IInfraredTorchControl> {};
template<> struct hash<winrt::Windows::Media::Devices::IIsoSpeedControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IIsoSpeedControl> {};
template<> struct hash<winrt::Windows::Media::Devices::IIsoSpeedControl2> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IIsoSpeedControl2> {};
template<> struct hash<winrt::Windows::Media::Devices::IKeypadPressedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IKeypadPressedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Devices::ILowLagPhotoControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::ILowLagPhotoControl> {};
template<> struct hash<winrt::Windows::Media::Devices::ILowLagPhotoSequenceControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::ILowLagPhotoSequenceControl> {};
template<> struct hash<winrt::Windows::Media::Devices::IMediaDeviceControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IMediaDeviceControl> {};
template<> struct hash<winrt::Windows::Media::Devices::IMediaDeviceControlCapabilities> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IMediaDeviceControlCapabilities> {};
template<> struct hash<winrt::Windows::Media::Devices::IMediaDeviceController> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IMediaDeviceController> {};
template<> struct hash<winrt::Windows::Media::Devices::IMediaDeviceStatics> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IMediaDeviceStatics> {};
template<> struct hash<winrt::Windows::Media::Devices::IModuleCommandResult> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IModuleCommandResult> {};
template<> struct hash<winrt::Windows::Media::Devices::IOpticalImageStabilizationControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IOpticalImageStabilizationControl> {};
template<> struct hash<winrt::Windows::Media::Devices::IPhotoConfirmationControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IPhotoConfirmationControl> {};
template<> struct hash<winrt::Windows::Media::Devices::IRedialRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IRedialRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Devices::IRegionOfInterest> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IRegionOfInterest> {};
template<> struct hash<winrt::Windows::Media::Devices::IRegionOfInterest2> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IRegionOfInterest2> {};
template<> struct hash<winrt::Windows::Media::Devices::IRegionsOfInterestControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IRegionsOfInterestControl> {};
template<> struct hash<winrt::Windows::Media::Devices::ISceneModeControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::ISceneModeControl> {};
template<> struct hash<winrt::Windows::Media::Devices::ITorchControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::ITorchControl> {};
template<> struct hash<winrt::Windows::Media::Devices::IVideoDeviceController> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IVideoDeviceController> {};
template<> struct hash<winrt::Windows::Media::Devices::IVideoDeviceControllerGetDevicePropertyResult> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IVideoDeviceControllerGetDevicePropertyResult> {};
template<> struct hash<winrt::Windows::Media::Devices::IVideoTemporalDenoisingControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IVideoTemporalDenoisingControl> {};
template<> struct hash<winrt::Windows::Media::Devices::IWhiteBalanceControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IWhiteBalanceControl> {};
template<> struct hash<winrt::Windows::Media::Devices::IZoomControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IZoomControl> {};
template<> struct hash<winrt::Windows::Media::Devices::IZoomControl2> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IZoomControl2> {};
template<> struct hash<winrt::Windows::Media::Devices::IZoomSettings> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IZoomSettings> {};
template<> struct hash<winrt::Windows::Media::Devices::AdvancedPhotoCaptureSettings> : winrt::impl::hash_base<winrt::Windows::Media::Devices::AdvancedPhotoCaptureSettings> {};
template<> struct hash<winrt::Windows::Media::Devices::AdvancedPhotoControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::AdvancedPhotoControl> {};
template<> struct hash<winrt::Windows::Media::Devices::AudioDeviceController> : winrt::impl::hash_base<winrt::Windows::Media::Devices::AudioDeviceController> {};
template<> struct hash<winrt::Windows::Media::Devices::AudioDeviceModule> : winrt::impl::hash_base<winrt::Windows::Media::Devices::AudioDeviceModule> {};
template<> struct hash<winrt::Windows::Media::Devices::AudioDeviceModuleNotificationEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Devices::AudioDeviceModuleNotificationEventArgs> {};
template<> struct hash<winrt::Windows::Media::Devices::AudioDeviceModulesManager> : winrt::impl::hash_base<winrt::Windows::Media::Devices::AudioDeviceModulesManager> {};
template<> struct hash<winrt::Windows::Media::Devices::CallControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::CallControl> {};
template<> struct hash<winrt::Windows::Media::Devices::DefaultAudioCaptureDeviceChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Devices::DefaultAudioCaptureDeviceChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Devices::DefaultAudioRenderDeviceChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Devices::DefaultAudioRenderDeviceChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Devices::DialRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Devices::DialRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Devices::ExposureCompensationControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::ExposureCompensationControl> {};
template<> struct hash<winrt::Windows::Media::Devices::ExposureControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::ExposureControl> {};
template<> struct hash<winrt::Windows::Media::Devices::ExposurePriorityVideoControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::ExposurePriorityVideoControl> {};
template<> struct hash<winrt::Windows::Media::Devices::FlashControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::FlashControl> {};
template<> struct hash<winrt::Windows::Media::Devices::FocusControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::FocusControl> {};
template<> struct hash<winrt::Windows::Media::Devices::FocusSettings> : winrt::impl::hash_base<winrt::Windows::Media::Devices::FocusSettings> {};
template<> struct hash<winrt::Windows::Media::Devices::HdrVideoControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::HdrVideoControl> {};
template<> struct hash<winrt::Windows::Media::Devices::InfraredTorchControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::InfraredTorchControl> {};
template<> struct hash<winrt::Windows::Media::Devices::IsoSpeedControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::IsoSpeedControl> {};
template<> struct hash<winrt::Windows::Media::Devices::KeypadPressedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Devices::KeypadPressedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Devices::LowLagPhotoControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::LowLagPhotoControl> {};
template<> struct hash<winrt::Windows::Media::Devices::LowLagPhotoSequenceControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::LowLagPhotoSequenceControl> {};
template<> struct hash<winrt::Windows::Media::Devices::MediaDevice> : winrt::impl::hash_base<winrt::Windows::Media::Devices::MediaDevice> {};
template<> struct hash<winrt::Windows::Media::Devices::MediaDeviceControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::MediaDeviceControl> {};
template<> struct hash<winrt::Windows::Media::Devices::MediaDeviceControlCapabilities> : winrt::impl::hash_base<winrt::Windows::Media::Devices::MediaDeviceControlCapabilities> {};
template<> struct hash<winrt::Windows::Media::Devices::ModuleCommandResult> : winrt::impl::hash_base<winrt::Windows::Media::Devices::ModuleCommandResult> {};
template<> struct hash<winrt::Windows::Media::Devices::OpticalImageStabilizationControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::OpticalImageStabilizationControl> {};
template<> struct hash<winrt::Windows::Media::Devices::PhotoConfirmationControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::PhotoConfirmationControl> {};
template<> struct hash<winrt::Windows::Media::Devices::RedialRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Devices::RedialRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Devices::RegionOfInterest> : winrt::impl::hash_base<winrt::Windows::Media::Devices::RegionOfInterest> {};
template<> struct hash<winrt::Windows::Media::Devices::RegionsOfInterestControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::RegionsOfInterestControl> {};
template<> struct hash<winrt::Windows::Media::Devices::SceneModeControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::SceneModeControl> {};
template<> struct hash<winrt::Windows::Media::Devices::TorchControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::TorchControl> {};
template<> struct hash<winrt::Windows::Media::Devices::VideoDeviceController> : winrt::impl::hash_base<winrt::Windows::Media::Devices::VideoDeviceController> {};
template<> struct hash<winrt::Windows::Media::Devices::VideoDeviceControllerGetDevicePropertyResult> : winrt::impl::hash_base<winrt::Windows::Media::Devices::VideoDeviceControllerGetDevicePropertyResult> {};
template<> struct hash<winrt::Windows::Media::Devices::VideoTemporalDenoisingControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::VideoTemporalDenoisingControl> {};
template<> struct hash<winrt::Windows::Media::Devices::WhiteBalanceControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::WhiteBalanceControl> {};
template<> struct hash<winrt::Windows::Media::Devices::ZoomControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::ZoomControl> {};
template<> struct hash<winrt::Windows::Media::Devices::ZoomSettings> : winrt::impl::hash_base<winrt::Windows::Media::Devices::ZoomSettings> {};

}
