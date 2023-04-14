// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Haptics.2.h"
#include "winrt/Windows.Devices.h"

namespace winrt::impl {

template <typename D> uint16_t consume_Windows_Devices_Haptics_IKnownSimpleHapticsControllerWaveformsStatics<D>::Click() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Haptics::IKnownSimpleHapticsControllerWaveformsStatics)->get_Click(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Haptics_IKnownSimpleHapticsControllerWaveformsStatics<D>::BuzzContinuous() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Haptics::IKnownSimpleHapticsControllerWaveformsStatics)->get_BuzzContinuous(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Haptics_IKnownSimpleHapticsControllerWaveformsStatics<D>::RumbleContinuous() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Haptics::IKnownSimpleHapticsControllerWaveformsStatics)->get_RumbleContinuous(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Haptics_IKnownSimpleHapticsControllerWaveformsStatics<D>::Press() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Haptics::IKnownSimpleHapticsControllerWaveformsStatics)->get_Press(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Haptics_IKnownSimpleHapticsControllerWaveformsStatics<D>::Release() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Haptics::IKnownSimpleHapticsControllerWaveformsStatics)->get_Release(&value));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Haptics_ISimpleHapticsController<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Haptics::ISimpleHapticsController)->get_Id(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Haptics::SimpleHapticsControllerFeedback> consume_Windows_Devices_Haptics_ISimpleHapticsController<D>::SupportedFeedback() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Haptics::SimpleHapticsControllerFeedback> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Haptics::ISimpleHapticsController)->get_SupportedFeedback(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_Haptics_ISimpleHapticsController<D>::IsIntensitySupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Haptics::ISimpleHapticsController)->get_IsIntensitySupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_Haptics_ISimpleHapticsController<D>::IsPlayCountSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Haptics::ISimpleHapticsController)->get_IsPlayCountSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_Haptics_ISimpleHapticsController<D>::IsPlayDurationSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Haptics::ISimpleHapticsController)->get_IsPlayDurationSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_Haptics_ISimpleHapticsController<D>::IsReplayPauseIntervalSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Haptics::ISimpleHapticsController)->get_IsReplayPauseIntervalSupported(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Haptics_ISimpleHapticsController<D>::StopFeedback() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Haptics::ISimpleHapticsController)->StopFeedback());
}

template <typename D> void consume_Windows_Devices_Haptics_ISimpleHapticsController<D>::SendHapticFeedback(Windows::Devices::Haptics::SimpleHapticsControllerFeedback const& feedback) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Haptics::ISimpleHapticsController)->SendHapticFeedback(get_abi(feedback)));
}

template <typename D> void consume_Windows_Devices_Haptics_ISimpleHapticsController<D>::SendHapticFeedback(Windows::Devices::Haptics::SimpleHapticsControllerFeedback const& feedback, double intensity) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Haptics::ISimpleHapticsController)->SendHapticFeedbackWithIntensity(get_abi(feedback), intensity));
}

template <typename D> void consume_Windows_Devices_Haptics_ISimpleHapticsController<D>::SendHapticFeedbackForDuration(Windows::Devices::Haptics::SimpleHapticsControllerFeedback const& feedback, double intensity, Windows::Foundation::TimeSpan const& playDuration) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Haptics::ISimpleHapticsController)->SendHapticFeedbackForDuration(get_abi(feedback), intensity, get_abi(playDuration)));
}

template <typename D> void consume_Windows_Devices_Haptics_ISimpleHapticsController<D>::SendHapticFeedbackForPlayCount(Windows::Devices::Haptics::SimpleHapticsControllerFeedback const& feedback, double intensity, int32_t playCount, Windows::Foundation::TimeSpan const& replayPauseInterval) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Haptics::ISimpleHapticsController)->SendHapticFeedbackForPlayCount(get_abi(feedback), intensity, playCount, get_abi(replayPauseInterval)));
}

template <typename D> uint16_t consume_Windows_Devices_Haptics_ISimpleHapticsControllerFeedback<D>::Waveform() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Haptics::ISimpleHapticsControllerFeedback)->get_Waveform(&value));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_Haptics_ISimpleHapticsControllerFeedback<D>::Duration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Haptics::ISimpleHapticsControllerFeedback)->get_Duration(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Haptics_IVibrationDevice<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Haptics::IVibrationDevice)->get_Id(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Haptics::SimpleHapticsController consume_Windows_Devices_Haptics_IVibrationDevice<D>::SimpleHapticsController() const
{
    Windows::Devices::Haptics::SimpleHapticsController value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Haptics::IVibrationDevice)->get_SimpleHapticsController(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Haptics::VibrationAccessStatus> consume_Windows_Devices_Haptics_IVibrationDeviceStatics<D>::RequestAccessAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Haptics::VibrationAccessStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Haptics::IVibrationDeviceStatics)->RequestAccessAsync(put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_Devices_Haptics_IVibrationDeviceStatics<D>::GetDeviceSelector() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Haptics::IVibrationDeviceStatics)->GetDeviceSelector(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Haptics::VibrationDevice> consume_Windows_Devices_Haptics_IVibrationDeviceStatics<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Haptics::VibrationDevice> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Haptics::IVibrationDeviceStatics)->FromIdAsync(get_abi(deviceId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Haptics::VibrationDevice> consume_Windows_Devices_Haptics_IVibrationDeviceStatics<D>::GetDefaultAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Haptics::VibrationDevice> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Haptics::IVibrationDeviceStatics)->GetDefaultAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Haptics::VibrationDevice>> consume_Windows_Devices_Haptics_IVibrationDeviceStatics<D>::FindAllAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Haptics::VibrationDevice>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Haptics::IVibrationDeviceStatics)->FindAllAsync(put_abi(operation)));
    return operation;
}

template <typename D>
struct produce<D, Windows::Devices::Haptics::IKnownSimpleHapticsControllerWaveformsStatics> : produce_base<D, Windows::Devices::Haptics::IKnownSimpleHapticsControllerWaveformsStatics>
{
    int32_t WINRT_CALL get_Click(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Click, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().Click());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BuzzContinuous(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BuzzContinuous, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().BuzzContinuous());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RumbleContinuous(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RumbleContinuous, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().RumbleContinuous());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Press(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Press, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().Press());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Release(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Release, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().Release());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Haptics::ISimpleHapticsController> : produce_base<D, Windows::Devices::Haptics::ISimpleHapticsController>
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

    int32_t WINRT_CALL get_SupportedFeedback(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedFeedback, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Haptics::SimpleHapticsControllerFeedback>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Haptics::SimpleHapticsControllerFeedback>>(this->shim().SupportedFeedback());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsIntensitySupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsIntensitySupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsIntensitySupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsPlayCountSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPlayCountSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPlayCountSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsPlayDurationSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPlayDurationSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPlayDurationSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsReplayPauseIntervalSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsReplayPauseIntervalSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsReplayPauseIntervalSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopFeedback() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopFeedback, WINRT_WRAP(void));
            this->shim().StopFeedback();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SendHapticFeedback(void* feedback) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendHapticFeedback, WINRT_WRAP(void), Windows::Devices::Haptics::SimpleHapticsControllerFeedback const&);
            this->shim().SendHapticFeedback(*reinterpret_cast<Windows::Devices::Haptics::SimpleHapticsControllerFeedback const*>(&feedback));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SendHapticFeedbackWithIntensity(void* feedback, double intensity) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendHapticFeedback, WINRT_WRAP(void), Windows::Devices::Haptics::SimpleHapticsControllerFeedback const&, double);
            this->shim().SendHapticFeedback(*reinterpret_cast<Windows::Devices::Haptics::SimpleHapticsControllerFeedback const*>(&feedback), intensity);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SendHapticFeedbackForDuration(void* feedback, double intensity, Windows::Foundation::TimeSpan playDuration) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendHapticFeedbackForDuration, WINRT_WRAP(void), Windows::Devices::Haptics::SimpleHapticsControllerFeedback const&, double, Windows::Foundation::TimeSpan const&);
            this->shim().SendHapticFeedbackForDuration(*reinterpret_cast<Windows::Devices::Haptics::SimpleHapticsControllerFeedback const*>(&feedback), intensity, *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&playDuration));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SendHapticFeedbackForPlayCount(void* feedback, double intensity, int32_t playCount, Windows::Foundation::TimeSpan replayPauseInterval) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendHapticFeedbackForPlayCount, WINRT_WRAP(void), Windows::Devices::Haptics::SimpleHapticsControllerFeedback const&, double, int32_t, Windows::Foundation::TimeSpan const&);
            this->shim().SendHapticFeedbackForPlayCount(*reinterpret_cast<Windows::Devices::Haptics::SimpleHapticsControllerFeedback const*>(&feedback), intensity, playCount, *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&replayPauseInterval));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Haptics::ISimpleHapticsControllerFeedback> : produce_base<D, Windows::Devices::Haptics::ISimpleHapticsControllerFeedback>
{
    int32_t WINRT_CALL get_Waveform(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Waveform, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().Waveform());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Duration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Haptics::IVibrationDevice> : produce_base<D, Windows::Devices::Haptics::IVibrationDevice>
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

    int32_t WINRT_CALL get_SimpleHapticsController(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SimpleHapticsController, WINRT_WRAP(Windows::Devices::Haptics::SimpleHapticsController));
            *value = detach_from<Windows::Devices::Haptics::SimpleHapticsController>(this->shim().SimpleHapticsController());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Haptics::IVibrationDeviceStatics> : produce_base<D, Windows::Devices::Haptics::IVibrationDeviceStatics>
{
    int32_t WINRT_CALL RequestAccessAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAccessAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Haptics::VibrationAccessStatus>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Haptics::VibrationAccessStatus>>(this->shim().RequestAccessAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Haptics::VibrationDevice>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Haptics::VibrationDevice>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
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
            WINRT_ASSERT_DECLARATION(GetDefaultAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Haptics::VibrationDevice>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Haptics::VibrationDevice>>(this->shim().GetDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAllAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAllAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Haptics::VibrationDevice>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Haptics::VibrationDevice>>>(this->shim().FindAllAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::Haptics {

inline uint16_t KnownSimpleHapticsControllerWaveforms::Click()
{
    return impl::call_factory<KnownSimpleHapticsControllerWaveforms, Windows::Devices::Haptics::IKnownSimpleHapticsControllerWaveformsStatics>([&](auto&& f) { return f.Click(); });
}

inline uint16_t KnownSimpleHapticsControllerWaveforms::BuzzContinuous()
{
    return impl::call_factory<KnownSimpleHapticsControllerWaveforms, Windows::Devices::Haptics::IKnownSimpleHapticsControllerWaveformsStatics>([&](auto&& f) { return f.BuzzContinuous(); });
}

inline uint16_t KnownSimpleHapticsControllerWaveforms::RumbleContinuous()
{
    return impl::call_factory<KnownSimpleHapticsControllerWaveforms, Windows::Devices::Haptics::IKnownSimpleHapticsControllerWaveformsStatics>([&](auto&& f) { return f.RumbleContinuous(); });
}

inline uint16_t KnownSimpleHapticsControllerWaveforms::Press()
{
    return impl::call_factory<KnownSimpleHapticsControllerWaveforms, Windows::Devices::Haptics::IKnownSimpleHapticsControllerWaveformsStatics>([&](auto&& f) { return f.Press(); });
}

inline uint16_t KnownSimpleHapticsControllerWaveforms::Release()
{
    return impl::call_factory<KnownSimpleHapticsControllerWaveforms, Windows::Devices::Haptics::IKnownSimpleHapticsControllerWaveformsStatics>([&](auto&& f) { return f.Release(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Haptics::VibrationAccessStatus> VibrationDevice::RequestAccessAsync()
{
    return impl::call_factory<VibrationDevice, Windows::Devices::Haptics::IVibrationDeviceStatics>([&](auto&& f) { return f.RequestAccessAsync(); });
}

inline hstring VibrationDevice::GetDeviceSelector()
{
    return impl::call_factory<VibrationDevice, Windows::Devices::Haptics::IVibrationDeviceStatics>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Haptics::VibrationDevice> VibrationDevice::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<VibrationDevice, Windows::Devices::Haptics::IVibrationDeviceStatics>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Haptics::VibrationDevice> VibrationDevice::GetDefaultAsync()
{
    return impl::call_factory<VibrationDevice, Windows::Devices::Haptics::IVibrationDeviceStatics>([&](auto&& f) { return f.GetDefaultAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Haptics::VibrationDevice>> VibrationDevice::FindAllAsync()
{
    return impl::call_factory<VibrationDevice, Windows::Devices::Haptics::IVibrationDeviceStatics>([&](auto&& f) { return f.FindAllAsync(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::Haptics::IKnownSimpleHapticsControllerWaveformsStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Haptics::IKnownSimpleHapticsControllerWaveformsStatics> {};
template<> struct hash<winrt::Windows::Devices::Haptics::ISimpleHapticsController> : winrt::impl::hash_base<winrt::Windows::Devices::Haptics::ISimpleHapticsController> {};
template<> struct hash<winrt::Windows::Devices::Haptics::ISimpleHapticsControllerFeedback> : winrt::impl::hash_base<winrt::Windows::Devices::Haptics::ISimpleHapticsControllerFeedback> {};
template<> struct hash<winrt::Windows::Devices::Haptics::IVibrationDevice> : winrt::impl::hash_base<winrt::Windows::Devices::Haptics::IVibrationDevice> {};
template<> struct hash<winrt::Windows::Devices::Haptics::IVibrationDeviceStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Haptics::IVibrationDeviceStatics> {};
template<> struct hash<winrt::Windows::Devices::Haptics::KnownSimpleHapticsControllerWaveforms> : winrt::impl::hash_base<winrt::Windows::Devices::Haptics::KnownSimpleHapticsControllerWaveforms> {};
template<> struct hash<winrt::Windows::Devices::Haptics::SimpleHapticsController> : winrt::impl::hash_base<winrt::Windows::Devices::Haptics::SimpleHapticsController> {};
template<> struct hash<winrt::Windows::Devices::Haptics::SimpleHapticsControllerFeedback> : winrt::impl::hash_base<winrt::Windows::Devices::Haptics::SimpleHapticsControllerFeedback> {};
template<> struct hash<winrt::Windows::Devices::Haptics::VibrationDevice> : winrt::impl::hash_base<winrt::Windows::Devices::Haptics::VibrationDevice> {};

}
