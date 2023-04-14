// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Gaming.Input.ForceFeedback.2.h"
#include "winrt/Windows.Gaming.Input.h"

namespace winrt::impl {

template <typename D> Windows::Gaming::Input::ForceFeedback::ConditionForceEffectKind consume_Windows_Gaming_Input_ForceFeedback_IConditionForceEffect<D>::Kind() const
{
    Windows::Gaming::Input::ForceFeedback::ConditionForceEffectKind value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::ForceFeedback::IConditionForceEffect)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Gaming_Input_ForceFeedback_IConditionForceEffect<D>::SetParameters(Windows::Foundation::Numerics::float3 const& direction, float positiveCoefficient, float negativeCoefficient, float maxPositiveMagnitude, float maxNegativeMagnitude, float deadZone, float bias) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::ForceFeedback::IConditionForceEffect)->SetParameters(get_abi(direction), positiveCoefficient, negativeCoefficient, maxPositiveMagnitude, maxNegativeMagnitude, deadZone, bias));
}

template <typename D> Windows::Gaming::Input::ForceFeedback::ConditionForceEffect consume_Windows_Gaming_Input_ForceFeedback_IConditionForceEffectFactory<D>::CreateInstance(Windows::Gaming::Input::ForceFeedback::ConditionForceEffectKind const& effectKind) const
{
    Windows::Gaming::Input::ForceFeedback::ConditionForceEffect value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::ForceFeedback::IConditionForceEffectFactory)->CreateInstance(get_abi(effectKind), put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Gaming_Input_ForceFeedback_IConstantForceEffect<D>::SetParameters(Windows::Foundation::Numerics::float3 const& vector, Windows::Foundation::TimeSpan const& duration) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::ForceFeedback::IConstantForceEffect)->SetParameters(get_abi(vector), get_abi(duration)));
}

template <typename D> void consume_Windows_Gaming_Input_ForceFeedback_IConstantForceEffect<D>::SetParametersWithEnvelope(Windows::Foundation::Numerics::float3 const& vector, float attackGain, float sustainGain, float releaseGain, Windows::Foundation::TimeSpan const& startDelay, Windows::Foundation::TimeSpan const& attackDuration, Windows::Foundation::TimeSpan const& sustainDuration, Windows::Foundation::TimeSpan const& releaseDuration, uint32_t repeatCount) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::ForceFeedback::IConstantForceEffect)->SetParametersWithEnvelope(get_abi(vector), attackGain, sustainGain, releaseGain, get_abi(startDelay), get_abi(attackDuration), get_abi(sustainDuration), get_abi(releaseDuration), repeatCount));
}

template <typename D> double consume_Windows_Gaming_Input_ForceFeedback_IForceFeedbackEffect<D>::Gain() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::ForceFeedback::IForceFeedbackEffect)->get_Gain(&value));
    return value;
}

template <typename D> void consume_Windows_Gaming_Input_ForceFeedback_IForceFeedbackEffect<D>::Gain(double value) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::ForceFeedback::IForceFeedbackEffect)->put_Gain(value));
}

template <typename D> Windows::Gaming::Input::ForceFeedback::ForceFeedbackEffectState consume_Windows_Gaming_Input_ForceFeedback_IForceFeedbackEffect<D>::State() const
{
    Windows::Gaming::Input::ForceFeedback::ForceFeedbackEffectState value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::ForceFeedback::IForceFeedbackEffect)->get_State(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Gaming_Input_ForceFeedback_IForceFeedbackEffect<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::ForceFeedback::IForceFeedbackEffect)->Start());
}

template <typename D> void consume_Windows_Gaming_Input_ForceFeedback_IForceFeedbackEffect<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::ForceFeedback::IForceFeedbackEffect)->Stop());
}

template <typename D> bool consume_Windows_Gaming_Input_ForceFeedback_IForceFeedbackMotor<D>::AreEffectsPaused() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::ForceFeedback::IForceFeedbackMotor)->get_AreEffectsPaused(&value));
    return value;
}

template <typename D> double consume_Windows_Gaming_Input_ForceFeedback_IForceFeedbackMotor<D>::MasterGain() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::ForceFeedback::IForceFeedbackMotor)->get_MasterGain(&value));
    return value;
}

template <typename D> void consume_Windows_Gaming_Input_ForceFeedback_IForceFeedbackMotor<D>::MasterGain(double value) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::ForceFeedback::IForceFeedbackMotor)->put_MasterGain(value));
}

template <typename D> bool consume_Windows_Gaming_Input_ForceFeedback_IForceFeedbackMotor<D>::IsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::ForceFeedback::IForceFeedbackMotor)->get_IsEnabled(&value));
    return value;
}

template <typename D> Windows::Gaming::Input::ForceFeedback::ForceFeedbackEffectAxes consume_Windows_Gaming_Input_ForceFeedback_IForceFeedbackMotor<D>::SupportedAxes() const
{
    Windows::Gaming::Input::ForceFeedback::ForceFeedbackEffectAxes value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::ForceFeedback::IForceFeedbackMotor)->get_SupportedAxes(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Gaming::Input::ForceFeedback::ForceFeedbackLoadEffectResult> consume_Windows_Gaming_Input_ForceFeedback_IForceFeedbackMotor<D>::LoadEffectAsync(Windows::Gaming::Input::ForceFeedback::IForceFeedbackEffect const& effect) const
{
    Windows::Foundation::IAsyncOperation<Windows::Gaming::Input::ForceFeedback::ForceFeedbackLoadEffectResult> asyncOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::ForceFeedback::IForceFeedbackMotor)->LoadEffectAsync(get_abi(effect), put_abi(asyncOperation)));
    return asyncOperation;
}

template <typename D> void consume_Windows_Gaming_Input_ForceFeedback_IForceFeedbackMotor<D>::PauseAllEffects() const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::ForceFeedback::IForceFeedbackMotor)->PauseAllEffects());
}

template <typename D> void consume_Windows_Gaming_Input_ForceFeedback_IForceFeedbackMotor<D>::ResumeAllEffects() const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::ForceFeedback::IForceFeedbackMotor)->ResumeAllEffects());
}

template <typename D> void consume_Windows_Gaming_Input_ForceFeedback_IForceFeedbackMotor<D>::StopAllEffects() const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::ForceFeedback::IForceFeedbackMotor)->StopAllEffects());
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Gaming_Input_ForceFeedback_IForceFeedbackMotor<D>::TryDisableAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> asyncOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::ForceFeedback::IForceFeedbackMotor)->TryDisableAsync(put_abi(asyncOperation)));
    return asyncOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Gaming_Input_ForceFeedback_IForceFeedbackMotor<D>::TryEnableAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> asyncOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::ForceFeedback::IForceFeedbackMotor)->TryEnableAsync(put_abi(asyncOperation)));
    return asyncOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Gaming_Input_ForceFeedback_IForceFeedbackMotor<D>::TryResetAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> asyncOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::ForceFeedback::IForceFeedbackMotor)->TryResetAsync(put_abi(asyncOperation)));
    return asyncOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Gaming_Input_ForceFeedback_IForceFeedbackMotor<D>::TryUnloadEffectAsync(Windows::Gaming::Input::ForceFeedback::IForceFeedbackEffect const& effect) const
{
    Windows::Foundation::IAsyncOperation<bool> asyncOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::ForceFeedback::IForceFeedbackMotor)->TryUnloadEffectAsync(get_abi(effect), put_abi(asyncOperation)));
    return asyncOperation;
}

template <typename D> Windows::Gaming::Input::ForceFeedback::PeriodicForceEffectKind consume_Windows_Gaming_Input_ForceFeedback_IPeriodicForceEffect<D>::Kind() const
{
    Windows::Gaming::Input::ForceFeedback::PeriodicForceEffectKind value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::ForceFeedback::IPeriodicForceEffect)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Gaming_Input_ForceFeedback_IPeriodicForceEffect<D>::SetParameters(Windows::Foundation::Numerics::float3 const& vector, float frequency, float phase, float bias, Windows::Foundation::TimeSpan const& duration) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::ForceFeedback::IPeriodicForceEffect)->SetParameters(get_abi(vector), frequency, phase, bias, get_abi(duration)));
}

template <typename D> void consume_Windows_Gaming_Input_ForceFeedback_IPeriodicForceEffect<D>::SetParametersWithEnvelope(Windows::Foundation::Numerics::float3 const& vector, float frequency, float phase, float bias, float attackGain, float sustainGain, float releaseGain, Windows::Foundation::TimeSpan const& startDelay, Windows::Foundation::TimeSpan const& attackDuration, Windows::Foundation::TimeSpan const& sustainDuration, Windows::Foundation::TimeSpan const& releaseDuration, uint32_t repeatCount) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::ForceFeedback::IPeriodicForceEffect)->SetParametersWithEnvelope(get_abi(vector), frequency, phase, bias, attackGain, sustainGain, releaseGain, get_abi(startDelay), get_abi(attackDuration), get_abi(sustainDuration), get_abi(releaseDuration), repeatCount));
}

template <typename D> Windows::Gaming::Input::ForceFeedback::PeriodicForceEffect consume_Windows_Gaming_Input_ForceFeedback_IPeriodicForceEffectFactory<D>::CreateInstance(Windows::Gaming::Input::ForceFeedback::PeriodicForceEffectKind const& effectKind) const
{
    Windows::Gaming::Input::ForceFeedback::PeriodicForceEffect value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::ForceFeedback::IPeriodicForceEffectFactory)->CreateInstance(get_abi(effectKind), put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Gaming_Input_ForceFeedback_IRampForceEffect<D>::SetParameters(Windows::Foundation::Numerics::float3 const& startVector, Windows::Foundation::Numerics::float3 const& endVector, Windows::Foundation::TimeSpan const& duration) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::ForceFeedback::IRampForceEffect)->SetParameters(get_abi(startVector), get_abi(endVector), get_abi(duration)));
}

template <typename D> void consume_Windows_Gaming_Input_ForceFeedback_IRampForceEffect<D>::SetParametersWithEnvelope(Windows::Foundation::Numerics::float3 const& startVector, Windows::Foundation::Numerics::float3 const& endVector, float attackGain, float sustainGain, float releaseGain, Windows::Foundation::TimeSpan const& startDelay, Windows::Foundation::TimeSpan const& attackDuration, Windows::Foundation::TimeSpan const& sustainDuration, Windows::Foundation::TimeSpan const& releaseDuration, uint32_t repeatCount) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::ForceFeedback::IRampForceEffect)->SetParametersWithEnvelope(get_abi(startVector), get_abi(endVector), attackGain, sustainGain, releaseGain, get_abi(startDelay), get_abi(attackDuration), get_abi(sustainDuration), get_abi(releaseDuration), repeatCount));
}

template <typename D>
struct produce<D, Windows::Gaming::Input::ForceFeedback::IConditionForceEffect> : produce_base<D, Windows::Gaming::Input::ForceFeedback::IConditionForceEffect>
{
    int32_t WINRT_CALL get_Kind(Windows::Gaming::Input::ForceFeedback::ConditionForceEffectKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::Gaming::Input::ForceFeedback::ConditionForceEffectKind));
            *value = detach_from<Windows::Gaming::Input::ForceFeedback::ConditionForceEffectKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetParameters(Windows::Foundation::Numerics::float3 direction, float positiveCoefficient, float negativeCoefficient, float maxPositiveMagnitude, float maxNegativeMagnitude, float deadZone, float bias) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetParameters, WINRT_WRAP(void), Windows::Foundation::Numerics::float3 const&, float, float, float, float, float, float);
            this->shim().SetParameters(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&direction), positiveCoefficient, negativeCoefficient, maxPositiveMagnitude, maxNegativeMagnitude, deadZone, bias);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::ForceFeedback::IConditionForceEffectFactory> : produce_base<D, Windows::Gaming::Input::ForceFeedback::IConditionForceEffectFactory>
{
    int32_t WINRT_CALL CreateInstance(Windows::Gaming::Input::ForceFeedback::ConditionForceEffectKind effectKind, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::Gaming::Input::ForceFeedback::ConditionForceEffect), Windows::Gaming::Input::ForceFeedback::ConditionForceEffectKind const&);
            *value = detach_from<Windows::Gaming::Input::ForceFeedback::ConditionForceEffect>(this->shim().CreateInstance(*reinterpret_cast<Windows::Gaming::Input::ForceFeedback::ConditionForceEffectKind const*>(&effectKind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::ForceFeedback::IConstantForceEffect> : produce_base<D, Windows::Gaming::Input::ForceFeedback::IConstantForceEffect>
{
    int32_t WINRT_CALL SetParameters(Windows::Foundation::Numerics::float3 vector, Windows::Foundation::TimeSpan duration) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetParameters, WINRT_WRAP(void), Windows::Foundation::Numerics::float3 const&, Windows::Foundation::TimeSpan const&);
            this->shim().SetParameters(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&vector), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&duration));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetParametersWithEnvelope(Windows::Foundation::Numerics::float3 vector, float attackGain, float sustainGain, float releaseGain, Windows::Foundation::TimeSpan startDelay, Windows::Foundation::TimeSpan attackDuration, Windows::Foundation::TimeSpan sustainDuration, Windows::Foundation::TimeSpan releaseDuration, uint32_t repeatCount) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetParametersWithEnvelope, WINRT_WRAP(void), Windows::Foundation::Numerics::float3 const&, float, float, float, Windows::Foundation::TimeSpan const&, Windows::Foundation::TimeSpan const&, Windows::Foundation::TimeSpan const&, Windows::Foundation::TimeSpan const&, uint32_t);
            this->shim().SetParametersWithEnvelope(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&vector), attackGain, sustainGain, releaseGain, *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&startDelay), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&attackDuration), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&sustainDuration), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&releaseDuration), repeatCount);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::ForceFeedback::IForceFeedbackEffect> : produce_base<D, Windows::Gaming::Input::ForceFeedback::IForceFeedbackEffect>
{
    int32_t WINRT_CALL get_Gain(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Gain, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Gain());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Gain(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Gain, WINRT_WRAP(void), double);
            this->shim().Gain(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_State(Windows::Gaming::Input::ForceFeedback::ForceFeedbackEffectState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::Gaming::Input::ForceFeedback::ForceFeedbackEffectState));
            *value = detach_from<Windows::Gaming::Input::ForceFeedback::ForceFeedbackEffectState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Start() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Start, WINRT_WRAP(void));
            this->shim().Start();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Stop() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stop, WINRT_WRAP(void));
            this->shim().Stop();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::ForceFeedback::IForceFeedbackMotor> : produce_base<D, Windows::Gaming::Input::ForceFeedback::IForceFeedbackMotor>
{
    int32_t WINRT_CALL get_AreEffectsPaused(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AreEffectsPaused, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AreEffectsPaused());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MasterGain(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MasterGain, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().MasterGain());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MasterGain(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MasterGain, WINRT_WRAP(void), double);
            this->shim().MasterGain(value);
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

    int32_t WINRT_CALL get_SupportedAxes(Windows::Gaming::Input::ForceFeedback::ForceFeedbackEffectAxes* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedAxes, WINRT_WRAP(Windows::Gaming::Input::ForceFeedback::ForceFeedbackEffectAxes));
            *value = detach_from<Windows::Gaming::Input::ForceFeedback::ForceFeedbackEffectAxes>(this->shim().SupportedAxes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LoadEffectAsync(void* effect, void** asyncOperation) noexcept final
    {
        try
        {
            *asyncOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadEffectAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Gaming::Input::ForceFeedback::ForceFeedbackLoadEffectResult>), Windows::Gaming::Input::ForceFeedback::IForceFeedbackEffect const);
            *asyncOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Gaming::Input::ForceFeedback::ForceFeedbackLoadEffectResult>>(this->shim().LoadEffectAsync(*reinterpret_cast<Windows::Gaming::Input::ForceFeedback::IForceFeedbackEffect const*>(&effect)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PauseAllEffects() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PauseAllEffects, WINRT_WRAP(void));
            this->shim().PauseAllEffects();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ResumeAllEffects() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResumeAllEffects, WINRT_WRAP(void));
            this->shim().ResumeAllEffects();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopAllEffects() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopAllEffects, WINRT_WRAP(void));
            this->shim().StopAllEffects();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryDisableAsync(void** asyncOperation) noexcept final
    {
        try
        {
            *asyncOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryDisableAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *asyncOperation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryDisableAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryEnableAsync(void** asyncOperation) noexcept final
    {
        try
        {
            *asyncOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryEnableAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *asyncOperation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryEnableAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryResetAsync(void** asyncOperation) noexcept final
    {
        try
        {
            *asyncOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryResetAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *asyncOperation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryResetAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryUnloadEffectAsync(void* effect, void** asyncOperation) noexcept final
    {
        try
        {
            *asyncOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryUnloadEffectAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Gaming::Input::ForceFeedback::IForceFeedbackEffect const);
            *asyncOperation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryUnloadEffectAsync(*reinterpret_cast<Windows::Gaming::Input::ForceFeedback::IForceFeedbackEffect const*>(&effect)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::ForceFeedback::IPeriodicForceEffect> : produce_base<D, Windows::Gaming::Input::ForceFeedback::IPeriodicForceEffect>
{
    int32_t WINRT_CALL get_Kind(Windows::Gaming::Input::ForceFeedback::PeriodicForceEffectKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::Gaming::Input::ForceFeedback::PeriodicForceEffectKind));
            *value = detach_from<Windows::Gaming::Input::ForceFeedback::PeriodicForceEffectKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetParameters(Windows::Foundation::Numerics::float3 vector, float frequency, float phase, float bias, Windows::Foundation::TimeSpan duration) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetParameters, WINRT_WRAP(void), Windows::Foundation::Numerics::float3 const&, float, float, float, Windows::Foundation::TimeSpan const&);
            this->shim().SetParameters(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&vector), frequency, phase, bias, *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&duration));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetParametersWithEnvelope(Windows::Foundation::Numerics::float3 vector, float frequency, float phase, float bias, float attackGain, float sustainGain, float releaseGain, Windows::Foundation::TimeSpan startDelay, Windows::Foundation::TimeSpan attackDuration, Windows::Foundation::TimeSpan sustainDuration, Windows::Foundation::TimeSpan releaseDuration, uint32_t repeatCount) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetParametersWithEnvelope, WINRT_WRAP(void), Windows::Foundation::Numerics::float3 const&, float, float, float, float, float, float, Windows::Foundation::TimeSpan const&, Windows::Foundation::TimeSpan const&, Windows::Foundation::TimeSpan const&, Windows::Foundation::TimeSpan const&, uint32_t);
            this->shim().SetParametersWithEnvelope(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&vector), frequency, phase, bias, attackGain, sustainGain, releaseGain, *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&startDelay), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&attackDuration), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&sustainDuration), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&releaseDuration), repeatCount);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::ForceFeedback::IPeriodicForceEffectFactory> : produce_base<D, Windows::Gaming::Input::ForceFeedback::IPeriodicForceEffectFactory>
{
    int32_t WINRT_CALL CreateInstance(Windows::Gaming::Input::ForceFeedback::PeriodicForceEffectKind effectKind, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::Gaming::Input::ForceFeedback::PeriodicForceEffect), Windows::Gaming::Input::ForceFeedback::PeriodicForceEffectKind const&);
            *value = detach_from<Windows::Gaming::Input::ForceFeedback::PeriodicForceEffect>(this->shim().CreateInstance(*reinterpret_cast<Windows::Gaming::Input::ForceFeedback::PeriodicForceEffectKind const*>(&effectKind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::ForceFeedback::IRampForceEffect> : produce_base<D, Windows::Gaming::Input::ForceFeedback::IRampForceEffect>
{
    int32_t WINRT_CALL SetParameters(Windows::Foundation::Numerics::float3 startVector, Windows::Foundation::Numerics::float3 endVector, Windows::Foundation::TimeSpan duration) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetParameters, WINRT_WRAP(void), Windows::Foundation::Numerics::float3 const&, Windows::Foundation::Numerics::float3 const&, Windows::Foundation::TimeSpan const&);
            this->shim().SetParameters(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&startVector), *reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&endVector), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&duration));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetParametersWithEnvelope(Windows::Foundation::Numerics::float3 startVector, Windows::Foundation::Numerics::float3 endVector, float attackGain, float sustainGain, float releaseGain, Windows::Foundation::TimeSpan startDelay, Windows::Foundation::TimeSpan attackDuration, Windows::Foundation::TimeSpan sustainDuration, Windows::Foundation::TimeSpan releaseDuration, uint32_t repeatCount) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetParametersWithEnvelope, WINRT_WRAP(void), Windows::Foundation::Numerics::float3 const&, Windows::Foundation::Numerics::float3 const&, float, float, float, Windows::Foundation::TimeSpan const&, Windows::Foundation::TimeSpan const&, Windows::Foundation::TimeSpan const&, Windows::Foundation::TimeSpan const&, uint32_t);
            this->shim().SetParametersWithEnvelope(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&startVector), *reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&endVector), attackGain, sustainGain, releaseGain, *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&startDelay), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&attackDuration), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&sustainDuration), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&releaseDuration), repeatCount);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Gaming::Input::ForceFeedback {

inline ConditionForceEffect::ConditionForceEffect(Windows::Gaming::Input::ForceFeedback::ConditionForceEffectKind const& effectKind) :
    ConditionForceEffect(impl::call_factory<ConditionForceEffect, Windows::Gaming::Input::ForceFeedback::IConditionForceEffectFactory>([&](auto&& f) { return f.CreateInstance(effectKind); }))
{}

inline ConstantForceEffect::ConstantForceEffect() :
    ConstantForceEffect(impl::call_factory<ConstantForceEffect>([](auto&& f) { return f.template ActivateInstance<ConstantForceEffect>(); }))
{}

inline PeriodicForceEffect::PeriodicForceEffect(Windows::Gaming::Input::ForceFeedback::PeriodicForceEffectKind const& effectKind) :
    PeriodicForceEffect(impl::call_factory<PeriodicForceEffect, Windows::Gaming::Input::ForceFeedback::IPeriodicForceEffectFactory>([&](auto&& f) { return f.CreateInstance(effectKind); }))
{}

inline RampForceEffect::RampForceEffect() :
    RampForceEffect(impl::call_factory<RampForceEffect>([](auto&& f) { return f.template ActivateInstance<RampForceEffect>(); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Gaming::Input::ForceFeedback::IConditionForceEffect> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::ForceFeedback::IConditionForceEffect> {};
template<> struct hash<winrt::Windows::Gaming::Input::ForceFeedback::IConditionForceEffectFactory> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::ForceFeedback::IConditionForceEffectFactory> {};
template<> struct hash<winrt::Windows::Gaming::Input::ForceFeedback::IConstantForceEffect> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::ForceFeedback::IConstantForceEffect> {};
template<> struct hash<winrt::Windows::Gaming::Input::ForceFeedback::IForceFeedbackEffect> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::ForceFeedback::IForceFeedbackEffect> {};
template<> struct hash<winrt::Windows::Gaming::Input::ForceFeedback::IForceFeedbackMotor> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::ForceFeedback::IForceFeedbackMotor> {};
template<> struct hash<winrt::Windows::Gaming::Input::ForceFeedback::IPeriodicForceEffect> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::ForceFeedback::IPeriodicForceEffect> {};
template<> struct hash<winrt::Windows::Gaming::Input::ForceFeedback::IPeriodicForceEffectFactory> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::ForceFeedback::IPeriodicForceEffectFactory> {};
template<> struct hash<winrt::Windows::Gaming::Input::ForceFeedback::IRampForceEffect> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::ForceFeedback::IRampForceEffect> {};
template<> struct hash<winrt::Windows::Gaming::Input::ForceFeedback::ConditionForceEffect> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::ForceFeedback::ConditionForceEffect> {};
template<> struct hash<winrt::Windows::Gaming::Input::ForceFeedback::ConstantForceEffect> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::ForceFeedback::ConstantForceEffect> {};
template<> struct hash<winrt::Windows::Gaming::Input::ForceFeedback::ForceFeedbackMotor> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::ForceFeedback::ForceFeedbackMotor> {};
template<> struct hash<winrt::Windows::Gaming::Input::ForceFeedback::PeriodicForceEffect> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::ForceFeedback::PeriodicForceEffect> {};
template<> struct hash<winrt::Windows::Gaming::Input::ForceFeedback::RampForceEffect> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::ForceFeedback::RampForceEffect> {};

}
