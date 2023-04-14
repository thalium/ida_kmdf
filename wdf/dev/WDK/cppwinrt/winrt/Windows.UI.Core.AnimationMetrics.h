// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.UI.Core.AnimationMetrics.2.h"
#include "winrt/Windows.UI.Core.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::Core::AnimationMetrics::IPropertyAnimation> consume_Windows_UI_Core_AnimationMetrics_IAnimationDescription<D>::Animations() const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::Core::AnimationMetrics::IPropertyAnimation> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::AnimationMetrics::IAnimationDescription)->get_Animations(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_UI_Core_AnimationMetrics_IAnimationDescription<D>::StaggerDelay() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::AnimationMetrics::IAnimationDescription)->get_StaggerDelay(put_abi(value)));
    return value;
}

template <typename D> float consume_Windows_UI_Core_AnimationMetrics_IAnimationDescription<D>::StaggerDelayFactor() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::AnimationMetrics::IAnimationDescription)->get_StaggerDelayFactor(&value));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_UI_Core_AnimationMetrics_IAnimationDescription<D>::DelayLimit() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::AnimationMetrics::IAnimationDescription)->get_DelayLimit(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Core_AnimationMetrics_IAnimationDescription<D>::ZOrder() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::AnimationMetrics::IAnimationDescription)->get_ZOrder(&value));
    return value;
}

template <typename D> Windows::UI::Core::AnimationMetrics::AnimationDescription consume_Windows_UI_Core_AnimationMetrics_IAnimationDescriptionFactory<D>::CreateInstance(Windows::UI::Core::AnimationMetrics::AnimationEffect const& effect, Windows::UI::Core::AnimationMetrics::AnimationEffectTarget const& target) const
{
    Windows::UI::Core::AnimationMetrics::AnimationDescription animation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::AnimationMetrics::IAnimationDescriptionFactory)->CreateInstance(get_abi(effect), get_abi(target), put_abi(animation)));
    return animation;
}

template <typename D> Windows::Foundation::IReference<float> consume_Windows_UI_Core_AnimationMetrics_IOpacityAnimation<D>::InitialOpacity() const
{
    Windows::Foundation::IReference<float> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::AnimationMetrics::IOpacityAnimation)->get_InitialOpacity(put_abi(value)));
    return value;
}

template <typename D> float consume_Windows_UI_Core_AnimationMetrics_IOpacityAnimation<D>::FinalOpacity() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::AnimationMetrics::IOpacityAnimation)->get_FinalOpacity(&value));
    return value;
}

template <typename D> Windows::UI::Core::AnimationMetrics::PropertyAnimationType consume_Windows_UI_Core_AnimationMetrics_IPropertyAnimation<D>::Type() const
{
    Windows::UI::Core::AnimationMetrics::PropertyAnimationType value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::AnimationMetrics::IPropertyAnimation)->get_Type(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_UI_Core_AnimationMetrics_IPropertyAnimation<D>::Delay() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::AnimationMetrics::IPropertyAnimation)->get_Delay(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_UI_Core_AnimationMetrics_IPropertyAnimation<D>::Duration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::AnimationMetrics::IPropertyAnimation)->get_Duration(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Core_AnimationMetrics_IPropertyAnimation<D>::Control1() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::AnimationMetrics::IPropertyAnimation)->get_Control1(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Core_AnimationMetrics_IPropertyAnimation<D>::Control2() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::AnimationMetrics::IPropertyAnimation)->get_Control2(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<float> consume_Windows_UI_Core_AnimationMetrics_IScaleAnimation<D>::InitialScaleX() const
{
    Windows::Foundation::IReference<float> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::AnimationMetrics::IScaleAnimation)->get_InitialScaleX(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<float> consume_Windows_UI_Core_AnimationMetrics_IScaleAnimation<D>::InitialScaleY() const
{
    Windows::Foundation::IReference<float> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::AnimationMetrics::IScaleAnimation)->get_InitialScaleY(put_abi(value)));
    return value;
}

template <typename D> float consume_Windows_UI_Core_AnimationMetrics_IScaleAnimation<D>::FinalScaleX() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::AnimationMetrics::IScaleAnimation)->get_FinalScaleX(&value));
    return value;
}

template <typename D> float consume_Windows_UI_Core_AnimationMetrics_IScaleAnimation<D>::FinalScaleY() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::AnimationMetrics::IScaleAnimation)->get_FinalScaleY(&value));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Core_AnimationMetrics_IScaleAnimation<D>::NormalizedOrigin() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::AnimationMetrics::IScaleAnimation)->get_NormalizedOrigin(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::UI::Core::AnimationMetrics::IAnimationDescription> : produce_base<D, Windows::UI::Core::AnimationMetrics::IAnimationDescription>
{
    int32_t WINRT_CALL get_Animations(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Animations, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::Core::AnimationMetrics::IPropertyAnimation>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::Core::AnimationMetrics::IPropertyAnimation>>(this->shim().Animations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StaggerDelay(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StaggerDelay, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().StaggerDelay());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StaggerDelayFactor(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StaggerDelayFactor, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().StaggerDelayFactor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DelayLimit(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DelayLimit, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().DelayLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ZOrder(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZOrder, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ZOrder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::AnimationMetrics::IAnimationDescriptionFactory> : produce_base<D, Windows::UI::Core::AnimationMetrics::IAnimationDescriptionFactory>
{
    int32_t WINRT_CALL CreateInstance(Windows::UI::Core::AnimationMetrics::AnimationEffect effect, Windows::UI::Core::AnimationMetrics::AnimationEffectTarget target, void** animation) noexcept final
    {
        try
        {
            *animation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Core::AnimationMetrics::AnimationDescription), Windows::UI::Core::AnimationMetrics::AnimationEffect const&, Windows::UI::Core::AnimationMetrics::AnimationEffectTarget const&);
            *animation = detach_from<Windows::UI::Core::AnimationMetrics::AnimationDescription>(this->shim().CreateInstance(*reinterpret_cast<Windows::UI::Core::AnimationMetrics::AnimationEffect const*>(&effect), *reinterpret_cast<Windows::UI::Core::AnimationMetrics::AnimationEffectTarget const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::AnimationMetrics::IOpacityAnimation> : produce_base<D, Windows::UI::Core::AnimationMetrics::IOpacityAnimation>
{
    int32_t WINRT_CALL get_InitialOpacity(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InitialOpacity, WINRT_WRAP(Windows::Foundation::IReference<float>));
            *value = detach_from<Windows::Foundation::IReference<float>>(this->shim().InitialOpacity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FinalOpacity(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FinalOpacity, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().FinalOpacity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::AnimationMetrics::IPropertyAnimation> : produce_base<D, Windows::UI::Core::AnimationMetrics::IPropertyAnimation>
{
    int32_t WINRT_CALL get_Type(Windows::UI::Core::AnimationMetrics::PropertyAnimationType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(Windows::UI::Core::AnimationMetrics::PropertyAnimationType));
            *value = detach_from<Windows::UI::Core::AnimationMetrics::PropertyAnimationType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Delay(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Delay, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Delay());
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

    int32_t WINRT_CALL get_Control1(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Control1, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Control1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Control2(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Control2, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Control2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::AnimationMetrics::IScaleAnimation> : produce_base<D, Windows::UI::Core::AnimationMetrics::IScaleAnimation>
{
    int32_t WINRT_CALL get_InitialScaleX(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InitialScaleX, WINRT_WRAP(Windows::Foundation::IReference<float>));
            *value = detach_from<Windows::Foundation::IReference<float>>(this->shim().InitialScaleX());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InitialScaleY(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InitialScaleY, WINRT_WRAP(Windows::Foundation::IReference<float>));
            *value = detach_from<Windows::Foundation::IReference<float>>(this->shim().InitialScaleY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FinalScaleX(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FinalScaleX, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().FinalScaleX());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FinalScaleY(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FinalScaleY, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().FinalScaleY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NormalizedOrigin(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NormalizedOrigin, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().NormalizedOrigin());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::Core::AnimationMetrics {

inline AnimationDescription::AnimationDescription(Windows::UI::Core::AnimationMetrics::AnimationEffect const& effect, Windows::UI::Core::AnimationMetrics::AnimationEffectTarget const& target) :
    AnimationDescription(impl::call_factory<AnimationDescription, Windows::UI::Core::AnimationMetrics::IAnimationDescriptionFactory>([&](auto&& f) { return f.CreateInstance(effect, target); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Core::AnimationMetrics::IAnimationDescription> : winrt::impl::hash_base<winrt::Windows::UI::Core::AnimationMetrics::IAnimationDescription> {};
template<> struct hash<winrt::Windows::UI::Core::AnimationMetrics::IAnimationDescriptionFactory> : winrt::impl::hash_base<winrt::Windows::UI::Core::AnimationMetrics::IAnimationDescriptionFactory> {};
template<> struct hash<winrt::Windows::UI::Core::AnimationMetrics::IOpacityAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Core::AnimationMetrics::IOpacityAnimation> {};
template<> struct hash<winrt::Windows::UI::Core::AnimationMetrics::IPropertyAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Core::AnimationMetrics::IPropertyAnimation> {};
template<> struct hash<winrt::Windows::UI::Core::AnimationMetrics::IScaleAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Core::AnimationMetrics::IScaleAnimation> {};
template<> struct hash<winrt::Windows::UI::Core::AnimationMetrics::AnimationDescription> : winrt::impl::hash_base<winrt::Windows::UI::Core::AnimationMetrics::AnimationDescription> {};
template<> struct hash<winrt::Windows::UI::Core::AnimationMetrics::OpacityAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Core::AnimationMetrics::OpacityAnimation> {};
template<> struct hash<winrt::Windows::UI::Core::AnimationMetrics::PropertyAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Core::AnimationMetrics::PropertyAnimation> {};
template<> struct hash<winrt::Windows::UI::Core::AnimationMetrics::ScaleAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Core::AnimationMetrics::ScaleAnimation> {};
template<> struct hash<winrt::Windows::UI::Core::AnimationMetrics::TranslationAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Core::AnimationMetrics::TranslationAnimation> {};

}
