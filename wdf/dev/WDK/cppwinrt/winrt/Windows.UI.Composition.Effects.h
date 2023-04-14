// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Graphics.Effects.2.h"
#include "winrt/impl/Windows.UI.Composition.Effects.2.h"
#include "winrt/Windows.UI.Composition.h"

namespace winrt::impl {

template <typename D> float consume_Windows_UI_Composition_Effects_ISceneLightingEffect<D>::AmbientAmount() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Effects::ISceneLightingEffect)->get_AmbientAmount(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Effects_ISceneLightingEffect<D>::AmbientAmount(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Effects::ISceneLightingEffect)->put_AmbientAmount(value));
}

template <typename D> float consume_Windows_UI_Composition_Effects_ISceneLightingEffect<D>::DiffuseAmount() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Effects::ISceneLightingEffect)->get_DiffuseAmount(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Effects_ISceneLightingEffect<D>::DiffuseAmount(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Effects::ISceneLightingEffect)->put_DiffuseAmount(value));
}

template <typename D> Windows::Graphics::Effects::IGraphicsEffectSource consume_Windows_UI_Composition_Effects_ISceneLightingEffect<D>::NormalMapSource() const
{
    Windows::Graphics::Effects::IGraphicsEffectSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Effects::ISceneLightingEffect)->get_NormalMapSource(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Effects_ISceneLightingEffect<D>::NormalMapSource(Windows::Graphics::Effects::IGraphicsEffectSource const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Effects::ISceneLightingEffect)->put_NormalMapSource(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_Effects_ISceneLightingEffect<D>::SpecularAmount() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Effects::ISceneLightingEffect)->get_SpecularAmount(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Effects_ISceneLightingEffect<D>::SpecularAmount(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Effects::ISceneLightingEffect)->put_SpecularAmount(value));
}

template <typename D> float consume_Windows_UI_Composition_Effects_ISceneLightingEffect<D>::SpecularShine() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Effects::ISceneLightingEffect)->get_SpecularShine(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Effects_ISceneLightingEffect<D>::SpecularShine(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Effects::ISceneLightingEffect)->put_SpecularShine(value));
}

template <typename D> Windows::UI::Composition::Effects::SceneLightingEffectReflectanceModel consume_Windows_UI_Composition_Effects_ISceneLightingEffect2<D>::ReflectanceModel() const
{
    Windows::UI::Composition::Effects::SceneLightingEffectReflectanceModel value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Effects::ISceneLightingEffect2)->get_ReflectanceModel(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Effects_ISceneLightingEffect2<D>::ReflectanceModel(Windows::UI::Composition::Effects::SceneLightingEffectReflectanceModel const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Effects::ISceneLightingEffect2)->put_ReflectanceModel(get_abi(value)));
}

template <typename D>
struct produce<D, Windows::UI::Composition::Effects::ISceneLightingEffect> : produce_base<D, Windows::UI::Composition::Effects::ISceneLightingEffect>
{
    int32_t WINRT_CALL get_AmbientAmount(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AmbientAmount, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().AmbientAmount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AmbientAmount(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AmbientAmount, WINRT_WRAP(void), float);
            this->shim().AmbientAmount(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DiffuseAmount(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DiffuseAmount, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().DiffuseAmount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DiffuseAmount(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DiffuseAmount, WINRT_WRAP(void), float);
            this->shim().DiffuseAmount(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NormalMapSource(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NormalMapSource, WINRT_WRAP(Windows::Graphics::Effects::IGraphicsEffectSource));
            *value = detach_from<Windows::Graphics::Effects::IGraphicsEffectSource>(this->shim().NormalMapSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_NormalMapSource(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NormalMapSource, WINRT_WRAP(void), Windows::Graphics::Effects::IGraphicsEffectSource const&);
            this->shim().NormalMapSource(*reinterpret_cast<Windows::Graphics::Effects::IGraphicsEffectSource const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SpecularAmount(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SpecularAmount, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().SpecularAmount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SpecularAmount(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SpecularAmount, WINRT_WRAP(void), float);
            this->shim().SpecularAmount(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SpecularShine(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SpecularShine, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().SpecularShine());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SpecularShine(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SpecularShine, WINRT_WRAP(void), float);
            this->shim().SpecularShine(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Effects::ISceneLightingEffect2> : produce_base<D, Windows::UI::Composition::Effects::ISceneLightingEffect2>
{
    int32_t WINRT_CALL get_ReflectanceModel(Windows::UI::Composition::Effects::SceneLightingEffectReflectanceModel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReflectanceModel, WINRT_WRAP(Windows::UI::Composition::Effects::SceneLightingEffectReflectanceModel));
            *value = detach_from<Windows::UI::Composition::Effects::SceneLightingEffectReflectanceModel>(this->shim().ReflectanceModel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ReflectanceModel(Windows::UI::Composition::Effects::SceneLightingEffectReflectanceModel value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReflectanceModel, WINRT_WRAP(void), Windows::UI::Composition::Effects::SceneLightingEffectReflectanceModel const&);
            this->shim().ReflectanceModel(*reinterpret_cast<Windows::UI::Composition::Effects::SceneLightingEffectReflectanceModel const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::Composition::Effects {

inline SceneLightingEffect::SceneLightingEffect() :
    SceneLightingEffect(impl::call_factory<SceneLightingEffect>([](auto&& f) { return f.template ActivateInstance<SceneLightingEffect>(); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Composition::Effects::ISceneLightingEffect> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Effects::ISceneLightingEffect> {};
template<> struct hash<winrt::Windows::UI::Composition::Effects::ISceneLightingEffect2> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Effects::ISceneLightingEffect2> {};
template<> struct hash<winrt::Windows::UI::Composition::Effects::SceneLightingEffect> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Effects::SceneLightingEffect> {};

}
