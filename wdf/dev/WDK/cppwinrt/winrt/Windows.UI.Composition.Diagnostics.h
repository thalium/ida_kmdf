// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.UI.Composition.2.h"
#include "winrt/impl/Windows.UI.Composition.Diagnostics.2.h"
#include "winrt/Windows.UI.Composition.h"

namespace winrt::impl {

template <typename D> void consume_Windows_UI_Composition_Diagnostics_ICompositionDebugHeatMaps<D>::Hide(Windows::UI::Composition::Visual const& subtree) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Diagnostics::ICompositionDebugHeatMaps)->Hide(get_abi(subtree)));
}

template <typename D> void consume_Windows_UI_Composition_Diagnostics_ICompositionDebugHeatMaps<D>::ShowMemoryUsage(Windows::UI::Composition::Visual const& subtree) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Diagnostics::ICompositionDebugHeatMaps)->ShowMemoryUsage(get_abi(subtree)));
}

template <typename D> void consume_Windows_UI_Composition_Diagnostics_ICompositionDebugHeatMaps<D>::ShowOverdraw(Windows::UI::Composition::Visual const& subtree, Windows::UI::Composition::Diagnostics::CompositionDebugOverdrawContentKinds const& contentKinds) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Diagnostics::ICompositionDebugHeatMaps)->ShowOverdraw(get_abi(subtree), get_abi(contentKinds)));
}

template <typename D> void consume_Windows_UI_Composition_Diagnostics_ICompositionDebugHeatMaps<D>::ShowRedraw(Windows::UI::Composition::Visual const& subtree) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Diagnostics::ICompositionDebugHeatMaps)->ShowRedraw(get_abi(subtree)));
}

template <typename D> Windows::UI::Composition::Diagnostics::CompositionDebugHeatMaps consume_Windows_UI_Composition_Diagnostics_ICompositionDebugSettings<D>::HeatMaps() const
{
    Windows::UI::Composition::Diagnostics::CompositionDebugHeatMaps result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Diagnostics::ICompositionDebugSettings)->get_HeatMaps(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::Diagnostics::CompositionDebugSettings consume_Windows_UI_Composition_Diagnostics_ICompositionDebugSettingsStatics<D>::TryGetSettings(Windows::UI::Composition::Compositor const& compositor) const
{
    Windows::UI::Composition::Diagnostics::CompositionDebugSettings result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Diagnostics::ICompositionDebugSettingsStatics)->TryGetSettings(get_abi(compositor), put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::UI::Composition::Diagnostics::ICompositionDebugHeatMaps> : produce_base<D, Windows::UI::Composition::Diagnostics::ICompositionDebugHeatMaps>
{
    int32_t WINRT_CALL Hide(void* subtree) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Hide, WINRT_WRAP(void), Windows::UI::Composition::Visual const&);
            this->shim().Hide(*reinterpret_cast<Windows::UI::Composition::Visual const*>(&subtree));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowMemoryUsage(void* subtree) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowMemoryUsage, WINRT_WRAP(void), Windows::UI::Composition::Visual const&);
            this->shim().ShowMemoryUsage(*reinterpret_cast<Windows::UI::Composition::Visual const*>(&subtree));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowOverdraw(void* subtree, Windows::UI::Composition::Diagnostics::CompositionDebugOverdrawContentKinds contentKinds) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowOverdraw, WINRT_WRAP(void), Windows::UI::Composition::Visual const&, Windows::UI::Composition::Diagnostics::CompositionDebugOverdrawContentKinds const&);
            this->shim().ShowOverdraw(*reinterpret_cast<Windows::UI::Composition::Visual const*>(&subtree), *reinterpret_cast<Windows::UI::Composition::Diagnostics::CompositionDebugOverdrawContentKinds const*>(&contentKinds));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowRedraw(void* subtree) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowRedraw, WINRT_WRAP(void), Windows::UI::Composition::Visual const&);
            this->shim().ShowRedraw(*reinterpret_cast<Windows::UI::Composition::Visual const*>(&subtree));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Diagnostics::ICompositionDebugSettings> : produce_base<D, Windows::UI::Composition::Diagnostics::ICompositionDebugSettings>
{
    int32_t WINRT_CALL get_HeatMaps(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeatMaps, WINRT_WRAP(Windows::UI::Composition::Diagnostics::CompositionDebugHeatMaps));
            *result = detach_from<Windows::UI::Composition::Diagnostics::CompositionDebugHeatMaps>(this->shim().HeatMaps());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Diagnostics::ICompositionDebugSettingsStatics> : produce_base<D, Windows::UI::Composition::Diagnostics::ICompositionDebugSettingsStatics>
{
    int32_t WINRT_CALL TryGetSettings(void* compositor, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetSettings, WINRT_WRAP(Windows::UI::Composition::Diagnostics::CompositionDebugSettings), Windows::UI::Composition::Compositor const&);
            *result = detach_from<Windows::UI::Composition::Diagnostics::CompositionDebugSettings>(this->shim().TryGetSettings(*reinterpret_cast<Windows::UI::Composition::Compositor const*>(&compositor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::Composition::Diagnostics {

inline Windows::UI::Composition::Diagnostics::CompositionDebugSettings CompositionDebugSettings::TryGetSettings(Windows::UI::Composition::Compositor const& compositor)
{
    return impl::call_factory<CompositionDebugSettings, Windows::UI::Composition::Diagnostics::ICompositionDebugSettingsStatics>([&](auto&& f) { return f.TryGetSettings(compositor); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Composition::Diagnostics::ICompositionDebugHeatMaps> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Diagnostics::ICompositionDebugHeatMaps> {};
template<> struct hash<winrt::Windows::UI::Composition::Diagnostics::ICompositionDebugSettings> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Diagnostics::ICompositionDebugSettings> {};
template<> struct hash<winrt::Windows::UI::Composition::Diagnostics::ICompositionDebugSettingsStatics> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Diagnostics::ICompositionDebugSettingsStatics> {};
template<> struct hash<winrt::Windows::UI::Composition::Diagnostics::CompositionDebugHeatMaps> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Diagnostics::CompositionDebugHeatMaps> {};
template<> struct hash<winrt::Windows::UI::Composition::Diagnostics::CompositionDebugSettings> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Diagnostics::CompositionDebugSettings> {};

}
