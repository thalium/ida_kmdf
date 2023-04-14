// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::UI::Composition {

struct Compositor;
struct Visual;

}

WINRT_EXPORT namespace winrt::Windows::UI::Composition::Diagnostics {

enum class CompositionDebugOverdrawContentKinds : uint32_t
{
    None = 0x0,
    OffscreenRendered = 0x1,
    Colors = 0x2,
    Effects = 0x4,
    Shadows = 0x8,
    Lights = 0x10,
    Surfaces = 0x20,
    SwapChains = 0x40,
    All = 0xFFFFFFFF,
};

struct ICompositionDebugHeatMaps;
struct ICompositionDebugSettings;
struct ICompositionDebugSettingsStatics;
struct CompositionDebugHeatMaps;
struct CompositionDebugSettings;

}

namespace winrt::impl {

template<> struct is_enum_flag<Windows::UI::Composition::Diagnostics::CompositionDebugOverdrawContentKinds> : std::true_type {};
template <> struct category<Windows::UI::Composition::Diagnostics::ICompositionDebugHeatMaps>{ using type = interface_category; };
template <> struct category<Windows::UI::Composition::Diagnostics::ICompositionDebugSettings>{ using type = interface_category; };
template <> struct category<Windows::UI::Composition::Diagnostics::ICompositionDebugSettingsStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Composition::Diagnostics::CompositionDebugHeatMaps>{ using type = class_category; };
template <> struct category<Windows::UI::Composition::Diagnostics::CompositionDebugSettings>{ using type = class_category; };
template <> struct category<Windows::UI::Composition::Diagnostics::CompositionDebugOverdrawContentKinds>{ using type = enum_category; };
template <> struct name<Windows::UI::Composition::Diagnostics::ICompositionDebugHeatMaps>{ static constexpr auto & value{ L"Windows.UI.Composition.Diagnostics.ICompositionDebugHeatMaps" }; };
template <> struct name<Windows::UI::Composition::Diagnostics::ICompositionDebugSettings>{ static constexpr auto & value{ L"Windows.UI.Composition.Diagnostics.ICompositionDebugSettings" }; };
template <> struct name<Windows::UI::Composition::Diagnostics::ICompositionDebugSettingsStatics>{ static constexpr auto & value{ L"Windows.UI.Composition.Diagnostics.ICompositionDebugSettingsStatics" }; };
template <> struct name<Windows::UI::Composition::Diagnostics::CompositionDebugHeatMaps>{ static constexpr auto & value{ L"Windows.UI.Composition.Diagnostics.CompositionDebugHeatMaps" }; };
template <> struct name<Windows::UI::Composition::Diagnostics::CompositionDebugSettings>{ static constexpr auto & value{ L"Windows.UI.Composition.Diagnostics.CompositionDebugSettings" }; };
template <> struct name<Windows::UI::Composition::Diagnostics::CompositionDebugOverdrawContentKinds>{ static constexpr auto & value{ L"Windows.UI.Composition.Diagnostics.CompositionDebugOverdrawContentKinds" }; };
template <> struct guid_storage<Windows::UI::Composition::Diagnostics::ICompositionDebugHeatMaps>{ static constexpr guid value{ 0xE49C90AC,0x2FF3,0x5805,{ 0x71,0x8C,0xB7,0x25,0xEE,0x07,0x65,0x0F } }; };
template <> struct guid_storage<Windows::UI::Composition::Diagnostics::ICompositionDebugSettings>{ static constexpr guid value{ 0x2831987E,0x1D82,0x4D38,{ 0xB7,0xB7,0xEF,0xD1,0x1C,0x7B,0xC3,0xD1 } }; };
template <> struct guid_storage<Windows::UI::Composition::Diagnostics::ICompositionDebugSettingsStatics>{ static constexpr guid value{ 0x64EC1F1E,0x6AF8,0x4AF8,{ 0xB8,0x14,0xC8,0x70,0xFD,0x5A,0x95,0x05 } }; };
template <> struct default_interface<Windows::UI::Composition::Diagnostics::CompositionDebugHeatMaps>{ using type = Windows::UI::Composition::Diagnostics::ICompositionDebugHeatMaps; };
template <> struct default_interface<Windows::UI::Composition::Diagnostics::CompositionDebugSettings>{ using type = Windows::UI::Composition::Diagnostics::ICompositionDebugSettings; };

template <> struct abi<Windows::UI::Composition::Diagnostics::ICompositionDebugHeatMaps>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Hide(void* subtree) noexcept = 0;
    virtual int32_t WINRT_CALL ShowMemoryUsage(void* subtree) noexcept = 0;
    virtual int32_t WINRT_CALL ShowOverdraw(void* subtree, Windows::UI::Composition::Diagnostics::CompositionDebugOverdrawContentKinds contentKinds) noexcept = 0;
    virtual int32_t WINRT_CALL ShowRedraw(void* subtree) noexcept = 0;
};};

template <> struct abi<Windows::UI::Composition::Diagnostics::ICompositionDebugSettings>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_HeatMaps(void** result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Composition::Diagnostics::ICompositionDebugSettingsStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL TryGetSettings(void* compositor, void** result) noexcept = 0;
};};

template <typename D>
struct consume_Windows_UI_Composition_Diagnostics_ICompositionDebugHeatMaps
{
    void Hide(Windows::UI::Composition::Visual const& subtree) const;
    void ShowMemoryUsage(Windows::UI::Composition::Visual const& subtree) const;
    void ShowOverdraw(Windows::UI::Composition::Visual const& subtree, Windows::UI::Composition::Diagnostics::CompositionDebugOverdrawContentKinds const& contentKinds) const;
    void ShowRedraw(Windows::UI::Composition::Visual const& subtree) const;
};
template <> struct consume<Windows::UI::Composition::Diagnostics::ICompositionDebugHeatMaps> { template <typename D> using type = consume_Windows_UI_Composition_Diagnostics_ICompositionDebugHeatMaps<D>; };

template <typename D>
struct consume_Windows_UI_Composition_Diagnostics_ICompositionDebugSettings
{
    Windows::UI::Composition::Diagnostics::CompositionDebugHeatMaps HeatMaps() const;
};
template <> struct consume<Windows::UI::Composition::Diagnostics::ICompositionDebugSettings> { template <typename D> using type = consume_Windows_UI_Composition_Diagnostics_ICompositionDebugSettings<D>; };

template <typename D>
struct consume_Windows_UI_Composition_Diagnostics_ICompositionDebugSettingsStatics
{
    Windows::UI::Composition::Diagnostics::CompositionDebugSettings TryGetSettings(Windows::UI::Composition::Compositor const& compositor) const;
};
template <> struct consume<Windows::UI::Composition::Diagnostics::ICompositionDebugSettingsStatics> { template <typename D> using type = consume_Windows_UI_Composition_Diagnostics_ICompositionDebugSettingsStatics<D>; };

}
