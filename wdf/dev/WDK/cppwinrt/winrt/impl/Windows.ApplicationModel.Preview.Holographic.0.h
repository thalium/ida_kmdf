// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Activation {

struct IActivatedEventArgs;

}

WINRT_EXPORT namespace winrt::Windows::Perception::Spatial {

struct SpatialCoordinateSystem;

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Preview::Holographic {

struct IHolographicApplicationPreviewStatics;
struct IHolographicKeyboardPlacementOverridePreview;
struct IHolographicKeyboardPlacementOverridePreviewStatics;
struct HolographicApplicationPreview;
struct HolographicKeyboardPlacementOverridePreview;

}

namespace winrt::impl {

template <> struct category<Windows::ApplicationModel::Preview::Holographic::IHolographicApplicationPreviewStatics>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreview>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreviewStatics>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Preview::Holographic::HolographicApplicationPreview>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Preview::Holographic::HolographicKeyboardPlacementOverridePreview>{ using type = class_category; };
template <> struct name<Windows::ApplicationModel::Preview::Holographic::IHolographicApplicationPreviewStatics>{ static constexpr auto & value{ L"Windows.ApplicationModel.Preview.Holographic.IHolographicApplicationPreviewStatics" }; };
template <> struct name<Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreview>{ static constexpr auto & value{ L"Windows.ApplicationModel.Preview.Holographic.IHolographicKeyboardPlacementOverridePreview" }; };
template <> struct name<Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreviewStatics>{ static constexpr auto & value{ L"Windows.ApplicationModel.Preview.Holographic.IHolographicKeyboardPlacementOverridePreviewStatics" }; };
template <> struct name<Windows::ApplicationModel::Preview::Holographic::HolographicApplicationPreview>{ static constexpr auto & value{ L"Windows.ApplicationModel.Preview.Holographic.HolographicApplicationPreview" }; };
template <> struct name<Windows::ApplicationModel::Preview::Holographic::HolographicKeyboardPlacementOverridePreview>{ static constexpr auto & value{ L"Windows.ApplicationModel.Preview.Holographic.HolographicKeyboardPlacementOverridePreview" }; };
template <> struct guid_storage<Windows::ApplicationModel::Preview::Holographic::IHolographicApplicationPreviewStatics>{ static constexpr guid value{ 0xFE038691,0x2A3A,0x45A9,{ 0xA2,0x08,0x7B,0xED,0x69,0x19,0x19,0xF3 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreview>{ static constexpr guid value{ 0xC8A8CE3A,0xDFDE,0x5A14,{ 0x8D,0x5F,0x18,0x2C,0x52,0x6D,0xD9,0xC4 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreviewStatics>{ static constexpr guid value{ 0x202E6039,0x1FF6,0x5A06,{ 0xAA,0xC4,0xA5,0xE2,0x4F,0xA3,0xEC,0x4B } }; };
template <> struct default_interface<Windows::ApplicationModel::Preview::Holographic::HolographicKeyboardPlacementOverridePreview>{ using type = Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreview; };

template <> struct abi<Windows::ApplicationModel::Preview::Holographic::IHolographicApplicationPreviewStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL IsCurrentViewPresentedOnHolographicDisplay(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL IsHolographicActivation(void* activatedEventArgs, bool* result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreview>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL SetPlacementOverride(void* coordinateSystem, Windows::Foundation::Numerics::float3 topCenterPosition, Windows::Foundation::Numerics::float3 normal) noexcept = 0;
    virtual int32_t WINRT_CALL SetPlacementOverrideWithMaxSize(void* coordinateSystem, Windows::Foundation::Numerics::float3 topCenterPosition, Windows::Foundation::Numerics::float3 normal, Windows::Foundation::Numerics::float2 maxSize) noexcept = 0;
    virtual int32_t WINRT_CALL ResetPlacementOverride() noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreviewStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetForCurrentView(void** result) noexcept = 0;
};};

template <typename D>
struct consume_Windows_ApplicationModel_Preview_Holographic_IHolographicApplicationPreviewStatics
{
    bool IsCurrentViewPresentedOnHolographicDisplay() const;
    bool IsHolographicActivation(Windows::ApplicationModel::Activation::IActivatedEventArgs const& activatedEventArgs) const;
};
template <> struct consume<Windows::ApplicationModel::Preview::Holographic::IHolographicApplicationPreviewStatics> { template <typename D> using type = consume_Windows_ApplicationModel_Preview_Holographic_IHolographicApplicationPreviewStatics<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Preview_Holographic_IHolographicKeyboardPlacementOverridePreview
{
    void SetPlacementOverride(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Foundation::Numerics::float3 const& topCenterPosition, Windows::Foundation::Numerics::float3 const& normal) const;
    void SetPlacementOverride(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Foundation::Numerics::float3 const& topCenterPosition, Windows::Foundation::Numerics::float3 const& normal, Windows::Foundation::Numerics::float2 const& maxSize) const;
    void ResetPlacementOverride() const;
};
template <> struct consume<Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreview> { template <typename D> using type = consume_Windows_ApplicationModel_Preview_Holographic_IHolographicKeyboardPlacementOverridePreview<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Preview_Holographic_IHolographicKeyboardPlacementOverridePreviewStatics
{
    Windows::ApplicationModel::Preview::Holographic::HolographicKeyboardPlacementOverridePreview GetForCurrentView() const;
};
template <> struct consume<Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreviewStatics> { template <typename D> using type = consume_Windows_ApplicationModel_Preview_Holographic_IHolographicKeyboardPlacementOverridePreviewStatics<D>; };

}
