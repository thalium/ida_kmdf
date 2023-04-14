// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.Activation.2.h"
#include "winrt/impl/Windows.Perception.Spatial.2.h"
#include "winrt/impl/Windows.ApplicationModel.Preview.Holographic.2.h"

namespace winrt::impl {

template <typename D> bool consume_Windows_ApplicationModel_Preview_Holographic_IHolographicApplicationPreviewStatics<D>::IsCurrentViewPresentedOnHolographicDisplay() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Preview::Holographic::IHolographicApplicationPreviewStatics)->IsCurrentViewPresentedOnHolographicDisplay(&result));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_Preview_Holographic_IHolographicApplicationPreviewStatics<D>::IsHolographicActivation(Windows::ApplicationModel::Activation::IActivatedEventArgs const& activatedEventArgs) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Preview::Holographic::IHolographicApplicationPreviewStatics)->IsHolographicActivation(get_abi(activatedEventArgs), &result));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Preview_Holographic_IHolographicKeyboardPlacementOverridePreview<D>::SetPlacementOverride(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Foundation::Numerics::float3 const& topCenterPosition, Windows::Foundation::Numerics::float3 const& normal) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreview)->SetPlacementOverride(get_abi(coordinateSystem), get_abi(topCenterPosition), get_abi(normal)));
}

template <typename D> void consume_Windows_ApplicationModel_Preview_Holographic_IHolographicKeyboardPlacementOverridePreview<D>::SetPlacementOverride(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Foundation::Numerics::float3 const& topCenterPosition, Windows::Foundation::Numerics::float3 const& normal, Windows::Foundation::Numerics::float2 const& maxSize) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreview)->SetPlacementOverrideWithMaxSize(get_abi(coordinateSystem), get_abi(topCenterPosition), get_abi(normal), get_abi(maxSize)));
}

template <typename D> void consume_Windows_ApplicationModel_Preview_Holographic_IHolographicKeyboardPlacementOverridePreview<D>::ResetPlacementOverride() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreview)->ResetPlacementOverride());
}

template <typename D> Windows::ApplicationModel::Preview::Holographic::HolographicKeyboardPlacementOverridePreview consume_Windows_ApplicationModel_Preview_Holographic_IHolographicKeyboardPlacementOverridePreviewStatics<D>::GetForCurrentView() const
{
    Windows::ApplicationModel::Preview::Holographic::HolographicKeyboardPlacementOverridePreview result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreviewStatics)->GetForCurrentView(put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::ApplicationModel::Preview::Holographic::IHolographicApplicationPreviewStatics> : produce_base<D, Windows::ApplicationModel::Preview::Holographic::IHolographicApplicationPreviewStatics>
{
    int32_t WINRT_CALL IsCurrentViewPresentedOnHolographicDisplay(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCurrentViewPresentedOnHolographicDisplay, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsCurrentViewPresentedOnHolographicDisplay());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsHolographicActivation(void* activatedEventArgs, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsHolographicActivation, WINRT_WRAP(bool), Windows::ApplicationModel::Activation::IActivatedEventArgs const&);
            *result = detach_from<bool>(this->shim().IsHolographicActivation(*reinterpret_cast<Windows::ApplicationModel::Activation::IActivatedEventArgs const*>(&activatedEventArgs)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreview> : produce_base<D, Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreview>
{
    int32_t WINRT_CALL SetPlacementOverride(void* coordinateSystem, Windows::Foundation::Numerics::float3 topCenterPosition, Windows::Foundation::Numerics::float3 normal) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPlacementOverride, WINRT_WRAP(void), Windows::Perception::Spatial::SpatialCoordinateSystem const&, Windows::Foundation::Numerics::float3 const&, Windows::Foundation::Numerics::float3 const&);
            this->shim().SetPlacementOverride(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem), *reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&topCenterPosition), *reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&normal));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPlacementOverrideWithMaxSize(void* coordinateSystem, Windows::Foundation::Numerics::float3 topCenterPosition, Windows::Foundation::Numerics::float3 normal, Windows::Foundation::Numerics::float2 maxSize) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPlacementOverride, WINRT_WRAP(void), Windows::Perception::Spatial::SpatialCoordinateSystem const&, Windows::Foundation::Numerics::float3 const&, Windows::Foundation::Numerics::float3 const&, Windows::Foundation::Numerics::float2 const&);
            this->shim().SetPlacementOverride(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem), *reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&topCenterPosition), *reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&normal), *reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&maxSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ResetPlacementOverride() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResetPlacementOverride, WINRT_WRAP(void));
            this->shim().ResetPlacementOverride();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreviewStatics> : produce_base<D, Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreviewStatics>
{
    int32_t WINRT_CALL GetForCurrentView(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentView, WINRT_WRAP(Windows::ApplicationModel::Preview::Holographic::HolographicKeyboardPlacementOverridePreview));
            *result = detach_from<Windows::ApplicationModel::Preview::Holographic::HolographicKeyboardPlacementOverridePreview>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Preview::Holographic {

inline bool HolographicApplicationPreview::IsCurrentViewPresentedOnHolographicDisplay()
{
    return impl::call_factory<HolographicApplicationPreview, Windows::ApplicationModel::Preview::Holographic::IHolographicApplicationPreviewStatics>([&](auto&& f) { return f.IsCurrentViewPresentedOnHolographicDisplay(); });
}

inline bool HolographicApplicationPreview::IsHolographicActivation(Windows::ApplicationModel::Activation::IActivatedEventArgs const& activatedEventArgs)
{
    return impl::call_factory<HolographicApplicationPreview, Windows::ApplicationModel::Preview::Holographic::IHolographicApplicationPreviewStatics>([&](auto&& f) { return f.IsHolographicActivation(activatedEventArgs); });
}

inline Windows::ApplicationModel::Preview::Holographic::HolographicKeyboardPlacementOverridePreview HolographicKeyboardPlacementOverridePreview::GetForCurrentView()
{
    return impl::call_factory<HolographicKeyboardPlacementOverridePreview, Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreviewStatics>([&](auto&& f) { return f.GetForCurrentView(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::Preview::Holographic::IHolographicApplicationPreviewStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Preview::Holographic::IHolographicApplicationPreviewStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreview> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreview> {};
template<> struct hash<winrt::Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreviewStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreviewStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::Preview::Holographic::HolographicApplicationPreview> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Preview::Holographic::HolographicApplicationPreview> {};
template<> struct hash<winrt::Windows::ApplicationModel::Preview::Holographic::HolographicKeyboardPlacementOverridePreview> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Preview::Holographic::HolographicKeyboardPlacementOverridePreview> {};

}
