// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.UI.Xaml.2.h"
#include "winrt/impl/Windows.UI.Xaml.Media.2.h"
#include "winrt/impl/Windows.UI.Xaml.Media.Media3D.2.h"
#include "winrt/impl/Windows.UI.Xaml.Core.Direct.2.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::GetObject(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject) const
{
    Windows::Foundation::IInspectable result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->GetObject(get_abi(xamlDirectObject), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Core::Direct::IXamlDirectObject consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::GetXamlDirectObject(Windows::Foundation::IInspectable const& object) const
{
    Windows::UI::Xaml::Core::Direct::IXamlDirectObject result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->GetXamlDirectObject(get_abi(object), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Core::Direct::IXamlDirectObject consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::CreateInstance(Windows::UI::Xaml::Core::Direct::XamlTypeIndex const& typeIndex) const
{
    Windows::UI::Xaml::Core::Direct::IXamlDirectObject result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->CreateInstance(get_abi(typeIndex), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::SetObjectProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex, Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->SetObjectProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::SetXamlDirectObjectProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex, Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->SetXamlDirectObjectProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::SetBooleanProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->SetBooleanProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), value));
}

template <typename D> void consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::SetDoubleProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex, double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->SetDoubleProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), value));
}

template <typename D> void consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::SetInt32Property(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex, int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->SetInt32Property(get_abi(xamlDirectObject), get_abi(propertyIndex), value));
}

template <typename D> void consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::SetStringProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex, param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->SetStringProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::SetDateTimeProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex, Windows::Foundation::DateTime const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->SetDateTimeProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::SetPointProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex, Windows::Foundation::Point const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->SetPointProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::SetRectProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex, Windows::Foundation::Rect const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->SetRectProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::SetSizeProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex, Windows::Foundation::Size const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->SetSizeProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::SetTimeSpanProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex, Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->SetTimeSpanProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::SetColorProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex, Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->SetColorProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::SetCornerRadiusProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex, Windows::UI::Xaml::CornerRadius const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->SetCornerRadiusProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::SetDurationProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex, Windows::UI::Xaml::Duration const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->SetDurationProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::SetGridLengthProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex, Windows::UI::Xaml::GridLength const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->SetGridLengthProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::SetThicknessProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex, Windows::UI::Xaml::Thickness const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->SetThicknessProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::SetMatrixProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex, Windows::UI::Xaml::Media::Matrix const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->SetMatrixProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::SetMatrix3DProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex, Windows::UI::Xaml::Media::Media3D::Matrix3D const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->SetMatrix3DProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::SetEnumProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex, uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->SetEnumProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), value));
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::GetObjectProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex) const
{
    Windows::Foundation::IInspectable result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->GetObjectProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Core::Direct::IXamlDirectObject consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::GetXamlDirectObjectProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex) const
{
    Windows::UI::Xaml::Core::Direct::IXamlDirectObject result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->GetXamlDirectObjectProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::GetBooleanProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->GetBooleanProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), &result));
    return result;
}

template <typename D> double consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::GetDoubleProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex) const
{
    double result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->GetDoubleProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), &result));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::GetInt32Property(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->GetInt32Property(get_abi(xamlDirectObject), get_abi(propertyIndex), &result));
    return result;
}

template <typename D> hstring consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::GetStringProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->GetStringProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::GetDateTimeProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex) const
{
    Windows::Foundation::DateTime result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->GetDateTimeProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::GetPointProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex) const
{
    Windows::Foundation::Point result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->GetPointProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::GetRectProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex) const
{
    Windows::Foundation::Rect result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->GetRectProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Size consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::GetSizeProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex) const
{
    Windows::Foundation::Size result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->GetSizeProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::GetTimeSpanProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex) const
{
    Windows::Foundation::TimeSpan result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->GetTimeSpanProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Color consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::GetColorProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex) const
{
    Windows::UI::Color result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->GetColorProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::CornerRadius consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::GetCornerRadiusProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex) const
{
    Windows::UI::Xaml::CornerRadius result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->GetCornerRadiusProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Duration consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::GetDurationProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex) const
{
    Windows::UI::Xaml::Duration result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->GetDurationProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::GridLength consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::GetGridLengthProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex) const
{
    Windows::UI::Xaml::GridLength result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->GetGridLengthProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Thickness consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::GetThicknessProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex) const
{
    Windows::UI::Xaml::Thickness result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->GetThicknessProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Media::Matrix consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::GetMatrixProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex) const
{
    Windows::UI::Xaml::Media::Matrix result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->GetMatrixProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Media::Media3D::Matrix3D consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::GetMatrix3DProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex) const
{
    Windows::UI::Xaml::Media::Media3D::Matrix3D result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->GetMatrix3DProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), put_abi(result)));
    return result;
}

template <typename D> uint32_t consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::GetEnumProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex) const
{
    uint32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->GetEnumProperty(get_abi(xamlDirectObject), get_abi(propertyIndex), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::ClearProperty(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const& propertyIndex) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->ClearProperty(get_abi(xamlDirectObject), get_abi(propertyIndex)));
}

template <typename D> uint32_t consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::GetCollectionCount(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject) const
{
    uint32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->GetCollectionCount(get_abi(xamlDirectObject), &result));
    return result;
}

template <typename D> Windows::UI::Xaml::Core::Direct::IXamlDirectObject consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::GetXamlDirectObjectFromCollectionAt(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, uint32_t index) const
{
    Windows::UI::Xaml::Core::Direct::IXamlDirectObject result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->GetXamlDirectObjectFromCollectionAt(get_abi(xamlDirectObject), index, put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::AddToCollection(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->AddToCollection(get_abi(xamlDirectObject), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::InsertIntoCollectionAt(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, uint32_t index, Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->InsertIntoCollectionAt(get_abi(xamlDirectObject), index, get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::RemoveFromCollection(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& value) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->RemoveFromCollection(get_abi(xamlDirectObject), get_abi(value), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::RemoveFromCollectionAt(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, uint32_t index) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->RemoveFromCollectionAt(get_abi(xamlDirectObject), index));
}

template <typename D> void consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::ClearCollection(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->ClearCollection(get_abi(xamlDirectObject)));
}

template <typename D> void consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::AddEventHandler(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlEventIndex const& eventIndex, Windows::Foundation::IInspectable const& handler) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->AddEventHandler(get_abi(xamlDirectObject), get_abi(eventIndex), get_abi(handler)));
}

template <typename D> void consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::AddEventHandler(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlEventIndex const& eventIndex, Windows::Foundation::IInspectable const& handler, bool handledEventsToo) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->AddEventHandler_HandledEventsToo(get_abi(xamlDirectObject), get_abi(eventIndex), get_abi(handler), handledEventsToo));
}

template <typename D> void consume_Windows_UI_Xaml_Core_Direct_IXamlDirect<D>::RemoveEventHandler(Windows::UI::Xaml::Core::Direct::IXamlDirectObject const& xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlEventIndex const& eventIndex, Windows::Foundation::IInspectable const& handler) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirect)->RemoveEventHandler(get_abi(xamlDirectObject), get_abi(eventIndex), get_abi(handler)));
}

template <typename D> Windows::UI::Xaml::Core::Direct::XamlDirect consume_Windows_UI_Xaml_Core_Direct_IXamlDirectStatics<D>::GetDefault() const
{
    Windows::UI::Xaml::Core::Direct::XamlDirect result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Core::Direct::IXamlDirectStatics)->GetDefault(put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::UI::Xaml::Core::Direct::IXamlDirect> : produce_base<D, Windows::UI::Xaml::Core::Direct::IXamlDirect>
{
    int32_t WINRT_CALL GetObject(void* xamlDirectObject, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetObject, WINRT_WRAP(Windows::Foundation::IInspectable), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&);
            *result = detach_from<Windows::Foundation::IInspectable>(this->shim().GetObject(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetXamlDirectObject(void* object, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetXamlDirectObject, WINRT_WRAP(Windows::UI::Xaml::Core::Direct::IXamlDirectObject), Windows::Foundation::IInspectable const&);
            *result = detach_from<Windows::UI::Xaml::Core::Direct::IXamlDirectObject>(this->shim().GetXamlDirectObject(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&object)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateInstance(Windows::UI::Xaml::Core::Direct::XamlTypeIndex typeIndex, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Core::Direct::IXamlDirectObject), Windows::UI::Xaml::Core::Direct::XamlTypeIndex const&);
            *result = detach_from<Windows::UI::Xaml::Core::Direct::IXamlDirectObject>(this->shim().CreateInstance(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlTypeIndex const*>(&typeIndex)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetObjectProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetObjectProperty, WINRT_WRAP(void), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&, Windows::Foundation::IInspectable const&);
            this->shim().SetObjectProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetXamlDirectObjectProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetXamlDirectObjectProperty, WINRT_WRAP(void), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&, Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&);
            this->shim().SetXamlDirectObjectProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetBooleanProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetBooleanProperty, WINRT_WRAP(void), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&, bool);
            this->shim().SetBooleanProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetDoubleProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetDoubleProperty, WINRT_WRAP(void), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&, double);
            this->shim().SetDoubleProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetInt32Property(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetInt32Property, WINRT_WRAP(void), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&, int32_t);
            this->shim().SetInt32Property(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetStringProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetStringProperty, WINRT_WRAP(void), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&, hstring const&);
            this->shim().SetStringProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex), *reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetDateTimeProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, Windows::Foundation::DateTime value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetDateTimeProperty, WINRT_WRAP(void), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&, Windows::Foundation::DateTime const&);
            this->shim().SetDateTimeProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex), *reinterpret_cast<Windows::Foundation::DateTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPointProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, Windows::Foundation::Point value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPointProperty, WINRT_WRAP(void), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&, Windows::Foundation::Point const&);
            this->shim().SetPointProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex), *reinterpret_cast<Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetRectProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, Windows::Foundation::Rect value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetRectProperty, WINRT_WRAP(void), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&, Windows::Foundation::Rect const&);
            this->shim().SetRectProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex), *reinterpret_cast<Windows::Foundation::Rect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetSizeProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, Windows::Foundation::Size value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetSizeProperty, WINRT_WRAP(void), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&, Windows::Foundation::Size const&);
            this->shim().SetSizeProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex), *reinterpret_cast<Windows::Foundation::Size const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetTimeSpanProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetTimeSpanProperty, WINRT_WRAP(void), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&, Windows::Foundation::TimeSpan const&);
            this->shim().SetTimeSpanProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetColorProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetColorProperty, WINRT_WRAP(void), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&, Windows::UI::Color const&);
            this->shim().SetColorProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex), *reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetCornerRadiusProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, struct struct_Windows_UI_Xaml_CornerRadius value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetCornerRadiusProperty, WINRT_WRAP(void), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&, Windows::UI::Xaml::CornerRadius const&);
            this->shim().SetCornerRadiusProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex), *reinterpret_cast<Windows::UI::Xaml::CornerRadius const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetDurationProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, struct struct_Windows_UI_Xaml_Duration value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetDurationProperty, WINRT_WRAP(void), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&, Windows::UI::Xaml::Duration const&);
            this->shim().SetDurationProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex), *reinterpret_cast<Windows::UI::Xaml::Duration const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetGridLengthProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, struct struct_Windows_UI_Xaml_GridLength value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetGridLengthProperty, WINRT_WRAP(void), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&, Windows::UI::Xaml::GridLength const&);
            this->shim().SetGridLengthProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex), *reinterpret_cast<Windows::UI::Xaml::GridLength const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetThicknessProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, struct struct_Windows_UI_Xaml_Thickness value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetThicknessProperty, WINRT_WRAP(void), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&, Windows::UI::Xaml::Thickness const&);
            this->shim().SetThicknessProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex), *reinterpret_cast<Windows::UI::Xaml::Thickness const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetMatrixProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, struct struct_Windows_UI_Xaml_Media_Matrix value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetMatrixProperty, WINRT_WRAP(void), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&, Windows::UI::Xaml::Media::Matrix const&);
            this->shim().SetMatrixProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex), *reinterpret_cast<Windows::UI::Xaml::Media::Matrix const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetMatrix3DProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, struct struct_Windows_UI_Xaml_Media_Media3D_Matrix3D value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetMatrix3DProperty, WINRT_WRAP(void), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&, Windows::UI::Xaml::Media::Media3D::Matrix3D const&);
            this->shim().SetMatrix3DProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex), *reinterpret_cast<Windows::UI::Xaml::Media::Media3D::Matrix3D const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetEnumProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetEnumProperty, WINRT_WRAP(void), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&, uint32_t);
            this->shim().SetEnumProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetObjectProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetObjectProperty, WINRT_WRAP(Windows::Foundation::IInspectable), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&);
            *result = detach_from<Windows::Foundation::IInspectable>(this->shim().GetObjectProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetXamlDirectObjectProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetXamlDirectObjectProperty, WINRT_WRAP(Windows::UI::Xaml::Core::Direct::IXamlDirectObject), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&);
            *result = detach_from<Windows::UI::Xaml::Core::Direct::IXamlDirectObject>(this->shim().GetXamlDirectObjectProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetBooleanProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetBooleanProperty, WINRT_WRAP(bool), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&);
            *result = detach_from<bool>(this->shim().GetBooleanProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDoubleProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, double* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDoubleProperty, WINRT_WRAP(double), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&);
            *result = detach_from<double>(this->shim().GetDoubleProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetInt32Property(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetInt32Property, WINRT_WRAP(int32_t), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&);
            *result = detach_from<int32_t>(this->shim().GetInt32Property(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStringProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStringProperty, WINRT_WRAP(hstring), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&);
            *result = detach_from<hstring>(this->shim().GetStringProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDateTimeProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, Windows::Foundation::DateTime* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDateTimeProperty, WINRT_WRAP(Windows::Foundation::DateTime), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&);
            *result = detach_from<Windows::Foundation::DateTime>(this->shim().GetDateTimeProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPointProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, Windows::Foundation::Point* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPointProperty, WINRT_WRAP(Windows::Foundation::Point), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&);
            *result = detach_from<Windows::Foundation::Point>(this->shim().GetPointProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetRectProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, Windows::Foundation::Rect* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetRectProperty, WINRT_WRAP(Windows::Foundation::Rect), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&);
            *result = detach_from<Windows::Foundation::Rect>(this->shim().GetRectProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSizeProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, Windows::Foundation::Size* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSizeProperty, WINRT_WRAP(Windows::Foundation::Size), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&);
            *result = detach_from<Windows::Foundation::Size>(this->shim().GetSizeProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetTimeSpanProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, Windows::Foundation::TimeSpan* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTimeSpanProperty, WINRT_WRAP(Windows::Foundation::TimeSpan), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&);
            *result = detach_from<Windows::Foundation::TimeSpan>(this->shim().GetTimeSpanProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetColorProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, struct struct_Windows_UI_Color* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetColorProperty, WINRT_WRAP(Windows::UI::Color), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&);
            *result = detach_from<Windows::UI::Color>(this->shim().GetColorProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCornerRadiusProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, struct struct_Windows_UI_Xaml_CornerRadius* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCornerRadiusProperty, WINRT_WRAP(Windows::UI::Xaml::CornerRadius), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&);
            *result = detach_from<Windows::UI::Xaml::CornerRadius>(this->shim().GetCornerRadiusProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDurationProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, struct struct_Windows_UI_Xaml_Duration* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDurationProperty, WINRT_WRAP(Windows::UI::Xaml::Duration), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&);
            *result = detach_from<Windows::UI::Xaml::Duration>(this->shim().GetDurationProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetGridLengthProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, struct struct_Windows_UI_Xaml_GridLength* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetGridLengthProperty, WINRT_WRAP(Windows::UI::Xaml::GridLength), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&);
            *result = detach_from<Windows::UI::Xaml::GridLength>(this->shim().GetGridLengthProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetThicknessProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, struct struct_Windows_UI_Xaml_Thickness* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetThicknessProperty, WINRT_WRAP(Windows::UI::Xaml::Thickness), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&);
            *result = detach_from<Windows::UI::Xaml::Thickness>(this->shim().GetThicknessProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetMatrixProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, struct struct_Windows_UI_Xaml_Media_Matrix* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetMatrixProperty, WINRT_WRAP(Windows::UI::Xaml::Media::Matrix), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&);
            *result = detach_from<Windows::UI::Xaml::Media::Matrix>(this->shim().GetMatrixProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetMatrix3DProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, struct struct_Windows_UI_Xaml_Media_Media3D_Matrix3D* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetMatrix3DProperty, WINRT_WRAP(Windows::UI::Xaml::Media::Media3D::Matrix3D), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&);
            *result = detach_from<Windows::UI::Xaml::Media::Media3D::Matrix3D>(this->shim().GetMatrix3DProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetEnumProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex, uint32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetEnumProperty, WINRT_WRAP(uint32_t), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&);
            *result = detach_from<uint32_t>(this->shim().GetEnumProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClearProperty(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex propertyIndex) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClearProperty, WINRT_WRAP(void), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const&);
            this->shim().ClearProperty(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlPropertyIndex const*>(&propertyIndex));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCollectionCount(void* xamlDirectObject, uint32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCollectionCount, WINRT_WRAP(uint32_t), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&);
            *result = detach_from<uint32_t>(this->shim().GetCollectionCount(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetXamlDirectObjectFromCollectionAt(void* xamlDirectObject, uint32_t index, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetXamlDirectObjectFromCollectionAt, WINRT_WRAP(Windows::UI::Xaml::Core::Direct::IXamlDirectObject), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, uint32_t);
            *result = detach_from<Windows::UI::Xaml::Core::Direct::IXamlDirectObject>(this->shim().GetXamlDirectObjectFromCollectionAt(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), index));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddToCollection(void* xamlDirectObject, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddToCollection, WINRT_WRAP(void), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&);
            this->shim().AddToCollection(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InsertIntoCollectionAt(void* xamlDirectObject, uint32_t index, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertIntoCollectionAt, WINRT_WRAP(void), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, uint32_t, Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&);
            this->shim().InsertIntoCollectionAt(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), index, *reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveFromCollection(void* xamlDirectObject, void* value, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveFromCollection, WINRT_WRAP(bool), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&);
            *result = detach_from<bool>(this->shim().RemoveFromCollection(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveFromCollectionAt(void* xamlDirectObject, uint32_t index) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveFromCollectionAt, WINRT_WRAP(void), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, uint32_t);
            this->shim().RemoveFromCollectionAt(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), index);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClearCollection(void* xamlDirectObject) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClearCollection, WINRT_WRAP(void), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&);
            this->shim().ClearCollection(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddEventHandler(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlEventIndex eventIndex, void* handler) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddEventHandler, WINRT_WRAP(void), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlEventIndex const&, Windows::Foundation::IInspectable const&);
            this->shim().AddEventHandler(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlEventIndex const*>(&eventIndex), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&handler));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddEventHandler_HandledEventsToo(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlEventIndex eventIndex, void* handler, bool handledEventsToo) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddEventHandler, WINRT_WRAP(void), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlEventIndex const&, Windows::Foundation::IInspectable const&, bool);
            this->shim().AddEventHandler(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlEventIndex const*>(&eventIndex), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&handler), handledEventsToo);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveEventHandler(void* xamlDirectObject, Windows::UI::Xaml::Core::Direct::XamlEventIndex eventIndex, void* handler) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveEventHandler, WINRT_WRAP(void), Windows::UI::Xaml::Core::Direct::IXamlDirectObject const&, Windows::UI::Xaml::Core::Direct::XamlEventIndex const&, Windows::Foundation::IInspectable const&);
            this->shim().RemoveEventHandler(*reinterpret_cast<Windows::UI::Xaml::Core::Direct::IXamlDirectObject const*>(&xamlDirectObject), *reinterpret_cast<Windows::UI::Xaml::Core::Direct::XamlEventIndex const*>(&eventIndex), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&handler));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Core::Direct::IXamlDirectObject> : produce_base<D, Windows::UI::Xaml::Core::Direct::IXamlDirectObject>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Core::Direct::IXamlDirectStatics> : produce_base<D, Windows::UI::Xaml::Core::Direct::IXamlDirectStatics>
{
    int32_t WINRT_CALL GetDefault(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::UI::Xaml::Core::Direct::XamlDirect));
            *result = detach_from<Windows::UI::Xaml::Core::Direct::XamlDirect>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Core::Direct {

inline Windows::UI::Xaml::Core::Direct::XamlDirect XamlDirect::GetDefault()
{
    return impl::call_factory<XamlDirect, Windows::UI::Xaml::Core::Direct::IXamlDirectStatics>([&](auto&& f) { return f.GetDefault(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Xaml::Core::Direct::IXamlDirect> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Core::Direct::IXamlDirect> {};
template<> struct hash<winrt::Windows::UI::Xaml::Core::Direct::IXamlDirectObject> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Core::Direct::IXamlDirectObject> {};
template<> struct hash<winrt::Windows::UI::Xaml::Core::Direct::IXamlDirectStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Core::Direct::IXamlDirectStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Core::Direct::XamlDirect> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Core::Direct::XamlDirect> {};

}
