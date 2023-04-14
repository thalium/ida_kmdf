// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.UI.Xaml.2.h"
#include "winrt/impl/Windows.UI.Xaml.Media.Media3D.2.h"
#include "winrt/Windows.UI.Xaml.Media.h"

namespace winrt::impl {

template <typename D> double consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::CenterX() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->get_CenterX(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::CenterX(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->put_CenterX(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::CenterY() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->get_CenterY(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::CenterY(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->put_CenterY(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::CenterZ() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->get_CenterZ(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::CenterZ(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->put_CenterZ(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::RotationX() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->get_RotationX(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::RotationX(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->put_RotationX(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::RotationY() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->get_RotationY(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::RotationY(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->put_RotationY(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::RotationZ() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->get_RotationZ(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::RotationZ(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->put_RotationZ(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::ScaleX() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->get_ScaleX(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::ScaleX(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->put_ScaleX(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::ScaleY() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->get_ScaleY(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::ScaleY(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->put_ScaleY(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::ScaleZ() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->get_ScaleZ(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::ScaleZ(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->put_ScaleZ(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::TranslateX() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->get_TranslateX(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::TranslateX(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->put_TranslateX(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::TranslateY() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->get_TranslateY(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::TranslateY(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->put_TranslateY(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::TranslateZ() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->get_TranslateZ(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::TranslateZ(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->put_TranslateZ(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3DStatics<D>::CenterXProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics)->get_CenterXProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3DStatics<D>::CenterYProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics)->get_CenterYProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3DStatics<D>::CenterZProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics)->get_CenterZProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3DStatics<D>::RotationXProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics)->get_RotationXProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3DStatics<D>::RotationYProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics)->get_RotationYProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3DStatics<D>::RotationZProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics)->get_RotationZProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3DStatics<D>::ScaleXProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics)->get_ScaleXProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3DStatics<D>::ScaleYProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics)->get_ScaleYProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3DStatics<D>::ScaleZProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics)->get_ScaleZProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3DStatics<D>::TranslateXProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics)->get_TranslateXProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3DStatics<D>::TranslateYProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics)->get_TranslateYProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3DStatics<D>::TranslateZProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics)->get_TranslateZProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Media3D::Matrix3D consume_Windows_UI_Xaml_Media_Media3D_IMatrix3DHelperStatics<D>::Identity() const
{
    Windows::UI::Xaml::Media::Media3D::Matrix3D value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::IMatrix3DHelperStatics)->get_Identity(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Media3D::Matrix3D consume_Windows_UI_Xaml_Media_Media3D_IMatrix3DHelperStatics<D>::Multiply(Windows::UI::Xaml::Media::Media3D::Matrix3D const& matrix1, Windows::UI::Xaml::Media::Media3D::Matrix3D const& matrix2) const
{
    Windows::UI::Xaml::Media::Media3D::Matrix3D result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::IMatrix3DHelperStatics)->Multiply(get_abi(matrix1), get_abi(matrix2), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Media::Media3D::Matrix3D consume_Windows_UI_Xaml_Media_Media3D_IMatrix3DHelperStatics<D>::FromElements(double m11, double m12, double m13, double m14, double m21, double m22, double m23, double m24, double m31, double m32, double m33, double m34, double offsetX, double offsetY, double offsetZ, double m44) const
{
    Windows::UI::Xaml::Media::Media3D::Matrix3D result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::IMatrix3DHelperStatics)->FromElements(m11, m12, m13, m14, m21, m22, m23, m24, m31, m32, m33, m34, offsetX, offsetY, offsetZ, m44, put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Media_Media3D_IMatrix3DHelperStatics<D>::GetHasInverse(Windows::UI::Xaml::Media::Media3D::Matrix3D const& target) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::IMatrix3DHelperStatics)->GetHasInverse(get_abi(target), &result));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Media_Media3D_IMatrix3DHelperStatics<D>::GetIsIdentity(Windows::UI::Xaml::Media::Media3D::Matrix3D const& target) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::IMatrix3DHelperStatics)->GetIsIdentity(get_abi(target), &result));
    return result;
}

template <typename D> Windows::UI::Xaml::Media::Media3D::Matrix3D consume_Windows_UI_Xaml_Media_Media3D_IMatrix3DHelperStatics<D>::Invert(Windows::UI::Xaml::Media::Media3D::Matrix3D const& target) const
{
    Windows::UI::Xaml::Media::Media3D::Matrix3D result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::IMatrix3DHelperStatics)->Invert(get_abi(target), put_abi(result)));
    return result;
}

template <typename D> double consume_Windows_UI_Xaml_Media_Media3D_IPerspectiveTransform3D<D>::Depth() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3D)->get_Depth(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Media3D_IPerspectiveTransform3D<D>::Depth(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3D)->put_Depth(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Media3D_IPerspectiveTransform3D<D>::OffsetX() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3D)->get_OffsetX(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Media3D_IPerspectiveTransform3D<D>::OffsetX(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3D)->put_OffsetX(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Media3D_IPerspectiveTransform3D<D>::OffsetY() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3D)->get_OffsetY(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Media3D_IPerspectiveTransform3D<D>::OffsetY(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3D)->put_OffsetY(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Media3D_IPerspectiveTransform3DStatics<D>::DepthProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3DStatics)->get_DepthProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Media3D_IPerspectiveTransform3DStatics<D>::OffsetXProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3DStatics)->get_OffsetXProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Media3D_IPerspectiveTransform3DStatics<D>::OffsetYProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3DStatics)->get_OffsetYProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Media3D::Transform3D consume_Windows_UI_Xaml_Media_Media3D_ITransform3DFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Media::Media3D::Transform3D value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Media3D::ITransform3DFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D> : produce_base<D, Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D>
{
    int32_t WINRT_CALL get_CenterX(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CenterX, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().CenterX());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CenterX(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CenterX, WINRT_WRAP(void), double);
            this->shim().CenterX(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CenterY(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CenterY, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().CenterY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CenterY(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CenterY, WINRT_WRAP(void), double);
            this->shim().CenterY(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CenterZ(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CenterZ, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().CenterZ());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CenterZ(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CenterZ, WINRT_WRAP(void), double);
            this->shim().CenterZ(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RotationX(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RotationX, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().RotationX());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RotationX(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RotationX, WINRT_WRAP(void), double);
            this->shim().RotationX(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RotationY(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RotationY, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().RotationY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RotationY(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RotationY, WINRT_WRAP(void), double);
            this->shim().RotationY(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RotationZ(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RotationZ, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().RotationZ());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RotationZ(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RotationZ, WINRT_WRAP(void), double);
            this->shim().RotationZ(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScaleX(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScaleX, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ScaleX());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ScaleX(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScaleX, WINRT_WRAP(void), double);
            this->shim().ScaleX(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScaleY(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScaleY, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ScaleY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ScaleY(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScaleY, WINRT_WRAP(void), double);
            this->shim().ScaleY(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScaleZ(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScaleZ, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ScaleZ());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ScaleZ(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScaleZ, WINRT_WRAP(void), double);
            this->shim().ScaleZ(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TranslateX(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TranslateX, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().TranslateX());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TranslateX(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TranslateX, WINRT_WRAP(void), double);
            this->shim().TranslateX(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TranslateY(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TranslateY, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().TranslateY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TranslateY(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TranslateY, WINRT_WRAP(void), double);
            this->shim().TranslateY(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TranslateZ(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TranslateZ, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().TranslateZ());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TranslateZ(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TranslateZ, WINRT_WRAP(void), double);
            this->shim().TranslateZ(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics> : produce_base<D, Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics>
{
    int32_t WINRT_CALL get_CenterXProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CenterXProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CenterXProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CenterYProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CenterYProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CenterYProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CenterZProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CenterZProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CenterZProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RotationXProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RotationXProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().RotationXProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RotationYProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RotationYProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().RotationYProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RotationZProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RotationZProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().RotationZProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScaleXProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScaleXProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ScaleXProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScaleYProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScaleYProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ScaleYProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScaleZProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScaleZProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ScaleZProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TranslateXProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TranslateXProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TranslateXProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TranslateYProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TranslateYProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TranslateYProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TranslateZProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TranslateZProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TranslateZProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Media3D::IMatrix3DHelper> : produce_base<D, Windows::UI::Xaml::Media::Media3D::IMatrix3DHelper>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Media3D::IMatrix3DHelperStatics> : produce_base<D, Windows::UI::Xaml::Media::Media3D::IMatrix3DHelperStatics>
{
    int32_t WINRT_CALL get_Identity(struct struct_Windows_UI_Xaml_Media_Media3D_Matrix3D* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Identity, WINRT_WRAP(Windows::UI::Xaml::Media::Media3D::Matrix3D));
            *value = detach_from<Windows::UI::Xaml::Media::Media3D::Matrix3D>(this->shim().Identity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Multiply(struct struct_Windows_UI_Xaml_Media_Media3D_Matrix3D matrix1, struct struct_Windows_UI_Xaml_Media_Media3D_Matrix3D matrix2, struct struct_Windows_UI_Xaml_Media_Media3D_Matrix3D* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Multiply, WINRT_WRAP(Windows::UI::Xaml::Media::Media3D::Matrix3D), Windows::UI::Xaml::Media::Media3D::Matrix3D const&, Windows::UI::Xaml::Media::Media3D::Matrix3D const&);
            *result = detach_from<Windows::UI::Xaml::Media::Media3D::Matrix3D>(this->shim().Multiply(*reinterpret_cast<Windows::UI::Xaml::Media::Media3D::Matrix3D const*>(&matrix1), *reinterpret_cast<Windows::UI::Xaml::Media::Media3D::Matrix3D const*>(&matrix2)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromElements(double m11, double m12, double m13, double m14, double m21, double m22, double m23, double m24, double m31, double m32, double m33, double m34, double offsetX, double offsetY, double offsetZ, double m44, struct struct_Windows_UI_Xaml_Media_Media3D_Matrix3D* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromElements, WINRT_WRAP(Windows::UI::Xaml::Media::Media3D::Matrix3D), double, double, double, double, double, double, double, double, double, double, double, double, double, double, double, double);
            *result = detach_from<Windows::UI::Xaml::Media::Media3D::Matrix3D>(this->shim().FromElements(m11, m12, m13, m14, m21, m22, m23, m24, m31, m32, m33, m34, offsetX, offsetY, offsetZ, m44));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetHasInverse(struct struct_Windows_UI_Xaml_Media_Media3D_Matrix3D target, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetHasInverse, WINRT_WRAP(bool), Windows::UI::Xaml::Media::Media3D::Matrix3D const&);
            *result = detach_from<bool>(this->shim().GetHasInverse(*reinterpret_cast<Windows::UI::Xaml::Media::Media3D::Matrix3D const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIsIdentity(struct struct_Windows_UI_Xaml_Media_Media3D_Matrix3D target, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIsIdentity, WINRT_WRAP(bool), Windows::UI::Xaml::Media::Media3D::Matrix3D const&);
            *result = detach_from<bool>(this->shim().GetIsIdentity(*reinterpret_cast<Windows::UI::Xaml::Media::Media3D::Matrix3D const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Invert(struct struct_Windows_UI_Xaml_Media_Media3D_Matrix3D target, struct struct_Windows_UI_Xaml_Media_Media3D_Matrix3D* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Invert, WINRT_WRAP(Windows::UI::Xaml::Media::Media3D::Matrix3D), Windows::UI::Xaml::Media::Media3D::Matrix3D const&);
            *result = detach_from<Windows::UI::Xaml::Media::Media3D::Matrix3D>(this->shim().Invert(*reinterpret_cast<Windows::UI::Xaml::Media::Media3D::Matrix3D const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3D> : produce_base<D, Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3D>
{
    int32_t WINRT_CALL get_Depth(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Depth, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Depth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Depth(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Depth, WINRT_WRAP(void), double);
            this->shim().Depth(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OffsetX(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OffsetX, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().OffsetX());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OffsetX(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OffsetX, WINRT_WRAP(void), double);
            this->shim().OffsetX(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OffsetY(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OffsetY, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().OffsetY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OffsetY(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OffsetY, WINRT_WRAP(void), double);
            this->shim().OffsetY(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3DStatics> : produce_base<D, Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3DStatics>
{
    int32_t WINRT_CALL get_DepthProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DepthProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().DepthProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OffsetXProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OffsetXProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().OffsetXProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OffsetYProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OffsetYProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().OffsetYProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Media3D::ITransform3D> : produce_base<D, Windows::UI::Xaml::Media::Media3D::ITransform3D>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Media3D::ITransform3DFactory> : produce_base<D, Windows::UI::Xaml::Media::Media3D::ITransform3DFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Media::Media3D::Transform3D), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Media::Media3D::Transform3D>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Media::Media3D {

inline CompositeTransform3D::CompositeTransform3D() :
    CompositeTransform3D(impl::call_factory<CompositeTransform3D>([](auto&& f) { return f.template ActivateInstance<CompositeTransform3D>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty CompositeTransform3D::CenterXProperty()
{
    return impl::call_factory<CompositeTransform3D, Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics>([&](auto&& f) { return f.CenterXProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty CompositeTransform3D::CenterYProperty()
{
    return impl::call_factory<CompositeTransform3D, Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics>([&](auto&& f) { return f.CenterYProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty CompositeTransform3D::CenterZProperty()
{
    return impl::call_factory<CompositeTransform3D, Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics>([&](auto&& f) { return f.CenterZProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty CompositeTransform3D::RotationXProperty()
{
    return impl::call_factory<CompositeTransform3D, Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics>([&](auto&& f) { return f.RotationXProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty CompositeTransform3D::RotationYProperty()
{
    return impl::call_factory<CompositeTransform3D, Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics>([&](auto&& f) { return f.RotationYProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty CompositeTransform3D::RotationZProperty()
{
    return impl::call_factory<CompositeTransform3D, Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics>([&](auto&& f) { return f.RotationZProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty CompositeTransform3D::ScaleXProperty()
{
    return impl::call_factory<CompositeTransform3D, Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics>([&](auto&& f) { return f.ScaleXProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty CompositeTransform3D::ScaleYProperty()
{
    return impl::call_factory<CompositeTransform3D, Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics>([&](auto&& f) { return f.ScaleYProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty CompositeTransform3D::ScaleZProperty()
{
    return impl::call_factory<CompositeTransform3D, Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics>([&](auto&& f) { return f.ScaleZProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty CompositeTransform3D::TranslateXProperty()
{
    return impl::call_factory<CompositeTransform3D, Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics>([&](auto&& f) { return f.TranslateXProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty CompositeTransform3D::TranslateYProperty()
{
    return impl::call_factory<CompositeTransform3D, Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics>([&](auto&& f) { return f.TranslateYProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty CompositeTransform3D::TranslateZProperty()
{
    return impl::call_factory<CompositeTransform3D, Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics>([&](auto&& f) { return f.TranslateZProperty(); });
}

inline Windows::UI::Xaml::Media::Media3D::Matrix3D Matrix3DHelper::Identity()
{
    return impl::call_factory<Matrix3DHelper, Windows::UI::Xaml::Media::Media3D::IMatrix3DHelperStatics>([&](auto&& f) { return f.Identity(); });
}

inline Windows::UI::Xaml::Media::Media3D::Matrix3D Matrix3DHelper::Multiply(Windows::UI::Xaml::Media::Media3D::Matrix3D const& matrix1, Windows::UI::Xaml::Media::Media3D::Matrix3D const& matrix2)
{
    return impl::call_factory<Matrix3DHelper, Windows::UI::Xaml::Media::Media3D::IMatrix3DHelperStatics>([&](auto&& f) { return f.Multiply(matrix1, matrix2); });
}

inline Windows::UI::Xaml::Media::Media3D::Matrix3D Matrix3DHelper::FromElements(double m11, double m12, double m13, double m14, double m21, double m22, double m23, double m24, double m31, double m32, double m33, double m34, double offsetX, double offsetY, double offsetZ, double m44)
{
    return impl::call_factory<Matrix3DHelper, Windows::UI::Xaml::Media::Media3D::IMatrix3DHelperStatics>([&](auto&& f) { return f.FromElements(m11, m12, m13, m14, m21, m22, m23, m24, m31, m32, m33, m34, offsetX, offsetY, offsetZ, m44); });
}

inline bool Matrix3DHelper::GetHasInverse(Windows::UI::Xaml::Media::Media3D::Matrix3D const& target)
{
    return impl::call_factory<Matrix3DHelper, Windows::UI::Xaml::Media::Media3D::IMatrix3DHelperStatics>([&](auto&& f) { return f.GetHasInverse(target); });
}

inline bool Matrix3DHelper::GetIsIdentity(Windows::UI::Xaml::Media::Media3D::Matrix3D const& target)
{
    return impl::call_factory<Matrix3DHelper, Windows::UI::Xaml::Media::Media3D::IMatrix3DHelperStatics>([&](auto&& f) { return f.GetIsIdentity(target); });
}

inline Windows::UI::Xaml::Media::Media3D::Matrix3D Matrix3DHelper::Invert(Windows::UI::Xaml::Media::Media3D::Matrix3D const& target)
{
    return impl::call_factory<Matrix3DHelper, Windows::UI::Xaml::Media::Media3D::IMatrix3DHelperStatics>([&](auto&& f) { return f.Invert(target); });
}

inline PerspectiveTransform3D::PerspectiveTransform3D() :
    PerspectiveTransform3D(impl::call_factory<PerspectiveTransform3D>([](auto&& f) { return f.template ActivateInstance<PerspectiveTransform3D>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty PerspectiveTransform3D::DepthProperty()
{
    return impl::call_factory<PerspectiveTransform3D, Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3DStatics>([&](auto&& f) { return f.DepthProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty PerspectiveTransform3D::OffsetXProperty()
{
    return impl::call_factory<PerspectiveTransform3D, Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3DStatics>([&](auto&& f) { return f.OffsetXProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty PerspectiveTransform3D::OffsetYProperty()
{
    return impl::call_factory<PerspectiveTransform3D, Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3DStatics>([&](auto&& f) { return f.OffsetYProperty(); });
}

template <typename D, typename... Interfaces>
struct Transform3DT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Media::Media3D::ITransform3D, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Media::Media3D::Transform3D, Windows::UI::Xaml::DependencyObject>
{
    using composable = Transform3D;

protected:
    Transform3DT()
    {
        impl::call_factory<Windows::UI::Xaml::Media::Media3D::Transform3D, Windows::UI::Xaml::Media::Media3D::ITransform3DFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Media3D::IMatrix3DHelper> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Media3D::IMatrix3DHelper> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Media3D::IMatrix3DHelperStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Media3D::IMatrix3DHelperStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3D> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3D> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3DStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3DStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Media3D::ITransform3D> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Media3D::ITransform3D> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Media3D::ITransform3DFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Media3D::ITransform3DFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Media3D::CompositeTransform3D> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Media3D::CompositeTransform3D> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Media3D::Matrix3DHelper> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Media3D::Matrix3DHelper> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Media3D::PerspectiveTransform3D> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Media3D::PerspectiveTransform3D> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Media3D::Transform3D> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Media3D::Transform3D> {};

}
