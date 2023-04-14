// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::UI::Xaml {

struct DependencyProperty;

}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Media::Media3D {

struct ICompositeTransform3D;
struct ICompositeTransform3DStatics;
struct IMatrix3DHelper;
struct IMatrix3DHelperStatics;
struct IPerspectiveTransform3D;
struct IPerspectiveTransform3DStatics;
struct ITransform3D;
struct ITransform3DFactory;
struct CompositeTransform3D;
struct Matrix3DHelper;
struct PerspectiveTransform3D;
struct Transform3D;
struct Matrix3D;

}

namespace winrt::impl {

template <> struct category<Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Media::Media3D::IMatrix3DHelper>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Media::Media3D::IMatrix3DHelperStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3D>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3DStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Media::Media3D::ITransform3D>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Media::Media3D::ITransform3DFactory>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Media::Media3D::CompositeTransform3D>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Media::Media3D::Matrix3DHelper>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Media::Media3D::PerspectiveTransform3D>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Media::Media3D::Transform3D>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Media::Media3D::Matrix3D>{ using type = struct_category<double,double,double,double,double,double,double,double,double,double,double,double,double,double,double,double>; };
template <> struct name<Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D>{ static constexpr auto & value{ L"Windows.UI.Xaml.Media.Media3D.ICompositeTransform3D" }; };
template <> struct name<Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics>{ static constexpr auto & value{ L"Windows.UI.Xaml.Media.Media3D.ICompositeTransform3DStatics" }; };
template <> struct name<Windows::UI::Xaml::Media::Media3D::IMatrix3DHelper>{ static constexpr auto & value{ L"Windows.UI.Xaml.Media.Media3D.IMatrix3DHelper" }; };
template <> struct name<Windows::UI::Xaml::Media::Media3D::IMatrix3DHelperStatics>{ static constexpr auto & value{ L"Windows.UI.Xaml.Media.Media3D.IMatrix3DHelperStatics" }; };
template <> struct name<Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3D>{ static constexpr auto & value{ L"Windows.UI.Xaml.Media.Media3D.IPerspectiveTransform3D" }; };
template <> struct name<Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3DStatics>{ static constexpr auto & value{ L"Windows.UI.Xaml.Media.Media3D.IPerspectiveTransform3DStatics" }; };
template <> struct name<Windows::UI::Xaml::Media::Media3D::ITransform3D>{ static constexpr auto & value{ L"Windows.UI.Xaml.Media.Media3D.ITransform3D" }; };
template <> struct name<Windows::UI::Xaml::Media::Media3D::ITransform3DFactory>{ static constexpr auto & value{ L"Windows.UI.Xaml.Media.Media3D.ITransform3DFactory" }; };
template <> struct name<Windows::UI::Xaml::Media::Media3D::CompositeTransform3D>{ static constexpr auto & value{ L"Windows.UI.Xaml.Media.Media3D.CompositeTransform3D" }; };
template <> struct name<Windows::UI::Xaml::Media::Media3D::Matrix3DHelper>{ static constexpr auto & value{ L"Windows.UI.Xaml.Media.Media3D.Matrix3DHelper" }; };
template <> struct name<Windows::UI::Xaml::Media::Media3D::PerspectiveTransform3D>{ static constexpr auto & value{ L"Windows.UI.Xaml.Media.Media3D.PerspectiveTransform3D" }; };
template <> struct name<Windows::UI::Xaml::Media::Media3D::Transform3D>{ static constexpr auto & value{ L"Windows.UI.Xaml.Media.Media3D.Transform3D" }; };
template <> struct name<Windows::UI::Xaml::Media::Media3D::Matrix3D>{ static constexpr auto & value{ L"Windows.UI.Xaml.Media.Media3D.Matrix3D" }; };
template <> struct guid_storage<Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D>{ static constexpr guid value{ 0x8977CB01,0xAF8D,0x4AF5,{ 0xB0,0x84,0xC0,0x8E,0xB9,0x70,0x4A,0xBE } }; };
template <> struct guid_storage<Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics>{ static constexpr guid value{ 0xDDBF4D67,0x2A25,0x48F3,{ 0x98,0x08,0xC5,0x1E,0xC3,0xD5,0x5B,0xEC } }; };
template <> struct guid_storage<Windows::UI::Xaml::Media::Media3D::IMatrix3DHelper>{ static constexpr guid value{ 0xE48C10EF,0x9927,0x4C9B,{ 0x82,0x13,0x07,0x77,0x55,0x12,0xBA,0x04 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Media::Media3D::IMatrix3DHelperStatics>{ static constexpr guid value{ 0x9264545E,0xE158,0x4E74,{ 0x88,0x99,0x68,0x91,0x60,0xBD,0x2F,0x8C } }; };
template <> struct guid_storage<Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3D>{ static constexpr guid value{ 0x9A7B532A,0x30F9,0x40A1,{ 0x96,0xC9,0xC5,0x9D,0x87,0xF9,0x5A,0xC3 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3DStatics>{ static constexpr guid value{ 0x8E6F6400,0x620C,0x48C7,{ 0x84,0x4D,0x3F,0x09,0x84,0xDA,0x5B,0x17 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Media::Media3D::ITransform3D>{ static constexpr guid value{ 0xAE3ED43A,0xA9FC,0x4C31,{ 0x86,0xCD,0x56,0xD9,0xCA,0x25,0x1A,0x69 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Media::Media3D::ITransform3DFactory>{ static constexpr guid value{ 0x052C1F7A,0x8D73,0x48CD,{ 0xBB,0xB8,0xD0,0x04,0x34,0xCA,0xAE,0x5D } }; };
template <> struct default_interface<Windows::UI::Xaml::Media::Media3D::CompositeTransform3D>{ using type = Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D; };
template <> struct default_interface<Windows::UI::Xaml::Media::Media3D::Matrix3DHelper>{ using type = Windows::UI::Xaml::Media::Media3D::IMatrix3DHelper; };
template <> struct default_interface<Windows::UI::Xaml::Media::Media3D::PerspectiveTransform3D>{ using type = Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3D; };
template <> struct default_interface<Windows::UI::Xaml::Media::Media3D::Transform3D>{ using type = Windows::UI::Xaml::Media::Media3D::ITransform3D; };

template <> struct abi<Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CenterX(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CenterX(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CenterY(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CenterY(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CenterZ(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CenterZ(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RotationX(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RotationX(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RotationY(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RotationY(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RotationZ(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RotationZ(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ScaleX(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ScaleX(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ScaleY(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ScaleY(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ScaleZ(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ScaleZ(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TranslateX(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_TranslateX(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TranslateY(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_TranslateY(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TranslateZ(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_TranslateZ(double value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CenterXProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CenterYProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CenterZProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RotationXProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RotationYProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RotationZProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ScaleXProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ScaleYProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ScaleZProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TranslateXProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TranslateYProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TranslateZProperty(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Media::Media3D::IMatrix3DHelper>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Xaml::Media::Media3D::IMatrix3DHelperStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Identity(struct struct_Windows_UI_Xaml_Media_Media3D_Matrix3D* value) noexcept = 0;
    virtual int32_t WINRT_CALL Multiply(struct struct_Windows_UI_Xaml_Media_Media3D_Matrix3D matrix1, struct struct_Windows_UI_Xaml_Media_Media3D_Matrix3D matrix2, struct struct_Windows_UI_Xaml_Media_Media3D_Matrix3D* result) noexcept = 0;
    virtual int32_t WINRT_CALL FromElements(double m11, double m12, double m13, double m14, double m21, double m22, double m23, double m24, double m31, double m32, double m33, double m34, double offsetX, double offsetY, double offsetZ, double m44, struct struct_Windows_UI_Xaml_Media_Media3D_Matrix3D* result) noexcept = 0;
    virtual int32_t WINRT_CALL GetHasInverse(struct struct_Windows_UI_Xaml_Media_Media3D_Matrix3D target, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL GetIsIdentity(struct struct_Windows_UI_Xaml_Media_Media3D_Matrix3D target, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL Invert(struct struct_Windows_UI_Xaml_Media_Media3D_Matrix3D target, struct struct_Windows_UI_Xaml_Media_Media3D_Matrix3D* result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3D>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Depth(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Depth(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OffsetX(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_OffsetX(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OffsetY(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_OffsetY(double value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3DStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DepthProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OffsetXProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OffsetYProperty(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Media::Media3D::ITransform3D>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Xaml::Media::Media3D::ITransform3DFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D
{
    double CenterX() const;
    void CenterX(double value) const;
    double CenterY() const;
    void CenterY(double value) const;
    double CenterZ() const;
    void CenterZ(double value) const;
    double RotationX() const;
    void RotationX(double value) const;
    double RotationY() const;
    void RotationY(double value) const;
    double RotationZ() const;
    void RotationZ(double value) const;
    double ScaleX() const;
    void ScaleX(double value) const;
    double ScaleY() const;
    void ScaleY(double value) const;
    double ScaleZ() const;
    void ScaleZ(double value) const;
    double TranslateX() const;
    void TranslateX(double value) const;
    double TranslateY() const;
    void TranslateY(double value) const;
    double TranslateZ() const;
    void TranslateZ(double value) const;
};
template <> struct consume<Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D> { template <typename D> using type = consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3DStatics
{
    Windows::UI::Xaml::DependencyProperty CenterXProperty() const;
    Windows::UI::Xaml::DependencyProperty CenterYProperty() const;
    Windows::UI::Xaml::DependencyProperty CenterZProperty() const;
    Windows::UI::Xaml::DependencyProperty RotationXProperty() const;
    Windows::UI::Xaml::DependencyProperty RotationYProperty() const;
    Windows::UI::Xaml::DependencyProperty RotationZProperty() const;
    Windows::UI::Xaml::DependencyProperty ScaleXProperty() const;
    Windows::UI::Xaml::DependencyProperty ScaleYProperty() const;
    Windows::UI::Xaml::DependencyProperty ScaleZProperty() const;
    Windows::UI::Xaml::DependencyProperty TranslateXProperty() const;
    Windows::UI::Xaml::DependencyProperty TranslateYProperty() const;
    Windows::UI::Xaml::DependencyProperty TranslateZProperty() const;
};
template <> struct consume<Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics> { template <typename D> using type = consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3DStatics<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Media_Media3D_IMatrix3DHelper
{
};
template <> struct consume<Windows::UI::Xaml::Media::Media3D::IMatrix3DHelper> { template <typename D> using type = consume_Windows_UI_Xaml_Media_Media3D_IMatrix3DHelper<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Media_Media3D_IMatrix3DHelperStatics
{
    Windows::UI::Xaml::Media::Media3D::Matrix3D Identity() const;
    Windows::UI::Xaml::Media::Media3D::Matrix3D Multiply(Windows::UI::Xaml::Media::Media3D::Matrix3D const& matrix1, Windows::UI::Xaml::Media::Media3D::Matrix3D const& matrix2) const;
    Windows::UI::Xaml::Media::Media3D::Matrix3D FromElements(double m11, double m12, double m13, double m14, double m21, double m22, double m23, double m24, double m31, double m32, double m33, double m34, double offsetX, double offsetY, double offsetZ, double m44) const;
    bool GetHasInverse(Windows::UI::Xaml::Media::Media3D::Matrix3D const& target) const;
    bool GetIsIdentity(Windows::UI::Xaml::Media::Media3D::Matrix3D const& target) const;
    Windows::UI::Xaml::Media::Media3D::Matrix3D Invert(Windows::UI::Xaml::Media::Media3D::Matrix3D const& target) const;
};
template <> struct consume<Windows::UI::Xaml::Media::Media3D::IMatrix3DHelperStatics> { template <typename D> using type = consume_Windows_UI_Xaml_Media_Media3D_IMatrix3DHelperStatics<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Media_Media3D_IPerspectiveTransform3D
{
    double Depth() const;
    void Depth(double value) const;
    double OffsetX() const;
    void OffsetX(double value) const;
    double OffsetY() const;
    void OffsetY(double value) const;
};
template <> struct consume<Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3D> { template <typename D> using type = consume_Windows_UI_Xaml_Media_Media3D_IPerspectiveTransform3D<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Media_Media3D_IPerspectiveTransform3DStatics
{
    Windows::UI::Xaml::DependencyProperty DepthProperty() const;
    Windows::UI::Xaml::DependencyProperty OffsetXProperty() const;
    Windows::UI::Xaml::DependencyProperty OffsetYProperty() const;
};
template <> struct consume<Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3DStatics> { template <typename D> using type = consume_Windows_UI_Xaml_Media_Media3D_IPerspectiveTransform3DStatics<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Media_Media3D_ITransform3D
{
};
template <> struct consume<Windows::UI::Xaml::Media::Media3D::ITransform3D> { template <typename D> using type = consume_Windows_UI_Xaml_Media_Media3D_ITransform3D<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Media_Media3D_ITransform3DFactory
{
    Windows::UI::Xaml::Media::Media3D::Transform3D CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const;
};
template <> struct consume<Windows::UI::Xaml::Media::Media3D::ITransform3DFactory> { template <typename D> using type = consume_Windows_UI_Xaml_Media_Media3D_ITransform3DFactory<D>; };

struct struct_Windows_UI_Xaml_Media_Media3D_Matrix3D
{
    double M11;
    double M12;
    double M13;
    double M14;
    double M21;
    double M22;
    double M23;
    double M24;
    double M31;
    double M32;
    double M33;
    double M34;
    double OffsetX;
    double OffsetY;
    double OffsetZ;
    double M44;
};
template <> struct abi<Windows::UI::Xaml::Media::Media3D::Matrix3D>{ using type = struct_Windows_UI_Xaml_Media_Media3D_Matrix3D; };


}
