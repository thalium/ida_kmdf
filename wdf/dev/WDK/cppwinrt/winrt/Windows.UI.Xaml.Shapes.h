// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.UI.Composition.2.h"
#include "winrt/impl/Windows.UI.Xaml.2.h"
#include "winrt/impl/Windows.UI.Xaml.Media.2.h"
#include "winrt/impl/Windows.UI.Xaml.Shapes.2.h"
#include "winrt/Windows.UI.Xaml.h"

namespace winrt::impl {

template <typename D> double consume_Windows_UI_Xaml_Shapes_ILine<D>::X1() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::ILine)->get_X1(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Shapes_ILine<D>::X1(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::ILine)->put_X1(value));
}

template <typename D> double consume_Windows_UI_Xaml_Shapes_ILine<D>::Y1() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::ILine)->get_Y1(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Shapes_ILine<D>::Y1(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::ILine)->put_Y1(value));
}

template <typename D> double consume_Windows_UI_Xaml_Shapes_ILine<D>::X2() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::ILine)->get_X2(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Shapes_ILine<D>::X2(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::ILine)->put_X2(value));
}

template <typename D> double consume_Windows_UI_Xaml_Shapes_ILine<D>::Y2() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::ILine)->get_Y2(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Shapes_ILine<D>::Y2(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::ILine)->put_Y2(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Shapes_ILineStatics<D>::X1Property() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::ILineStatics)->get_X1Property(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Shapes_ILineStatics<D>::Y1Property() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::ILineStatics)->get_Y1Property(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Shapes_ILineStatics<D>::X2Property() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::ILineStatics)->get_X2Property(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Shapes_ILineStatics<D>::Y2Property() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::ILineStatics)->get_Y2Property(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Geometry consume_Windows_UI_Xaml_Shapes_IPath<D>::Data() const
{
    Windows::UI::Xaml::Media::Geometry value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IPath)->get_Data(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Shapes_IPath<D>::Data(Windows::UI::Xaml::Media::Geometry const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IPath)->put_Data(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Shapes::Path consume_Windows_UI_Xaml_Shapes_IPathFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Shapes::Path value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IPathFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Shapes_IPathStatics<D>::DataProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IPathStatics)->get_DataProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::FillRule consume_Windows_UI_Xaml_Shapes_IPolygon<D>::FillRule() const
{
    Windows::UI::Xaml::Media::FillRule value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IPolygon)->get_FillRule(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Shapes_IPolygon<D>::FillRule(Windows::UI::Xaml::Media::FillRule const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IPolygon)->put_FillRule(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::PointCollection consume_Windows_UI_Xaml_Shapes_IPolygon<D>::Points() const
{
    Windows::UI::Xaml::Media::PointCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IPolygon)->get_Points(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Shapes_IPolygon<D>::Points(Windows::UI::Xaml::Media::PointCollection const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IPolygon)->put_Points(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Shapes_IPolygonStatics<D>::FillRuleProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IPolygonStatics)->get_FillRuleProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Shapes_IPolygonStatics<D>::PointsProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IPolygonStatics)->get_PointsProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::FillRule consume_Windows_UI_Xaml_Shapes_IPolyline<D>::FillRule() const
{
    Windows::UI::Xaml::Media::FillRule value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IPolyline)->get_FillRule(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Shapes_IPolyline<D>::FillRule(Windows::UI::Xaml::Media::FillRule const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IPolyline)->put_FillRule(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::PointCollection consume_Windows_UI_Xaml_Shapes_IPolyline<D>::Points() const
{
    Windows::UI::Xaml::Media::PointCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IPolyline)->get_Points(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Shapes_IPolyline<D>::Points(Windows::UI::Xaml::Media::PointCollection const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IPolyline)->put_Points(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Shapes_IPolylineStatics<D>::FillRuleProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IPolylineStatics)->get_FillRuleProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Shapes_IPolylineStatics<D>::PointsProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IPolylineStatics)->get_PointsProperty(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Shapes_IRectangle<D>::RadiusX() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IRectangle)->get_RadiusX(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Shapes_IRectangle<D>::RadiusX(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IRectangle)->put_RadiusX(value));
}

template <typename D> double consume_Windows_UI_Xaml_Shapes_IRectangle<D>::RadiusY() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IRectangle)->get_RadiusY(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Shapes_IRectangle<D>::RadiusY(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IRectangle)->put_RadiusY(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Shapes_IRectangleStatics<D>::RadiusXProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IRectangleStatics)->get_RadiusXProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Shapes_IRectangleStatics<D>::RadiusYProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IRectangleStatics)->get_RadiusYProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Shapes_IShape<D>::Fill() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShape)->get_Fill(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Shapes_IShape<D>::Fill(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShape)->put_Fill(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Shapes_IShape<D>::Stroke() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShape)->get_Stroke(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Shapes_IShape<D>::Stroke(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShape)->put_Stroke(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_Shapes_IShape<D>::StrokeMiterLimit() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShape)->get_StrokeMiterLimit(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Shapes_IShape<D>::StrokeMiterLimit(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShape)->put_StrokeMiterLimit(value));
}

template <typename D> double consume_Windows_UI_Xaml_Shapes_IShape<D>::StrokeThickness() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShape)->get_StrokeThickness(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Shapes_IShape<D>::StrokeThickness(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShape)->put_StrokeThickness(value));
}

template <typename D> Windows::UI::Xaml::Media::PenLineCap consume_Windows_UI_Xaml_Shapes_IShape<D>::StrokeStartLineCap() const
{
    Windows::UI::Xaml::Media::PenLineCap value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShape)->get_StrokeStartLineCap(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Shapes_IShape<D>::StrokeStartLineCap(Windows::UI::Xaml::Media::PenLineCap const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShape)->put_StrokeStartLineCap(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::PenLineCap consume_Windows_UI_Xaml_Shapes_IShape<D>::StrokeEndLineCap() const
{
    Windows::UI::Xaml::Media::PenLineCap value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShape)->get_StrokeEndLineCap(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Shapes_IShape<D>::StrokeEndLineCap(Windows::UI::Xaml::Media::PenLineCap const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShape)->put_StrokeEndLineCap(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::PenLineJoin consume_Windows_UI_Xaml_Shapes_IShape<D>::StrokeLineJoin() const
{
    Windows::UI::Xaml::Media::PenLineJoin value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShape)->get_StrokeLineJoin(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Shapes_IShape<D>::StrokeLineJoin(Windows::UI::Xaml::Media::PenLineJoin const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShape)->put_StrokeLineJoin(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_Shapes_IShape<D>::StrokeDashOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShape)->get_StrokeDashOffset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Shapes_IShape<D>::StrokeDashOffset(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShape)->put_StrokeDashOffset(value));
}

template <typename D> Windows::UI::Xaml::Media::PenLineCap consume_Windows_UI_Xaml_Shapes_IShape<D>::StrokeDashCap() const
{
    Windows::UI::Xaml::Media::PenLineCap value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShape)->get_StrokeDashCap(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Shapes_IShape<D>::StrokeDashCap(Windows::UI::Xaml::Media::PenLineCap const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShape)->put_StrokeDashCap(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::DoubleCollection consume_Windows_UI_Xaml_Shapes_IShape<D>::StrokeDashArray() const
{
    Windows::UI::Xaml::Media::DoubleCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShape)->get_StrokeDashArray(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Shapes_IShape<D>::StrokeDashArray(Windows::UI::Xaml::Media::DoubleCollection const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShape)->put_StrokeDashArray(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Stretch consume_Windows_UI_Xaml_Shapes_IShape<D>::Stretch() const
{
    Windows::UI::Xaml::Media::Stretch value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShape)->get_Stretch(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Shapes_IShape<D>::Stretch(Windows::UI::Xaml::Media::Stretch const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShape)->put_Stretch(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Transform consume_Windows_UI_Xaml_Shapes_IShape<D>::GeometryTransform() const
{
    Windows::UI::Xaml::Media::Transform value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShape)->get_GeometryTransform(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Composition::CompositionBrush consume_Windows_UI_Xaml_Shapes_IShape2<D>::GetAlphaMask() const
{
    Windows::UI::Composition::CompositionBrush result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShape2)->GetAlphaMask(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Shapes::Shape consume_Windows_UI_Xaml_Shapes_IShapeFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Shapes::Shape value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShapeFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Shapes_IShapeStatics<D>::FillProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShapeStatics)->get_FillProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Shapes_IShapeStatics<D>::StrokeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShapeStatics)->get_StrokeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Shapes_IShapeStatics<D>::StrokeMiterLimitProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShapeStatics)->get_StrokeMiterLimitProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Shapes_IShapeStatics<D>::StrokeThicknessProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShapeStatics)->get_StrokeThicknessProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Shapes_IShapeStatics<D>::StrokeStartLineCapProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShapeStatics)->get_StrokeStartLineCapProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Shapes_IShapeStatics<D>::StrokeEndLineCapProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShapeStatics)->get_StrokeEndLineCapProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Shapes_IShapeStatics<D>::StrokeLineJoinProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShapeStatics)->get_StrokeLineJoinProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Shapes_IShapeStatics<D>::StrokeDashOffsetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShapeStatics)->get_StrokeDashOffsetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Shapes_IShapeStatics<D>::StrokeDashCapProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShapeStatics)->get_StrokeDashCapProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Shapes_IShapeStatics<D>::StrokeDashArrayProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShapeStatics)->get_StrokeDashArrayProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Shapes_IShapeStatics<D>::StretchProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Shapes::IShapeStatics)->get_StretchProperty(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::UI::Xaml::Shapes::IEllipse> : produce_base<D, Windows::UI::Xaml::Shapes::IEllipse>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Shapes::ILine> : produce_base<D, Windows::UI::Xaml::Shapes::ILine>
{
    int32_t WINRT_CALL get_X1(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(X1, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().X1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_X1(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(X1, WINRT_WRAP(void), double);
            this->shim().X1(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Y1(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Y1, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Y1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Y1(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Y1, WINRT_WRAP(void), double);
            this->shim().Y1(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_X2(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(X2, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().X2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_X2(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(X2, WINRT_WRAP(void), double);
            this->shim().X2(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Y2(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Y2, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Y2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Y2(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Y2, WINRT_WRAP(void), double);
            this->shim().Y2(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Shapes::ILineStatics> : produce_base<D, Windows::UI::Xaml::Shapes::ILineStatics>
{
    int32_t WINRT_CALL get_X1Property(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(X1Property, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().X1Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Y1Property(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Y1Property, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().Y1Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_X2Property(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(X2Property, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().X2Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Y2Property(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Y2Property, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().Y2Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Shapes::IPath> : produce_base<D, Windows::UI::Xaml::Shapes::IPath>
{
    int32_t WINRT_CALL get_Data(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Data, WINRT_WRAP(Windows::UI::Xaml::Media::Geometry));
            *value = detach_from<Windows::UI::Xaml::Media::Geometry>(this->shim().Data());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Data(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Data, WINRT_WRAP(void), Windows::UI::Xaml::Media::Geometry const&);
            this->shim().Data(*reinterpret_cast<Windows::UI::Xaml::Media::Geometry const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Shapes::IPathFactory> : produce_base<D, Windows::UI::Xaml::Shapes::IPathFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Shapes::Path), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Shapes::Path>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Shapes::IPathStatics> : produce_base<D, Windows::UI::Xaml::Shapes::IPathStatics>
{
    int32_t WINRT_CALL get_DataProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().DataProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Shapes::IPolygon> : produce_base<D, Windows::UI::Xaml::Shapes::IPolygon>
{
    int32_t WINRT_CALL get_FillRule(Windows::UI::Xaml::Media::FillRule* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FillRule, WINRT_WRAP(Windows::UI::Xaml::Media::FillRule));
            *value = detach_from<Windows::UI::Xaml::Media::FillRule>(this->shim().FillRule());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FillRule(Windows::UI::Xaml::Media::FillRule value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FillRule, WINRT_WRAP(void), Windows::UI::Xaml::Media::FillRule const&);
            this->shim().FillRule(*reinterpret_cast<Windows::UI::Xaml::Media::FillRule const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Points(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Points, WINRT_WRAP(Windows::UI::Xaml::Media::PointCollection));
            *value = detach_from<Windows::UI::Xaml::Media::PointCollection>(this->shim().Points());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Points(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Points, WINRT_WRAP(void), Windows::UI::Xaml::Media::PointCollection const&);
            this->shim().Points(*reinterpret_cast<Windows::UI::Xaml::Media::PointCollection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Shapes::IPolygonStatics> : produce_base<D, Windows::UI::Xaml::Shapes::IPolygonStatics>
{
    int32_t WINRT_CALL get_FillRuleProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FillRuleProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FillRuleProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PointsProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointsProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().PointsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Shapes::IPolyline> : produce_base<D, Windows::UI::Xaml::Shapes::IPolyline>
{
    int32_t WINRT_CALL get_FillRule(Windows::UI::Xaml::Media::FillRule* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FillRule, WINRT_WRAP(Windows::UI::Xaml::Media::FillRule));
            *value = detach_from<Windows::UI::Xaml::Media::FillRule>(this->shim().FillRule());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FillRule(Windows::UI::Xaml::Media::FillRule value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FillRule, WINRT_WRAP(void), Windows::UI::Xaml::Media::FillRule const&);
            this->shim().FillRule(*reinterpret_cast<Windows::UI::Xaml::Media::FillRule const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Points(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Points, WINRT_WRAP(Windows::UI::Xaml::Media::PointCollection));
            *value = detach_from<Windows::UI::Xaml::Media::PointCollection>(this->shim().Points());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Points(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Points, WINRT_WRAP(void), Windows::UI::Xaml::Media::PointCollection const&);
            this->shim().Points(*reinterpret_cast<Windows::UI::Xaml::Media::PointCollection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Shapes::IPolylineStatics> : produce_base<D, Windows::UI::Xaml::Shapes::IPolylineStatics>
{
    int32_t WINRT_CALL get_FillRuleProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FillRuleProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FillRuleProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PointsProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointsProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().PointsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Shapes::IRectangle> : produce_base<D, Windows::UI::Xaml::Shapes::IRectangle>
{
    int32_t WINRT_CALL get_RadiusX(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RadiusX, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().RadiusX());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RadiusX(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RadiusX, WINRT_WRAP(void), double);
            this->shim().RadiusX(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RadiusY(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RadiusY, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().RadiusY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RadiusY(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RadiusY, WINRT_WRAP(void), double);
            this->shim().RadiusY(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Shapes::IRectangleStatics> : produce_base<D, Windows::UI::Xaml::Shapes::IRectangleStatics>
{
    int32_t WINRT_CALL get_RadiusXProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RadiusXProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().RadiusXProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RadiusYProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RadiusYProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().RadiusYProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Shapes::IShape> : produce_base<D, Windows::UI::Xaml::Shapes::IShape>
{
    int32_t WINRT_CALL get_Fill(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Fill, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().Fill());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Fill(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Fill, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().Fill(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Stroke(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stroke, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().Stroke());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Stroke(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stroke, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().Stroke(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeMiterLimit(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeMiterLimit, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().StrokeMiterLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StrokeMiterLimit(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeMiterLimit, WINRT_WRAP(void), double);
            this->shim().StrokeMiterLimit(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeThickness(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeThickness, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().StrokeThickness());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StrokeThickness(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeThickness, WINRT_WRAP(void), double);
            this->shim().StrokeThickness(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeStartLineCap(Windows::UI::Xaml::Media::PenLineCap* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeStartLineCap, WINRT_WRAP(Windows::UI::Xaml::Media::PenLineCap));
            *value = detach_from<Windows::UI::Xaml::Media::PenLineCap>(this->shim().StrokeStartLineCap());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StrokeStartLineCap(Windows::UI::Xaml::Media::PenLineCap value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeStartLineCap, WINRT_WRAP(void), Windows::UI::Xaml::Media::PenLineCap const&);
            this->shim().StrokeStartLineCap(*reinterpret_cast<Windows::UI::Xaml::Media::PenLineCap const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeEndLineCap(Windows::UI::Xaml::Media::PenLineCap* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeEndLineCap, WINRT_WRAP(Windows::UI::Xaml::Media::PenLineCap));
            *value = detach_from<Windows::UI::Xaml::Media::PenLineCap>(this->shim().StrokeEndLineCap());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StrokeEndLineCap(Windows::UI::Xaml::Media::PenLineCap value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeEndLineCap, WINRT_WRAP(void), Windows::UI::Xaml::Media::PenLineCap const&);
            this->shim().StrokeEndLineCap(*reinterpret_cast<Windows::UI::Xaml::Media::PenLineCap const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeLineJoin(Windows::UI::Xaml::Media::PenLineJoin* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeLineJoin, WINRT_WRAP(Windows::UI::Xaml::Media::PenLineJoin));
            *value = detach_from<Windows::UI::Xaml::Media::PenLineJoin>(this->shim().StrokeLineJoin());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StrokeLineJoin(Windows::UI::Xaml::Media::PenLineJoin value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeLineJoin, WINRT_WRAP(void), Windows::UI::Xaml::Media::PenLineJoin const&);
            this->shim().StrokeLineJoin(*reinterpret_cast<Windows::UI::Xaml::Media::PenLineJoin const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeDashOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeDashOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().StrokeDashOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StrokeDashOffset(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeDashOffset, WINRT_WRAP(void), double);
            this->shim().StrokeDashOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeDashCap(Windows::UI::Xaml::Media::PenLineCap* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeDashCap, WINRT_WRAP(Windows::UI::Xaml::Media::PenLineCap));
            *value = detach_from<Windows::UI::Xaml::Media::PenLineCap>(this->shim().StrokeDashCap());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StrokeDashCap(Windows::UI::Xaml::Media::PenLineCap value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeDashCap, WINRT_WRAP(void), Windows::UI::Xaml::Media::PenLineCap const&);
            this->shim().StrokeDashCap(*reinterpret_cast<Windows::UI::Xaml::Media::PenLineCap const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeDashArray(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeDashArray, WINRT_WRAP(Windows::UI::Xaml::Media::DoubleCollection));
            *value = detach_from<Windows::UI::Xaml::Media::DoubleCollection>(this->shim().StrokeDashArray());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StrokeDashArray(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeDashArray, WINRT_WRAP(void), Windows::UI::Xaml::Media::DoubleCollection const&);
            this->shim().StrokeDashArray(*reinterpret_cast<Windows::UI::Xaml::Media::DoubleCollection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Stretch(Windows::UI::Xaml::Media::Stretch* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stretch, WINRT_WRAP(Windows::UI::Xaml::Media::Stretch));
            *value = detach_from<Windows::UI::Xaml::Media::Stretch>(this->shim().Stretch());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Stretch(Windows::UI::Xaml::Media::Stretch value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stretch, WINRT_WRAP(void), Windows::UI::Xaml::Media::Stretch const&);
            this->shim().Stretch(*reinterpret_cast<Windows::UI::Xaml::Media::Stretch const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GeometryTransform(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GeometryTransform, WINRT_WRAP(Windows::UI::Xaml::Media::Transform));
            *value = detach_from<Windows::UI::Xaml::Media::Transform>(this->shim().GeometryTransform());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Shapes::IShape2> : produce_base<D, Windows::UI::Xaml::Shapes::IShape2>
{
    int32_t WINRT_CALL GetAlphaMask(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAlphaMask, WINRT_WRAP(Windows::UI::Composition::CompositionBrush));
            *result = detach_from<Windows::UI::Composition::CompositionBrush>(this->shim().GetAlphaMask());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Shapes::IShapeFactory> : produce_base<D, Windows::UI::Xaml::Shapes::IShapeFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Shapes::Shape), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Shapes::Shape>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Shapes::IShapeStatics> : produce_base<D, Windows::UI::Xaml::Shapes::IShapeStatics>
{
    int32_t WINRT_CALL get_FillProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FillProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FillProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StrokeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeMiterLimitProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeMiterLimitProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StrokeMiterLimitProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeThicknessProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeThicknessProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StrokeThicknessProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeStartLineCapProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeStartLineCapProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StrokeStartLineCapProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeEndLineCapProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeEndLineCapProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StrokeEndLineCapProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeLineJoinProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeLineJoinProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StrokeLineJoinProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeDashOffsetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeDashOffsetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StrokeDashOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeDashCapProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeDashCapProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StrokeDashCapProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeDashArrayProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeDashArrayProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StrokeDashArrayProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StretchProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StretchProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StretchProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Shapes {

inline Ellipse::Ellipse() :
    Ellipse(impl::call_factory<Ellipse>([](auto&& f) { return f.template ActivateInstance<Ellipse>(); }))
{}

inline Line::Line() :
    Line(impl::call_factory<Line>([](auto&& f) { return f.template ActivateInstance<Line>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty Line::X1Property()
{
    return impl::call_factory<Line, Windows::UI::Xaml::Shapes::ILineStatics>([&](auto&& f) { return f.X1Property(); });
}

inline Windows::UI::Xaml::DependencyProperty Line::Y1Property()
{
    return impl::call_factory<Line, Windows::UI::Xaml::Shapes::ILineStatics>([&](auto&& f) { return f.Y1Property(); });
}

inline Windows::UI::Xaml::DependencyProperty Line::X2Property()
{
    return impl::call_factory<Line, Windows::UI::Xaml::Shapes::ILineStatics>([&](auto&& f) { return f.X2Property(); });
}

inline Windows::UI::Xaml::DependencyProperty Line::Y2Property()
{
    return impl::call_factory<Line, Windows::UI::Xaml::Shapes::ILineStatics>([&](auto&& f) { return f.Y2Property(); });
}

inline Path::Path()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<Path, Windows::UI::Xaml::Shapes::IPathFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline Windows::UI::Xaml::DependencyProperty Path::DataProperty()
{
    return impl::call_factory<Path, Windows::UI::Xaml::Shapes::IPathStatics>([&](auto&& f) { return f.DataProperty(); });
}

inline Polygon::Polygon() :
    Polygon(impl::call_factory<Polygon>([](auto&& f) { return f.template ActivateInstance<Polygon>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty Polygon::FillRuleProperty()
{
    return impl::call_factory<Polygon, Windows::UI::Xaml::Shapes::IPolygonStatics>([&](auto&& f) { return f.FillRuleProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Polygon::PointsProperty()
{
    return impl::call_factory<Polygon, Windows::UI::Xaml::Shapes::IPolygonStatics>([&](auto&& f) { return f.PointsProperty(); });
}

inline Polyline::Polyline() :
    Polyline(impl::call_factory<Polyline>([](auto&& f) { return f.template ActivateInstance<Polyline>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty Polyline::FillRuleProperty()
{
    return impl::call_factory<Polyline, Windows::UI::Xaml::Shapes::IPolylineStatics>([&](auto&& f) { return f.FillRuleProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Polyline::PointsProperty()
{
    return impl::call_factory<Polyline, Windows::UI::Xaml::Shapes::IPolylineStatics>([&](auto&& f) { return f.PointsProperty(); });
}

inline Rectangle::Rectangle() :
    Rectangle(impl::call_factory<Rectangle>([](auto&& f) { return f.template ActivateInstance<Rectangle>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty Rectangle::RadiusXProperty()
{
    return impl::call_factory<Rectangle, Windows::UI::Xaml::Shapes::IRectangleStatics>([&](auto&& f) { return f.RadiusXProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Rectangle::RadiusYProperty()
{
    return impl::call_factory<Rectangle, Windows::UI::Xaml::Shapes::IRectangleStatics>([&](auto&& f) { return f.RadiusYProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Shape::FillProperty()
{
    return impl::call_factory<Shape, Windows::UI::Xaml::Shapes::IShapeStatics>([&](auto&& f) { return f.FillProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Shape::StrokeProperty()
{
    return impl::call_factory<Shape, Windows::UI::Xaml::Shapes::IShapeStatics>([&](auto&& f) { return f.StrokeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Shape::StrokeMiterLimitProperty()
{
    return impl::call_factory<Shape, Windows::UI::Xaml::Shapes::IShapeStatics>([&](auto&& f) { return f.StrokeMiterLimitProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Shape::StrokeThicknessProperty()
{
    return impl::call_factory<Shape, Windows::UI::Xaml::Shapes::IShapeStatics>([&](auto&& f) { return f.StrokeThicknessProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Shape::StrokeStartLineCapProperty()
{
    return impl::call_factory<Shape, Windows::UI::Xaml::Shapes::IShapeStatics>([&](auto&& f) { return f.StrokeStartLineCapProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Shape::StrokeEndLineCapProperty()
{
    return impl::call_factory<Shape, Windows::UI::Xaml::Shapes::IShapeStatics>([&](auto&& f) { return f.StrokeEndLineCapProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Shape::StrokeLineJoinProperty()
{
    return impl::call_factory<Shape, Windows::UI::Xaml::Shapes::IShapeStatics>([&](auto&& f) { return f.StrokeLineJoinProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Shape::StrokeDashOffsetProperty()
{
    return impl::call_factory<Shape, Windows::UI::Xaml::Shapes::IShapeStatics>([&](auto&& f) { return f.StrokeDashOffsetProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Shape::StrokeDashCapProperty()
{
    return impl::call_factory<Shape, Windows::UI::Xaml::Shapes::IShapeStatics>([&](auto&& f) { return f.StrokeDashCapProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Shape::StrokeDashArrayProperty()
{
    return impl::call_factory<Shape, Windows::UI::Xaml::Shapes::IShapeStatics>([&](auto&& f) { return f.StrokeDashArrayProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Shape::StretchProperty()
{
    return impl::call_factory<Shape, Windows::UI::Xaml::Shapes::IShapeStatics>([&](auto&& f) { return f.StretchProperty(); });
}

template <typename D, typename... Interfaces>
struct PathT :
    implements<D, Windows::UI::Xaml::IFrameworkElementOverrides, Windows::UI::Xaml::IFrameworkElementOverrides2, Windows::UI::Xaml::IUIElementOverrides, Windows::UI::Xaml::IUIElementOverrides7, Windows::UI::Xaml::IUIElementOverrides8, Windows::UI::Xaml::IUIElementOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Shapes::IPath, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::IVisualElement, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::IFrameworkElement, Windows::UI::Xaml::IFrameworkElement2, Windows::UI::Xaml::IFrameworkElement3, Windows::UI::Xaml::IFrameworkElement4, Windows::UI::Xaml::IFrameworkElement6, Windows::UI::Xaml::IFrameworkElement7, Windows::UI::Xaml::IFrameworkElementProtected7, Windows::UI::Xaml::IUIElement, Windows::UI::Xaml::IUIElement10, Windows::UI::Xaml::IUIElement2, Windows::UI::Xaml::IUIElement3, Windows::UI::Xaml::IUIElement4, Windows::UI::Xaml::IUIElement5, Windows::UI::Xaml::IUIElement7, Windows::UI::Xaml::IUIElement8, Windows::UI::Xaml::IUIElement9, Windows::UI::Xaml::Shapes::IShape, Windows::UI::Xaml::Shapes::IShape2>,
    impl::base<D, Windows::UI::Xaml::Shapes::Path, Windows::UI::Xaml::Shapes::Shape, Windows::UI::Xaml::FrameworkElement, Windows::UI::Xaml::UIElement, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::IFrameworkElementOverridesT<D>, Windows::UI::Xaml::IFrameworkElementOverrides2T<D>, Windows::UI::Xaml::IUIElementOverridesT<D>, Windows::UI::Xaml::IUIElementOverrides7T<D>, Windows::UI::Xaml::IUIElementOverrides8T<D>, Windows::UI::Xaml::IUIElementOverrides9T<D>
{
    using composable = Path;

protected:
    PathT()
    {
        impl::call_factory<Windows::UI::Xaml::Shapes::Path, Windows::UI::Xaml::Shapes::IPathFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ShapeT :
    implements<D, Windows::UI::Xaml::IFrameworkElementOverrides, Windows::UI::Xaml::IFrameworkElementOverrides2, Windows::UI::Xaml::IUIElementOverrides, Windows::UI::Xaml::IUIElementOverrides7, Windows::UI::Xaml::IUIElementOverrides8, Windows::UI::Xaml::IUIElementOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Shapes::IShape, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::IVisualElement, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::IFrameworkElement, Windows::UI::Xaml::IFrameworkElement2, Windows::UI::Xaml::IFrameworkElement3, Windows::UI::Xaml::IFrameworkElement4, Windows::UI::Xaml::IFrameworkElement6, Windows::UI::Xaml::IFrameworkElement7, Windows::UI::Xaml::IFrameworkElementProtected7, Windows::UI::Xaml::IUIElement, Windows::UI::Xaml::IUIElement10, Windows::UI::Xaml::IUIElement2, Windows::UI::Xaml::IUIElement3, Windows::UI::Xaml::IUIElement4, Windows::UI::Xaml::IUIElement5, Windows::UI::Xaml::IUIElement7, Windows::UI::Xaml::IUIElement8, Windows::UI::Xaml::IUIElement9, Windows::UI::Xaml::Shapes::IShape2>,
    impl::base<D, Windows::UI::Xaml::Shapes::Shape, Windows::UI::Xaml::FrameworkElement, Windows::UI::Xaml::UIElement, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::IFrameworkElementOverridesT<D>, Windows::UI::Xaml::IFrameworkElementOverrides2T<D>, Windows::UI::Xaml::IUIElementOverridesT<D>, Windows::UI::Xaml::IUIElementOverrides7T<D>, Windows::UI::Xaml::IUIElementOverrides8T<D>, Windows::UI::Xaml::IUIElementOverrides9T<D>
{
    using composable = Shape;

protected:
    ShapeT()
    {
        impl::call_factory<Windows::UI::Xaml::Shapes::Shape, Windows::UI::Xaml::Shapes::IShapeFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Xaml::Shapes::IEllipse> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Shapes::IEllipse> {};
template<> struct hash<winrt::Windows::UI::Xaml::Shapes::ILine> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Shapes::ILine> {};
template<> struct hash<winrt::Windows::UI::Xaml::Shapes::ILineStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Shapes::ILineStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Shapes::IPath> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Shapes::IPath> {};
template<> struct hash<winrt::Windows::UI::Xaml::Shapes::IPathFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Shapes::IPathFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Shapes::IPathStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Shapes::IPathStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Shapes::IPolygon> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Shapes::IPolygon> {};
template<> struct hash<winrt::Windows::UI::Xaml::Shapes::IPolygonStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Shapes::IPolygonStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Shapes::IPolyline> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Shapes::IPolyline> {};
template<> struct hash<winrt::Windows::UI::Xaml::Shapes::IPolylineStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Shapes::IPolylineStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Shapes::IRectangle> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Shapes::IRectangle> {};
template<> struct hash<winrt::Windows::UI::Xaml::Shapes::IRectangleStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Shapes::IRectangleStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Shapes::IShape> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Shapes::IShape> {};
template<> struct hash<winrt::Windows::UI::Xaml::Shapes::IShape2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Shapes::IShape2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Shapes::IShapeFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Shapes::IShapeFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Shapes::IShapeStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Shapes::IShapeStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Shapes::Ellipse> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Shapes::Ellipse> {};
template<> struct hash<winrt::Windows::UI::Xaml::Shapes::Line> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Shapes::Line> {};
template<> struct hash<winrt::Windows::UI::Xaml::Shapes::Path> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Shapes::Path> {};
template<> struct hash<winrt::Windows::UI::Xaml::Shapes::Polygon> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Shapes::Polygon> {};
template<> struct hash<winrt::Windows::UI::Xaml::Shapes::Polyline> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Shapes::Polyline> {};
template<> struct hash<winrt::Windows::UI::Xaml::Shapes::Rectangle> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Shapes::Rectangle> {};
template<> struct hash<winrt::Windows::UI::Xaml::Shapes::Shape> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Shapes::Shape> {};

}
