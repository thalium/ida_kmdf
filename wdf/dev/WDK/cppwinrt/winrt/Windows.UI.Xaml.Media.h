// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Media.Playback.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.UI.Composition.2.h"
#include "winrt/impl/Windows.UI.Xaml.2.h"
#include "winrt/impl/Windows.UI.Xaml.Controls.Primitives.2.h"
#include "winrt/impl/Windows.UI.Xaml.Media.Media3D.2.h"
#include "winrt/impl/Windows.UI.Xaml.Media.2.h"
#include "winrt/Windows.UI.Xaml.h"

namespace winrt::impl {

template <typename D> Windows::UI::Xaml::Media::AcrylicBackgroundSource consume_Windows_UI_Xaml_Media_IAcrylicBrush<D>::BackgroundSource() const
{
    Windows::UI::Xaml::Media::AcrylicBackgroundSource value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IAcrylicBrush)->get_BackgroundSource(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IAcrylicBrush<D>::BackgroundSource(Windows::UI::Xaml::Media::AcrylicBackgroundSource const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IAcrylicBrush)->put_BackgroundSource(get_abi(value)));
}

template <typename D> Windows::UI::Color consume_Windows_UI_Xaml_Media_IAcrylicBrush<D>::TintColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IAcrylicBrush)->get_TintColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IAcrylicBrush<D>::TintColor(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IAcrylicBrush)->put_TintColor(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_Media_IAcrylicBrush<D>::TintOpacity() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IAcrylicBrush)->get_TintOpacity(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IAcrylicBrush<D>::TintOpacity(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IAcrylicBrush)->put_TintOpacity(value));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_UI_Xaml_Media_IAcrylicBrush<D>::TintTransitionDuration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IAcrylicBrush)->get_TintTransitionDuration(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IAcrylicBrush<D>::TintTransitionDuration(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IAcrylicBrush)->put_TintTransitionDuration(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_Media_IAcrylicBrush<D>::AlwaysUseFallback() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IAcrylicBrush)->get_AlwaysUseFallback(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IAcrylicBrush<D>::AlwaysUseFallback(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IAcrylicBrush)->put_AlwaysUseFallback(value));
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_UI_Xaml_Media_IAcrylicBrush2<D>::TintLuminosityOpacity() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IAcrylicBrush2)->get_TintLuminosityOpacity(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IAcrylicBrush2<D>::TintLuminosityOpacity(optional<double> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IAcrylicBrush2)->put_TintLuminosityOpacity(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::AcrylicBrush consume_Windows_UI_Xaml_Media_IAcrylicBrushFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Media::AcrylicBrush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IAcrylicBrushFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IAcrylicBrushStatics<D>::BackgroundSourceProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IAcrylicBrushStatics)->get_BackgroundSourceProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IAcrylicBrushStatics<D>::TintColorProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IAcrylicBrushStatics)->get_TintColorProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IAcrylicBrushStatics<D>::TintOpacityProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IAcrylicBrushStatics)->get_TintOpacityProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IAcrylicBrushStatics<D>::TintTransitionDurationProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IAcrylicBrushStatics)->get_TintTransitionDurationProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IAcrylicBrushStatics<D>::AlwaysUseFallbackProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IAcrylicBrushStatics)->get_AlwaysUseFallbackProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IAcrylicBrushStatics2<D>::TintLuminosityOpacityProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IAcrylicBrushStatics2)->get_TintLuminosityOpacityProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Media_IArcSegment<D>::Point() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IArcSegment)->get_Point(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IArcSegment<D>::Point(Windows::Foundation::Point const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IArcSegment)->put_Point(get_abi(value)));
}

template <typename D> Windows::Foundation::Size consume_Windows_UI_Xaml_Media_IArcSegment<D>::Size() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IArcSegment)->get_Size(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IArcSegment<D>::Size(Windows::Foundation::Size const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IArcSegment)->put_Size(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_Media_IArcSegment<D>::RotationAngle() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IArcSegment)->get_RotationAngle(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IArcSegment<D>::RotationAngle(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IArcSegment)->put_RotationAngle(value));
}

template <typename D> bool consume_Windows_UI_Xaml_Media_IArcSegment<D>::IsLargeArc() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IArcSegment)->get_IsLargeArc(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IArcSegment<D>::IsLargeArc(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IArcSegment)->put_IsLargeArc(value));
}

template <typename D> Windows::UI::Xaml::Media::SweepDirection consume_Windows_UI_Xaml_Media_IArcSegment<D>::SweepDirection() const
{
    Windows::UI::Xaml::Media::SweepDirection value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IArcSegment)->get_SweepDirection(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IArcSegment<D>::SweepDirection(Windows::UI::Xaml::Media::SweepDirection const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IArcSegment)->put_SweepDirection(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IArcSegmentStatics<D>::PointProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IArcSegmentStatics)->get_PointProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IArcSegmentStatics<D>::SizeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IArcSegmentStatics)->get_SizeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IArcSegmentStatics<D>::RotationAngleProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IArcSegmentStatics)->get_RotationAngleProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IArcSegmentStatics<D>::IsLargeArcProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IArcSegmentStatics)->get_IsLargeArcProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IArcSegmentStatics<D>::SweepDirectionProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IArcSegmentStatics)->get_SweepDirectionProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Media_IBezierSegment<D>::Point1() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IBezierSegment)->get_Point1(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IBezierSegment<D>::Point1(Windows::Foundation::Point const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IBezierSegment)->put_Point1(get_abi(value)));
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Media_IBezierSegment<D>::Point2() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IBezierSegment)->get_Point2(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IBezierSegment<D>::Point2(Windows::Foundation::Point const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IBezierSegment)->put_Point2(get_abi(value)));
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Media_IBezierSegment<D>::Point3() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IBezierSegment)->get_Point3(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IBezierSegment<D>::Point3(Windows::Foundation::Point const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IBezierSegment)->put_Point3(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IBezierSegmentStatics<D>::Point1Property() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IBezierSegmentStatics)->get_Point1Property(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IBezierSegmentStatics<D>::Point2Property() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IBezierSegmentStatics)->get_Point2Property(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IBezierSegmentStatics<D>::Point3Property() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IBezierSegmentStatics)->get_Point3Property(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Media_IBrush<D>::Opacity() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IBrush)->get_Opacity(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IBrush<D>::Opacity(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IBrush)->put_Opacity(value));
}

template <typename D> Windows::UI::Xaml::Media::Transform consume_Windows_UI_Xaml_Media_IBrush<D>::Transform() const
{
    Windows::UI::Xaml::Media::Transform value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IBrush)->get_Transform(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IBrush<D>::Transform(Windows::UI::Xaml::Media::Transform const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IBrush)->put_Transform(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Transform consume_Windows_UI_Xaml_Media_IBrush<D>::RelativeTransform() const
{
    Windows::UI::Xaml::Media::Transform value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IBrush)->get_RelativeTransform(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IBrush<D>::RelativeTransform(Windows::UI::Xaml::Media::Transform const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IBrush)->put_RelativeTransform(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Media_IBrushFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IBrushFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IBrushOverrides2<D>::PopulatePropertyInfoOverride(param::hstring const& propertyName, Windows::UI::Composition::AnimationPropertyInfo const& animationPropertyInfo) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IBrushOverrides2)->PopulatePropertyInfoOverride(get_abi(propertyName), get_abi(animationPropertyInfo)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IBrushStatics<D>::OpacityProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IBrushStatics)->get_OpacityProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IBrushStatics<D>::TransformProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IBrushStatics)->get_TransformProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IBrushStatics<D>::RelativeTransformProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IBrushStatics)->get_RelativeTransformProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::CacheMode consume_Windows_UI_Xaml_Media_ICacheModeFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Media::CacheMode value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ICacheModeFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Media_ICompositeTransform<D>::CenterX() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ICompositeTransform)->get_CenterX(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_ICompositeTransform<D>::CenterX(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ICompositeTransform)->put_CenterX(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_ICompositeTransform<D>::CenterY() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ICompositeTransform)->get_CenterY(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_ICompositeTransform<D>::CenterY(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ICompositeTransform)->put_CenterY(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_ICompositeTransform<D>::ScaleX() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ICompositeTransform)->get_ScaleX(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_ICompositeTransform<D>::ScaleX(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ICompositeTransform)->put_ScaleX(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_ICompositeTransform<D>::ScaleY() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ICompositeTransform)->get_ScaleY(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_ICompositeTransform<D>::ScaleY(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ICompositeTransform)->put_ScaleY(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_ICompositeTransform<D>::SkewX() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ICompositeTransform)->get_SkewX(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_ICompositeTransform<D>::SkewX(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ICompositeTransform)->put_SkewX(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_ICompositeTransform<D>::SkewY() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ICompositeTransform)->get_SkewY(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_ICompositeTransform<D>::SkewY(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ICompositeTransform)->put_SkewY(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_ICompositeTransform<D>::Rotation() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ICompositeTransform)->get_Rotation(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_ICompositeTransform<D>::Rotation(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ICompositeTransform)->put_Rotation(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_ICompositeTransform<D>::TranslateX() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ICompositeTransform)->get_TranslateX(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_ICompositeTransform<D>::TranslateX(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ICompositeTransform)->put_TranslateX(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_ICompositeTransform<D>::TranslateY() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ICompositeTransform)->get_TranslateY(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_ICompositeTransform<D>::TranslateY(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ICompositeTransform)->put_TranslateY(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_ICompositeTransformStatics<D>::CenterXProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ICompositeTransformStatics)->get_CenterXProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_ICompositeTransformStatics<D>::CenterYProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ICompositeTransformStatics)->get_CenterYProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_ICompositeTransformStatics<D>::ScaleXProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ICompositeTransformStatics)->get_ScaleXProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_ICompositeTransformStatics<D>::ScaleYProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ICompositeTransformStatics)->get_ScaleYProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_ICompositeTransformStatics<D>::SkewXProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ICompositeTransformStatics)->get_SkewXProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_ICompositeTransformStatics<D>::SkewYProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ICompositeTransformStatics)->get_SkewYProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_ICompositeTransformStatics<D>::RotationProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ICompositeTransformStatics)->get_RotationProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_ICompositeTransformStatics<D>::TranslateXProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ICompositeTransformStatics)->get_TranslateXProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_ICompositeTransformStatics<D>::TranslateYProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ICompositeTransformStatics)->get_TranslateYProperty(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Media_ICompositionTargetStatics<D>::Rendering(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ICompositionTargetStatics)->add_Rendering(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Media_ICompositionTargetStatics<D>::Rendering_revoker consume_Windows_UI_Xaml_Media_ICompositionTargetStatics<D>::Rendering(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Rendering_revoker>(this, Rendering(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Media_ICompositionTargetStatics<D>::Rendering(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Media::ICompositionTargetStatics)->remove_Rendering(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Media_ICompositionTargetStatics<D>::SurfaceContentsLost(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ICompositionTargetStatics)->add_SurfaceContentsLost(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Media_ICompositionTargetStatics<D>::SurfaceContentsLost_revoker consume_Windows_UI_Xaml_Media_ICompositionTargetStatics<D>::SurfaceContentsLost(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, SurfaceContentsLost_revoker>(this, SurfaceContentsLost(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Media_ICompositionTargetStatics<D>::SurfaceContentsLost(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Media::ICompositionTargetStatics)->remove_SurfaceContentsLost(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Media_ICompositionTargetStatics3<D>::Rendered(Windows::Foundation::EventHandler<Windows::UI::Xaml::Media::RenderedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ICompositionTargetStatics3)->add_Rendered(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Media_ICompositionTargetStatics3<D>::Rendered_revoker consume_Windows_UI_Xaml_Media_ICompositionTargetStatics3<D>::Rendered(auto_revoke_t, Windows::Foundation::EventHandler<Windows::UI::Xaml::Media::RenderedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Rendered_revoker>(this, Rendered(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Media_ICompositionTargetStatics3<D>::Rendered(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Media::ICompositionTargetStatics3)->remove_Rendered(get_abi(token)));
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Media_IEllipseGeometry<D>::Center() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IEllipseGeometry)->get_Center(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IEllipseGeometry<D>::Center(Windows::Foundation::Point const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IEllipseGeometry)->put_Center(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_Media_IEllipseGeometry<D>::RadiusX() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IEllipseGeometry)->get_RadiusX(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IEllipseGeometry<D>::RadiusX(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IEllipseGeometry)->put_RadiusX(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_IEllipseGeometry<D>::RadiusY() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IEllipseGeometry)->get_RadiusY(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IEllipseGeometry<D>::RadiusY(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IEllipseGeometry)->put_RadiusY(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IEllipseGeometryStatics<D>::CenterProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IEllipseGeometryStatics)->get_CenterProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IEllipseGeometryStatics<D>::RadiusXProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IEllipseGeometryStatics)->get_RadiusXProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IEllipseGeometryStatics<D>::RadiusYProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IEllipseGeometryStatics)->get_RadiusYProperty(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Media_IFontFamily<D>::Source() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IFontFamily)->get_Source(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::FontFamily consume_Windows_UI_Xaml_Media_IFontFamilyFactory<D>::CreateInstanceWithName(param::hstring const& familyName, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Media::FontFamily value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IFontFamilyFactory)->CreateInstanceWithName(get_abi(familyName), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::FontFamily consume_Windows_UI_Xaml_Media_IFontFamilyStatics2<D>::XamlAutoFontFamily() const
{
    Windows::UI::Xaml::Media::FontFamily value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IFontFamilyStatics2)->get_XamlAutoFontFamily(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::GeneralTransform consume_Windows_UI_Xaml_Media_IGeneralTransform<D>::Inverse() const
{
    Windows::UI::Xaml::Media::GeneralTransform value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGeneralTransform)->get_Inverse(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Media_IGeneralTransform<D>::TransformPoint(Windows::Foundation::Point const& point) const
{
    Windows::Foundation::Point result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGeneralTransform)->TransformPoint(get_abi(point), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Media_IGeneralTransform<D>::TryTransform(Windows::Foundation::Point const& inPoint, Windows::Foundation::Point& outPoint) const
{
    bool returnValue{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGeneralTransform)->TryTransform(get_abi(inPoint), put_abi(outPoint), &returnValue));
    return returnValue;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Xaml_Media_IGeneralTransform<D>::TransformBounds(Windows::Foundation::Rect const& rect) const
{
    Windows::Foundation::Rect result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGeneralTransform)->TransformBounds(get_abi(rect), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Media::GeneralTransform consume_Windows_UI_Xaml_Media_IGeneralTransformFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Media::GeneralTransform value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGeneralTransformFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::GeneralTransform consume_Windows_UI_Xaml_Media_IGeneralTransformOverrides<D>::InverseCore() const
{
    Windows::UI::Xaml::Media::GeneralTransform value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGeneralTransformOverrides)->get_InverseCore(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Media_IGeneralTransformOverrides<D>::TryTransformCore(Windows::Foundation::Point const& inPoint, Windows::Foundation::Point& outPoint) const
{
    bool returnValue{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGeneralTransformOverrides)->TryTransformCore(get_abi(inPoint), put_abi(outPoint), &returnValue));
    return returnValue;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Xaml_Media_IGeneralTransformOverrides<D>::TransformBoundsCore(Windows::Foundation::Rect const& rect) const
{
    Windows::Foundation::Rect result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGeneralTransformOverrides)->TransformBoundsCore(get_abi(rect), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Media::Transform consume_Windows_UI_Xaml_Media_IGeometry<D>::Transform() const
{
    Windows::UI::Xaml::Media::Transform value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGeometry)->get_Transform(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IGeometry<D>::Transform(Windows::UI::Xaml::Media::Transform const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGeometry)->put_Transform(get_abi(value)));
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Xaml_Media_IGeometry<D>::Bounds() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGeometry)->get_Bounds(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::FillRule consume_Windows_UI_Xaml_Media_IGeometryGroup<D>::FillRule() const
{
    Windows::UI::Xaml::Media::FillRule value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGeometryGroup)->get_FillRule(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IGeometryGroup<D>::FillRule(Windows::UI::Xaml::Media::FillRule const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGeometryGroup)->put_FillRule(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::GeometryCollection consume_Windows_UI_Xaml_Media_IGeometryGroup<D>::Children() const
{
    Windows::UI::Xaml::Media::GeometryCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGeometryGroup)->get_Children(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IGeometryGroup<D>::Children(Windows::UI::Xaml::Media::GeometryCollection const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGeometryGroup)->put_Children(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IGeometryGroupStatics<D>::FillRuleProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGeometryGroupStatics)->get_FillRuleProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IGeometryGroupStatics<D>::ChildrenProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGeometryGroupStatics)->get_ChildrenProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Geometry consume_Windows_UI_Xaml_Media_IGeometryStatics<D>::Empty() const
{
    Windows::UI::Xaml::Media::Geometry value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGeometryStatics)->get_Empty(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Media_IGeometryStatics<D>::StandardFlatteningTolerance() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGeometryStatics)->get_StandardFlatteningTolerance(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IGeometryStatics<D>::TransformProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGeometryStatics)->get_TransformProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::GradientSpreadMethod consume_Windows_UI_Xaml_Media_IGradientBrush<D>::SpreadMethod() const
{
    Windows::UI::Xaml::Media::GradientSpreadMethod value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGradientBrush)->get_SpreadMethod(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IGradientBrush<D>::SpreadMethod(Windows::UI::Xaml::Media::GradientSpreadMethod const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGradientBrush)->put_SpreadMethod(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::BrushMappingMode consume_Windows_UI_Xaml_Media_IGradientBrush<D>::MappingMode() const
{
    Windows::UI::Xaml::Media::BrushMappingMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGradientBrush)->get_MappingMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IGradientBrush<D>::MappingMode(Windows::UI::Xaml::Media::BrushMappingMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGradientBrush)->put_MappingMode(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::ColorInterpolationMode consume_Windows_UI_Xaml_Media_IGradientBrush<D>::ColorInterpolationMode() const
{
    Windows::UI::Xaml::Media::ColorInterpolationMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGradientBrush)->get_ColorInterpolationMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IGradientBrush<D>::ColorInterpolationMode(Windows::UI::Xaml::Media::ColorInterpolationMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGradientBrush)->put_ColorInterpolationMode(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::GradientStopCollection consume_Windows_UI_Xaml_Media_IGradientBrush<D>::GradientStops() const
{
    Windows::UI::Xaml::Media::GradientStopCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGradientBrush)->get_GradientStops(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IGradientBrush<D>::GradientStops(Windows::UI::Xaml::Media::GradientStopCollection const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGradientBrush)->put_GradientStops(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::GradientBrush consume_Windows_UI_Xaml_Media_IGradientBrushFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Media::GradientBrush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGradientBrushFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IGradientBrushStatics<D>::SpreadMethodProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGradientBrushStatics)->get_SpreadMethodProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IGradientBrushStatics<D>::MappingModeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGradientBrushStatics)->get_MappingModeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IGradientBrushStatics<D>::ColorInterpolationModeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGradientBrushStatics)->get_ColorInterpolationModeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IGradientBrushStatics<D>::GradientStopsProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGradientBrushStatics)->get_GradientStopsProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_Xaml_Media_IGradientStop<D>::Color() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGradientStop)->get_Color(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IGradientStop<D>::Color(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGradientStop)->put_Color(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_Media_IGradientStop<D>::Offset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGradientStop)->get_Offset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IGradientStop<D>::Offset(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGradientStop)->put_Offset(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IGradientStopStatics<D>::ColorProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGradientStopStatics)->get_ColorProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IGradientStopStatics<D>::OffsetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IGradientStopStatics)->get_OffsetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::ImageSource consume_Windows_UI_Xaml_Media_IImageBrush<D>::ImageSource() const
{
    Windows::UI::Xaml::Media::ImageSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IImageBrush)->get_ImageSource(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IImageBrush<D>::ImageSource(Windows::UI::Xaml::Media::ImageSource const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IImageBrush)->put_ImageSource(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Media_IImageBrush<D>::ImageFailed(Windows::UI::Xaml::ExceptionRoutedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IImageBrush)->add_ImageFailed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Media_IImageBrush<D>::ImageFailed_revoker consume_Windows_UI_Xaml_Media_IImageBrush<D>::ImageFailed(auto_revoke_t, Windows::UI::Xaml::ExceptionRoutedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, ImageFailed_revoker>(this, ImageFailed(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Media_IImageBrush<D>::ImageFailed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Media::IImageBrush)->remove_ImageFailed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Media_IImageBrush<D>::ImageOpened(Windows::UI::Xaml::RoutedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IImageBrush)->add_ImageOpened(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Media_IImageBrush<D>::ImageOpened_revoker consume_Windows_UI_Xaml_Media_IImageBrush<D>::ImageOpened(auto_revoke_t, Windows::UI::Xaml::RoutedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, ImageOpened_revoker>(this, ImageOpened(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Media_IImageBrush<D>::ImageOpened(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Media::IImageBrush)->remove_ImageOpened(get_abi(token)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IImageBrushStatics<D>::ImageSourceProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IImageBrushStatics)->get_ImageSourceProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Media_ILineGeometry<D>::StartPoint() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ILineGeometry)->get_StartPoint(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_ILineGeometry<D>::StartPoint(Windows::Foundation::Point const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ILineGeometry)->put_StartPoint(get_abi(value)));
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Media_ILineGeometry<D>::EndPoint() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ILineGeometry)->get_EndPoint(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_ILineGeometry<D>::EndPoint(Windows::Foundation::Point const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ILineGeometry)->put_EndPoint(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_ILineGeometryStatics<D>::StartPointProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ILineGeometryStatics)->get_StartPointProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_ILineGeometryStatics<D>::EndPointProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ILineGeometryStatics)->get_EndPointProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Media_ILineSegment<D>::Point() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ILineSegment)->get_Point(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_ILineSegment<D>::Point(Windows::Foundation::Point const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ILineSegment)->put_Point(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_ILineSegmentStatics<D>::PointProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ILineSegmentStatics)->get_PointProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Media_ILinearGradientBrush<D>::StartPoint() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ILinearGradientBrush)->get_StartPoint(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_ILinearGradientBrush<D>::StartPoint(Windows::Foundation::Point const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ILinearGradientBrush)->put_StartPoint(get_abi(value)));
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Media_ILinearGradientBrush<D>::EndPoint() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ILinearGradientBrush)->get_EndPoint(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_ILinearGradientBrush<D>::EndPoint(Windows::Foundation::Point const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ILinearGradientBrush)->put_EndPoint(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::LinearGradientBrush consume_Windows_UI_Xaml_Media_ILinearGradientBrushFactory<D>::CreateInstanceWithGradientStopCollectionAndAngle(Windows::UI::Xaml::Media::GradientStopCollection const& gradientStopCollection, double angle) const
{
    Windows::UI::Xaml::Media::LinearGradientBrush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ILinearGradientBrushFactory)->CreateInstanceWithGradientStopCollectionAndAngle(get_abi(gradientStopCollection), angle, put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_ILinearGradientBrushStatics<D>::StartPointProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ILinearGradientBrushStatics)->get_StartPointProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_ILinearGradientBrushStatics<D>::EndPointProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ILinearGradientBrushStatics)->get_EndPointProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::LoadedImageSourceLoadStatus consume_Windows_UI_Xaml_Media_ILoadedImageSourceLoadCompletedEventArgs<D>::Status() const
{
    Windows::UI::Xaml::Media::LoadedImageSourceLoadStatus value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ILoadedImageSourceLoadCompletedEventArgs)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Size consume_Windows_UI_Xaml_Media_ILoadedImageSurface<D>::DecodedPhysicalSize() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ILoadedImageSurface)->get_DecodedPhysicalSize(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Size consume_Windows_UI_Xaml_Media_ILoadedImageSurface<D>::DecodedSize() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ILoadedImageSurface)->get_DecodedSize(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Size consume_Windows_UI_Xaml_Media_ILoadedImageSurface<D>::NaturalSize() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ILoadedImageSurface)->get_NaturalSize(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Media_ILoadedImageSurface<D>::LoadCompleted(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Media::LoadedImageSurface, Windows::UI::Xaml::Media::LoadedImageSourceLoadCompletedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ILoadedImageSurface)->add_LoadCompleted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Media_ILoadedImageSurface<D>::LoadCompleted_revoker consume_Windows_UI_Xaml_Media_ILoadedImageSurface<D>::LoadCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Media::LoadedImageSurface, Windows::UI::Xaml::Media::LoadedImageSourceLoadCompletedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, LoadCompleted_revoker>(this, LoadCompleted(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Media_ILoadedImageSurface<D>::LoadCompleted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Media::ILoadedImageSurface)->remove_LoadCompleted(get_abi(token)));
}

template <typename D> Windows::UI::Xaml::Media::LoadedImageSurface consume_Windows_UI_Xaml_Media_ILoadedImageSurfaceStatics<D>::StartLoadFromUri(Windows::Foundation::Uri const& uri, Windows::Foundation::Size const& desiredMaxSize) const
{
    Windows::UI::Xaml::Media::LoadedImageSurface result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ILoadedImageSurfaceStatics)->StartLoadFromUriWithSize(get_abi(uri), get_abi(desiredMaxSize), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Media::LoadedImageSurface consume_Windows_UI_Xaml_Media_ILoadedImageSurfaceStatics<D>::StartLoadFromUri(Windows::Foundation::Uri const& uri) const
{
    Windows::UI::Xaml::Media::LoadedImageSurface result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ILoadedImageSurfaceStatics)->StartLoadFromUri(get_abi(uri), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Media::LoadedImageSurface consume_Windows_UI_Xaml_Media_ILoadedImageSurfaceStatics<D>::StartLoadFromStream(Windows::Storage::Streams::IRandomAccessStream const& stream, Windows::Foundation::Size const& desiredMaxSize) const
{
    Windows::UI::Xaml::Media::LoadedImageSurface result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ILoadedImageSurfaceStatics)->StartLoadFromStreamWithSize(get_abi(stream), get_abi(desiredMaxSize), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Media::LoadedImageSurface consume_Windows_UI_Xaml_Media_ILoadedImageSurfaceStatics<D>::StartLoadFromStream(Windows::Storage::Streams::IRandomAccessStream const& stream) const
{
    Windows::UI::Xaml::Media::LoadedImageSurface result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ILoadedImageSurfaceStatics)->StartLoadFromStream(get_abi(stream), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Media::Media3D::Matrix3D consume_Windows_UI_Xaml_Media_IMatrix3DProjection<D>::ProjectionMatrix() const
{
    Windows::UI::Xaml::Media::Media3D::Matrix3D value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IMatrix3DProjection)->get_ProjectionMatrix(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IMatrix3DProjection<D>::ProjectionMatrix(Windows::UI::Xaml::Media::Media3D::Matrix3D const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IMatrix3DProjection)->put_ProjectionMatrix(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IMatrix3DProjectionStatics<D>::ProjectionMatrixProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IMatrix3DProjectionStatics)->get_ProjectionMatrixProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Matrix consume_Windows_UI_Xaml_Media_IMatrixHelperStatics<D>::Identity() const
{
    Windows::UI::Xaml::Media::Matrix value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IMatrixHelperStatics)->get_Identity(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Matrix consume_Windows_UI_Xaml_Media_IMatrixHelperStatics<D>::FromElements(double m11, double m12, double m21, double m22, double offsetX, double offsetY) const
{
    Windows::UI::Xaml::Media::Matrix result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IMatrixHelperStatics)->FromElements(m11, m12, m21, m22, offsetX, offsetY, put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Media_IMatrixHelperStatics<D>::GetIsIdentity(Windows::UI::Xaml::Media::Matrix const& target) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IMatrixHelperStatics)->GetIsIdentity(get_abi(target), &result));
    return result;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Media_IMatrixHelperStatics<D>::Transform(Windows::UI::Xaml::Media::Matrix const& target, Windows::Foundation::Point const& point) const
{
    Windows::Foundation::Point result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IMatrixHelperStatics)->Transform(get_abi(target), get_abi(point), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Media::Matrix consume_Windows_UI_Xaml_Media_IMatrixTransform<D>::Matrix() const
{
    Windows::UI::Xaml::Media::Matrix value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IMatrixTransform)->get_Matrix(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IMatrixTransform<D>::Matrix(Windows::UI::Xaml::Media::Matrix const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IMatrixTransform)->put_Matrix(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IMatrixTransformStatics<D>::MatrixProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IMatrixTransformStatics)->get_MatrixProperty(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IMediaTransportControlsThumbnailRequestedEventArgs<D>::SetThumbnailImage(Windows::Storage::Streams::IInputStream const& source) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IMediaTransportControlsThumbnailRequestedEventArgs)->SetThumbnailImage(get_abi(source)));
}

template <typename D> Windows::Foundation::Deferral consume_Windows_UI_Xaml_Media_IMediaTransportControlsThumbnailRequestedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IMediaTransportControlsThumbnailRequestedEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> Windows::Media::Playback::FailedMediaStreamKind consume_Windows_UI_Xaml_Media_IPartialMediaFailureDetectedEventArgs<D>::StreamKind() const
{
    Windows::Media::Playback::FailedMediaStreamKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPartialMediaFailureDetectedEventArgs)->get_StreamKind(put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_UI_Xaml_Media_IPartialMediaFailureDetectedEventArgs2<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPartialMediaFailureDetectedEventArgs2)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::PathSegmentCollection consume_Windows_UI_Xaml_Media_IPathFigure<D>::Segments() const
{
    Windows::UI::Xaml::Media::PathSegmentCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPathFigure)->get_Segments(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IPathFigure<D>::Segments(Windows::UI::Xaml::Media::PathSegmentCollection const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPathFigure)->put_Segments(get_abi(value)));
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Media_IPathFigure<D>::StartPoint() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPathFigure)->get_StartPoint(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IPathFigure<D>::StartPoint(Windows::Foundation::Point const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPathFigure)->put_StartPoint(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_Media_IPathFigure<D>::IsClosed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPathFigure)->get_IsClosed(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IPathFigure<D>::IsClosed(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPathFigure)->put_IsClosed(value));
}

template <typename D> bool consume_Windows_UI_Xaml_Media_IPathFigure<D>::IsFilled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPathFigure)->get_IsFilled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IPathFigure<D>::IsFilled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPathFigure)->put_IsFilled(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IPathFigureStatics<D>::SegmentsProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPathFigureStatics)->get_SegmentsProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IPathFigureStatics<D>::StartPointProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPathFigureStatics)->get_StartPointProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IPathFigureStatics<D>::IsClosedProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPathFigureStatics)->get_IsClosedProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IPathFigureStatics<D>::IsFilledProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPathFigureStatics)->get_IsFilledProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::FillRule consume_Windows_UI_Xaml_Media_IPathGeometry<D>::FillRule() const
{
    Windows::UI::Xaml::Media::FillRule value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPathGeometry)->get_FillRule(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IPathGeometry<D>::FillRule(Windows::UI::Xaml::Media::FillRule const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPathGeometry)->put_FillRule(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::PathFigureCollection consume_Windows_UI_Xaml_Media_IPathGeometry<D>::Figures() const
{
    Windows::UI::Xaml::Media::PathFigureCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPathGeometry)->get_Figures(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IPathGeometry<D>::Figures(Windows::UI::Xaml::Media::PathFigureCollection const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPathGeometry)->put_Figures(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IPathGeometryStatics<D>::FillRuleProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPathGeometryStatics)->get_FillRuleProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IPathGeometryStatics<D>::FiguresProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPathGeometryStatics)->get_FiguresProperty(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Media_IPlaneProjection<D>::LocalOffsetX() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjection)->get_LocalOffsetX(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IPlaneProjection<D>::LocalOffsetX(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjection)->put_LocalOffsetX(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_IPlaneProjection<D>::LocalOffsetY() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjection)->get_LocalOffsetY(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IPlaneProjection<D>::LocalOffsetY(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjection)->put_LocalOffsetY(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_IPlaneProjection<D>::LocalOffsetZ() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjection)->get_LocalOffsetZ(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IPlaneProjection<D>::LocalOffsetZ(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjection)->put_LocalOffsetZ(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_IPlaneProjection<D>::RotationX() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjection)->get_RotationX(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IPlaneProjection<D>::RotationX(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjection)->put_RotationX(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_IPlaneProjection<D>::RotationY() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjection)->get_RotationY(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IPlaneProjection<D>::RotationY(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjection)->put_RotationY(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_IPlaneProjection<D>::RotationZ() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjection)->get_RotationZ(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IPlaneProjection<D>::RotationZ(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjection)->put_RotationZ(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_IPlaneProjection<D>::CenterOfRotationX() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjection)->get_CenterOfRotationX(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IPlaneProjection<D>::CenterOfRotationX(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjection)->put_CenterOfRotationX(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_IPlaneProjection<D>::CenterOfRotationY() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjection)->get_CenterOfRotationY(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IPlaneProjection<D>::CenterOfRotationY(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjection)->put_CenterOfRotationY(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_IPlaneProjection<D>::CenterOfRotationZ() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjection)->get_CenterOfRotationZ(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IPlaneProjection<D>::CenterOfRotationZ(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjection)->put_CenterOfRotationZ(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_IPlaneProjection<D>::GlobalOffsetX() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjection)->get_GlobalOffsetX(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IPlaneProjection<D>::GlobalOffsetX(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjection)->put_GlobalOffsetX(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_IPlaneProjection<D>::GlobalOffsetY() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjection)->get_GlobalOffsetY(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IPlaneProjection<D>::GlobalOffsetY(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjection)->put_GlobalOffsetY(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_IPlaneProjection<D>::GlobalOffsetZ() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjection)->get_GlobalOffsetZ(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IPlaneProjection<D>::GlobalOffsetZ(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjection)->put_GlobalOffsetZ(value));
}

template <typename D> Windows::UI::Xaml::Media::Media3D::Matrix3D consume_Windows_UI_Xaml_Media_IPlaneProjection<D>::ProjectionMatrix() const
{
    Windows::UI::Xaml::Media::Media3D::Matrix3D value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjection)->get_ProjectionMatrix(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IPlaneProjectionStatics<D>::LocalOffsetXProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjectionStatics)->get_LocalOffsetXProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IPlaneProjectionStatics<D>::LocalOffsetYProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjectionStatics)->get_LocalOffsetYProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IPlaneProjectionStatics<D>::LocalOffsetZProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjectionStatics)->get_LocalOffsetZProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IPlaneProjectionStatics<D>::RotationXProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjectionStatics)->get_RotationXProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IPlaneProjectionStatics<D>::RotationYProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjectionStatics)->get_RotationYProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IPlaneProjectionStatics<D>::RotationZProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjectionStatics)->get_RotationZProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IPlaneProjectionStatics<D>::CenterOfRotationXProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjectionStatics)->get_CenterOfRotationXProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IPlaneProjectionStatics<D>::CenterOfRotationYProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjectionStatics)->get_CenterOfRotationYProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IPlaneProjectionStatics<D>::CenterOfRotationZProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjectionStatics)->get_CenterOfRotationZProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IPlaneProjectionStatics<D>::GlobalOffsetXProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjectionStatics)->get_GlobalOffsetXProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IPlaneProjectionStatics<D>::GlobalOffsetYProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjectionStatics)->get_GlobalOffsetYProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IPlaneProjectionStatics<D>::GlobalOffsetZProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjectionStatics)->get_GlobalOffsetZProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IPlaneProjectionStatics<D>::ProjectionMatrixProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPlaneProjectionStatics)->get_ProjectionMatrixProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::PointCollection consume_Windows_UI_Xaml_Media_IPolyBezierSegment<D>::Points() const
{
    Windows::UI::Xaml::Media::PointCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPolyBezierSegment)->get_Points(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IPolyBezierSegment<D>::Points(Windows::UI::Xaml::Media::PointCollection const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPolyBezierSegment)->put_Points(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IPolyBezierSegmentStatics<D>::PointsProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPolyBezierSegmentStatics)->get_PointsProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::PointCollection consume_Windows_UI_Xaml_Media_IPolyLineSegment<D>::Points() const
{
    Windows::UI::Xaml::Media::PointCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPolyLineSegment)->get_Points(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IPolyLineSegment<D>::Points(Windows::UI::Xaml::Media::PointCollection const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPolyLineSegment)->put_Points(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IPolyLineSegmentStatics<D>::PointsProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPolyLineSegmentStatics)->get_PointsProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::PointCollection consume_Windows_UI_Xaml_Media_IPolyQuadraticBezierSegment<D>::Points() const
{
    Windows::UI::Xaml::Media::PointCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPolyQuadraticBezierSegment)->get_Points(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IPolyQuadraticBezierSegment<D>::Points(Windows::UI::Xaml::Media::PointCollection const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPolyQuadraticBezierSegment)->put_Points(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IPolyQuadraticBezierSegmentStatics<D>::PointsProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IPolyQuadraticBezierSegmentStatics)->get_PointsProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Projection consume_Windows_UI_Xaml_Media_IProjectionFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Media::Projection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IProjectionFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Media_IQuadraticBezierSegment<D>::Point1() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IQuadraticBezierSegment)->get_Point1(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IQuadraticBezierSegment<D>::Point1(Windows::Foundation::Point const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IQuadraticBezierSegment)->put_Point1(get_abi(value)));
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Media_IQuadraticBezierSegment<D>::Point2() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IQuadraticBezierSegment)->get_Point2(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IQuadraticBezierSegment<D>::Point2(Windows::Foundation::Point const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IQuadraticBezierSegment)->put_Point2(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IQuadraticBezierSegmentStatics<D>::Point1Property() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IQuadraticBezierSegmentStatics)->get_Point1Property(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IQuadraticBezierSegmentStatics<D>::Point2Property() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IQuadraticBezierSegmentStatics)->get_Point2Property(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Xaml_Media_IRectangleGeometry<D>::Rect() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IRectangleGeometry)->get_Rect(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IRectangleGeometry<D>::Rect(Windows::Foundation::Rect const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IRectangleGeometry)->put_Rect(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IRectangleGeometryStatics<D>::RectProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IRectangleGeometryStatics)->get_RectProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_UI_Xaml_Media_IRenderedEventArgs<D>::FrameDuration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IRenderedEventArgs)->get_FrameDuration(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_UI_Xaml_Media_IRenderingEventArgs<D>::RenderingTime() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IRenderingEventArgs)->get_RenderingTime(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::RevealBackgroundBrush consume_Windows_UI_Xaml_Media_IRevealBackgroundBrushFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Media::RevealBackgroundBrush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IRevealBackgroundBrushFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::RevealBorderBrush consume_Windows_UI_Xaml_Media_IRevealBorderBrushFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Media::RevealBorderBrush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IRevealBorderBrushFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_Xaml_Media_IRevealBrush<D>::Color() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IRevealBrush)->get_Color(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IRevealBrush<D>::Color(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IRevealBrush)->put_Color(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::ApplicationTheme consume_Windows_UI_Xaml_Media_IRevealBrush<D>::TargetTheme() const
{
    Windows::UI::Xaml::ApplicationTheme value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IRevealBrush)->get_TargetTheme(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IRevealBrush<D>::TargetTheme(Windows::UI::Xaml::ApplicationTheme const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IRevealBrush)->put_TargetTheme(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_Media_IRevealBrush<D>::AlwaysUseFallback() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IRevealBrush)->get_AlwaysUseFallback(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IRevealBrush<D>::AlwaysUseFallback(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IRevealBrush)->put_AlwaysUseFallback(value));
}

template <typename D> Windows::UI::Xaml::Media::RevealBrush consume_Windows_UI_Xaml_Media_IRevealBrushFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Media::RevealBrush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IRevealBrushFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IRevealBrushStatics<D>::ColorProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IRevealBrushStatics)->get_ColorProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IRevealBrushStatics<D>::TargetThemeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IRevealBrushStatics)->get_TargetThemeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IRevealBrushStatics<D>::AlwaysUseFallbackProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IRevealBrushStatics)->get_AlwaysUseFallbackProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IRevealBrushStatics<D>::StateProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IRevealBrushStatics)->get_StateProperty(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IRevealBrushStatics<D>::SetState(Windows::UI::Xaml::UIElement const& element, Windows::UI::Xaml::Media::RevealBrushState const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IRevealBrushStatics)->SetState(get_abi(element), get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::RevealBrushState consume_Windows_UI_Xaml_Media_IRevealBrushStatics<D>::GetState(Windows::UI::Xaml::UIElement const& element) const
{
    Windows::UI::Xaml::Media::RevealBrushState result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IRevealBrushStatics)->GetState(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> double consume_Windows_UI_Xaml_Media_IRotateTransform<D>::CenterX() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IRotateTransform)->get_CenterX(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IRotateTransform<D>::CenterX(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IRotateTransform)->put_CenterX(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_IRotateTransform<D>::CenterY() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IRotateTransform)->get_CenterY(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IRotateTransform<D>::CenterY(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IRotateTransform)->put_CenterY(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_IRotateTransform<D>::Angle() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IRotateTransform)->get_Angle(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IRotateTransform<D>::Angle(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IRotateTransform)->put_Angle(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IRotateTransformStatics<D>::CenterXProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IRotateTransformStatics)->get_CenterXProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IRotateTransformStatics<D>::CenterYProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IRotateTransformStatics)->get_CenterYProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IRotateTransformStatics<D>::AngleProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IRotateTransformStatics)->get_AngleProperty(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Media_IScaleTransform<D>::CenterX() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IScaleTransform)->get_CenterX(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IScaleTransform<D>::CenterX(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IScaleTransform)->put_CenterX(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_IScaleTransform<D>::CenterY() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IScaleTransform)->get_CenterY(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IScaleTransform<D>::CenterY(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IScaleTransform)->put_CenterY(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_IScaleTransform<D>::ScaleX() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IScaleTransform)->get_ScaleX(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IScaleTransform<D>::ScaleX(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IScaleTransform)->put_ScaleX(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_IScaleTransform<D>::ScaleY() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IScaleTransform)->get_ScaleY(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IScaleTransform<D>::ScaleY(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IScaleTransform)->put_ScaleY(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IScaleTransformStatics<D>::CenterXProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IScaleTransformStatics)->get_CenterXProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IScaleTransformStatics<D>::CenterYProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IScaleTransformStatics)->get_CenterYProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IScaleTransformStatics<D>::ScaleXProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IScaleTransformStatics)->get_ScaleXProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IScaleTransformStatics<D>::ScaleYProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IScaleTransformStatics)->get_ScaleYProperty(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Media_ISkewTransform<D>::CenterX() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ISkewTransform)->get_CenterX(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_ISkewTransform<D>::CenterX(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ISkewTransform)->put_CenterX(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_ISkewTransform<D>::CenterY() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ISkewTransform)->get_CenterY(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_ISkewTransform<D>::CenterY(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ISkewTransform)->put_CenterY(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_ISkewTransform<D>::AngleX() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ISkewTransform)->get_AngleX(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_ISkewTransform<D>::AngleX(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ISkewTransform)->put_AngleX(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_ISkewTransform<D>::AngleY() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ISkewTransform)->get_AngleY(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_ISkewTransform<D>::AngleY(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ISkewTransform)->put_AngleY(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_ISkewTransformStatics<D>::CenterXProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ISkewTransformStatics)->get_CenterXProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_ISkewTransformStatics<D>::CenterYProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ISkewTransformStatics)->get_CenterYProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_ISkewTransformStatics<D>::AngleXProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ISkewTransformStatics)->get_AngleXProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_ISkewTransformStatics<D>::AngleYProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ISkewTransformStatics)->get_AngleYProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_Xaml_Media_ISolidColorBrush<D>::Color() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ISolidColorBrush)->get_Color(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_ISolidColorBrush<D>::Color(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ISolidColorBrush)->put_Color(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::SolidColorBrush consume_Windows_UI_Xaml_Media_ISolidColorBrushFactory<D>::CreateInstanceWithColor(Windows::UI::Color const& color) const
{
    Windows::UI::Xaml::Media::SolidColorBrush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ISolidColorBrushFactory)->CreateInstanceWithColor(get_abi(color), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_ISolidColorBrushStatics<D>::ColorProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ISolidColorBrushStatics)->get_ColorProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::UIElementWeakCollection consume_Windows_UI_Xaml_Media_IThemeShadow<D>::Receivers() const
{
    Windows::UI::Xaml::UIElementWeakCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IThemeShadow)->get_Receivers(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::ThemeShadow consume_Windows_UI_Xaml_Media_IThemeShadowFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Media::ThemeShadow value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IThemeShadowFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::AlignmentX consume_Windows_UI_Xaml_Media_ITileBrush<D>::AlignmentX() const
{
    Windows::UI::Xaml::Media::AlignmentX value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ITileBrush)->get_AlignmentX(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_ITileBrush<D>::AlignmentX(Windows::UI::Xaml::Media::AlignmentX const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ITileBrush)->put_AlignmentX(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::AlignmentY consume_Windows_UI_Xaml_Media_ITileBrush<D>::AlignmentY() const
{
    Windows::UI::Xaml::Media::AlignmentY value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ITileBrush)->get_AlignmentY(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_ITileBrush<D>::AlignmentY(Windows::UI::Xaml::Media::AlignmentY const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ITileBrush)->put_AlignmentY(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Stretch consume_Windows_UI_Xaml_Media_ITileBrush<D>::Stretch() const
{
    Windows::UI::Xaml::Media::Stretch value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ITileBrush)->get_Stretch(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_ITileBrush<D>::Stretch(Windows::UI::Xaml::Media::Stretch const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ITileBrush)->put_Stretch(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::TileBrush consume_Windows_UI_Xaml_Media_ITileBrushFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Media::TileBrush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ITileBrushFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_ITileBrushStatics<D>::AlignmentXProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ITileBrushStatics)->get_AlignmentXProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_ITileBrushStatics<D>::AlignmentYProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ITileBrushStatics)->get_AlignmentYProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_ITileBrushStatics<D>::StretchProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ITileBrushStatics)->get_StretchProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_UI_Xaml_Media_ITimelineMarker<D>::Time() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ITimelineMarker)->get_Time(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_ITimelineMarker<D>::Time(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ITimelineMarker)->put_Time(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Xaml_Media_ITimelineMarker<D>::Type() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ITimelineMarker)->get_Type(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_ITimelineMarker<D>::Type(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ITimelineMarker)->put_Type(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Xaml_Media_ITimelineMarker<D>::Text() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ITimelineMarker)->get_Text(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_ITimelineMarker<D>::Text(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ITimelineMarker)->put_Text(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::TimelineMarker consume_Windows_UI_Xaml_Media_ITimelineMarkerRoutedEventArgs<D>::Marker() const
{
    Windows::UI::Xaml::Media::TimelineMarker value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ITimelineMarkerRoutedEventArgs)->get_Marker(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_ITimelineMarkerRoutedEventArgs<D>::Marker(Windows::UI::Xaml::Media::TimelineMarker const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ITimelineMarkerRoutedEventArgs)->put_Marker(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_ITimelineMarkerStatics<D>::TimeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ITimelineMarkerStatics)->get_TimeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_ITimelineMarkerStatics<D>::TypeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ITimelineMarkerStatics)->get_TypeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_ITimelineMarkerStatics<D>::TextProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ITimelineMarkerStatics)->get_TextProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::TransformCollection consume_Windows_UI_Xaml_Media_ITransformGroup<D>::Children() const
{
    Windows::UI::Xaml::Media::TransformCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ITransformGroup)->get_Children(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_ITransformGroup<D>::Children(Windows::UI::Xaml::Media::TransformCollection const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ITransformGroup)->put_Children(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Matrix consume_Windows_UI_Xaml_Media_ITransformGroup<D>::Value() const
{
    Windows::UI::Xaml::Media::Matrix value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ITransformGroup)->get_Value(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_ITransformGroupStatics<D>::ChildrenProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ITransformGroupStatics)->get_ChildrenProperty(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Media_ITranslateTransform<D>::X() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ITranslateTransform)->get_X(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_ITranslateTransform<D>::X(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ITranslateTransform)->put_X(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_ITranslateTransform<D>::Y() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ITranslateTransform)->get_Y(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_ITranslateTransform<D>::Y(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ITranslateTransform)->put_Y(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_ITranslateTransformStatics<D>::XProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ITranslateTransformStatics)->get_XProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_ITranslateTransformStatics<D>::YProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::ITranslateTransformStatics)->get_YProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::UIElement> consume_Windows_UI_Xaml_Media_IVisualTreeHelperStatics<D>::FindElementsInHostCoordinates(Windows::Foundation::Point const& intersectingPoint, Windows::UI::Xaml::UIElement const& subtree) const
{
    Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::UIElement> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IVisualTreeHelperStatics)->FindElementsInHostCoordinatesPoint(get_abi(intersectingPoint), get_abi(subtree), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::UIElement> consume_Windows_UI_Xaml_Media_IVisualTreeHelperStatics<D>::FindElementsInHostCoordinates(Windows::Foundation::Rect const& intersectingRect, Windows::UI::Xaml::UIElement const& subtree) const
{
    Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::UIElement> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IVisualTreeHelperStatics)->FindElementsInHostCoordinatesRect(get_abi(intersectingRect), get_abi(subtree), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::UIElement> consume_Windows_UI_Xaml_Media_IVisualTreeHelperStatics<D>::FindElementsInHostCoordinates(Windows::Foundation::Point const& intersectingPoint, Windows::UI::Xaml::UIElement const& subtree, bool includeAllElements) const
{
    Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::UIElement> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IVisualTreeHelperStatics)->FindAllElementsInHostCoordinatesPoint(get_abi(intersectingPoint), get_abi(subtree), includeAllElements, put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::UIElement> consume_Windows_UI_Xaml_Media_IVisualTreeHelperStatics<D>::FindElementsInHostCoordinates(Windows::Foundation::Rect const& intersectingRect, Windows::UI::Xaml::UIElement const& subtree, bool includeAllElements) const
{
    Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::UIElement> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IVisualTreeHelperStatics)->FindAllElementsInHostCoordinatesRect(get_abi(intersectingRect), get_abi(subtree), includeAllElements, put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Media_IVisualTreeHelperStatics<D>::GetChild(Windows::UI::Xaml::DependencyObject const& reference, int32_t childIndex) const
{
    Windows::UI::Xaml::DependencyObject result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IVisualTreeHelperStatics)->GetChild(get_abi(reference), childIndex, put_abi(result)));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Media_IVisualTreeHelperStatics<D>::GetChildrenCount(Windows::UI::Xaml::DependencyObject const& reference) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IVisualTreeHelperStatics)->GetChildrenCount(get_abi(reference), &result));
    return result;
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Media_IVisualTreeHelperStatics<D>::GetParent(Windows::UI::Xaml::DependencyObject const& reference) const
{
    Windows::UI::Xaml::DependencyObject result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IVisualTreeHelperStatics)->GetParent(get_abi(reference), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IVisualTreeHelperStatics<D>::DisconnectChildrenRecursive(Windows::UI::Xaml::UIElement const& element) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IVisualTreeHelperStatics)->DisconnectChildrenRecursive(get_abi(element)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Controls::Primitives::Popup> consume_Windows_UI_Xaml_Media_IVisualTreeHelperStatics2<D>::GetOpenPopups(Windows::UI::Xaml::Window const& window) const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Controls::Primitives::Popup> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IVisualTreeHelperStatics2)->GetOpenPopups(get_abi(window), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Controls::Primitives::Popup> consume_Windows_UI_Xaml_Media_IVisualTreeHelperStatics3<D>::GetOpenPopupsForXamlRoot(Windows::UI::Xaml::XamlRoot const& xamlRoot) const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Controls::Primitives::Popup> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IVisualTreeHelperStatics3)->GetOpenPopupsForXamlRoot(get_abi(xamlRoot), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Color consume_Windows_UI_Xaml_Media_IXamlCompositionBrushBase<D>::FallbackColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IXamlCompositionBrushBase)->get_FallbackColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IXamlCompositionBrushBase<D>::FallbackColor(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IXamlCompositionBrushBase)->put_FallbackColor(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::XamlCompositionBrushBase consume_Windows_UI_Xaml_Media_IXamlCompositionBrushBaseFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Media::XamlCompositionBrushBase value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IXamlCompositionBrushBaseFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IXamlCompositionBrushBaseOverrides<D>::OnConnected() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IXamlCompositionBrushBaseOverrides)->OnConnected());
}

template <typename D> void consume_Windows_UI_Xaml_Media_IXamlCompositionBrushBaseOverrides<D>::OnDisconnected() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IXamlCompositionBrushBaseOverrides)->OnDisconnected());
}

template <typename D> Windows::UI::Composition::CompositionBrush consume_Windows_UI_Xaml_Media_IXamlCompositionBrushBaseProtected<D>::CompositionBrush() const
{
    Windows::UI::Composition::CompositionBrush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IXamlCompositionBrushBaseProtected)->get_CompositionBrush(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IXamlCompositionBrushBaseProtected<D>::CompositionBrush(Windows::UI::Composition::CompositionBrush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IXamlCompositionBrushBaseProtected)->put_CompositionBrush(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_IXamlCompositionBrushBaseStatics<D>::FallbackColorProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IXamlCompositionBrushBaseStatics)->get_FallbackColorProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::XamlLight consume_Windows_UI_Xaml_Media_IXamlLightFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Media::XamlLight value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IXamlLightFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Media_IXamlLightOverrides<D>::GetId() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IXamlLightOverrides)->GetId(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IXamlLightOverrides<D>::OnConnected(Windows::UI::Xaml::UIElement const& newElement) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IXamlLightOverrides)->OnConnected(get_abi(newElement)));
}

template <typename D> void consume_Windows_UI_Xaml_Media_IXamlLightOverrides<D>::OnDisconnected(Windows::UI::Xaml::UIElement const& oldElement) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IXamlLightOverrides)->OnDisconnected(get_abi(oldElement)));
}

template <typename D> Windows::UI::Composition::CompositionLight consume_Windows_UI_Xaml_Media_IXamlLightProtected<D>::CompositionLight() const
{
    Windows::UI::Composition::CompositionLight value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IXamlLightProtected)->get_CompositionLight(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_IXamlLightProtected<D>::CompositionLight(Windows::UI::Composition::CompositionLight const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IXamlLightProtected)->put_CompositionLight(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Media_IXamlLightStatics<D>::AddTargetElement(param::hstring const& lightId, Windows::UI::Xaml::UIElement const& element) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IXamlLightStatics)->AddTargetElement(get_abi(lightId), get_abi(element)));
}

template <typename D> void consume_Windows_UI_Xaml_Media_IXamlLightStatics<D>::RemoveTargetElement(param::hstring const& lightId, Windows::UI::Xaml::UIElement const& element) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IXamlLightStatics)->RemoveTargetElement(get_abi(lightId), get_abi(element)));
}

template <typename D> void consume_Windows_UI_Xaml_Media_IXamlLightStatics<D>::AddTargetBrush(param::hstring const& lightId, Windows::UI::Xaml::Media::Brush const& brush) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IXamlLightStatics)->AddTargetBrush(get_abi(lightId), get_abi(brush)));
}

template <typename D> void consume_Windows_UI_Xaml_Media_IXamlLightStatics<D>::RemoveTargetBrush(param::hstring const& lightId, Windows::UI::Xaml::Media::Brush const& brush) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::IXamlLightStatics)->RemoveTargetBrush(get_abi(lightId), get_abi(brush)));
}

template <> struct delegate<Windows::UI::Xaml::Media::RateChangedRoutedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::Media::RateChangedRoutedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::Media::RateChangedRoutedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::Media::RateChangedRoutedEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::Media::TimelineMarkerRoutedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::Media::TimelineMarkerRoutedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::Media::TimelineMarkerRoutedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::Media::TimelineMarkerRoutedEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IAcrylicBrush> : produce_base<D, Windows::UI::Xaml::Media::IAcrylicBrush>
{
    int32_t WINRT_CALL get_BackgroundSource(Windows::UI::Xaml::Media::AcrylicBackgroundSource* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackgroundSource, WINRT_WRAP(Windows::UI::Xaml::Media::AcrylicBackgroundSource));
            *value = detach_from<Windows::UI::Xaml::Media::AcrylicBackgroundSource>(this->shim().BackgroundSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BackgroundSource(Windows::UI::Xaml::Media::AcrylicBackgroundSource value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackgroundSource, WINRT_WRAP(void), Windows::UI::Xaml::Media::AcrylicBackgroundSource const&);
            this->shim().BackgroundSource(*reinterpret_cast<Windows::UI::Xaml::Media::AcrylicBackgroundSource const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TintColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TintColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().TintColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TintColor(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TintColor, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().TintColor(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TintOpacity(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TintOpacity, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().TintOpacity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TintOpacity(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TintOpacity, WINRT_WRAP(void), double);
            this->shim().TintOpacity(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TintTransitionDuration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TintTransitionDuration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().TintTransitionDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TintTransitionDuration(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TintTransitionDuration, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().TintTransitionDuration(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AlwaysUseFallback(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlwaysUseFallback, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AlwaysUseFallback());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AlwaysUseFallback(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlwaysUseFallback, WINRT_WRAP(void), bool);
            this->shim().AlwaysUseFallback(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IAcrylicBrush2> : produce_base<D, Windows::UI::Xaml::Media::IAcrylicBrush2>
{
    int32_t WINRT_CALL get_TintLuminosityOpacity(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TintLuminosityOpacity, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().TintLuminosityOpacity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TintLuminosityOpacity(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TintLuminosityOpacity, WINRT_WRAP(void), Windows::Foundation::IReference<double> const&);
            this->shim().TintLuminosityOpacity(*reinterpret_cast<Windows::Foundation::IReference<double> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IAcrylicBrushFactory> : produce_base<D, Windows::UI::Xaml::Media::IAcrylicBrushFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Media::AcrylicBrush), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Media::AcrylicBrush>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IAcrylicBrushStatics> : produce_base<D, Windows::UI::Xaml::Media::IAcrylicBrushStatics>
{
    int32_t WINRT_CALL get_BackgroundSourceProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackgroundSourceProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().BackgroundSourceProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TintColorProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TintColorProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TintColorProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TintOpacityProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TintOpacityProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TintOpacityProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TintTransitionDurationProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TintTransitionDurationProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TintTransitionDurationProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AlwaysUseFallbackProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlwaysUseFallbackProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().AlwaysUseFallbackProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IAcrylicBrushStatics2> : produce_base<D, Windows::UI::Xaml::Media::IAcrylicBrushStatics2>
{
    int32_t WINRT_CALL get_TintLuminosityOpacityProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TintLuminosityOpacityProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TintLuminosityOpacityProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IArcSegment> : produce_base<D, Windows::UI::Xaml::Media::IArcSegment>
{
    int32_t WINRT_CALL get_Point(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Point, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Point());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Point(Windows::Foundation::Point value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Point, WINRT_WRAP(void), Windows::Foundation::Point const&);
            this->shim().Point(*reinterpret_cast<Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Size(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Size, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().Size());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Size(Windows::Foundation::Size value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Size, WINRT_WRAP(void), Windows::Foundation::Size const&);
            this->shim().Size(*reinterpret_cast<Windows::Foundation::Size const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RotationAngle(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RotationAngle, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().RotationAngle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RotationAngle(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RotationAngle, WINRT_WRAP(void), double);
            this->shim().RotationAngle(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsLargeArc(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsLargeArc, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsLargeArc());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsLargeArc(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsLargeArc, WINRT_WRAP(void), bool);
            this->shim().IsLargeArc(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SweepDirection(Windows::UI::Xaml::Media::SweepDirection* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SweepDirection, WINRT_WRAP(Windows::UI::Xaml::Media::SweepDirection));
            *value = detach_from<Windows::UI::Xaml::Media::SweepDirection>(this->shim().SweepDirection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SweepDirection(Windows::UI::Xaml::Media::SweepDirection value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SweepDirection, WINRT_WRAP(void), Windows::UI::Xaml::Media::SweepDirection const&);
            this->shim().SweepDirection(*reinterpret_cast<Windows::UI::Xaml::Media::SweepDirection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IArcSegmentStatics> : produce_base<D, Windows::UI::Xaml::Media::IArcSegmentStatics>
{
    int32_t WINRT_CALL get_PointProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().PointProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SizeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SizeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().SizeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RotationAngleProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RotationAngleProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().RotationAngleProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsLargeArcProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsLargeArcProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsLargeArcProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SweepDirectionProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SweepDirectionProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().SweepDirectionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IBezierSegment> : produce_base<D, Windows::UI::Xaml::Media::IBezierSegment>
{
    int32_t WINRT_CALL get_Point1(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Point1, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Point1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Point1(Windows::Foundation::Point value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Point1, WINRT_WRAP(void), Windows::Foundation::Point const&);
            this->shim().Point1(*reinterpret_cast<Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Point2(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Point2, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Point2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Point2(Windows::Foundation::Point value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Point2, WINRT_WRAP(void), Windows::Foundation::Point const&);
            this->shim().Point2(*reinterpret_cast<Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Point3(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Point3, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Point3());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Point3(Windows::Foundation::Point value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Point3, WINRT_WRAP(void), Windows::Foundation::Point const&);
            this->shim().Point3(*reinterpret_cast<Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IBezierSegmentStatics> : produce_base<D, Windows::UI::Xaml::Media::IBezierSegmentStatics>
{
    int32_t WINRT_CALL get_Point1Property(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Point1Property, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().Point1Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Point2Property(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Point2Property, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().Point2Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Point3Property(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Point3Property, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().Point3Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IBitmapCache> : produce_base<D, Windows::UI::Xaml::Media::IBitmapCache>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IBrush> : produce_base<D, Windows::UI::Xaml::Media::IBrush>
{
    int32_t WINRT_CALL get_Opacity(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Opacity, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Opacity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Opacity(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Opacity, WINRT_WRAP(void), double);
            this->shim().Opacity(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Transform(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Transform, WINRT_WRAP(Windows::UI::Xaml::Media::Transform));
            *value = detach_from<Windows::UI::Xaml::Media::Transform>(this->shim().Transform());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Transform(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Transform, WINRT_WRAP(void), Windows::UI::Xaml::Media::Transform const&);
            this->shim().Transform(*reinterpret_cast<Windows::UI::Xaml::Media::Transform const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RelativeTransform(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RelativeTransform, WINRT_WRAP(Windows::UI::Xaml::Media::Transform));
            *value = detach_from<Windows::UI::Xaml::Media::Transform>(this->shim().RelativeTransform());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RelativeTransform(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RelativeTransform, WINRT_WRAP(void), Windows::UI::Xaml::Media::Transform const&);
            this->shim().RelativeTransform(*reinterpret_cast<Windows::UI::Xaml::Media::Transform const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IBrushFactory> : produce_base<D, Windows::UI::Xaml::Media::IBrushFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Media::Brush), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IBrushOverrides2> : produce_base<D, Windows::UI::Xaml::Media::IBrushOverrides2>
{
    int32_t WINRT_CALL PopulatePropertyInfoOverride(void* propertyName, void* animationPropertyInfo) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PopulatePropertyInfoOverride, WINRT_WRAP(void), hstring const&, Windows::UI::Composition::AnimationPropertyInfo const&);
            this->shim().PopulatePropertyInfoOverride(*reinterpret_cast<hstring const*>(&propertyName), *reinterpret_cast<Windows::UI::Composition::AnimationPropertyInfo const*>(&animationPropertyInfo));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IBrushStatics> : produce_base<D, Windows::UI::Xaml::Media::IBrushStatics>
{
    int32_t WINRT_CALL get_OpacityProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpacityProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().OpacityProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransformProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransformProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TransformProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RelativeTransformProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RelativeTransformProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().RelativeTransformProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::ICacheMode> : produce_base<D, Windows::UI::Xaml::Media::ICacheMode>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::ICacheModeFactory> : produce_base<D, Windows::UI::Xaml::Media::ICacheModeFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Media::CacheMode), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Media::CacheMode>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::ICompositeTransform> : produce_base<D, Windows::UI::Xaml::Media::ICompositeTransform>
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

    int32_t WINRT_CALL get_SkewX(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SkewX, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().SkewX());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SkewX(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SkewX, WINRT_WRAP(void), double);
            this->shim().SkewX(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SkewY(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SkewY, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().SkewY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SkewY(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SkewY, WINRT_WRAP(void), double);
            this->shim().SkewY(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Rotation(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rotation, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Rotation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Rotation(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rotation, WINRT_WRAP(void), double);
            this->shim().Rotation(value);
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
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::ICompositeTransformStatics> : produce_base<D, Windows::UI::Xaml::Media::ICompositeTransformStatics>
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

    int32_t WINRT_CALL get_SkewXProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SkewXProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().SkewXProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SkewYProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SkewYProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().SkewYProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RotationProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RotationProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().RotationProperty());
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
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::ICompositionTarget> : produce_base<D, Windows::UI::Xaml::Media::ICompositionTarget>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::ICompositionTargetStatics> : produce_base<D, Windows::UI::Xaml::Media::ICompositionTargetStatics>
{
    int32_t WINRT_CALL add_Rendering(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rendering, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Rendering(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Rendering(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Rendering, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Rendering(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_SurfaceContentsLost(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SurfaceContentsLost, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().SurfaceContentsLost(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SurfaceContentsLost(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SurfaceContentsLost, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SurfaceContentsLost(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::ICompositionTargetStatics3> : produce_base<D, Windows::UI::Xaml::Media::ICompositionTargetStatics3>
{
    int32_t WINRT_CALL add_Rendered(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rendered, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::UI::Xaml::Media::RenderedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Rendered(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::UI::Xaml::Media::RenderedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Rendered(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Rendered, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Rendered(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IEllipseGeometry> : produce_base<D, Windows::UI::Xaml::Media::IEllipseGeometry>
{
    int32_t WINRT_CALL get_Center(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Center, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Center());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Center(Windows::Foundation::Point value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Center, WINRT_WRAP(void), Windows::Foundation::Point const&);
            this->shim().Center(*reinterpret_cast<Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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
struct produce<D, Windows::UI::Xaml::Media::IEllipseGeometryStatics> : produce_base<D, Windows::UI::Xaml::Media::IEllipseGeometryStatics>
{
    int32_t WINRT_CALL get_CenterProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CenterProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CenterProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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
struct produce<D, Windows::UI::Xaml::Media::IFontFamily> : produce_base<D, Windows::UI::Xaml::Media::IFontFamily>
{
    int32_t WINRT_CALL get_Source(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Source, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Source());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IFontFamilyFactory> : produce_base<D, Windows::UI::Xaml::Media::IFontFamilyFactory>
{
    int32_t WINRT_CALL CreateInstanceWithName(void* familyName, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithName, WINRT_WRAP(Windows::UI::Xaml::Media::FontFamily), hstring const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Media::FontFamily>(this->shim().CreateInstanceWithName(*reinterpret_cast<hstring const*>(&familyName), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IFontFamilyStatics2> : produce_base<D, Windows::UI::Xaml::Media::IFontFamilyStatics2>
{
    int32_t WINRT_CALL get_XamlAutoFontFamily(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XamlAutoFontFamily, WINRT_WRAP(Windows::UI::Xaml::Media::FontFamily));
            *value = detach_from<Windows::UI::Xaml::Media::FontFamily>(this->shim().XamlAutoFontFamily());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IGeneralTransform> : produce_base<D, Windows::UI::Xaml::Media::IGeneralTransform>
{
    int32_t WINRT_CALL get_Inverse(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Inverse, WINRT_WRAP(Windows::UI::Xaml::Media::GeneralTransform));
            *value = detach_from<Windows::UI::Xaml::Media::GeneralTransform>(this->shim().Inverse());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TransformPoint(Windows::Foundation::Point point, Windows::Foundation::Point* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransformPoint, WINRT_WRAP(Windows::Foundation::Point), Windows::Foundation::Point const&);
            *result = detach_from<Windows::Foundation::Point>(this->shim().TransformPoint(*reinterpret_cast<Windows::Foundation::Point const*>(&point)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryTransform(Windows::Foundation::Point inPoint, Windows::Foundation::Point* outPoint, bool* returnValue) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryTransform, WINRT_WRAP(bool), Windows::Foundation::Point const&, Windows::Foundation::Point&);
            *returnValue = detach_from<bool>(this->shim().TryTransform(*reinterpret_cast<Windows::Foundation::Point const*>(&inPoint), *reinterpret_cast<Windows::Foundation::Point*>(outPoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TransformBounds(Windows::Foundation::Rect rect, Windows::Foundation::Rect* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransformBounds, WINRT_WRAP(Windows::Foundation::Rect), Windows::Foundation::Rect const&);
            *result = detach_from<Windows::Foundation::Rect>(this->shim().TransformBounds(*reinterpret_cast<Windows::Foundation::Rect const*>(&rect)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IGeneralTransformFactory> : produce_base<D, Windows::UI::Xaml::Media::IGeneralTransformFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Media::GeneralTransform), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Media::GeneralTransform>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IGeneralTransformOverrides> : produce_base<D, Windows::UI::Xaml::Media::IGeneralTransformOverrides>
{
    int32_t WINRT_CALL get_InverseCore(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InverseCore, WINRT_WRAP(Windows::UI::Xaml::Media::GeneralTransform));
            *value = detach_from<Windows::UI::Xaml::Media::GeneralTransform>(this->shim().InverseCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryTransformCore(Windows::Foundation::Point inPoint, Windows::Foundation::Point* outPoint, bool* returnValue) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryTransformCore, WINRT_WRAP(bool), Windows::Foundation::Point const&, Windows::Foundation::Point&);
            *returnValue = detach_from<bool>(this->shim().TryTransformCore(*reinterpret_cast<Windows::Foundation::Point const*>(&inPoint), *reinterpret_cast<Windows::Foundation::Point*>(outPoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TransformBoundsCore(Windows::Foundation::Rect rect, Windows::Foundation::Rect* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransformBoundsCore, WINRT_WRAP(Windows::Foundation::Rect), Windows::Foundation::Rect const&);
            *result = detach_from<Windows::Foundation::Rect>(this->shim().TransformBoundsCore(*reinterpret_cast<Windows::Foundation::Rect const*>(&rect)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IGeometry> : produce_base<D, Windows::UI::Xaml::Media::IGeometry>
{
    int32_t WINRT_CALL get_Transform(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Transform, WINRT_WRAP(Windows::UI::Xaml::Media::Transform));
            *value = detach_from<Windows::UI::Xaml::Media::Transform>(this->shim().Transform());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Transform(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Transform, WINRT_WRAP(void), Windows::UI::Xaml::Media::Transform const&);
            this->shim().Transform(*reinterpret_cast<Windows::UI::Xaml::Media::Transform const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Bounds(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bounds, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().Bounds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IGeometryFactory> : produce_base<D, Windows::UI::Xaml::Media::IGeometryFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IGeometryGroup> : produce_base<D, Windows::UI::Xaml::Media::IGeometryGroup>
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

    int32_t WINRT_CALL get_Children(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Children, WINRT_WRAP(Windows::UI::Xaml::Media::GeometryCollection));
            *value = detach_from<Windows::UI::Xaml::Media::GeometryCollection>(this->shim().Children());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Children(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Children, WINRT_WRAP(void), Windows::UI::Xaml::Media::GeometryCollection const&);
            this->shim().Children(*reinterpret_cast<Windows::UI::Xaml::Media::GeometryCollection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IGeometryGroupStatics> : produce_base<D, Windows::UI::Xaml::Media::IGeometryGroupStatics>
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

    int32_t WINRT_CALL get_ChildrenProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChildrenProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ChildrenProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IGeometryStatics> : produce_base<D, Windows::UI::Xaml::Media::IGeometryStatics>
{
    int32_t WINRT_CALL get_Empty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Empty, WINRT_WRAP(Windows::UI::Xaml::Media::Geometry));
            *value = detach_from<Windows::UI::Xaml::Media::Geometry>(this->shim().Empty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StandardFlatteningTolerance(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StandardFlatteningTolerance, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().StandardFlatteningTolerance());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransformProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransformProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TransformProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IGradientBrush> : produce_base<D, Windows::UI::Xaml::Media::IGradientBrush>
{
    int32_t WINRT_CALL get_SpreadMethod(Windows::UI::Xaml::Media::GradientSpreadMethod* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SpreadMethod, WINRT_WRAP(Windows::UI::Xaml::Media::GradientSpreadMethod));
            *value = detach_from<Windows::UI::Xaml::Media::GradientSpreadMethod>(this->shim().SpreadMethod());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SpreadMethod(Windows::UI::Xaml::Media::GradientSpreadMethod value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SpreadMethod, WINRT_WRAP(void), Windows::UI::Xaml::Media::GradientSpreadMethod const&);
            this->shim().SpreadMethod(*reinterpret_cast<Windows::UI::Xaml::Media::GradientSpreadMethod const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MappingMode(Windows::UI::Xaml::Media::BrushMappingMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MappingMode, WINRT_WRAP(Windows::UI::Xaml::Media::BrushMappingMode));
            *value = detach_from<Windows::UI::Xaml::Media::BrushMappingMode>(this->shim().MappingMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MappingMode(Windows::UI::Xaml::Media::BrushMappingMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MappingMode, WINRT_WRAP(void), Windows::UI::Xaml::Media::BrushMappingMode const&);
            this->shim().MappingMode(*reinterpret_cast<Windows::UI::Xaml::Media::BrushMappingMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ColorInterpolationMode(Windows::UI::Xaml::Media::ColorInterpolationMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColorInterpolationMode, WINRT_WRAP(Windows::UI::Xaml::Media::ColorInterpolationMode));
            *value = detach_from<Windows::UI::Xaml::Media::ColorInterpolationMode>(this->shim().ColorInterpolationMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ColorInterpolationMode(Windows::UI::Xaml::Media::ColorInterpolationMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColorInterpolationMode, WINRT_WRAP(void), Windows::UI::Xaml::Media::ColorInterpolationMode const&);
            this->shim().ColorInterpolationMode(*reinterpret_cast<Windows::UI::Xaml::Media::ColorInterpolationMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GradientStops(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GradientStops, WINRT_WRAP(Windows::UI::Xaml::Media::GradientStopCollection));
            *value = detach_from<Windows::UI::Xaml::Media::GradientStopCollection>(this->shim().GradientStops());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_GradientStops(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GradientStops, WINRT_WRAP(void), Windows::UI::Xaml::Media::GradientStopCollection const&);
            this->shim().GradientStops(*reinterpret_cast<Windows::UI::Xaml::Media::GradientStopCollection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IGradientBrushFactory> : produce_base<D, Windows::UI::Xaml::Media::IGradientBrushFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Media::GradientBrush), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Media::GradientBrush>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IGradientBrushStatics> : produce_base<D, Windows::UI::Xaml::Media::IGradientBrushStatics>
{
    int32_t WINRT_CALL get_SpreadMethodProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SpreadMethodProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().SpreadMethodProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MappingModeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MappingModeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().MappingModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ColorInterpolationModeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColorInterpolationModeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ColorInterpolationModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GradientStopsProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GradientStopsProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().GradientStopsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IGradientStop> : produce_base<D, Windows::UI::Xaml::Media::IGradientStop>
{
    int32_t WINRT_CALL get_Color(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Color, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Color());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Color(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Color, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().Color(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Offset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Offset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Offset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Offset(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Offset, WINRT_WRAP(void), double);
            this->shim().Offset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IGradientStopStatics> : produce_base<D, Windows::UI::Xaml::Media::IGradientStopStatics>
{
    int32_t WINRT_CALL get_ColorProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColorProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ColorProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OffsetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OffsetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().OffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IImageBrush> : produce_base<D, Windows::UI::Xaml::Media::IImageBrush>
{
    int32_t WINRT_CALL get_ImageSource(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImageSource, WINRT_WRAP(Windows::UI::Xaml::Media::ImageSource));
            *value = detach_from<Windows::UI::Xaml::Media::ImageSource>(this->shim().ImageSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ImageSource(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImageSource, WINRT_WRAP(void), Windows::UI::Xaml::Media::ImageSource const&);
            this->shim().ImageSource(*reinterpret_cast<Windows::UI::Xaml::Media::ImageSource const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ImageFailed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImageFailed, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::ExceptionRoutedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().ImageFailed(*reinterpret_cast<Windows::UI::Xaml::ExceptionRoutedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ImageFailed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ImageFailed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ImageFailed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ImageOpened(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImageOpened, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::RoutedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().ImageOpened(*reinterpret_cast<Windows::UI::Xaml::RoutedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ImageOpened(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ImageOpened, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ImageOpened(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IImageBrushStatics> : produce_base<D, Windows::UI::Xaml::Media::IImageBrushStatics>
{
    int32_t WINRT_CALL get_ImageSourceProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImageSourceProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ImageSourceProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IImageSource> : produce_base<D, Windows::UI::Xaml::Media::IImageSource>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IImageSourceFactory> : produce_base<D, Windows::UI::Xaml::Media::IImageSourceFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::ILineGeometry> : produce_base<D, Windows::UI::Xaml::Media::ILineGeometry>
{
    int32_t WINRT_CALL get_StartPoint(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartPoint, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().StartPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StartPoint(Windows::Foundation::Point value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartPoint, WINRT_WRAP(void), Windows::Foundation::Point const&);
            this->shim().StartPoint(*reinterpret_cast<Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EndPoint(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndPoint, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().EndPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EndPoint(Windows::Foundation::Point value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndPoint, WINRT_WRAP(void), Windows::Foundation::Point const&);
            this->shim().EndPoint(*reinterpret_cast<Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::ILineGeometryStatics> : produce_base<D, Windows::UI::Xaml::Media::ILineGeometryStatics>
{
    int32_t WINRT_CALL get_StartPointProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartPointProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StartPointProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EndPointProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndPointProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().EndPointProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::ILineSegment> : produce_base<D, Windows::UI::Xaml::Media::ILineSegment>
{
    int32_t WINRT_CALL get_Point(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Point, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Point());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Point(Windows::Foundation::Point value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Point, WINRT_WRAP(void), Windows::Foundation::Point const&);
            this->shim().Point(*reinterpret_cast<Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::ILineSegmentStatics> : produce_base<D, Windows::UI::Xaml::Media::ILineSegmentStatics>
{
    int32_t WINRT_CALL get_PointProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().PointProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::ILinearGradientBrush> : produce_base<D, Windows::UI::Xaml::Media::ILinearGradientBrush>
{
    int32_t WINRT_CALL get_StartPoint(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartPoint, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().StartPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StartPoint(Windows::Foundation::Point value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartPoint, WINRT_WRAP(void), Windows::Foundation::Point const&);
            this->shim().StartPoint(*reinterpret_cast<Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EndPoint(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndPoint, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().EndPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EndPoint(Windows::Foundation::Point value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndPoint, WINRT_WRAP(void), Windows::Foundation::Point const&);
            this->shim().EndPoint(*reinterpret_cast<Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::ILinearGradientBrushFactory> : produce_base<D, Windows::UI::Xaml::Media::ILinearGradientBrushFactory>
{
    int32_t WINRT_CALL CreateInstanceWithGradientStopCollectionAndAngle(void* gradientStopCollection, double angle, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstanceWithGradientStopCollectionAndAngle, WINRT_WRAP(Windows::UI::Xaml::Media::LinearGradientBrush), Windows::UI::Xaml::Media::GradientStopCollection const&, double);
            *value = detach_from<Windows::UI::Xaml::Media::LinearGradientBrush>(this->shim().CreateInstanceWithGradientStopCollectionAndAngle(*reinterpret_cast<Windows::UI::Xaml::Media::GradientStopCollection const*>(&gradientStopCollection), angle));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::ILinearGradientBrushStatics> : produce_base<D, Windows::UI::Xaml::Media::ILinearGradientBrushStatics>
{
    int32_t WINRT_CALL get_StartPointProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartPointProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StartPointProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EndPointProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndPointProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().EndPointProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::ILoadedImageSourceLoadCompletedEventArgs> : produce_base<D, Windows::UI::Xaml::Media::ILoadedImageSourceLoadCompletedEventArgs>
{
    int32_t WINRT_CALL get_Status(Windows::UI::Xaml::Media::LoadedImageSourceLoadStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::UI::Xaml::Media::LoadedImageSourceLoadStatus));
            *value = detach_from<Windows::UI::Xaml::Media::LoadedImageSourceLoadStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::ILoadedImageSurface> : produce_base<D, Windows::UI::Xaml::Media::ILoadedImageSurface>
{
    int32_t WINRT_CALL get_DecodedPhysicalSize(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DecodedPhysicalSize, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().DecodedPhysicalSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DecodedSize(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DecodedSize, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().DecodedSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NaturalSize(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NaturalSize, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().NaturalSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_LoadCompleted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Media::LoadedImageSurface, Windows::UI::Xaml::Media::LoadedImageSourceLoadCompletedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().LoadCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Media::LoadedImageSurface, Windows::UI::Xaml::Media::LoadedImageSourceLoadCompletedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_LoadCompleted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(LoadCompleted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().LoadCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::ILoadedImageSurfaceStatics> : produce_base<D, Windows::UI::Xaml::Media::ILoadedImageSurfaceStatics>
{
    int32_t WINRT_CALL StartLoadFromUriWithSize(void* uri, Windows::Foundation::Size desiredMaxSize, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartLoadFromUri, WINRT_WRAP(Windows::UI::Xaml::Media::LoadedImageSurface), Windows::Foundation::Uri const&, Windows::Foundation::Size const&);
            *result = detach_from<Windows::UI::Xaml::Media::LoadedImageSurface>(this->shim().StartLoadFromUri(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<Windows::Foundation::Size const*>(&desiredMaxSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartLoadFromUri(void* uri, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartLoadFromUri, WINRT_WRAP(Windows::UI::Xaml::Media::LoadedImageSurface), Windows::Foundation::Uri const&);
            *result = detach_from<Windows::UI::Xaml::Media::LoadedImageSurface>(this->shim().StartLoadFromUri(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartLoadFromStreamWithSize(void* stream, Windows::Foundation::Size desiredMaxSize, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartLoadFromStream, WINRT_WRAP(Windows::UI::Xaml::Media::LoadedImageSurface), Windows::Storage::Streams::IRandomAccessStream const&, Windows::Foundation::Size const&);
            *result = detach_from<Windows::UI::Xaml::Media::LoadedImageSurface>(this->shim().StartLoadFromStream(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&stream), *reinterpret_cast<Windows::Foundation::Size const*>(&desiredMaxSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartLoadFromStream(void* stream, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartLoadFromStream, WINRT_WRAP(Windows::UI::Xaml::Media::LoadedImageSurface), Windows::Storage::Streams::IRandomAccessStream const&);
            *result = detach_from<Windows::UI::Xaml::Media::LoadedImageSurface>(this->shim().StartLoadFromStream(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&stream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IMatrix3DProjection> : produce_base<D, Windows::UI::Xaml::Media::IMatrix3DProjection>
{
    int32_t WINRT_CALL get_ProjectionMatrix(struct struct_Windows_UI_Xaml_Media_Media3D_Matrix3D* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProjectionMatrix, WINRT_WRAP(Windows::UI::Xaml::Media::Media3D::Matrix3D));
            *value = detach_from<Windows::UI::Xaml::Media::Media3D::Matrix3D>(this->shim().ProjectionMatrix());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ProjectionMatrix(struct struct_Windows_UI_Xaml_Media_Media3D_Matrix3D value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProjectionMatrix, WINRT_WRAP(void), Windows::UI::Xaml::Media::Media3D::Matrix3D const&);
            this->shim().ProjectionMatrix(*reinterpret_cast<Windows::UI::Xaml::Media::Media3D::Matrix3D const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IMatrix3DProjectionStatics> : produce_base<D, Windows::UI::Xaml::Media::IMatrix3DProjectionStatics>
{
    int32_t WINRT_CALL get_ProjectionMatrixProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProjectionMatrixProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ProjectionMatrixProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IMatrixHelper> : produce_base<D, Windows::UI::Xaml::Media::IMatrixHelper>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IMatrixHelperStatics> : produce_base<D, Windows::UI::Xaml::Media::IMatrixHelperStatics>
{
    int32_t WINRT_CALL get_Identity(struct struct_Windows_UI_Xaml_Media_Matrix* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Identity, WINRT_WRAP(Windows::UI::Xaml::Media::Matrix));
            *value = detach_from<Windows::UI::Xaml::Media::Matrix>(this->shim().Identity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromElements(double m11, double m12, double m21, double m22, double offsetX, double offsetY, struct struct_Windows_UI_Xaml_Media_Matrix* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromElements, WINRT_WRAP(Windows::UI::Xaml::Media::Matrix), double, double, double, double, double, double);
            *result = detach_from<Windows::UI::Xaml::Media::Matrix>(this->shim().FromElements(m11, m12, m21, m22, offsetX, offsetY));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIsIdentity(struct struct_Windows_UI_Xaml_Media_Matrix target, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIsIdentity, WINRT_WRAP(bool), Windows::UI::Xaml::Media::Matrix const&);
            *result = detach_from<bool>(this->shim().GetIsIdentity(*reinterpret_cast<Windows::UI::Xaml::Media::Matrix const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Transform(struct struct_Windows_UI_Xaml_Media_Matrix target, Windows::Foundation::Point point, Windows::Foundation::Point* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Transform, WINRT_WRAP(Windows::Foundation::Point), Windows::UI::Xaml::Media::Matrix const&, Windows::Foundation::Point const&);
            *result = detach_from<Windows::Foundation::Point>(this->shim().Transform(*reinterpret_cast<Windows::UI::Xaml::Media::Matrix const*>(&target), *reinterpret_cast<Windows::Foundation::Point const*>(&point)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IMatrixTransform> : produce_base<D, Windows::UI::Xaml::Media::IMatrixTransform>
{
    int32_t WINRT_CALL get_Matrix(struct struct_Windows_UI_Xaml_Media_Matrix* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Matrix, WINRT_WRAP(Windows::UI::Xaml::Media::Matrix));
            *value = detach_from<Windows::UI::Xaml::Media::Matrix>(this->shim().Matrix());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Matrix(struct struct_Windows_UI_Xaml_Media_Matrix value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Matrix, WINRT_WRAP(void), Windows::UI::Xaml::Media::Matrix const&);
            this->shim().Matrix(*reinterpret_cast<Windows::UI::Xaml::Media::Matrix const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IMatrixTransformStatics> : produce_base<D, Windows::UI::Xaml::Media::IMatrixTransformStatics>
{
    int32_t WINRT_CALL get_MatrixProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MatrixProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().MatrixProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IMediaTransportControlsThumbnailRequestedEventArgs> : produce_base<D, Windows::UI::Xaml::Media::IMediaTransportControlsThumbnailRequestedEventArgs>
{
    int32_t WINRT_CALL SetThumbnailImage(void* source) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetThumbnailImage, WINRT_WRAP(void), Windows::Storage::Streams::IInputStream const&);
            this->shim().SetThumbnailImage(*reinterpret_cast<Windows::Storage::Streams::IInputStream const*>(&source));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeferral(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Foundation::Deferral));
            *result = detach_from<Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IPartialMediaFailureDetectedEventArgs> : produce_base<D, Windows::UI::Xaml::Media::IPartialMediaFailureDetectedEventArgs>
{
    int32_t WINRT_CALL get_StreamKind(Windows::Media::Playback::FailedMediaStreamKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StreamKind, WINRT_WRAP(Windows::Media::Playback::FailedMediaStreamKind));
            *value = detach_from<Windows::Media::Playback::FailedMediaStreamKind>(this->shim().StreamKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IPartialMediaFailureDetectedEventArgs2> : produce_base<D, Windows::UI::Xaml::Media::IPartialMediaFailureDetectedEventArgs2>
{
    int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedError, WINRT_WRAP(winrt::hresult));
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IPathFigure> : produce_base<D, Windows::UI::Xaml::Media::IPathFigure>
{
    int32_t WINRT_CALL get_Segments(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Segments, WINRT_WRAP(Windows::UI::Xaml::Media::PathSegmentCollection));
            *value = detach_from<Windows::UI::Xaml::Media::PathSegmentCollection>(this->shim().Segments());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Segments(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Segments, WINRT_WRAP(void), Windows::UI::Xaml::Media::PathSegmentCollection const&);
            this->shim().Segments(*reinterpret_cast<Windows::UI::Xaml::Media::PathSegmentCollection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StartPoint(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartPoint, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().StartPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StartPoint(Windows::Foundation::Point value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartPoint, WINRT_WRAP(void), Windows::Foundation::Point const&);
            this->shim().StartPoint(*reinterpret_cast<Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsClosed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsClosed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsClosed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsClosed(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsClosed, WINRT_WRAP(void), bool);
            this->shim().IsClosed(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsFilled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsFilled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsFilled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsFilled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsFilled, WINRT_WRAP(void), bool);
            this->shim().IsFilled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IPathFigureStatics> : produce_base<D, Windows::UI::Xaml::Media::IPathFigureStatics>
{
    int32_t WINRT_CALL get_SegmentsProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SegmentsProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().SegmentsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StartPointProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartPointProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StartPointProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsClosedProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsClosedProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsClosedProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsFilledProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsFilledProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsFilledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IPathGeometry> : produce_base<D, Windows::UI::Xaml::Media::IPathGeometry>
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

    int32_t WINRT_CALL get_Figures(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Figures, WINRT_WRAP(Windows::UI::Xaml::Media::PathFigureCollection));
            *value = detach_from<Windows::UI::Xaml::Media::PathFigureCollection>(this->shim().Figures());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Figures(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Figures, WINRT_WRAP(void), Windows::UI::Xaml::Media::PathFigureCollection const&);
            this->shim().Figures(*reinterpret_cast<Windows::UI::Xaml::Media::PathFigureCollection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IPathGeometryStatics> : produce_base<D, Windows::UI::Xaml::Media::IPathGeometryStatics>
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

    int32_t WINRT_CALL get_FiguresProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FiguresProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FiguresProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IPathSegment> : produce_base<D, Windows::UI::Xaml::Media::IPathSegment>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IPathSegmentFactory> : produce_base<D, Windows::UI::Xaml::Media::IPathSegmentFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IPlaneProjection> : produce_base<D, Windows::UI::Xaml::Media::IPlaneProjection>
{
    int32_t WINRT_CALL get_LocalOffsetX(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalOffsetX, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().LocalOffsetX());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LocalOffsetX(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalOffsetX, WINRT_WRAP(void), double);
            this->shim().LocalOffsetX(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LocalOffsetY(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalOffsetY, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().LocalOffsetY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LocalOffsetY(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalOffsetY, WINRT_WRAP(void), double);
            this->shim().LocalOffsetY(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LocalOffsetZ(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalOffsetZ, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().LocalOffsetZ());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LocalOffsetZ(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalOffsetZ, WINRT_WRAP(void), double);
            this->shim().LocalOffsetZ(value);
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

    int32_t WINRT_CALL get_CenterOfRotationX(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CenterOfRotationX, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().CenterOfRotationX());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CenterOfRotationX(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CenterOfRotationX, WINRT_WRAP(void), double);
            this->shim().CenterOfRotationX(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CenterOfRotationY(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CenterOfRotationY, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().CenterOfRotationY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CenterOfRotationY(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CenterOfRotationY, WINRT_WRAP(void), double);
            this->shim().CenterOfRotationY(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CenterOfRotationZ(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CenterOfRotationZ, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().CenterOfRotationZ());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CenterOfRotationZ(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CenterOfRotationZ, WINRT_WRAP(void), double);
            this->shim().CenterOfRotationZ(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GlobalOffsetX(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GlobalOffsetX, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().GlobalOffsetX());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_GlobalOffsetX(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GlobalOffsetX, WINRT_WRAP(void), double);
            this->shim().GlobalOffsetX(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GlobalOffsetY(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GlobalOffsetY, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().GlobalOffsetY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_GlobalOffsetY(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GlobalOffsetY, WINRT_WRAP(void), double);
            this->shim().GlobalOffsetY(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GlobalOffsetZ(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GlobalOffsetZ, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().GlobalOffsetZ());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_GlobalOffsetZ(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GlobalOffsetZ, WINRT_WRAP(void), double);
            this->shim().GlobalOffsetZ(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProjectionMatrix(struct struct_Windows_UI_Xaml_Media_Media3D_Matrix3D* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProjectionMatrix, WINRT_WRAP(Windows::UI::Xaml::Media::Media3D::Matrix3D));
            *value = detach_from<Windows::UI::Xaml::Media::Media3D::Matrix3D>(this->shim().ProjectionMatrix());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IPlaneProjectionStatics> : produce_base<D, Windows::UI::Xaml::Media::IPlaneProjectionStatics>
{
    int32_t WINRT_CALL get_LocalOffsetXProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalOffsetXProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().LocalOffsetXProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LocalOffsetYProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalOffsetYProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().LocalOffsetYProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LocalOffsetZProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalOffsetZProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().LocalOffsetZProperty());
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

    int32_t WINRT_CALL get_CenterOfRotationXProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CenterOfRotationXProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CenterOfRotationXProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CenterOfRotationYProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CenterOfRotationYProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CenterOfRotationYProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CenterOfRotationZProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CenterOfRotationZProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CenterOfRotationZProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GlobalOffsetXProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GlobalOffsetXProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().GlobalOffsetXProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GlobalOffsetYProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GlobalOffsetYProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().GlobalOffsetYProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GlobalOffsetZProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GlobalOffsetZProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().GlobalOffsetZProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProjectionMatrixProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProjectionMatrixProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ProjectionMatrixProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IPolyBezierSegment> : produce_base<D, Windows::UI::Xaml::Media::IPolyBezierSegment>
{
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
struct produce<D, Windows::UI::Xaml::Media::IPolyBezierSegmentStatics> : produce_base<D, Windows::UI::Xaml::Media::IPolyBezierSegmentStatics>
{
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
struct produce<D, Windows::UI::Xaml::Media::IPolyLineSegment> : produce_base<D, Windows::UI::Xaml::Media::IPolyLineSegment>
{
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
struct produce<D, Windows::UI::Xaml::Media::IPolyLineSegmentStatics> : produce_base<D, Windows::UI::Xaml::Media::IPolyLineSegmentStatics>
{
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
struct produce<D, Windows::UI::Xaml::Media::IPolyQuadraticBezierSegment> : produce_base<D, Windows::UI::Xaml::Media::IPolyQuadraticBezierSegment>
{
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
struct produce<D, Windows::UI::Xaml::Media::IPolyQuadraticBezierSegmentStatics> : produce_base<D, Windows::UI::Xaml::Media::IPolyQuadraticBezierSegmentStatics>
{
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
struct produce<D, Windows::UI::Xaml::Media::IProjection> : produce_base<D, Windows::UI::Xaml::Media::IProjection>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IProjectionFactory> : produce_base<D, Windows::UI::Xaml::Media::IProjectionFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Media::Projection), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Media::Projection>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IQuadraticBezierSegment> : produce_base<D, Windows::UI::Xaml::Media::IQuadraticBezierSegment>
{
    int32_t WINRT_CALL get_Point1(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Point1, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Point1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Point1(Windows::Foundation::Point value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Point1, WINRT_WRAP(void), Windows::Foundation::Point const&);
            this->shim().Point1(*reinterpret_cast<Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Point2(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Point2, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Point2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Point2(Windows::Foundation::Point value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Point2, WINRT_WRAP(void), Windows::Foundation::Point const&);
            this->shim().Point2(*reinterpret_cast<Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IQuadraticBezierSegmentStatics> : produce_base<D, Windows::UI::Xaml::Media::IQuadraticBezierSegmentStatics>
{
    int32_t WINRT_CALL get_Point1Property(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Point1Property, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().Point1Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Point2Property(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Point2Property, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().Point2Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IRateChangedRoutedEventArgs> : produce_base<D, Windows::UI::Xaml::Media::IRateChangedRoutedEventArgs>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IRectangleGeometry> : produce_base<D, Windows::UI::Xaml::Media::IRectangleGeometry>
{
    int32_t WINRT_CALL get_Rect(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rect, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().Rect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Rect(Windows::Foundation::Rect value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rect, WINRT_WRAP(void), Windows::Foundation::Rect const&);
            this->shim().Rect(*reinterpret_cast<Windows::Foundation::Rect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IRectangleGeometryStatics> : produce_base<D, Windows::UI::Xaml::Media::IRectangleGeometryStatics>
{
    int32_t WINRT_CALL get_RectProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RectProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().RectProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IRenderedEventArgs> : produce_base<D, Windows::UI::Xaml::Media::IRenderedEventArgs>
{
    int32_t WINRT_CALL get_FrameDuration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameDuration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().FrameDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IRenderingEventArgs> : produce_base<D, Windows::UI::Xaml::Media::IRenderingEventArgs>
{
    int32_t WINRT_CALL get_RenderingTime(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RenderingTime, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().RenderingTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IRevealBackgroundBrush> : produce_base<D, Windows::UI::Xaml::Media::IRevealBackgroundBrush>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IRevealBackgroundBrushFactory> : produce_base<D, Windows::UI::Xaml::Media::IRevealBackgroundBrushFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Media::RevealBackgroundBrush), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Media::RevealBackgroundBrush>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IRevealBorderBrush> : produce_base<D, Windows::UI::Xaml::Media::IRevealBorderBrush>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IRevealBorderBrushFactory> : produce_base<D, Windows::UI::Xaml::Media::IRevealBorderBrushFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Media::RevealBorderBrush), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Media::RevealBorderBrush>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IRevealBrush> : produce_base<D, Windows::UI::Xaml::Media::IRevealBrush>
{
    int32_t WINRT_CALL get_Color(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Color, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Color());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Color(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Color, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().Color(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TargetTheme(Windows::UI::Xaml::ApplicationTheme* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetTheme, WINRT_WRAP(Windows::UI::Xaml::ApplicationTheme));
            *value = detach_from<Windows::UI::Xaml::ApplicationTheme>(this->shim().TargetTheme());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TargetTheme(Windows::UI::Xaml::ApplicationTheme value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetTheme, WINRT_WRAP(void), Windows::UI::Xaml::ApplicationTheme const&);
            this->shim().TargetTheme(*reinterpret_cast<Windows::UI::Xaml::ApplicationTheme const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AlwaysUseFallback(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlwaysUseFallback, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AlwaysUseFallback());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AlwaysUseFallback(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlwaysUseFallback, WINRT_WRAP(void), bool);
            this->shim().AlwaysUseFallback(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IRevealBrushFactory> : produce_base<D, Windows::UI::Xaml::Media::IRevealBrushFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Media::RevealBrush), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Media::RevealBrush>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IRevealBrushStatics> : produce_base<D, Windows::UI::Xaml::Media::IRevealBrushStatics>
{
    int32_t WINRT_CALL get_ColorProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColorProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ColorProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TargetThemeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetThemeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TargetThemeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AlwaysUseFallbackProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlwaysUseFallbackProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().AlwaysUseFallbackProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StateProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StateProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StateProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetState(void* element, Windows::UI::Xaml::Media::RevealBrushState value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetState, WINRT_WRAP(void), Windows::UI::Xaml::UIElement const&, Windows::UI::Xaml::Media::RevealBrushState const&);
            this->shim().SetState(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&element), *reinterpret_cast<Windows::UI::Xaml::Media::RevealBrushState const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetState(void* element, Windows::UI::Xaml::Media::RevealBrushState* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetState, WINRT_WRAP(Windows::UI::Xaml::Media::RevealBrushState), Windows::UI::Xaml::UIElement const&);
            *result = detach_from<Windows::UI::Xaml::Media::RevealBrushState>(this->shim().GetState(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IRotateTransform> : produce_base<D, Windows::UI::Xaml::Media::IRotateTransform>
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

    int32_t WINRT_CALL get_Angle(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Angle, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Angle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Angle(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Angle, WINRT_WRAP(void), double);
            this->shim().Angle(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IRotateTransformStatics> : produce_base<D, Windows::UI::Xaml::Media::IRotateTransformStatics>
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

    int32_t WINRT_CALL get_AngleProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AngleProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().AngleProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IScaleTransform> : produce_base<D, Windows::UI::Xaml::Media::IScaleTransform>
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
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IScaleTransformStatics> : produce_base<D, Windows::UI::Xaml::Media::IScaleTransformStatics>
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
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IShadow> : produce_base<D, Windows::UI::Xaml::Media::IShadow>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IShadowFactory> : produce_base<D, Windows::UI::Xaml::Media::IShadowFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::ISkewTransform> : produce_base<D, Windows::UI::Xaml::Media::ISkewTransform>
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

    int32_t WINRT_CALL get_AngleX(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AngleX, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().AngleX());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AngleX(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AngleX, WINRT_WRAP(void), double);
            this->shim().AngleX(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AngleY(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AngleY, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().AngleY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AngleY(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AngleY, WINRT_WRAP(void), double);
            this->shim().AngleY(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::ISkewTransformStatics> : produce_base<D, Windows::UI::Xaml::Media::ISkewTransformStatics>
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

    int32_t WINRT_CALL get_AngleXProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AngleXProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().AngleXProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AngleYProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AngleYProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().AngleYProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::ISolidColorBrush> : produce_base<D, Windows::UI::Xaml::Media::ISolidColorBrush>
{
    int32_t WINRT_CALL get_Color(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Color, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Color());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Color(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Color, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().Color(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::ISolidColorBrushFactory> : produce_base<D, Windows::UI::Xaml::Media::ISolidColorBrushFactory>
{
    int32_t WINRT_CALL CreateInstanceWithColor(struct struct_Windows_UI_Color color, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstanceWithColor, WINRT_WRAP(Windows::UI::Xaml::Media::SolidColorBrush), Windows::UI::Color const&);
            *value = detach_from<Windows::UI::Xaml::Media::SolidColorBrush>(this->shim().CreateInstanceWithColor(*reinterpret_cast<Windows::UI::Color const*>(&color)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::ISolidColorBrushStatics> : produce_base<D, Windows::UI::Xaml::Media::ISolidColorBrushStatics>
{
    int32_t WINRT_CALL get_ColorProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColorProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ColorProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IThemeShadow> : produce_base<D, Windows::UI::Xaml::Media::IThemeShadow>
{
    int32_t WINRT_CALL get_Receivers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Receivers, WINRT_WRAP(Windows::UI::Xaml::UIElementWeakCollection));
            *value = detach_from<Windows::UI::Xaml::UIElementWeakCollection>(this->shim().Receivers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IThemeShadowFactory> : produce_base<D, Windows::UI::Xaml::Media::IThemeShadowFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Media::ThemeShadow), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Media::ThemeShadow>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::ITileBrush> : produce_base<D, Windows::UI::Xaml::Media::ITileBrush>
{
    int32_t WINRT_CALL get_AlignmentX(Windows::UI::Xaml::Media::AlignmentX* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlignmentX, WINRT_WRAP(Windows::UI::Xaml::Media::AlignmentX));
            *value = detach_from<Windows::UI::Xaml::Media::AlignmentX>(this->shim().AlignmentX());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AlignmentX(Windows::UI::Xaml::Media::AlignmentX value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlignmentX, WINRT_WRAP(void), Windows::UI::Xaml::Media::AlignmentX const&);
            this->shim().AlignmentX(*reinterpret_cast<Windows::UI::Xaml::Media::AlignmentX const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AlignmentY(Windows::UI::Xaml::Media::AlignmentY* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlignmentY, WINRT_WRAP(Windows::UI::Xaml::Media::AlignmentY));
            *value = detach_from<Windows::UI::Xaml::Media::AlignmentY>(this->shim().AlignmentY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AlignmentY(Windows::UI::Xaml::Media::AlignmentY value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlignmentY, WINRT_WRAP(void), Windows::UI::Xaml::Media::AlignmentY const&);
            this->shim().AlignmentY(*reinterpret_cast<Windows::UI::Xaml::Media::AlignmentY const*>(&value));
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
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::ITileBrushFactory> : produce_base<D, Windows::UI::Xaml::Media::ITileBrushFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Media::TileBrush), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Media::TileBrush>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::ITileBrushStatics> : produce_base<D, Windows::UI::Xaml::Media::ITileBrushStatics>
{
    int32_t WINRT_CALL get_AlignmentXProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlignmentXProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().AlignmentXProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AlignmentYProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlignmentYProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().AlignmentYProperty());
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

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::ITimelineMarker> : produce_base<D, Windows::UI::Xaml::Media::ITimelineMarker>
{
    int32_t WINRT_CALL get_Time(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Time, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Time());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Time(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Time, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().Time(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Type(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Type(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(void), hstring const&);
            this->shim().Type(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Text(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Text, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Text());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Text(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Text, WINRT_WRAP(void), hstring const&);
            this->shim().Text(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::ITimelineMarkerRoutedEventArgs> : produce_base<D, Windows::UI::Xaml::Media::ITimelineMarkerRoutedEventArgs>
{
    int32_t WINRT_CALL get_Marker(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Marker, WINRT_WRAP(Windows::UI::Xaml::Media::TimelineMarker));
            *value = detach_from<Windows::UI::Xaml::Media::TimelineMarker>(this->shim().Marker());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Marker(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Marker, WINRT_WRAP(void), Windows::UI::Xaml::Media::TimelineMarker const&);
            this->shim().Marker(*reinterpret_cast<Windows::UI::Xaml::Media::TimelineMarker const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::ITimelineMarkerStatics> : produce_base<D, Windows::UI::Xaml::Media::ITimelineMarkerStatics>
{
    int32_t WINRT_CALL get_TimeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TimeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TimeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TypeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TypeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TypeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TextProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TextProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TextProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::ITransform> : produce_base<D, Windows::UI::Xaml::Media::ITransform>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::ITransformFactory> : produce_base<D, Windows::UI::Xaml::Media::ITransformFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::ITransformGroup> : produce_base<D, Windows::UI::Xaml::Media::ITransformGroup>
{
    int32_t WINRT_CALL get_Children(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Children, WINRT_WRAP(Windows::UI::Xaml::Media::TransformCollection));
            *value = detach_from<Windows::UI::Xaml::Media::TransformCollection>(this->shim().Children());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Children(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Children, WINRT_WRAP(void), Windows::UI::Xaml::Media::TransformCollection const&);
            this->shim().Children(*reinterpret_cast<Windows::UI::Xaml::Media::TransformCollection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Value(struct struct_Windows_UI_Xaml_Media_Matrix* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(Windows::UI::Xaml::Media::Matrix));
            *value = detach_from<Windows::UI::Xaml::Media::Matrix>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::ITransformGroupStatics> : produce_base<D, Windows::UI::Xaml::Media::ITransformGroupStatics>
{
    int32_t WINRT_CALL get_ChildrenProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChildrenProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ChildrenProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::ITranslateTransform> : produce_base<D, Windows::UI::Xaml::Media::ITranslateTransform>
{
    int32_t WINRT_CALL get_X(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(X, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().X());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_X(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(X, WINRT_WRAP(void), double);
            this->shim().X(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Y(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Y, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Y());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Y(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Y, WINRT_WRAP(void), double);
            this->shim().Y(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::ITranslateTransformStatics> : produce_base<D, Windows::UI::Xaml::Media::ITranslateTransformStatics>
{
    int32_t WINRT_CALL get_XProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().XProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_YProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(YProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().YProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IVisualTreeHelper> : produce_base<D, Windows::UI::Xaml::Media::IVisualTreeHelper>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IVisualTreeHelperStatics> : produce_base<D, Windows::UI::Xaml::Media::IVisualTreeHelperStatics>
{
    int32_t WINRT_CALL FindElementsInHostCoordinatesPoint(Windows::Foundation::Point intersectingPoint, void* subtree, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindElementsInHostCoordinates, WINRT_WRAP(Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::UIElement>), Windows::Foundation::Point const&, Windows::UI::Xaml::UIElement const&);
            *result = detach_from<Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::UIElement>>(this->shim().FindElementsInHostCoordinates(*reinterpret_cast<Windows::Foundation::Point const*>(&intersectingPoint), *reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&subtree)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindElementsInHostCoordinatesRect(Windows::Foundation::Rect intersectingRect, void* subtree, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindElementsInHostCoordinates, WINRT_WRAP(Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::UIElement>), Windows::Foundation::Rect const&, Windows::UI::Xaml::UIElement const&);
            *result = detach_from<Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::UIElement>>(this->shim().FindElementsInHostCoordinates(*reinterpret_cast<Windows::Foundation::Rect const*>(&intersectingRect), *reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&subtree)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAllElementsInHostCoordinatesPoint(Windows::Foundation::Point intersectingPoint, void* subtree, bool includeAllElements, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindElementsInHostCoordinates, WINRT_WRAP(Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::UIElement>), Windows::Foundation::Point const&, Windows::UI::Xaml::UIElement const&, bool);
            *result = detach_from<Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::UIElement>>(this->shim().FindElementsInHostCoordinates(*reinterpret_cast<Windows::Foundation::Point const*>(&intersectingPoint), *reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&subtree), includeAllElements));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAllElementsInHostCoordinatesRect(Windows::Foundation::Rect intersectingRect, void* subtree, bool includeAllElements, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindElementsInHostCoordinates, WINRT_WRAP(Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::UIElement>), Windows::Foundation::Rect const&, Windows::UI::Xaml::UIElement const&, bool);
            *result = detach_from<Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::UIElement>>(this->shim().FindElementsInHostCoordinates(*reinterpret_cast<Windows::Foundation::Rect const*>(&intersectingRect), *reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&subtree), includeAllElements));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetChild(void* reference, int32_t childIndex, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetChild, WINRT_WRAP(Windows::UI::Xaml::DependencyObject), Windows::UI::Xaml::DependencyObject const&, int32_t);
            *result = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().GetChild(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&reference), childIndex));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetChildrenCount(void* reference, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetChildrenCount, WINRT_WRAP(int32_t), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<int32_t>(this->shim().GetChildrenCount(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&reference)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetParent(void* reference, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetParent, WINRT_WRAP(Windows::UI::Xaml::DependencyObject), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().GetParent(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&reference)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DisconnectChildrenRecursive(void* element) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisconnectChildrenRecursive, WINRT_WRAP(void), Windows::UI::Xaml::UIElement const&);
            this->shim().DisconnectChildrenRecursive(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&element));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IVisualTreeHelperStatics2> : produce_base<D, Windows::UI::Xaml::Media::IVisualTreeHelperStatics2>
{
    int32_t WINRT_CALL GetOpenPopups(void* window, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetOpenPopups, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Controls::Primitives::Popup>), Windows::UI::Xaml::Window const&);
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Controls::Primitives::Popup>>(this->shim().GetOpenPopups(*reinterpret_cast<Windows::UI::Xaml::Window const*>(&window)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IVisualTreeHelperStatics3> : produce_base<D, Windows::UI::Xaml::Media::IVisualTreeHelperStatics3>
{
    int32_t WINRT_CALL GetOpenPopupsForXamlRoot(void* xamlRoot, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetOpenPopupsForXamlRoot, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Controls::Primitives::Popup>), Windows::UI::Xaml::XamlRoot const&);
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Controls::Primitives::Popup>>(this->shim().GetOpenPopupsForXamlRoot(*reinterpret_cast<Windows::UI::Xaml::XamlRoot const*>(&xamlRoot)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IXamlCompositionBrushBase> : produce_base<D, Windows::UI::Xaml::Media::IXamlCompositionBrushBase>
{
    int32_t WINRT_CALL get_FallbackColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FallbackColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().FallbackColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FallbackColor(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FallbackColor, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().FallbackColor(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IXamlCompositionBrushBaseFactory> : produce_base<D, Windows::UI::Xaml::Media::IXamlCompositionBrushBaseFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Media::XamlCompositionBrushBase), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Media::XamlCompositionBrushBase>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IXamlCompositionBrushBaseOverrides> : produce_base<D, Windows::UI::Xaml::Media::IXamlCompositionBrushBaseOverrides>
{
    int32_t WINRT_CALL OnConnected() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnConnected, WINRT_WRAP(void));
            this->shim().OnConnected();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OnDisconnected() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnDisconnected, WINRT_WRAP(void));
            this->shim().OnDisconnected();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IXamlCompositionBrushBaseProtected> : produce_base<D, Windows::UI::Xaml::Media::IXamlCompositionBrushBaseProtected>
{
    int32_t WINRT_CALL get_CompositionBrush(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompositionBrush, WINRT_WRAP(Windows::UI::Composition::CompositionBrush));
            *value = detach_from<Windows::UI::Composition::CompositionBrush>(this->shim().CompositionBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CompositionBrush(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompositionBrush, WINRT_WRAP(void), Windows::UI::Composition::CompositionBrush const&);
            this->shim().CompositionBrush(*reinterpret_cast<Windows::UI::Composition::CompositionBrush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IXamlCompositionBrushBaseStatics> : produce_base<D, Windows::UI::Xaml::Media::IXamlCompositionBrushBaseStatics>
{
    int32_t WINRT_CALL get_FallbackColorProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FallbackColorProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FallbackColorProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IXamlLight> : produce_base<D, Windows::UI::Xaml::Media::IXamlLight>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IXamlLightFactory> : produce_base<D, Windows::UI::Xaml::Media::IXamlLightFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Media::XamlLight), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Media::XamlLight>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IXamlLightOverrides> : produce_base<D, Windows::UI::Xaml::Media::IXamlLightOverrides>
{
    int32_t WINRT_CALL GetId(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetId, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OnConnected(void* newElement) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnConnected, WINRT_WRAP(void), Windows::UI::Xaml::UIElement const&);
            this->shim().OnConnected(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&newElement));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OnDisconnected(void* oldElement) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnDisconnected, WINRT_WRAP(void), Windows::UI::Xaml::UIElement const&);
            this->shim().OnDisconnected(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&oldElement));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IXamlLightProtected> : produce_base<D, Windows::UI::Xaml::Media::IXamlLightProtected>
{
    int32_t WINRT_CALL get_CompositionLight(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompositionLight, WINRT_WRAP(Windows::UI::Composition::CompositionLight));
            *value = detach_from<Windows::UI::Composition::CompositionLight>(this->shim().CompositionLight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CompositionLight(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompositionLight, WINRT_WRAP(void), Windows::UI::Composition::CompositionLight const&);
            this->shim().CompositionLight(*reinterpret_cast<Windows::UI::Composition::CompositionLight const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::IXamlLightStatics> : produce_base<D, Windows::UI::Xaml::Media::IXamlLightStatics>
{
    int32_t WINRT_CALL AddTargetElement(void* lightId, void* element) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddTargetElement, WINRT_WRAP(void), hstring const&, Windows::UI::Xaml::UIElement const&);
            this->shim().AddTargetElement(*reinterpret_cast<hstring const*>(&lightId), *reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&element));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveTargetElement(void* lightId, void* element) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveTargetElement, WINRT_WRAP(void), hstring const&, Windows::UI::Xaml::UIElement const&);
            this->shim().RemoveTargetElement(*reinterpret_cast<hstring const*>(&lightId), *reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&element));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddTargetBrush(void* lightId, void* brush) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddTargetBrush, WINRT_WRAP(void), hstring const&, Windows::UI::Xaml::Media::Brush const&);
            this->shim().AddTargetBrush(*reinterpret_cast<hstring const*>(&lightId), *reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&brush));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveTargetBrush(void* lightId, void* brush) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveTargetBrush, WINRT_WRAP(void), hstring const&, Windows::UI::Xaml::Media::Brush const&);
            this->shim().RemoveTargetBrush(*reinterpret_cast<hstring const*>(&lightId), *reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&brush));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename T, typename D>
struct WINRT_EBO produce_dispatch_to_overridable<T, D, Windows::UI::Xaml::Media::IBrushOverrides2>
    : produce_dispatch_to_overridable_base<T, D, Windows::UI::Xaml::Media::IBrushOverrides2>
{
    void PopulatePropertyInfoOverride(hstring const& propertyName, Windows::UI::Composition::AnimationPropertyInfo const& animationPropertyInfo)
    {
        Windows::UI::Xaml::Media::IBrushOverrides2 overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.PopulatePropertyInfoOverride(propertyName, animationPropertyInfo);
        }
        return this->shim().PopulatePropertyInfoOverride(propertyName, animationPropertyInfo);
    }
};
template <typename T, typename D>
struct WINRT_EBO produce_dispatch_to_overridable<T, D, Windows::UI::Xaml::Media::IGeneralTransformOverrides>
    : produce_dispatch_to_overridable_base<T, D, Windows::UI::Xaml::Media::IGeneralTransformOverrides>
{
    Windows::UI::Xaml::Media::GeneralTransform InverseCore()
    {
        Windows::UI::Xaml::Media::IGeneralTransformOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.InverseCore();
        }
        return this->shim().InverseCore();
    }
    bool TryTransformCore(Windows::Foundation::Point const& inPoint, Windows::Foundation::Point& outPoint)
    {
        Windows::UI::Xaml::Media::IGeneralTransformOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.TryTransformCore(inPoint, outPoint);
        }
        return this->shim().TryTransformCore(inPoint, outPoint);
    }
    Windows::Foundation::Rect TransformBoundsCore(Windows::Foundation::Rect const& rect)
    {
        Windows::UI::Xaml::Media::IGeneralTransformOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.TransformBoundsCore(rect);
        }
        return this->shim().TransformBoundsCore(rect);
    }
};
template <typename T, typename D>
struct WINRT_EBO produce_dispatch_to_overridable<T, D, Windows::UI::Xaml::Media::IXamlCompositionBrushBaseOverrides>
    : produce_dispatch_to_overridable_base<T, D, Windows::UI::Xaml::Media::IXamlCompositionBrushBaseOverrides>
{
    void OnConnected()
    {
        Windows::UI::Xaml::Media::IXamlCompositionBrushBaseOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.OnConnected();
        }
        return this->shim().OnConnected();
    }
    void OnDisconnected()
    {
        Windows::UI::Xaml::Media::IXamlCompositionBrushBaseOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.OnDisconnected();
        }
        return this->shim().OnDisconnected();
    }
};
template <typename T, typename D>
struct WINRT_EBO produce_dispatch_to_overridable<T, D, Windows::UI::Xaml::Media::IXamlLightOverrides>
    : produce_dispatch_to_overridable_base<T, D, Windows::UI::Xaml::Media::IXamlLightOverrides>
{
    hstring GetId()
    {
        Windows::UI::Xaml::Media::IXamlLightOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetId();
        }
        return this->shim().GetId();
    }
    void OnConnected(Windows::UI::Xaml::UIElement const& newElement)
    {
        Windows::UI::Xaml::Media::IXamlLightOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.OnConnected(newElement);
        }
        return this->shim().OnConnected(newElement);
    }
    void OnDisconnected(Windows::UI::Xaml::UIElement const& oldElement)
    {
        Windows::UI::Xaml::Media::IXamlLightOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.OnDisconnected(oldElement);
        }
        return this->shim().OnDisconnected(oldElement);
    }
};
}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Media {

inline AcrylicBrush::AcrylicBrush()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<AcrylicBrush, Windows::UI::Xaml::Media::IAcrylicBrushFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline Windows::UI::Xaml::DependencyProperty AcrylicBrush::BackgroundSourceProperty()
{
    return impl::call_factory<AcrylicBrush, Windows::UI::Xaml::Media::IAcrylicBrushStatics>([&](auto&& f) { return f.BackgroundSourceProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty AcrylicBrush::TintColorProperty()
{
    return impl::call_factory<AcrylicBrush, Windows::UI::Xaml::Media::IAcrylicBrushStatics>([&](auto&& f) { return f.TintColorProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty AcrylicBrush::TintOpacityProperty()
{
    return impl::call_factory<AcrylicBrush, Windows::UI::Xaml::Media::IAcrylicBrushStatics>([&](auto&& f) { return f.TintOpacityProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty AcrylicBrush::TintTransitionDurationProperty()
{
    return impl::call_factory<AcrylicBrush, Windows::UI::Xaml::Media::IAcrylicBrushStatics>([&](auto&& f) { return f.TintTransitionDurationProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty AcrylicBrush::AlwaysUseFallbackProperty()
{
    return impl::call_factory<AcrylicBrush, Windows::UI::Xaml::Media::IAcrylicBrushStatics>([&](auto&& f) { return f.AlwaysUseFallbackProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty AcrylicBrush::TintLuminosityOpacityProperty()
{
    return impl::call_factory<AcrylicBrush, Windows::UI::Xaml::Media::IAcrylicBrushStatics2>([&](auto&& f) { return f.TintLuminosityOpacityProperty(); });
}

inline ArcSegment::ArcSegment() :
    ArcSegment(impl::call_factory<ArcSegment>([](auto&& f) { return f.template ActivateInstance<ArcSegment>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty ArcSegment::PointProperty()
{
    return impl::call_factory<ArcSegment, Windows::UI::Xaml::Media::IArcSegmentStatics>([&](auto&& f) { return f.PointProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ArcSegment::SizeProperty()
{
    return impl::call_factory<ArcSegment, Windows::UI::Xaml::Media::IArcSegmentStatics>([&](auto&& f) { return f.SizeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ArcSegment::RotationAngleProperty()
{
    return impl::call_factory<ArcSegment, Windows::UI::Xaml::Media::IArcSegmentStatics>([&](auto&& f) { return f.RotationAngleProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ArcSegment::IsLargeArcProperty()
{
    return impl::call_factory<ArcSegment, Windows::UI::Xaml::Media::IArcSegmentStatics>([&](auto&& f) { return f.IsLargeArcProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ArcSegment::SweepDirectionProperty()
{
    return impl::call_factory<ArcSegment, Windows::UI::Xaml::Media::IArcSegmentStatics>([&](auto&& f) { return f.SweepDirectionProperty(); });
}

inline BezierSegment::BezierSegment() :
    BezierSegment(impl::call_factory<BezierSegment>([](auto&& f) { return f.template ActivateInstance<BezierSegment>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty BezierSegment::Point1Property()
{
    return impl::call_factory<BezierSegment, Windows::UI::Xaml::Media::IBezierSegmentStatics>([&](auto&& f) { return f.Point1Property(); });
}

inline Windows::UI::Xaml::DependencyProperty BezierSegment::Point2Property()
{
    return impl::call_factory<BezierSegment, Windows::UI::Xaml::Media::IBezierSegmentStatics>([&](auto&& f) { return f.Point2Property(); });
}

inline Windows::UI::Xaml::DependencyProperty BezierSegment::Point3Property()
{
    return impl::call_factory<BezierSegment, Windows::UI::Xaml::Media::IBezierSegmentStatics>([&](auto&& f) { return f.Point3Property(); });
}

inline BitmapCache::BitmapCache() :
    BitmapCache(impl::call_factory<BitmapCache>([](auto&& f) { return f.template ActivateInstance<BitmapCache>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty Brush::OpacityProperty()
{
    return impl::call_factory<Brush, Windows::UI::Xaml::Media::IBrushStatics>([&](auto&& f) { return f.OpacityProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Brush::TransformProperty()
{
    return impl::call_factory<Brush, Windows::UI::Xaml::Media::IBrushStatics>([&](auto&& f) { return f.TransformProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Brush::RelativeTransformProperty()
{
    return impl::call_factory<Brush, Windows::UI::Xaml::Media::IBrushStatics>([&](auto&& f) { return f.RelativeTransformProperty(); });
}

inline BrushCollection::BrushCollection() :
    BrushCollection(impl::call_factory<BrushCollection>([](auto&& f) { return f.template ActivateInstance<BrushCollection>(); }))
{}

inline CompositeTransform::CompositeTransform() :
    CompositeTransform(impl::call_factory<CompositeTransform>([](auto&& f) { return f.template ActivateInstance<CompositeTransform>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty CompositeTransform::CenterXProperty()
{
    return impl::call_factory<CompositeTransform, Windows::UI::Xaml::Media::ICompositeTransformStatics>([&](auto&& f) { return f.CenterXProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty CompositeTransform::CenterYProperty()
{
    return impl::call_factory<CompositeTransform, Windows::UI::Xaml::Media::ICompositeTransformStatics>([&](auto&& f) { return f.CenterYProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty CompositeTransform::ScaleXProperty()
{
    return impl::call_factory<CompositeTransform, Windows::UI::Xaml::Media::ICompositeTransformStatics>([&](auto&& f) { return f.ScaleXProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty CompositeTransform::ScaleYProperty()
{
    return impl::call_factory<CompositeTransform, Windows::UI::Xaml::Media::ICompositeTransformStatics>([&](auto&& f) { return f.ScaleYProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty CompositeTransform::SkewXProperty()
{
    return impl::call_factory<CompositeTransform, Windows::UI::Xaml::Media::ICompositeTransformStatics>([&](auto&& f) { return f.SkewXProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty CompositeTransform::SkewYProperty()
{
    return impl::call_factory<CompositeTransform, Windows::UI::Xaml::Media::ICompositeTransformStatics>([&](auto&& f) { return f.SkewYProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty CompositeTransform::RotationProperty()
{
    return impl::call_factory<CompositeTransform, Windows::UI::Xaml::Media::ICompositeTransformStatics>([&](auto&& f) { return f.RotationProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty CompositeTransform::TranslateXProperty()
{
    return impl::call_factory<CompositeTransform, Windows::UI::Xaml::Media::ICompositeTransformStatics>([&](auto&& f) { return f.TranslateXProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty CompositeTransform::TranslateYProperty()
{
    return impl::call_factory<CompositeTransform, Windows::UI::Xaml::Media::ICompositeTransformStatics>([&](auto&& f) { return f.TranslateYProperty(); });
}

inline winrt::event_token CompositionTarget::Rendering(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<CompositionTarget, Windows::UI::Xaml::Media::ICompositionTargetStatics>([&](auto&& f) { return f.Rendering(handler); });
}

inline CompositionTarget::Rendering_revoker CompositionTarget::Rendering(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<CompositionTarget, Windows::UI::Xaml::Media::ICompositionTargetStatics>();
    return { f, f.Rendering(handler) };
}

inline void CompositionTarget::Rendering(winrt::event_token const& token)
{
    impl::call_factory<CompositionTarget, Windows::UI::Xaml::Media::ICompositionTargetStatics>([&](auto&& f) { return f.Rendering(token); });
}

inline winrt::event_token CompositionTarget::SurfaceContentsLost(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<CompositionTarget, Windows::UI::Xaml::Media::ICompositionTargetStatics>([&](auto&& f) { return f.SurfaceContentsLost(handler); });
}

inline CompositionTarget::SurfaceContentsLost_revoker CompositionTarget::SurfaceContentsLost(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<CompositionTarget, Windows::UI::Xaml::Media::ICompositionTargetStatics>();
    return { f, f.SurfaceContentsLost(handler) };
}

inline void CompositionTarget::SurfaceContentsLost(winrt::event_token const& token)
{
    impl::call_factory<CompositionTarget, Windows::UI::Xaml::Media::ICompositionTargetStatics>([&](auto&& f) { return f.SurfaceContentsLost(token); });
}

inline winrt::event_token CompositionTarget::Rendered(Windows::Foundation::EventHandler<Windows::UI::Xaml::Media::RenderedEventArgs> const& handler)
{
    return impl::call_factory<CompositionTarget, Windows::UI::Xaml::Media::ICompositionTargetStatics3>([&](auto&& f) { return f.Rendered(handler); });
}

inline CompositionTarget::Rendered_revoker CompositionTarget::Rendered(auto_revoke_t, Windows::Foundation::EventHandler<Windows::UI::Xaml::Media::RenderedEventArgs> const& handler)
{
    auto f = get_activation_factory<CompositionTarget, Windows::UI::Xaml::Media::ICompositionTargetStatics3>();
    return { f, f.Rendered(handler) };
}

inline void CompositionTarget::Rendered(winrt::event_token const& token)
{
    impl::call_factory<CompositionTarget, Windows::UI::Xaml::Media::ICompositionTargetStatics3>([&](auto&& f) { return f.Rendered(token); });
}

inline DoubleCollection::DoubleCollection() :
    DoubleCollection(impl::call_factory<DoubleCollection>([](auto&& f) { return f.template ActivateInstance<DoubleCollection>(); }))
{}

inline EllipseGeometry::EllipseGeometry() :
    EllipseGeometry(impl::call_factory<EllipseGeometry>([](auto&& f) { return f.template ActivateInstance<EllipseGeometry>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty EllipseGeometry::CenterProperty()
{
    return impl::call_factory<EllipseGeometry, Windows::UI::Xaml::Media::IEllipseGeometryStatics>([&](auto&& f) { return f.CenterProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty EllipseGeometry::RadiusXProperty()
{
    return impl::call_factory<EllipseGeometry, Windows::UI::Xaml::Media::IEllipseGeometryStatics>([&](auto&& f) { return f.RadiusXProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty EllipseGeometry::RadiusYProperty()
{
    return impl::call_factory<EllipseGeometry, Windows::UI::Xaml::Media::IEllipseGeometryStatics>([&](auto&& f) { return f.RadiusYProperty(); });
}

inline FontFamily::FontFamily(param::hstring const& familyName)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<FontFamily, Windows::UI::Xaml::Media::IFontFamilyFactory>([&](auto&& f) { return f.CreateInstanceWithName(familyName, baseInterface, innerInterface); });
}

inline Windows::UI::Xaml::Media::FontFamily FontFamily::XamlAutoFontFamily()
{
    return impl::call_factory<FontFamily, Windows::UI::Xaml::Media::IFontFamilyStatics2>([&](auto&& f) { return f.XamlAutoFontFamily(); });
}

inline Windows::UI::Xaml::Media::Geometry Geometry::Empty()
{
    return impl::call_factory<Geometry, Windows::UI::Xaml::Media::IGeometryStatics>([&](auto&& f) { return f.Empty(); });
}

inline double Geometry::StandardFlatteningTolerance()
{
    return impl::call_factory<Geometry, Windows::UI::Xaml::Media::IGeometryStatics>([&](auto&& f) { return f.StandardFlatteningTolerance(); });
}

inline Windows::UI::Xaml::DependencyProperty Geometry::TransformProperty()
{
    return impl::call_factory<Geometry, Windows::UI::Xaml::Media::IGeometryStatics>([&](auto&& f) { return f.TransformProperty(); });
}

inline GeometryCollection::GeometryCollection() :
    GeometryCollection(impl::call_factory<GeometryCollection>([](auto&& f) { return f.template ActivateInstance<GeometryCollection>(); }))
{}

inline GeometryGroup::GeometryGroup() :
    GeometryGroup(impl::call_factory<GeometryGroup>([](auto&& f) { return f.template ActivateInstance<GeometryGroup>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty GeometryGroup::FillRuleProperty()
{
    return impl::call_factory<GeometryGroup, Windows::UI::Xaml::Media::IGeometryGroupStatics>([&](auto&& f) { return f.FillRuleProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty GeometryGroup::ChildrenProperty()
{
    return impl::call_factory<GeometryGroup, Windows::UI::Xaml::Media::IGeometryGroupStatics>([&](auto&& f) { return f.ChildrenProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty GradientBrush::SpreadMethodProperty()
{
    return impl::call_factory<GradientBrush, Windows::UI::Xaml::Media::IGradientBrushStatics>([&](auto&& f) { return f.SpreadMethodProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty GradientBrush::MappingModeProperty()
{
    return impl::call_factory<GradientBrush, Windows::UI::Xaml::Media::IGradientBrushStatics>([&](auto&& f) { return f.MappingModeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty GradientBrush::ColorInterpolationModeProperty()
{
    return impl::call_factory<GradientBrush, Windows::UI::Xaml::Media::IGradientBrushStatics>([&](auto&& f) { return f.ColorInterpolationModeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty GradientBrush::GradientStopsProperty()
{
    return impl::call_factory<GradientBrush, Windows::UI::Xaml::Media::IGradientBrushStatics>([&](auto&& f) { return f.GradientStopsProperty(); });
}

inline GradientStop::GradientStop() :
    GradientStop(impl::call_factory<GradientStop>([](auto&& f) { return f.template ActivateInstance<GradientStop>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty GradientStop::ColorProperty()
{
    return impl::call_factory<GradientStop, Windows::UI::Xaml::Media::IGradientStopStatics>([&](auto&& f) { return f.ColorProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty GradientStop::OffsetProperty()
{
    return impl::call_factory<GradientStop, Windows::UI::Xaml::Media::IGradientStopStatics>([&](auto&& f) { return f.OffsetProperty(); });
}

inline GradientStopCollection::GradientStopCollection() :
    GradientStopCollection(impl::call_factory<GradientStopCollection>([](auto&& f) { return f.template ActivateInstance<GradientStopCollection>(); }))
{}

inline ImageBrush::ImageBrush() :
    ImageBrush(impl::call_factory<ImageBrush>([](auto&& f) { return f.template ActivateInstance<ImageBrush>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty ImageBrush::ImageSourceProperty()
{
    return impl::call_factory<ImageBrush, Windows::UI::Xaml::Media::IImageBrushStatics>([&](auto&& f) { return f.ImageSourceProperty(); });
}

inline LineGeometry::LineGeometry() :
    LineGeometry(impl::call_factory<LineGeometry>([](auto&& f) { return f.template ActivateInstance<LineGeometry>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty LineGeometry::StartPointProperty()
{
    return impl::call_factory<LineGeometry, Windows::UI::Xaml::Media::ILineGeometryStatics>([&](auto&& f) { return f.StartPointProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty LineGeometry::EndPointProperty()
{
    return impl::call_factory<LineGeometry, Windows::UI::Xaml::Media::ILineGeometryStatics>([&](auto&& f) { return f.EndPointProperty(); });
}

inline LineSegment::LineSegment() :
    LineSegment(impl::call_factory<LineSegment>([](auto&& f) { return f.template ActivateInstance<LineSegment>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty LineSegment::PointProperty()
{
    return impl::call_factory<LineSegment, Windows::UI::Xaml::Media::ILineSegmentStatics>([&](auto&& f) { return f.PointProperty(); });
}

inline LinearGradientBrush::LinearGradientBrush() :
    LinearGradientBrush(impl::call_factory<LinearGradientBrush>([](auto&& f) { return f.template ActivateInstance<LinearGradientBrush>(); }))
{}

inline LinearGradientBrush::LinearGradientBrush(Windows::UI::Xaml::Media::GradientStopCollection const& gradientStopCollection, double angle) :
    LinearGradientBrush(impl::call_factory<LinearGradientBrush, Windows::UI::Xaml::Media::ILinearGradientBrushFactory>([&](auto&& f) { return f.CreateInstanceWithGradientStopCollectionAndAngle(gradientStopCollection, angle); }))
{}

inline Windows::UI::Xaml::DependencyProperty LinearGradientBrush::StartPointProperty()
{
    return impl::call_factory<LinearGradientBrush, Windows::UI::Xaml::Media::ILinearGradientBrushStatics>([&](auto&& f) { return f.StartPointProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty LinearGradientBrush::EndPointProperty()
{
    return impl::call_factory<LinearGradientBrush, Windows::UI::Xaml::Media::ILinearGradientBrushStatics>([&](auto&& f) { return f.EndPointProperty(); });
}

inline Windows::UI::Xaml::Media::LoadedImageSurface LoadedImageSurface::StartLoadFromUri(Windows::Foundation::Uri const& uri, Windows::Foundation::Size const& desiredMaxSize)
{
    return impl::call_factory<LoadedImageSurface, Windows::UI::Xaml::Media::ILoadedImageSurfaceStatics>([&](auto&& f) { return f.StartLoadFromUri(uri, desiredMaxSize); });
}

inline Windows::UI::Xaml::Media::LoadedImageSurface LoadedImageSurface::StartLoadFromUri(Windows::Foundation::Uri const& uri)
{
    return impl::call_factory<LoadedImageSurface, Windows::UI::Xaml::Media::ILoadedImageSurfaceStatics>([&](auto&& f) { return f.StartLoadFromUri(uri); });
}

inline Windows::UI::Xaml::Media::LoadedImageSurface LoadedImageSurface::StartLoadFromStream(Windows::Storage::Streams::IRandomAccessStream const& stream, Windows::Foundation::Size const& desiredMaxSize)
{
    return impl::call_factory<LoadedImageSurface, Windows::UI::Xaml::Media::ILoadedImageSurfaceStatics>([&](auto&& f) { return f.StartLoadFromStream(stream, desiredMaxSize); });
}

inline Windows::UI::Xaml::Media::LoadedImageSurface LoadedImageSurface::StartLoadFromStream(Windows::Storage::Streams::IRandomAccessStream const& stream)
{
    return impl::call_factory<LoadedImageSurface, Windows::UI::Xaml::Media::ILoadedImageSurfaceStatics>([&](auto&& f) { return f.StartLoadFromStream(stream); });
}

inline Matrix3DProjection::Matrix3DProjection() :
    Matrix3DProjection(impl::call_factory<Matrix3DProjection>([](auto&& f) { return f.template ActivateInstance<Matrix3DProjection>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty Matrix3DProjection::ProjectionMatrixProperty()
{
    return impl::call_factory<Matrix3DProjection, Windows::UI::Xaml::Media::IMatrix3DProjectionStatics>([&](auto&& f) { return f.ProjectionMatrixProperty(); });
}

inline Windows::UI::Xaml::Media::Matrix MatrixHelper::Identity()
{
    return impl::call_factory<MatrixHelper, Windows::UI::Xaml::Media::IMatrixHelperStatics>([&](auto&& f) { return f.Identity(); });
}

inline Windows::UI::Xaml::Media::Matrix MatrixHelper::FromElements(double m11, double m12, double m21, double m22, double offsetX, double offsetY)
{
    return impl::call_factory<MatrixHelper, Windows::UI::Xaml::Media::IMatrixHelperStatics>([&](auto&& f) { return f.FromElements(m11, m12, m21, m22, offsetX, offsetY); });
}

inline bool MatrixHelper::GetIsIdentity(Windows::UI::Xaml::Media::Matrix const& target)
{
    return impl::call_factory<MatrixHelper, Windows::UI::Xaml::Media::IMatrixHelperStatics>([&](auto&& f) { return f.GetIsIdentity(target); });
}

inline Windows::Foundation::Point MatrixHelper::Transform(Windows::UI::Xaml::Media::Matrix const& target, Windows::Foundation::Point const& point)
{
    return impl::call_factory<MatrixHelper, Windows::UI::Xaml::Media::IMatrixHelperStatics>([&](auto&& f) { return f.Transform(target, point); });
}

inline MatrixTransform::MatrixTransform() :
    MatrixTransform(impl::call_factory<MatrixTransform>([](auto&& f) { return f.template ActivateInstance<MatrixTransform>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty MatrixTransform::MatrixProperty()
{
    return impl::call_factory<MatrixTransform, Windows::UI::Xaml::Media::IMatrixTransformStatics>([&](auto&& f) { return f.MatrixProperty(); });
}

inline PartialMediaFailureDetectedEventArgs::PartialMediaFailureDetectedEventArgs() :
    PartialMediaFailureDetectedEventArgs(impl::call_factory<PartialMediaFailureDetectedEventArgs>([](auto&& f) { return f.template ActivateInstance<PartialMediaFailureDetectedEventArgs>(); }))
{}

inline PathFigure::PathFigure() :
    PathFigure(impl::call_factory<PathFigure>([](auto&& f) { return f.template ActivateInstance<PathFigure>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty PathFigure::SegmentsProperty()
{
    return impl::call_factory<PathFigure, Windows::UI::Xaml::Media::IPathFigureStatics>([&](auto&& f) { return f.SegmentsProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty PathFigure::StartPointProperty()
{
    return impl::call_factory<PathFigure, Windows::UI::Xaml::Media::IPathFigureStatics>([&](auto&& f) { return f.StartPointProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty PathFigure::IsClosedProperty()
{
    return impl::call_factory<PathFigure, Windows::UI::Xaml::Media::IPathFigureStatics>([&](auto&& f) { return f.IsClosedProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty PathFigure::IsFilledProperty()
{
    return impl::call_factory<PathFigure, Windows::UI::Xaml::Media::IPathFigureStatics>([&](auto&& f) { return f.IsFilledProperty(); });
}

inline PathFigureCollection::PathFigureCollection() :
    PathFigureCollection(impl::call_factory<PathFigureCollection>([](auto&& f) { return f.template ActivateInstance<PathFigureCollection>(); }))
{}

inline PathGeometry::PathGeometry() :
    PathGeometry(impl::call_factory<PathGeometry>([](auto&& f) { return f.template ActivateInstance<PathGeometry>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty PathGeometry::FillRuleProperty()
{
    return impl::call_factory<PathGeometry, Windows::UI::Xaml::Media::IPathGeometryStatics>([&](auto&& f) { return f.FillRuleProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty PathGeometry::FiguresProperty()
{
    return impl::call_factory<PathGeometry, Windows::UI::Xaml::Media::IPathGeometryStatics>([&](auto&& f) { return f.FiguresProperty(); });
}

inline PathSegmentCollection::PathSegmentCollection() :
    PathSegmentCollection(impl::call_factory<PathSegmentCollection>([](auto&& f) { return f.template ActivateInstance<PathSegmentCollection>(); }))
{}

inline PlaneProjection::PlaneProjection() :
    PlaneProjection(impl::call_factory<PlaneProjection>([](auto&& f) { return f.template ActivateInstance<PlaneProjection>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty PlaneProjection::LocalOffsetXProperty()
{
    return impl::call_factory<PlaneProjection, Windows::UI::Xaml::Media::IPlaneProjectionStatics>([&](auto&& f) { return f.LocalOffsetXProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty PlaneProjection::LocalOffsetYProperty()
{
    return impl::call_factory<PlaneProjection, Windows::UI::Xaml::Media::IPlaneProjectionStatics>([&](auto&& f) { return f.LocalOffsetYProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty PlaneProjection::LocalOffsetZProperty()
{
    return impl::call_factory<PlaneProjection, Windows::UI::Xaml::Media::IPlaneProjectionStatics>([&](auto&& f) { return f.LocalOffsetZProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty PlaneProjection::RotationXProperty()
{
    return impl::call_factory<PlaneProjection, Windows::UI::Xaml::Media::IPlaneProjectionStatics>([&](auto&& f) { return f.RotationXProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty PlaneProjection::RotationYProperty()
{
    return impl::call_factory<PlaneProjection, Windows::UI::Xaml::Media::IPlaneProjectionStatics>([&](auto&& f) { return f.RotationYProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty PlaneProjection::RotationZProperty()
{
    return impl::call_factory<PlaneProjection, Windows::UI::Xaml::Media::IPlaneProjectionStatics>([&](auto&& f) { return f.RotationZProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty PlaneProjection::CenterOfRotationXProperty()
{
    return impl::call_factory<PlaneProjection, Windows::UI::Xaml::Media::IPlaneProjectionStatics>([&](auto&& f) { return f.CenterOfRotationXProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty PlaneProjection::CenterOfRotationYProperty()
{
    return impl::call_factory<PlaneProjection, Windows::UI::Xaml::Media::IPlaneProjectionStatics>([&](auto&& f) { return f.CenterOfRotationYProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty PlaneProjection::CenterOfRotationZProperty()
{
    return impl::call_factory<PlaneProjection, Windows::UI::Xaml::Media::IPlaneProjectionStatics>([&](auto&& f) { return f.CenterOfRotationZProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty PlaneProjection::GlobalOffsetXProperty()
{
    return impl::call_factory<PlaneProjection, Windows::UI::Xaml::Media::IPlaneProjectionStatics>([&](auto&& f) { return f.GlobalOffsetXProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty PlaneProjection::GlobalOffsetYProperty()
{
    return impl::call_factory<PlaneProjection, Windows::UI::Xaml::Media::IPlaneProjectionStatics>([&](auto&& f) { return f.GlobalOffsetYProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty PlaneProjection::GlobalOffsetZProperty()
{
    return impl::call_factory<PlaneProjection, Windows::UI::Xaml::Media::IPlaneProjectionStatics>([&](auto&& f) { return f.GlobalOffsetZProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty PlaneProjection::ProjectionMatrixProperty()
{
    return impl::call_factory<PlaneProjection, Windows::UI::Xaml::Media::IPlaneProjectionStatics>([&](auto&& f) { return f.ProjectionMatrixProperty(); });
}

inline PointCollection::PointCollection() :
    PointCollection(impl::call_factory<PointCollection>([](auto&& f) { return f.template ActivateInstance<PointCollection>(); }))
{}

inline PolyBezierSegment::PolyBezierSegment() :
    PolyBezierSegment(impl::call_factory<PolyBezierSegment>([](auto&& f) { return f.template ActivateInstance<PolyBezierSegment>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty PolyBezierSegment::PointsProperty()
{
    return impl::call_factory<PolyBezierSegment, Windows::UI::Xaml::Media::IPolyBezierSegmentStatics>([&](auto&& f) { return f.PointsProperty(); });
}

inline PolyLineSegment::PolyLineSegment() :
    PolyLineSegment(impl::call_factory<PolyLineSegment>([](auto&& f) { return f.template ActivateInstance<PolyLineSegment>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty PolyLineSegment::PointsProperty()
{
    return impl::call_factory<PolyLineSegment, Windows::UI::Xaml::Media::IPolyLineSegmentStatics>([&](auto&& f) { return f.PointsProperty(); });
}

inline PolyQuadraticBezierSegment::PolyQuadraticBezierSegment() :
    PolyQuadraticBezierSegment(impl::call_factory<PolyQuadraticBezierSegment>([](auto&& f) { return f.template ActivateInstance<PolyQuadraticBezierSegment>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty PolyQuadraticBezierSegment::PointsProperty()
{
    return impl::call_factory<PolyQuadraticBezierSegment, Windows::UI::Xaml::Media::IPolyQuadraticBezierSegmentStatics>([&](auto&& f) { return f.PointsProperty(); });
}

inline QuadraticBezierSegment::QuadraticBezierSegment() :
    QuadraticBezierSegment(impl::call_factory<QuadraticBezierSegment>([](auto&& f) { return f.template ActivateInstance<QuadraticBezierSegment>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty QuadraticBezierSegment::Point1Property()
{
    return impl::call_factory<QuadraticBezierSegment, Windows::UI::Xaml::Media::IQuadraticBezierSegmentStatics>([&](auto&& f) { return f.Point1Property(); });
}

inline Windows::UI::Xaml::DependencyProperty QuadraticBezierSegment::Point2Property()
{
    return impl::call_factory<QuadraticBezierSegment, Windows::UI::Xaml::Media::IQuadraticBezierSegmentStatics>([&](auto&& f) { return f.Point2Property(); });
}

inline RateChangedRoutedEventArgs::RateChangedRoutedEventArgs() :
    RateChangedRoutedEventArgs(impl::call_factory<RateChangedRoutedEventArgs>([](auto&& f) { return f.template ActivateInstance<RateChangedRoutedEventArgs>(); }))
{}

inline RectangleGeometry::RectangleGeometry() :
    RectangleGeometry(impl::call_factory<RectangleGeometry>([](auto&& f) { return f.template ActivateInstance<RectangleGeometry>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty RectangleGeometry::RectProperty()
{
    return impl::call_factory<RectangleGeometry, Windows::UI::Xaml::Media::IRectangleGeometryStatics>([&](auto&& f) { return f.RectProperty(); });
}

inline RevealBackgroundBrush::RevealBackgroundBrush()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<RevealBackgroundBrush, Windows::UI::Xaml::Media::IRevealBackgroundBrushFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline RevealBorderBrush::RevealBorderBrush()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<RevealBorderBrush, Windows::UI::Xaml::Media::IRevealBorderBrushFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline Windows::UI::Xaml::DependencyProperty RevealBrush::ColorProperty()
{
    return impl::call_factory<RevealBrush, Windows::UI::Xaml::Media::IRevealBrushStatics>([&](auto&& f) { return f.ColorProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty RevealBrush::TargetThemeProperty()
{
    return impl::call_factory<RevealBrush, Windows::UI::Xaml::Media::IRevealBrushStatics>([&](auto&& f) { return f.TargetThemeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty RevealBrush::AlwaysUseFallbackProperty()
{
    return impl::call_factory<RevealBrush, Windows::UI::Xaml::Media::IRevealBrushStatics>([&](auto&& f) { return f.AlwaysUseFallbackProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty RevealBrush::StateProperty()
{
    return impl::call_factory<RevealBrush, Windows::UI::Xaml::Media::IRevealBrushStatics>([&](auto&& f) { return f.StateProperty(); });
}

inline void RevealBrush::SetState(Windows::UI::Xaml::UIElement const& element, Windows::UI::Xaml::Media::RevealBrushState const& value)
{
    impl::call_factory<RevealBrush, Windows::UI::Xaml::Media::IRevealBrushStatics>([&](auto&& f) { return f.SetState(element, value); });
}

inline Windows::UI::Xaml::Media::RevealBrushState RevealBrush::GetState(Windows::UI::Xaml::UIElement const& element)
{
    return impl::call_factory<RevealBrush, Windows::UI::Xaml::Media::IRevealBrushStatics>([&](auto&& f) { return f.GetState(element); });
}

inline RotateTransform::RotateTransform() :
    RotateTransform(impl::call_factory<RotateTransform>([](auto&& f) { return f.template ActivateInstance<RotateTransform>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty RotateTransform::CenterXProperty()
{
    return impl::call_factory<RotateTransform, Windows::UI::Xaml::Media::IRotateTransformStatics>([&](auto&& f) { return f.CenterXProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty RotateTransform::CenterYProperty()
{
    return impl::call_factory<RotateTransform, Windows::UI::Xaml::Media::IRotateTransformStatics>([&](auto&& f) { return f.CenterYProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty RotateTransform::AngleProperty()
{
    return impl::call_factory<RotateTransform, Windows::UI::Xaml::Media::IRotateTransformStatics>([&](auto&& f) { return f.AngleProperty(); });
}

inline ScaleTransform::ScaleTransform() :
    ScaleTransform(impl::call_factory<ScaleTransform>([](auto&& f) { return f.template ActivateInstance<ScaleTransform>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty ScaleTransform::CenterXProperty()
{
    return impl::call_factory<ScaleTransform, Windows::UI::Xaml::Media::IScaleTransformStatics>([&](auto&& f) { return f.CenterXProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ScaleTransform::CenterYProperty()
{
    return impl::call_factory<ScaleTransform, Windows::UI::Xaml::Media::IScaleTransformStatics>([&](auto&& f) { return f.CenterYProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ScaleTransform::ScaleXProperty()
{
    return impl::call_factory<ScaleTransform, Windows::UI::Xaml::Media::IScaleTransformStatics>([&](auto&& f) { return f.ScaleXProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ScaleTransform::ScaleYProperty()
{
    return impl::call_factory<ScaleTransform, Windows::UI::Xaml::Media::IScaleTransformStatics>([&](auto&& f) { return f.ScaleYProperty(); });
}

inline SkewTransform::SkewTransform() :
    SkewTransform(impl::call_factory<SkewTransform>([](auto&& f) { return f.template ActivateInstance<SkewTransform>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty SkewTransform::CenterXProperty()
{
    return impl::call_factory<SkewTransform, Windows::UI::Xaml::Media::ISkewTransformStatics>([&](auto&& f) { return f.CenterXProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty SkewTransform::CenterYProperty()
{
    return impl::call_factory<SkewTransform, Windows::UI::Xaml::Media::ISkewTransformStatics>([&](auto&& f) { return f.CenterYProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty SkewTransform::AngleXProperty()
{
    return impl::call_factory<SkewTransform, Windows::UI::Xaml::Media::ISkewTransformStatics>([&](auto&& f) { return f.AngleXProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty SkewTransform::AngleYProperty()
{
    return impl::call_factory<SkewTransform, Windows::UI::Xaml::Media::ISkewTransformStatics>([&](auto&& f) { return f.AngleYProperty(); });
}

inline SolidColorBrush::SolidColorBrush() :
    SolidColorBrush(impl::call_factory<SolidColorBrush>([](auto&& f) { return f.template ActivateInstance<SolidColorBrush>(); }))
{}

inline SolidColorBrush::SolidColorBrush(Windows::UI::Color const& color) :
    SolidColorBrush(impl::call_factory<SolidColorBrush, Windows::UI::Xaml::Media::ISolidColorBrushFactory>([&](auto&& f) { return f.CreateInstanceWithColor(color); }))
{}

inline Windows::UI::Xaml::DependencyProperty SolidColorBrush::ColorProperty()
{
    return impl::call_factory<SolidColorBrush, Windows::UI::Xaml::Media::ISolidColorBrushStatics>([&](auto&& f) { return f.ColorProperty(); });
}

inline ThemeShadow::ThemeShadow()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ThemeShadow, Windows::UI::Xaml::Media::IThemeShadowFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline Windows::UI::Xaml::DependencyProperty TileBrush::AlignmentXProperty()
{
    return impl::call_factory<TileBrush, Windows::UI::Xaml::Media::ITileBrushStatics>([&](auto&& f) { return f.AlignmentXProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty TileBrush::AlignmentYProperty()
{
    return impl::call_factory<TileBrush, Windows::UI::Xaml::Media::ITileBrushStatics>([&](auto&& f) { return f.AlignmentYProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty TileBrush::StretchProperty()
{
    return impl::call_factory<TileBrush, Windows::UI::Xaml::Media::ITileBrushStatics>([&](auto&& f) { return f.StretchProperty(); });
}

inline TimelineMarker::TimelineMarker() :
    TimelineMarker(impl::call_factory<TimelineMarker>([](auto&& f) { return f.template ActivateInstance<TimelineMarker>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty TimelineMarker::TimeProperty()
{
    return impl::call_factory<TimelineMarker, Windows::UI::Xaml::Media::ITimelineMarkerStatics>([&](auto&& f) { return f.TimeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty TimelineMarker::TypeProperty()
{
    return impl::call_factory<TimelineMarker, Windows::UI::Xaml::Media::ITimelineMarkerStatics>([&](auto&& f) { return f.TypeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty TimelineMarker::TextProperty()
{
    return impl::call_factory<TimelineMarker, Windows::UI::Xaml::Media::ITimelineMarkerStatics>([&](auto&& f) { return f.TextProperty(); });
}

inline TimelineMarkerCollection::TimelineMarkerCollection() :
    TimelineMarkerCollection(impl::call_factory<TimelineMarkerCollection>([](auto&& f) { return f.template ActivateInstance<TimelineMarkerCollection>(); }))
{}

inline TimelineMarkerRoutedEventArgs::TimelineMarkerRoutedEventArgs() :
    TimelineMarkerRoutedEventArgs(impl::call_factory<TimelineMarkerRoutedEventArgs>([](auto&& f) { return f.template ActivateInstance<TimelineMarkerRoutedEventArgs>(); }))
{}

inline TransformCollection::TransformCollection() :
    TransformCollection(impl::call_factory<TransformCollection>([](auto&& f) { return f.template ActivateInstance<TransformCollection>(); }))
{}

inline TransformGroup::TransformGroup() :
    TransformGroup(impl::call_factory<TransformGroup>([](auto&& f) { return f.template ActivateInstance<TransformGroup>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty TransformGroup::ChildrenProperty()
{
    return impl::call_factory<TransformGroup, Windows::UI::Xaml::Media::ITransformGroupStatics>([&](auto&& f) { return f.ChildrenProperty(); });
}

inline TranslateTransform::TranslateTransform() :
    TranslateTransform(impl::call_factory<TranslateTransform>([](auto&& f) { return f.template ActivateInstance<TranslateTransform>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty TranslateTransform::XProperty()
{
    return impl::call_factory<TranslateTransform, Windows::UI::Xaml::Media::ITranslateTransformStatics>([&](auto&& f) { return f.XProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty TranslateTransform::YProperty()
{
    return impl::call_factory<TranslateTransform, Windows::UI::Xaml::Media::ITranslateTransformStatics>([&](auto&& f) { return f.YProperty(); });
}

inline Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::UIElement> VisualTreeHelper::FindElementsInHostCoordinates(Windows::Foundation::Point const& intersectingPoint, Windows::UI::Xaml::UIElement const& subtree)
{
    return impl::call_factory<VisualTreeHelper, Windows::UI::Xaml::Media::IVisualTreeHelperStatics>([&](auto&& f) { return f.FindElementsInHostCoordinates(intersectingPoint, subtree); });
}

inline Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::UIElement> VisualTreeHelper::FindElementsInHostCoordinates(Windows::Foundation::Rect const& intersectingRect, Windows::UI::Xaml::UIElement const& subtree)
{
    return impl::call_factory<VisualTreeHelper, Windows::UI::Xaml::Media::IVisualTreeHelperStatics>([&](auto&& f) { return f.FindElementsInHostCoordinates(intersectingRect, subtree); });
}

inline Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::UIElement> VisualTreeHelper::FindElementsInHostCoordinates(Windows::Foundation::Point const& intersectingPoint, Windows::UI::Xaml::UIElement const& subtree, bool includeAllElements)
{
    return impl::call_factory<VisualTreeHelper, Windows::UI::Xaml::Media::IVisualTreeHelperStatics>([&](auto&& f) { return f.FindElementsInHostCoordinates(intersectingPoint, subtree, includeAllElements); });
}

inline Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::UIElement> VisualTreeHelper::FindElementsInHostCoordinates(Windows::Foundation::Rect const& intersectingRect, Windows::UI::Xaml::UIElement const& subtree, bool includeAllElements)
{
    return impl::call_factory<VisualTreeHelper, Windows::UI::Xaml::Media::IVisualTreeHelperStatics>([&](auto&& f) { return f.FindElementsInHostCoordinates(intersectingRect, subtree, includeAllElements); });
}

inline Windows::UI::Xaml::DependencyObject VisualTreeHelper::GetChild(Windows::UI::Xaml::DependencyObject const& reference, int32_t childIndex)
{
    return impl::call_factory<VisualTreeHelper, Windows::UI::Xaml::Media::IVisualTreeHelperStatics>([&](auto&& f) { return f.GetChild(reference, childIndex); });
}

inline int32_t VisualTreeHelper::GetChildrenCount(Windows::UI::Xaml::DependencyObject const& reference)
{
    return impl::call_factory<VisualTreeHelper, Windows::UI::Xaml::Media::IVisualTreeHelperStatics>([&](auto&& f) { return f.GetChildrenCount(reference); });
}

inline Windows::UI::Xaml::DependencyObject VisualTreeHelper::GetParent(Windows::UI::Xaml::DependencyObject const& reference)
{
    return impl::call_factory<VisualTreeHelper, Windows::UI::Xaml::Media::IVisualTreeHelperStatics>([&](auto&& f) { return f.GetParent(reference); });
}

inline void VisualTreeHelper::DisconnectChildrenRecursive(Windows::UI::Xaml::UIElement const& element)
{
    impl::call_factory<VisualTreeHelper, Windows::UI::Xaml::Media::IVisualTreeHelperStatics>([&](auto&& f) { return f.DisconnectChildrenRecursive(element); });
}

inline Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Controls::Primitives::Popup> VisualTreeHelper::GetOpenPopups(Windows::UI::Xaml::Window const& window)
{
    return impl::call_factory<VisualTreeHelper, Windows::UI::Xaml::Media::IVisualTreeHelperStatics2>([&](auto&& f) { return f.GetOpenPopups(window); });
}

inline Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Controls::Primitives::Popup> VisualTreeHelper::GetOpenPopupsForXamlRoot(Windows::UI::Xaml::XamlRoot const& xamlRoot)
{
    return impl::call_factory<VisualTreeHelper, Windows::UI::Xaml::Media::IVisualTreeHelperStatics3>([&](auto&& f) { return f.GetOpenPopupsForXamlRoot(xamlRoot); });
}

inline Windows::UI::Xaml::DependencyProperty XamlCompositionBrushBase::FallbackColorProperty()
{
    return impl::call_factory<XamlCompositionBrushBase, Windows::UI::Xaml::Media::IXamlCompositionBrushBaseStatics>([&](auto&& f) { return f.FallbackColorProperty(); });
}

inline XamlLight::XamlLight()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<XamlLight, Windows::UI::Xaml::Media::IXamlLightFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline void XamlLight::AddTargetElement(param::hstring const& lightId, Windows::UI::Xaml::UIElement const& element)
{
    impl::call_factory<XamlLight, Windows::UI::Xaml::Media::IXamlLightStatics>([&](auto&& f) { return f.AddTargetElement(lightId, element); });
}

inline void XamlLight::RemoveTargetElement(param::hstring const& lightId, Windows::UI::Xaml::UIElement const& element)
{
    impl::call_factory<XamlLight, Windows::UI::Xaml::Media::IXamlLightStatics>([&](auto&& f) { return f.RemoveTargetElement(lightId, element); });
}

inline void XamlLight::AddTargetBrush(param::hstring const& lightId, Windows::UI::Xaml::Media::Brush const& brush)
{
    impl::call_factory<XamlLight, Windows::UI::Xaml::Media::IXamlLightStatics>([&](auto&& f) { return f.AddTargetBrush(lightId, brush); });
}

inline void XamlLight::RemoveTargetBrush(param::hstring const& lightId, Windows::UI::Xaml::Media::Brush const& brush)
{
    impl::call_factory<XamlLight, Windows::UI::Xaml::Media::IXamlLightStatics>([&](auto&& f) { return f.RemoveTargetBrush(lightId, brush); });
}

template <typename L> RateChangedRoutedEventHandler::RateChangedRoutedEventHandler(L handler) :
    RateChangedRoutedEventHandler(impl::make_delegate<RateChangedRoutedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> RateChangedRoutedEventHandler::RateChangedRoutedEventHandler(F* handler) :
    RateChangedRoutedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> RateChangedRoutedEventHandler::RateChangedRoutedEventHandler(O* object, M method) :
    RateChangedRoutedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> RateChangedRoutedEventHandler::RateChangedRoutedEventHandler(com_ptr<O>&& object, M method) :
    RateChangedRoutedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> RateChangedRoutedEventHandler::RateChangedRoutedEventHandler(weak_ref<O>&& object, M method) :
    RateChangedRoutedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void RateChangedRoutedEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Media::RateChangedRoutedEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<RateChangedRoutedEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> TimelineMarkerRoutedEventHandler::TimelineMarkerRoutedEventHandler(L handler) :
    TimelineMarkerRoutedEventHandler(impl::make_delegate<TimelineMarkerRoutedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> TimelineMarkerRoutedEventHandler::TimelineMarkerRoutedEventHandler(F* handler) :
    TimelineMarkerRoutedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> TimelineMarkerRoutedEventHandler::TimelineMarkerRoutedEventHandler(O* object, M method) :
    TimelineMarkerRoutedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> TimelineMarkerRoutedEventHandler::TimelineMarkerRoutedEventHandler(com_ptr<O>&& object, M method) :
    TimelineMarkerRoutedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> TimelineMarkerRoutedEventHandler::TimelineMarkerRoutedEventHandler(weak_ref<O>&& object, M method) :
    TimelineMarkerRoutedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void TimelineMarkerRoutedEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Media::TimelineMarkerRoutedEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<TimelineMarkerRoutedEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename D> void IBrushOverrides2T<D>::PopulatePropertyInfoOverride(param::hstring const& propertyName, Windows::UI::Composition::AnimationPropertyInfo const& animationPropertyInfo) const
{
    return shim().template try_as<IBrushOverrides2>().PopulatePropertyInfoOverride(propertyName, animationPropertyInfo);
}

template <typename D> Windows::UI::Xaml::Media::GeneralTransform IGeneralTransformOverridesT<D>::InverseCore() const
{
    return shim().template try_as<IGeneralTransformOverrides>().InverseCore();
}

template <typename D> bool IGeneralTransformOverridesT<D>::TryTransformCore(Windows::Foundation::Point const& inPoint, Windows::Foundation::Point& outPoint) const
{
    return shim().template try_as<IGeneralTransformOverrides>().TryTransformCore(inPoint, outPoint);
}

template <typename D> Windows::Foundation::Rect IGeneralTransformOverridesT<D>::TransformBoundsCore(Windows::Foundation::Rect const& rect) const
{
    return shim().template try_as<IGeneralTransformOverrides>().TransformBoundsCore(rect);
}

template <typename D> void IXamlCompositionBrushBaseOverridesT<D>::OnConnected() const
{
    return shim().template try_as<IXamlCompositionBrushBaseOverrides>().OnConnected();
}

template <typename D> void IXamlCompositionBrushBaseOverridesT<D>::OnDisconnected() const
{
    return shim().template try_as<IXamlCompositionBrushBaseOverrides>().OnDisconnected();
}

template <typename D> hstring IXamlLightOverridesT<D>::GetId() const
{
    return shim().template try_as<IXamlLightOverrides>().GetId();
}

template <typename D> void IXamlLightOverridesT<D>::OnConnected(Windows::UI::Xaml::UIElement const& newElement) const
{
    return shim().template try_as<IXamlLightOverrides>().OnConnected(newElement);
}

template <typename D> void IXamlLightOverridesT<D>::OnDisconnected(Windows::UI::Xaml::UIElement const& oldElement) const
{
    return shim().template try_as<IXamlLightOverrides>().OnDisconnected(oldElement);
}

template <typename D, typename... Interfaces>
struct AcrylicBrushT :
    implements<D, Windows::UI::Xaml::Media::IBrushOverrides2, Windows::UI::Xaml::Media::IXamlCompositionBrushBaseOverrides, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Media::IAcrylicBrush, Windows::UI::Composition::IAnimationObject, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::Media::IAcrylicBrush2, Windows::UI::Xaml::Media::IBrush, Windows::UI::Xaml::Media::IXamlCompositionBrushBase, Windows::UI::Xaml::Media::IXamlCompositionBrushBaseProtected>,
    impl::base<D, Windows::UI::Xaml::Media::AcrylicBrush, Windows::UI::Xaml::Media::XamlCompositionBrushBase, Windows::UI::Xaml::Media::Brush, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Media::IBrushOverrides2T<D>, Windows::UI::Xaml::Media::IXamlCompositionBrushBaseOverridesT<D>
{
    using composable = AcrylicBrush;

protected:
    AcrylicBrushT()
    {
        impl::call_factory<Windows::UI::Xaml::Media::AcrylicBrush, Windows::UI::Xaml::Media::IAcrylicBrushFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct BrushT :
    implements<D, Windows::UI::Xaml::Media::IBrushOverrides2, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Media::IBrush, Windows::UI::Composition::IAnimationObject, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Media::Brush, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Media::IBrushOverrides2T<D>
{
    using composable = Brush;

protected:
    BrushT()
    {
        impl::call_factory<Windows::UI::Xaml::Media::Brush, Windows::UI::Xaml::Media::IBrushFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct CacheModeT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Media::ICacheMode, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Media::CacheMode, Windows::UI::Xaml::DependencyObject>
{
    using composable = CacheMode;

protected:
    CacheModeT()
    {
        impl::call_factory<Windows::UI::Xaml::Media::CacheMode, Windows::UI::Xaml::Media::ICacheModeFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct FontFamilyT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Media::IFontFamily>,
    impl::base<D, Windows::UI::Xaml::Media::FontFamily>
{
    using composable = FontFamily;

protected:
    FontFamilyT(param::hstring const& familyName)
    {
        impl::call_factory<Windows::UI::Xaml::Media::FontFamily, Windows::UI::Xaml::Media::IFontFamilyFactory>([&](auto&& f) { f.CreateInstanceWithName(familyName, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct GeneralTransformT :
    implements<D, Windows::UI::Xaml::Media::IGeneralTransformOverrides, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Media::IGeneralTransform, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Media::GeneralTransform, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Media::IGeneralTransformOverridesT<D>
{
    using composable = GeneralTransform;

protected:
    GeneralTransformT()
    {
        impl::call_factory<Windows::UI::Xaml::Media::GeneralTransform, Windows::UI::Xaml::Media::IGeneralTransformFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct GradientBrushT :
    implements<D, Windows::UI::Xaml::Media::IBrushOverrides2, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Media::IGradientBrush, Windows::UI::Composition::IAnimationObject, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::Media::IBrush>,
    impl::base<D, Windows::UI::Xaml::Media::GradientBrush, Windows::UI::Xaml::Media::Brush, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Media::IBrushOverrides2T<D>
{
    using composable = GradientBrush;

protected:
    GradientBrushT()
    {
        impl::call_factory<Windows::UI::Xaml::Media::GradientBrush, Windows::UI::Xaml::Media::IGradientBrushFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ProjectionT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Media::IProjection, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Media::Projection, Windows::UI::Xaml::DependencyObject>
{
    using composable = Projection;

protected:
    ProjectionT()
    {
        impl::call_factory<Windows::UI::Xaml::Media::Projection, Windows::UI::Xaml::Media::IProjectionFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct RevealBackgroundBrushT :
    implements<D, Windows::UI::Xaml::Media::IBrushOverrides2, Windows::UI::Xaml::Media::IXamlCompositionBrushBaseOverrides, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Media::IRevealBackgroundBrush, Windows::UI::Composition::IAnimationObject, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::Media::IBrush, Windows::UI::Xaml::Media::IRevealBrush, Windows::UI::Xaml::Media::IXamlCompositionBrushBase, Windows::UI::Xaml::Media::IXamlCompositionBrushBaseProtected>,
    impl::base<D, Windows::UI::Xaml::Media::RevealBackgroundBrush, Windows::UI::Xaml::Media::RevealBrush, Windows::UI::Xaml::Media::XamlCompositionBrushBase, Windows::UI::Xaml::Media::Brush, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Media::IBrushOverrides2T<D>, Windows::UI::Xaml::Media::IXamlCompositionBrushBaseOverridesT<D>
{
    using composable = RevealBackgroundBrush;

protected:
    RevealBackgroundBrushT()
    {
        impl::call_factory<Windows::UI::Xaml::Media::RevealBackgroundBrush, Windows::UI::Xaml::Media::IRevealBackgroundBrushFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct RevealBorderBrushT :
    implements<D, Windows::UI::Xaml::Media::IBrushOverrides2, Windows::UI::Xaml::Media::IXamlCompositionBrushBaseOverrides, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Media::IRevealBorderBrush, Windows::UI::Composition::IAnimationObject, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::Media::IBrush, Windows::UI::Xaml::Media::IRevealBrush, Windows::UI::Xaml::Media::IXamlCompositionBrushBase, Windows::UI::Xaml::Media::IXamlCompositionBrushBaseProtected>,
    impl::base<D, Windows::UI::Xaml::Media::RevealBorderBrush, Windows::UI::Xaml::Media::RevealBrush, Windows::UI::Xaml::Media::XamlCompositionBrushBase, Windows::UI::Xaml::Media::Brush, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Media::IBrushOverrides2T<D>, Windows::UI::Xaml::Media::IXamlCompositionBrushBaseOverridesT<D>
{
    using composable = RevealBorderBrush;

protected:
    RevealBorderBrushT()
    {
        impl::call_factory<Windows::UI::Xaml::Media::RevealBorderBrush, Windows::UI::Xaml::Media::IRevealBorderBrushFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct RevealBrushT :
    implements<D, Windows::UI::Xaml::Media::IBrushOverrides2, Windows::UI::Xaml::Media::IXamlCompositionBrushBaseOverrides, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Media::IRevealBrush, Windows::UI::Composition::IAnimationObject, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::Media::IBrush, Windows::UI::Xaml::Media::IXamlCompositionBrushBase, Windows::UI::Xaml::Media::IXamlCompositionBrushBaseProtected>,
    impl::base<D, Windows::UI::Xaml::Media::RevealBrush, Windows::UI::Xaml::Media::XamlCompositionBrushBase, Windows::UI::Xaml::Media::Brush, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Media::IBrushOverrides2T<D>, Windows::UI::Xaml::Media::IXamlCompositionBrushBaseOverridesT<D>
{
    using composable = RevealBrush;

protected:
    RevealBrushT()
    {
        impl::call_factory<Windows::UI::Xaml::Media::RevealBrush, Windows::UI::Xaml::Media::IRevealBrushFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ThemeShadowT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Media::IThemeShadow, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::Media::IShadow>,
    impl::base<D, Windows::UI::Xaml::Media::ThemeShadow, Windows::UI::Xaml::Media::Shadow, Windows::UI::Xaml::DependencyObject>
{
    using composable = ThemeShadow;

protected:
    ThemeShadowT()
    {
        impl::call_factory<Windows::UI::Xaml::Media::ThemeShadow, Windows::UI::Xaml::Media::IThemeShadowFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct TileBrushT :
    implements<D, Windows::UI::Xaml::Media::IBrushOverrides2, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Media::ITileBrush, Windows::UI::Composition::IAnimationObject, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::Media::IBrush>,
    impl::base<D, Windows::UI::Xaml::Media::TileBrush, Windows::UI::Xaml::Media::Brush, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Media::IBrushOverrides2T<D>
{
    using composable = TileBrush;

protected:
    TileBrushT()
    {
        impl::call_factory<Windows::UI::Xaml::Media::TileBrush, Windows::UI::Xaml::Media::ITileBrushFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct XamlCompositionBrushBaseT :
    implements<D, Windows::UI::Xaml::Media::IBrushOverrides2, Windows::UI::Xaml::Media::IXamlCompositionBrushBaseOverrides, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Media::IXamlCompositionBrushBase, Windows::UI::Composition::IAnimationObject, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::Media::IBrush, Windows::UI::Xaml::Media::IXamlCompositionBrushBaseProtected>,
    impl::base<D, Windows::UI::Xaml::Media::XamlCompositionBrushBase, Windows::UI::Xaml::Media::Brush, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Media::IBrushOverrides2T<D>, Windows::UI::Xaml::Media::IXamlCompositionBrushBaseOverridesT<D>
{
    using composable = XamlCompositionBrushBase;

protected:
    XamlCompositionBrushBaseT()
    {
        impl::call_factory<Windows::UI::Xaml::Media::XamlCompositionBrushBase, Windows::UI::Xaml::Media::IXamlCompositionBrushBaseFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct XamlLightT :
    implements<D, Windows::UI::Xaml::Media::IXamlLightOverrides, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Media::IXamlLight, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::Media::IXamlLightProtected>,
    impl::base<D, Windows::UI::Xaml::Media::XamlLight, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Media::IXamlLightOverridesT<D>
{
    using composable = XamlLight;

protected:
    XamlLightT()
    {
        impl::call_factory<Windows::UI::Xaml::Media::XamlLight, Windows::UI::Xaml::Media::IXamlLightFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Xaml::Media::IAcrylicBrush> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IAcrylicBrush> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IAcrylicBrush2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IAcrylicBrush2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IAcrylicBrushFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IAcrylicBrushFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IAcrylicBrushStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IAcrylicBrushStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IAcrylicBrushStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IAcrylicBrushStatics2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IArcSegment> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IArcSegment> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IArcSegmentStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IArcSegmentStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IBezierSegment> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IBezierSegment> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IBezierSegmentStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IBezierSegmentStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IBitmapCache> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IBitmapCache> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IBrush> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IBrush> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IBrushFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IBrushFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IBrushOverrides2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IBrushOverrides2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IBrushStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IBrushStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ICacheMode> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ICacheMode> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ICacheModeFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ICacheModeFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ICompositeTransform> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ICompositeTransform> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ICompositeTransformStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ICompositeTransformStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ICompositionTarget> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ICompositionTarget> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ICompositionTargetStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ICompositionTargetStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ICompositionTargetStatics3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ICompositionTargetStatics3> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IEllipseGeometry> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IEllipseGeometry> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IEllipseGeometryStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IEllipseGeometryStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IFontFamily> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IFontFamily> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IFontFamilyFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IFontFamilyFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IFontFamilyStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IFontFamilyStatics2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IGeneralTransform> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IGeneralTransform> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IGeneralTransformFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IGeneralTransformFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IGeneralTransformOverrides> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IGeneralTransformOverrides> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IGeometry> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IGeometry> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IGeometryFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IGeometryFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IGeometryGroup> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IGeometryGroup> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IGeometryGroupStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IGeometryGroupStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IGeometryStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IGeometryStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IGradientBrush> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IGradientBrush> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IGradientBrushFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IGradientBrushFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IGradientBrushStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IGradientBrushStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IGradientStop> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IGradientStop> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IGradientStopStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IGradientStopStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IImageBrush> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IImageBrush> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IImageBrushStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IImageBrushStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IImageSource> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IImageSource> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IImageSourceFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IImageSourceFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ILineGeometry> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ILineGeometry> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ILineGeometryStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ILineGeometryStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ILineSegment> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ILineSegment> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ILineSegmentStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ILineSegmentStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ILinearGradientBrush> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ILinearGradientBrush> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ILinearGradientBrushFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ILinearGradientBrushFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ILinearGradientBrushStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ILinearGradientBrushStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ILoadedImageSourceLoadCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ILoadedImageSourceLoadCompletedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ILoadedImageSurface> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ILoadedImageSurface> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ILoadedImageSurfaceStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ILoadedImageSurfaceStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IMatrix3DProjection> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IMatrix3DProjection> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IMatrix3DProjectionStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IMatrix3DProjectionStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IMatrixHelper> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IMatrixHelper> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IMatrixHelperStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IMatrixHelperStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IMatrixTransform> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IMatrixTransform> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IMatrixTransformStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IMatrixTransformStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IMediaTransportControlsThumbnailRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IMediaTransportControlsThumbnailRequestedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IPartialMediaFailureDetectedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IPartialMediaFailureDetectedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IPartialMediaFailureDetectedEventArgs2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IPartialMediaFailureDetectedEventArgs2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IPathFigure> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IPathFigure> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IPathFigureStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IPathFigureStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IPathGeometry> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IPathGeometry> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IPathGeometryStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IPathGeometryStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IPathSegment> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IPathSegment> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IPathSegmentFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IPathSegmentFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IPlaneProjection> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IPlaneProjection> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IPlaneProjectionStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IPlaneProjectionStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IPolyBezierSegment> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IPolyBezierSegment> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IPolyBezierSegmentStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IPolyBezierSegmentStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IPolyLineSegment> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IPolyLineSegment> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IPolyLineSegmentStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IPolyLineSegmentStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IPolyQuadraticBezierSegment> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IPolyQuadraticBezierSegment> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IPolyQuadraticBezierSegmentStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IPolyQuadraticBezierSegmentStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IProjection> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IProjection> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IProjectionFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IProjectionFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IQuadraticBezierSegment> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IQuadraticBezierSegment> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IQuadraticBezierSegmentStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IQuadraticBezierSegmentStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IRateChangedRoutedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IRateChangedRoutedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IRectangleGeometry> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IRectangleGeometry> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IRectangleGeometryStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IRectangleGeometryStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IRenderedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IRenderedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IRenderingEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IRenderingEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IRevealBackgroundBrush> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IRevealBackgroundBrush> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IRevealBackgroundBrushFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IRevealBackgroundBrushFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IRevealBorderBrush> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IRevealBorderBrush> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IRevealBorderBrushFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IRevealBorderBrushFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IRevealBrush> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IRevealBrush> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IRevealBrushFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IRevealBrushFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IRevealBrushStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IRevealBrushStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IRotateTransform> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IRotateTransform> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IRotateTransformStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IRotateTransformStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IScaleTransform> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IScaleTransform> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IScaleTransformStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IScaleTransformStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IShadow> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IShadow> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IShadowFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IShadowFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ISkewTransform> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ISkewTransform> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ISkewTransformStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ISkewTransformStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ISolidColorBrush> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ISolidColorBrush> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ISolidColorBrushFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ISolidColorBrushFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ISolidColorBrushStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ISolidColorBrushStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IThemeShadow> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IThemeShadow> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IThemeShadowFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IThemeShadowFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ITileBrush> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ITileBrush> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ITileBrushFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ITileBrushFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ITileBrushStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ITileBrushStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ITimelineMarker> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ITimelineMarker> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ITimelineMarkerRoutedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ITimelineMarkerRoutedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ITimelineMarkerStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ITimelineMarkerStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ITransform> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ITransform> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ITransformFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ITransformFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ITransformGroup> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ITransformGroup> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ITransformGroupStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ITransformGroupStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ITranslateTransform> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ITranslateTransform> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ITranslateTransformStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ITranslateTransformStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IVisualTreeHelper> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IVisualTreeHelper> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IVisualTreeHelperStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IVisualTreeHelperStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IVisualTreeHelperStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IVisualTreeHelperStatics2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IVisualTreeHelperStatics3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IVisualTreeHelperStatics3> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IXamlCompositionBrushBase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IXamlCompositionBrushBase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IXamlCompositionBrushBaseFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IXamlCompositionBrushBaseFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IXamlCompositionBrushBaseOverrides> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IXamlCompositionBrushBaseOverrides> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IXamlCompositionBrushBaseProtected> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IXamlCompositionBrushBaseProtected> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IXamlCompositionBrushBaseStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IXamlCompositionBrushBaseStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IXamlLight> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IXamlLight> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IXamlLightFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IXamlLightFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IXamlLightOverrides> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IXamlLightOverrides> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IXamlLightProtected> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IXamlLightProtected> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::IXamlLightStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::IXamlLightStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::AcrylicBrush> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::AcrylicBrush> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ArcSegment> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ArcSegment> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::BezierSegment> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::BezierSegment> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::BitmapCache> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::BitmapCache> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Brush> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Brush> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::BrushCollection> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::BrushCollection> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::CacheMode> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::CacheMode> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::CompositeTransform> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::CompositeTransform> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::CompositionTarget> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::CompositionTarget> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::DoubleCollection> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::DoubleCollection> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::EllipseGeometry> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::EllipseGeometry> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::FontFamily> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::FontFamily> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::GeneralTransform> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::GeneralTransform> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Geometry> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Geometry> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::GeometryCollection> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::GeometryCollection> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::GeometryGroup> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::GeometryGroup> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::GradientBrush> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::GradientBrush> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::GradientStop> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::GradientStop> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::GradientStopCollection> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::GradientStopCollection> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ImageBrush> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ImageBrush> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ImageSource> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ImageSource> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::LineGeometry> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::LineGeometry> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::LineSegment> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::LineSegment> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::LinearGradientBrush> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::LinearGradientBrush> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::LoadedImageSourceLoadCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::LoadedImageSourceLoadCompletedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::LoadedImageSurface> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::LoadedImageSurface> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Matrix3DProjection> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Matrix3DProjection> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::MatrixHelper> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::MatrixHelper> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::MatrixTransform> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::MatrixTransform> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::MediaTransportControlsThumbnailRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::MediaTransportControlsThumbnailRequestedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::PartialMediaFailureDetectedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::PartialMediaFailureDetectedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::PathFigure> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::PathFigure> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::PathFigureCollection> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::PathFigureCollection> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::PathGeometry> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::PathGeometry> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::PathSegment> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::PathSegment> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::PathSegmentCollection> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::PathSegmentCollection> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::PlaneProjection> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::PlaneProjection> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::PointCollection> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::PointCollection> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::PolyBezierSegment> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::PolyBezierSegment> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::PolyLineSegment> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::PolyLineSegment> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::PolyQuadraticBezierSegment> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::PolyQuadraticBezierSegment> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Projection> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Projection> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::QuadraticBezierSegment> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::QuadraticBezierSegment> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::RateChangedRoutedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::RateChangedRoutedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::RectangleGeometry> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::RectangleGeometry> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::RenderedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::RenderedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::RenderingEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::RenderingEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::RevealBackgroundBrush> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::RevealBackgroundBrush> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::RevealBorderBrush> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::RevealBorderBrush> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::RevealBrush> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::RevealBrush> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::RotateTransform> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::RotateTransform> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ScaleTransform> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ScaleTransform> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Shadow> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Shadow> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::SkewTransform> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::SkewTransform> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::SolidColorBrush> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::SolidColorBrush> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::ThemeShadow> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::ThemeShadow> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::TileBrush> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::TileBrush> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::TimelineMarker> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::TimelineMarker> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::TimelineMarkerCollection> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::TimelineMarkerCollection> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::TimelineMarkerRoutedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::TimelineMarkerRoutedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Transform> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Transform> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::TransformCollection> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::TransformCollection> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::TransformGroup> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::TransformGroup> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::TranslateTransform> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::TranslateTransform> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::VisualTreeHelper> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::VisualTreeHelper> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::XamlCompositionBrushBase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::XamlCompositionBrushBase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::XamlLight> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::XamlLight> {};

}
