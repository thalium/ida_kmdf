// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.UI.Core.2.h"
#include "winrt/impl/Windows.UI.Input.2.h"
#include "winrt/impl/Windows.UI.Input.Inking.2.h"
#include "winrt/Windows.UI.Input.h"

namespace winrt::impl {

template <typename D> Windows::UI::Color consume_Windows_UI_Input_Inking_IInkDrawingAttributes<D>::Color() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkDrawingAttributes)->get_Color(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkDrawingAttributes<D>::Color(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkDrawingAttributes)->put_Color(get_abi(value)));
}

template <typename D> Windows::UI::Input::Inking::PenTipShape consume_Windows_UI_Input_Inking_IInkDrawingAttributes<D>::PenTip() const
{
    Windows::UI::Input::Inking::PenTipShape value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkDrawingAttributes)->get_PenTip(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkDrawingAttributes<D>::PenTip(Windows::UI::Input::Inking::PenTipShape const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkDrawingAttributes)->put_PenTip(get_abi(value)));
}

template <typename D> Windows::Foundation::Size consume_Windows_UI_Input_Inking_IInkDrawingAttributes<D>::Size() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkDrawingAttributes)->get_Size(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkDrawingAttributes<D>::Size(Windows::Foundation::Size const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkDrawingAttributes)->put_Size(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Input_Inking_IInkDrawingAttributes<D>::IgnorePressure() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkDrawingAttributes)->get_IgnorePressure(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkDrawingAttributes<D>::IgnorePressure(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkDrawingAttributes)->put_IgnorePressure(value));
}

template <typename D> bool consume_Windows_UI_Input_Inking_IInkDrawingAttributes<D>::FitToCurve() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkDrawingAttributes)->get_FitToCurve(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkDrawingAttributes<D>::FitToCurve(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkDrawingAttributes)->put_FitToCurve(value));
}

template <typename D> Windows::Foundation::Numerics::float3x2 consume_Windows_UI_Input_Inking_IInkDrawingAttributes2<D>::PenTipTransform() const
{
    Windows::Foundation::Numerics::float3x2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkDrawingAttributes2)->get_PenTipTransform(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkDrawingAttributes2<D>::PenTipTransform(Windows::Foundation::Numerics::float3x2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkDrawingAttributes2)->put_PenTipTransform(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Input_Inking_IInkDrawingAttributes2<D>::DrawAsHighlighter() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkDrawingAttributes2)->get_DrawAsHighlighter(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkDrawingAttributes2<D>::DrawAsHighlighter(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkDrawingAttributes2)->put_DrawAsHighlighter(value));
}

template <typename D> Windows::UI::Input::Inking::InkDrawingAttributesKind consume_Windows_UI_Input_Inking_IInkDrawingAttributes3<D>::Kind() const
{
    Windows::UI::Input::Inking::InkDrawingAttributesKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkDrawingAttributes3)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Inking::InkDrawingAttributesPencilProperties consume_Windows_UI_Input_Inking_IInkDrawingAttributes3<D>::PencilProperties() const
{
    Windows::UI::Input::Inking::InkDrawingAttributesPencilProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkDrawingAttributes3)->get_PencilProperties(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_Inking_IInkDrawingAttributes4<D>::IgnoreTilt() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkDrawingAttributes4)->get_IgnoreTilt(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkDrawingAttributes4<D>::IgnoreTilt(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkDrawingAttributes4)->put_IgnoreTilt(value));
}

template <typename D> Windows::UI::Input::Inking::InkModelerAttributes consume_Windows_UI_Input_Inking_IInkDrawingAttributes5<D>::ModelerAttributes() const
{
    Windows::UI::Input::Inking::InkModelerAttributes value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkDrawingAttributes5)->get_ModelerAttributes(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Input_Inking_IInkDrawingAttributesPencilProperties<D>::Opacity() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkDrawingAttributesPencilProperties)->get_Opacity(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkDrawingAttributesPencilProperties<D>::Opacity(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkDrawingAttributesPencilProperties)->put_Opacity(value));
}

template <typename D> Windows::UI::Input::Inking::InkDrawingAttributes consume_Windows_UI_Input_Inking_IInkDrawingAttributesStatics<D>::CreateForPencil() const
{
    Windows::UI::Input::Inking::InkDrawingAttributes result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkDrawingAttributesStatics)->CreateForPencil(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_Input_Inking_IInkInputConfiguration<D>::IsPrimaryBarrelButtonInputEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkInputConfiguration)->get_IsPrimaryBarrelButtonInputEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkInputConfiguration<D>::IsPrimaryBarrelButtonInputEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkInputConfiguration)->put_IsPrimaryBarrelButtonInputEnabled(value));
}

template <typename D> bool consume_Windows_UI_Input_Inking_IInkInputConfiguration<D>::IsEraserInputEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkInputConfiguration)->get_IsEraserInputEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkInputConfiguration<D>::IsEraserInputEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkInputConfiguration)->put_IsEraserInputEnabled(value));
}

template <typename D> Windows::UI::Input::Inking::InkInputProcessingMode consume_Windows_UI_Input_Inking_IInkInputProcessingConfiguration<D>::Mode() const
{
    Windows::UI::Input::Inking::InkInputProcessingMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkInputProcessingConfiguration)->get_Mode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkInputProcessingConfiguration<D>::Mode(Windows::UI::Input::Inking::InkInputProcessingMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkInputProcessingConfiguration)->put_Mode(get_abi(value)));
}

template <typename D> Windows::UI::Input::Inking::InkInputRightDragAction consume_Windows_UI_Input_Inking_IInkInputProcessingConfiguration<D>::RightDragAction() const
{
    Windows::UI::Input::Inking::InkInputRightDragAction value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkInputProcessingConfiguration)->get_RightDragAction(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkInputProcessingConfiguration<D>::RightDragAction(Windows::UI::Input::Inking::InkInputRightDragAction const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkInputProcessingConfiguration)->put_RightDragAction(get_abi(value)));
}

template <typename D> Windows::UI::Input::Inking::InkManipulationMode consume_Windows_UI_Input_Inking_IInkManager<D>::Mode() const
{
    Windows::UI::Input::Inking::InkManipulationMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkManager)->get_Mode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkManager<D>::Mode(Windows::UI::Input::Inking::InkManipulationMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkManager)->put_Mode(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkManager<D>::ProcessPointerDown(Windows::UI::Input::PointerPoint const& pointerPoint) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkManager)->ProcessPointerDown(get_abi(pointerPoint)));
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Input_Inking_IInkManager<D>::ProcessPointerUpdate(Windows::UI::Input::PointerPoint const& pointerPoint) const
{
    Windows::Foundation::IInspectable updateInformation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkManager)->ProcessPointerUpdate(get_abi(pointerPoint), put_abi(updateInformation)));
    return updateInformation;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Input_Inking_IInkManager<D>::ProcessPointerUp(Windows::UI::Input::PointerPoint const& pointerPoint) const
{
    Windows::Foundation::Rect updateRectangle{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkManager)->ProcessPointerUp(get_abi(pointerPoint), put_abi(updateRectangle)));
    return updateRectangle;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkManager<D>::SetDefaultDrawingAttributes(Windows::UI::Input::Inking::InkDrawingAttributes const& drawingAttributes) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkManager)->SetDefaultDrawingAttributes(get_abi(drawingAttributes)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkRecognitionResult>> consume_Windows_UI_Input_Inking_IInkManager<D>::RecognizeAsync(Windows::UI::Input::Inking::InkRecognitionTarget const& recognitionTarget) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkRecognitionResult>> recognitionResults{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkManager)->RecognizeAsync2(get_abi(recognitionTarget), put_abi(recognitionResults)));
    return recognitionResults;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_UI_Input_Inking_IInkModelerAttributes<D>::PredictionTime() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkModelerAttributes)->get_PredictionTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkModelerAttributes<D>::PredictionTime(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkModelerAttributes)->put_PredictionTime(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Input_Inking_IInkModelerAttributes<D>::ScalingFactor() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkModelerAttributes)->get_ScalingFactor(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkModelerAttributes<D>::ScalingFactor(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkModelerAttributes)->put_ScalingFactor(value));
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Input_Inking_IInkPoint<D>::Position() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPoint)->get_Position(put_abi(value)));
    return value;
}

template <typename D> float consume_Windows_UI_Input_Inking_IInkPoint<D>::Pressure() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPoint)->get_Pressure(&value));
    return value;
}

template <typename D> float consume_Windows_UI_Input_Inking_IInkPoint2<D>::TiltX() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPoint2)->get_TiltX(&value));
    return value;
}

template <typename D> float consume_Windows_UI_Input_Inking_IInkPoint2<D>::TiltY() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPoint2)->get_TiltY(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_UI_Input_Inking_IInkPoint2<D>::Timestamp() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPoint2)->get_Timestamp(&value));
    return value;
}

template <typename D> Windows::UI::Input::Inking::InkPoint consume_Windows_UI_Input_Inking_IInkPointFactory<D>::CreateInkPoint(Windows::Foundation::Point const& position, float pressure) const
{
    Windows::UI::Input::Inking::InkPoint result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPointFactory)->CreateInkPoint(get_abi(position), pressure, put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Input::Inking::InkPoint consume_Windows_UI_Input_Inking_IInkPointFactory2<D>::CreateInkPointWithTiltAndTimestamp(Windows::Foundation::Point const& position, float pressure, float tiltX, float tiltY, uint64_t timestamp) const
{
    Windows::UI::Input::Inking::InkPoint result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPointFactory2)->CreateInkPointWithTiltAndTimestamp(get_abi(position), pressure, tiltX, tiltY, timestamp, put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_Input_Inking_IInkPresenter<D>::IsInputEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenter)->get_IsInputEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkPresenter<D>::IsInputEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenter)->put_IsInputEnabled(value));
}

template <typename D> Windows::UI::Core::CoreInputDeviceTypes consume_Windows_UI_Input_Inking_IInkPresenter<D>::InputDeviceTypes() const
{
    Windows::UI::Core::CoreInputDeviceTypes value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenter)->get_InputDeviceTypes(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkPresenter<D>::InputDeviceTypes(Windows::UI::Core::CoreInputDeviceTypes const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenter)->put_InputDeviceTypes(get_abi(value)));
}

template <typename D> Windows::UI::Input::Inking::InkUnprocessedInput consume_Windows_UI_Input_Inking_IInkPresenter<D>::UnprocessedInput() const
{
    Windows::UI::Input::Inking::InkUnprocessedInput value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenter)->get_UnprocessedInput(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Inking::InkStrokeInput consume_Windows_UI_Input_Inking_IInkPresenter<D>::StrokeInput() const
{
    Windows::UI::Input::Inking::InkStrokeInput value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenter)->get_StrokeInput(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Inking::InkInputProcessingConfiguration consume_Windows_UI_Input_Inking_IInkPresenter<D>::InputProcessingConfiguration() const
{
    Windows::UI::Input::Inking::InkInputProcessingConfiguration value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenter)->get_InputProcessingConfiguration(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Inking::InkStrokeContainer consume_Windows_UI_Input_Inking_IInkPresenter<D>::StrokeContainer() const
{
    Windows::UI::Input::Inking::InkStrokeContainer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenter)->get_StrokeContainer(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkPresenter<D>::StrokeContainer(Windows::UI::Input::Inking::InkStrokeContainer const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenter)->put_StrokeContainer(get_abi(value)));
}

template <typename D> Windows::UI::Input::Inking::InkDrawingAttributes consume_Windows_UI_Input_Inking_IInkPresenter<D>::CopyDefaultDrawingAttributes() const
{
    Windows::UI::Input::Inking::InkDrawingAttributes value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenter)->CopyDefaultDrawingAttributes(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkPresenter<D>::UpdateDefaultDrawingAttributes(Windows::UI::Input::Inking::InkDrawingAttributes const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenter)->UpdateDefaultDrawingAttributes(get_abi(value)));
}

template <typename D> Windows::UI::Input::Inking::InkSynchronizer consume_Windows_UI_Input_Inking_IInkPresenter<D>::ActivateCustomDrying() const
{
    Windows::UI::Input::Inking::InkSynchronizer inkSynchronizer{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenter)->ActivateCustomDrying(put_abi(inkSynchronizer)));
    return inkSynchronizer;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkPresenter<D>::SetPredefinedConfiguration(Windows::UI::Input::Inking::InkPresenterPredefinedConfiguration const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenter)->SetPredefinedConfiguration(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Inking_IInkPresenter<D>::StrokesCollected(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkPresenter, Windows::UI::Input::Inking::InkStrokesCollectedEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenter)->add_StrokesCollected(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Input_Inking_IInkPresenter<D>::StrokesCollected_revoker consume_Windows_UI_Input_Inking_IInkPresenter<D>::StrokesCollected(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkPresenter, Windows::UI::Input::Inking::InkStrokesCollectedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, StrokesCollected_revoker>(this, StrokesCollected(handler));
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkPresenter<D>::StrokesCollected(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenter)->remove_StrokesCollected(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Inking_IInkPresenter<D>::StrokesErased(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkPresenter, Windows::UI::Input::Inking::InkStrokesErasedEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenter)->add_StrokesErased(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Input_Inking_IInkPresenter<D>::StrokesErased_revoker consume_Windows_UI_Input_Inking_IInkPresenter<D>::StrokesErased(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkPresenter, Windows::UI::Input::Inking::InkStrokesErasedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, StrokesErased_revoker>(this, StrokesErased(handler));
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkPresenter<D>::StrokesErased(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenter)->remove_StrokesErased(get_abi(cookie)));
}

template <typename D> Windows::UI::Input::Inking::InkHighContrastAdjustment consume_Windows_UI_Input_Inking_IInkPresenter2<D>::HighContrastAdjustment() const
{
    Windows::UI::Input::Inking::InkHighContrastAdjustment value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenter2)->get_HighContrastAdjustment(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkPresenter2<D>::HighContrastAdjustment(Windows::UI::Input::Inking::InkHighContrastAdjustment const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenter2)->put_HighContrastAdjustment(get_abi(value)));
}

template <typename D> Windows::UI::Input::Inking::InkInputConfiguration consume_Windows_UI_Input_Inking_IInkPresenter3<D>::InputConfiguration() const
{
    Windows::UI::Input::Inking::InkInputConfiguration value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenter3)->get_InputConfiguration(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_Inking_IInkPresenterProtractor<D>::AreTickMarksVisible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenterProtractor)->get_AreTickMarksVisible(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkPresenterProtractor<D>::AreTickMarksVisible(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenterProtractor)->put_AreTickMarksVisible(value));
}

template <typename D> bool consume_Windows_UI_Input_Inking_IInkPresenterProtractor<D>::AreRaysVisible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenterProtractor)->get_AreRaysVisible(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkPresenterProtractor<D>::AreRaysVisible(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenterProtractor)->put_AreRaysVisible(value));
}

template <typename D> bool consume_Windows_UI_Input_Inking_IInkPresenterProtractor<D>::IsCenterMarkerVisible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenterProtractor)->get_IsCenterMarkerVisible(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkPresenterProtractor<D>::IsCenterMarkerVisible(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenterProtractor)->put_IsCenterMarkerVisible(value));
}

template <typename D> bool consume_Windows_UI_Input_Inking_IInkPresenterProtractor<D>::IsAngleReadoutVisible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenterProtractor)->get_IsAngleReadoutVisible(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkPresenterProtractor<D>::IsAngleReadoutVisible(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenterProtractor)->put_IsAngleReadoutVisible(value));
}

template <typename D> bool consume_Windows_UI_Input_Inking_IInkPresenterProtractor<D>::IsResizable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenterProtractor)->get_IsResizable(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkPresenterProtractor<D>::IsResizable(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenterProtractor)->put_IsResizable(value));
}

template <typename D> double consume_Windows_UI_Input_Inking_IInkPresenterProtractor<D>::Radius() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenterProtractor)->get_Radius(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkPresenterProtractor<D>::Radius(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenterProtractor)->put_Radius(value));
}

template <typename D> Windows::UI::Color consume_Windows_UI_Input_Inking_IInkPresenterProtractor<D>::AccentColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenterProtractor)->get_AccentColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkPresenterProtractor<D>::AccentColor(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenterProtractor)->put_AccentColor(get_abi(value)));
}

template <typename D> Windows::UI::Input::Inking::InkPresenterProtractor consume_Windows_UI_Input_Inking_IInkPresenterProtractorFactory<D>::Create(Windows::UI::Input::Inking::InkPresenter const& inkPresenter) const
{
    Windows::UI::Input::Inking::InkPresenterProtractor inkPresenterProtractor{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenterProtractorFactory)->Create(get_abi(inkPresenter), put_abi(inkPresenterProtractor)));
    return inkPresenterProtractor;
}

template <typename D> double consume_Windows_UI_Input_Inking_IInkPresenterRuler<D>::Length() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenterRuler)->get_Length(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkPresenterRuler<D>::Length(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenterRuler)->put_Length(value));
}

template <typename D> double consume_Windows_UI_Input_Inking_IInkPresenterRuler<D>::Width() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenterRuler)->get_Width(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkPresenterRuler<D>::Width(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenterRuler)->put_Width(value));
}

template <typename D> bool consume_Windows_UI_Input_Inking_IInkPresenterRuler2<D>::AreTickMarksVisible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenterRuler2)->get_AreTickMarksVisible(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkPresenterRuler2<D>::AreTickMarksVisible(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenterRuler2)->put_AreTickMarksVisible(value));
}

template <typename D> bool consume_Windows_UI_Input_Inking_IInkPresenterRuler2<D>::IsCompassVisible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenterRuler2)->get_IsCompassVisible(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkPresenterRuler2<D>::IsCompassVisible(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenterRuler2)->put_IsCompassVisible(value));
}

template <typename D> Windows::UI::Input::Inking::InkPresenterRuler consume_Windows_UI_Input_Inking_IInkPresenterRulerFactory<D>::Create(Windows::UI::Input::Inking::InkPresenter const& inkPresenter) const
{
    Windows::UI::Input::Inking::InkPresenterRuler inkPresenterRuler{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenterRulerFactory)->Create(get_abi(inkPresenter), put_abi(inkPresenterRuler)));
    return inkPresenterRuler;
}

template <typename D> Windows::UI::Input::Inking::InkPresenterStencilKind consume_Windows_UI_Input_Inking_IInkPresenterStencil<D>::Kind() const
{
    Windows::UI::Input::Inking::InkPresenterStencilKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenterStencil)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_Inking_IInkPresenterStencil<D>::IsVisible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenterStencil)->get_IsVisible(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkPresenterStencil<D>::IsVisible(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenterStencil)->put_IsVisible(value));
}

template <typename D> Windows::UI::Color consume_Windows_UI_Input_Inking_IInkPresenterStencil<D>::BackgroundColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenterStencil)->get_BackgroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkPresenterStencil<D>::BackgroundColor(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenterStencil)->put_BackgroundColor(get_abi(value)));
}

template <typename D> Windows::UI::Color consume_Windows_UI_Input_Inking_IInkPresenterStencil<D>::ForegroundColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenterStencil)->get_ForegroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkPresenterStencil<D>::ForegroundColor(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenterStencil)->put_ForegroundColor(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float3x2 consume_Windows_UI_Input_Inking_IInkPresenterStencil<D>::Transform() const
{
    Windows::Foundation::Numerics::float3x2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenterStencil)->get_Transform(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkPresenterStencil<D>::Transform(Windows::Foundation::Numerics::float3x2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkPresenterStencil)->put_Transform(get_abi(value)));
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Input_Inking_IInkRecognitionResult<D>::BoundingRect() const
{
    Windows::Foundation::Rect boundingRect{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkRecognitionResult)->get_BoundingRect(put_abi(boundingRect)));
    return boundingRect;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_UI_Input_Inking_IInkRecognitionResult<D>::GetTextCandidates() const
{
    Windows::Foundation::Collections::IVectorView<hstring> textCandidates{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkRecognitionResult)->GetTextCandidates(put_abi(textCandidates)));
    return textCandidates;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkStroke> consume_Windows_UI_Input_Inking_IInkRecognitionResult<D>::GetStrokes() const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkStroke> strokes{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkRecognitionResult)->GetStrokes(put_abi(strokes)));
    return strokes;
}

template <typename D> hstring consume_Windows_UI_Input_Inking_IInkRecognizer<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkRecognizer)->get_Name(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkRecognizerContainer<D>::SetDefaultRecognizer(Windows::UI::Input::Inking::InkRecognizer const& recognizer) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkRecognizerContainer)->SetDefaultRecognizer(get_abi(recognizer)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkRecognitionResult>> consume_Windows_UI_Input_Inking_IInkRecognizerContainer<D>::RecognizeAsync(Windows::UI::Input::Inking::InkStrokeContainer const& strokeCollection, Windows::UI::Input::Inking::InkRecognitionTarget const& recognitionTarget) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkRecognitionResult>> recognitionResults{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkRecognizerContainer)->RecognizeAsync(get_abi(strokeCollection), get_abi(recognitionTarget), put_abi(recognitionResults)));
    return recognitionResults;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkRecognizer> consume_Windows_UI_Input_Inking_IInkRecognizerContainer<D>::GetRecognizers() const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkRecognizer> recognizerView{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkRecognizerContainer)->GetRecognizers(put_abi(recognizerView)));
    return recognizerView;
}

template <typename D> Windows::UI::Input::Inking::InkDrawingAttributes consume_Windows_UI_Input_Inking_IInkStroke<D>::DrawingAttributes() const
{
    Windows::UI::Input::Inking::InkDrawingAttributes value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStroke)->get_DrawingAttributes(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkStroke<D>::DrawingAttributes(Windows::UI::Input::Inking::InkDrawingAttributes const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStroke)->put_DrawingAttributes(get_abi(value)));
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Input_Inking_IInkStroke<D>::BoundingRect() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStroke)->get_BoundingRect(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_Inking_IInkStroke<D>::Selected() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStroke)->get_Selected(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkStroke<D>::Selected(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStroke)->put_Selected(value));
}

template <typename D> bool consume_Windows_UI_Input_Inking_IInkStroke<D>::Recognized() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStroke)->get_Recognized(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkStrokeRenderingSegment> consume_Windows_UI_Input_Inking_IInkStroke<D>::GetRenderingSegments() const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkStrokeRenderingSegment> renderingSegments{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStroke)->GetRenderingSegments(put_abi(renderingSegments)));
    return renderingSegments;
}

template <typename D> Windows::UI::Input::Inking::InkStroke consume_Windows_UI_Input_Inking_IInkStroke<D>::Clone() const
{
    Windows::UI::Input::Inking::InkStroke clonedStroke{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStroke)->Clone(put_abi(clonedStroke)));
    return clonedStroke;
}

template <typename D> Windows::Foundation::Numerics::float3x2 consume_Windows_UI_Input_Inking_IInkStroke2<D>::PointTransform() const
{
    Windows::Foundation::Numerics::float3x2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStroke2)->get_PointTransform(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkStroke2<D>::PointTransform(Windows::Foundation::Numerics::float3x2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStroke2)->put_PointTransform(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkPoint> consume_Windows_UI_Input_Inking_IInkStroke2<D>::GetInkPoints() const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkPoint> inkPoints{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStroke2)->GetInkPoints(put_abi(inkPoints)));
    return inkPoints;
}

template <typename D> uint32_t consume_Windows_UI_Input_Inking_IInkStroke3<D>::Id() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStroke3)->get_Id(&value));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_UI_Input_Inking_IInkStroke3<D>::StrokeStartedTime() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStroke3)->get_StrokeStartedTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkStroke3<D>::StrokeStartedTime(optional<Windows::Foundation::DateTime> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStroke3)->put_StrokeStartedTime(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_UI_Input_Inking_IInkStroke3<D>::StrokeDuration() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStroke3)->get_StrokeDuration(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkStroke3<D>::StrokeDuration(optional<Windows::Foundation::TimeSpan> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStroke3)->put_StrokeDuration(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkStrokeBuilder<D>::BeginStroke(Windows::UI::Input::PointerPoint const& pointerPoint) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeBuilder)->BeginStroke(get_abi(pointerPoint)));
}

template <typename D> Windows::UI::Input::PointerPoint consume_Windows_UI_Input_Inking_IInkStrokeBuilder<D>::AppendToStroke(Windows::UI::Input::PointerPoint const& pointerPoint) const
{
    Windows::UI::Input::PointerPoint previousPointerPoint{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeBuilder)->AppendToStroke(get_abi(pointerPoint), put_abi(previousPointerPoint)));
    return previousPointerPoint;
}

template <typename D> Windows::UI::Input::Inking::InkStroke consume_Windows_UI_Input_Inking_IInkStrokeBuilder<D>::EndStroke(Windows::UI::Input::PointerPoint const& pointerPoint) const
{
    Windows::UI::Input::Inking::InkStroke stroke{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeBuilder)->EndStroke(get_abi(pointerPoint), put_abi(stroke)));
    return stroke;
}

template <typename D> Windows::UI::Input::Inking::InkStroke consume_Windows_UI_Input_Inking_IInkStrokeBuilder<D>::CreateStroke(param::iterable<Windows::Foundation::Point> const& points) const
{
    Windows::UI::Input::Inking::InkStroke stroke{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeBuilder)->CreateStroke(get_abi(points), put_abi(stroke)));
    return stroke;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkStrokeBuilder<D>::SetDefaultDrawingAttributes(Windows::UI::Input::Inking::InkDrawingAttributes const& drawingAttributes) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeBuilder)->SetDefaultDrawingAttributes(get_abi(drawingAttributes)));
}

template <typename D> Windows::UI::Input::Inking::InkStroke consume_Windows_UI_Input_Inking_IInkStrokeBuilder2<D>::CreateStrokeFromInkPoints(param::iterable<Windows::UI::Input::Inking::InkPoint> const& inkPoints, Windows::Foundation::Numerics::float3x2 const& transform) const
{
    Windows::UI::Input::Inking::InkStroke result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeBuilder2)->CreateStrokeFromInkPoints(get_abi(inkPoints), get_abi(transform), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Input::Inking::InkStroke consume_Windows_UI_Input_Inking_IInkStrokeBuilder3<D>::CreateStrokeFromInkPoints(param::iterable<Windows::UI::Input::Inking::InkPoint> const& inkPoints, Windows::Foundation::Numerics::float3x2 const& transform, optional<Windows::Foundation::DateTime> const& strokeStartedTime, optional<Windows::Foundation::TimeSpan> const& strokeDuration) const
{
    Windows::UI::Input::Inking::InkStroke result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeBuilder3)->CreateStrokeFromInkPoints(get_abi(inkPoints), get_abi(transform), get_abi(strokeStartedTime), get_abi(strokeDuration), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Input_Inking_IInkStrokeContainer<D>::BoundingRect() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeContainer)->get_BoundingRect(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkStrokeContainer<D>::AddStroke(Windows::UI::Input::Inking::InkStroke const& stroke) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeContainer)->AddStroke(get_abi(stroke)));
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Input_Inking_IInkStrokeContainer<D>::DeleteSelected() const
{
    Windows::Foundation::Rect invalidatedRect{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeContainer)->DeleteSelected(put_abi(invalidatedRect)));
    return invalidatedRect;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Input_Inking_IInkStrokeContainer<D>::MoveSelected(Windows::Foundation::Point const& translation) const
{
    Windows::Foundation::Rect invalidatedRectangle{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeContainer)->MoveSelected(get_abi(translation), put_abi(invalidatedRectangle)));
    return invalidatedRectangle;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Input_Inking_IInkStrokeContainer<D>::SelectWithPolyLine(param::iterable<Windows::Foundation::Point> const& polyline) const
{
    Windows::Foundation::Rect invalidatedRectangle{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeContainer)->SelectWithPolyLine(get_abi(polyline), put_abi(invalidatedRectangle)));
    return invalidatedRectangle;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Input_Inking_IInkStrokeContainer<D>::SelectWithLine(Windows::Foundation::Point const& from, Windows::Foundation::Point const& to) const
{
    Windows::Foundation::Rect invalidatedRectangle{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeContainer)->SelectWithLine(get_abi(from), get_abi(to), put_abi(invalidatedRectangle)));
    return invalidatedRectangle;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkStrokeContainer<D>::CopySelectedToClipboard() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeContainer)->CopySelectedToClipboard());
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Input_Inking_IInkStrokeContainer<D>::PasteFromClipboard(Windows::Foundation::Point const& position) const
{
    Windows::Foundation::Rect invalidatedRectangle{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeContainer)->PasteFromClipboard(get_abi(position), put_abi(invalidatedRectangle)));
    return invalidatedRectangle;
}

template <typename D> bool consume_Windows_UI_Input_Inking_IInkStrokeContainer<D>::CanPasteFromClipboard() const
{
    bool canPaste{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeContainer)->CanPasteFromClipboard(&canPaste));
    return canPaste;
}

template <typename D> Windows::Foundation::IAsyncActionWithProgress<uint64_t> consume_Windows_UI_Input_Inking_IInkStrokeContainer<D>::LoadAsync(Windows::Storage::Streams::IInputStream const& inputStream) const
{
    Windows::Foundation::IAsyncActionWithProgress<uint64_t> loadAction{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeContainer)->LoadAsync(get_abi(inputStream), put_abi(loadAction)));
    return loadAction;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t> consume_Windows_UI_Input_Inking_IInkStrokeContainer<D>::SaveAsync(Windows::Storage::Streams::IOutputStream const& outputStream) const
{
    Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t> outputStreamOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeContainer)->SaveAsync(get_abi(outputStream), put_abi(outputStreamOperation)));
    return outputStreamOperation;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkStrokeContainer<D>::UpdateRecognitionResults(param::vector_view<Windows::UI::Input::Inking::InkRecognitionResult> const& recognitionResults) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeContainer)->UpdateRecognitionResults(get_abi(recognitionResults)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkStroke> consume_Windows_UI_Input_Inking_IInkStrokeContainer<D>::GetStrokes() const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkStroke> strokeView{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeContainer)->GetStrokes(put_abi(strokeView)));
    return strokeView;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkRecognitionResult> consume_Windows_UI_Input_Inking_IInkStrokeContainer<D>::GetRecognitionResults() const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkRecognitionResult> recognitionResults{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeContainer)->GetRecognitionResults(put_abi(recognitionResults)));
    return recognitionResults;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkStrokeContainer2<D>::AddStrokes(param::iterable<Windows::UI::Input::Inking::InkStroke> const& strokes) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeContainer2)->AddStrokes(get_abi(strokes)));
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkStrokeContainer2<D>::Clear() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeContainer2)->Clear());
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t> consume_Windows_UI_Input_Inking_IInkStrokeContainer3<D>::SaveAsync(Windows::Storage::Streams::IOutputStream const& outputStream, Windows::UI::Input::Inking::InkPersistenceFormat const& inkPersistenceFormat) const
{
    Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t> outputStreamOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeContainer3)->SaveWithFormatAsync(get_abi(outputStream), get_abi(inkPersistenceFormat), put_abi(outputStreamOperation)));
    return outputStreamOperation;
}

template <typename D> Windows::UI::Input::Inking::InkStroke consume_Windows_UI_Input_Inking_IInkStrokeContainer3<D>::GetStrokeById(uint32_t id) const
{
    Windows::UI::Input::Inking::InkStroke stroke{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeContainer3)->GetStrokeById(id, put_abi(stroke)));
    return stroke;
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Inking_IInkStrokeInput<D>::StrokeStarted(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkStrokeInput, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeInput)->add_StrokeStarted(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Input_Inking_IInkStrokeInput<D>::StrokeStarted_revoker consume_Windows_UI_Input_Inking_IInkStrokeInput<D>::StrokeStarted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkStrokeInput, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, StrokeStarted_revoker>(this, StrokeStarted(handler));
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkStrokeInput<D>::StrokeStarted(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeInput)->remove_StrokeStarted(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Inking_IInkStrokeInput<D>::StrokeContinued(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkStrokeInput, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeInput)->add_StrokeContinued(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Input_Inking_IInkStrokeInput<D>::StrokeContinued_revoker consume_Windows_UI_Input_Inking_IInkStrokeInput<D>::StrokeContinued(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkStrokeInput, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, StrokeContinued_revoker>(this, StrokeContinued(handler));
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkStrokeInput<D>::StrokeContinued(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeInput)->remove_StrokeContinued(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Inking_IInkStrokeInput<D>::StrokeEnded(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkStrokeInput, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeInput)->add_StrokeEnded(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Input_Inking_IInkStrokeInput<D>::StrokeEnded_revoker consume_Windows_UI_Input_Inking_IInkStrokeInput<D>::StrokeEnded(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkStrokeInput, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, StrokeEnded_revoker>(this, StrokeEnded(handler));
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkStrokeInput<D>::StrokeEnded(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeInput)->remove_StrokeEnded(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Inking_IInkStrokeInput<D>::StrokeCanceled(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkStrokeInput, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeInput)->add_StrokeCanceled(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Input_Inking_IInkStrokeInput<D>::StrokeCanceled_revoker consume_Windows_UI_Input_Inking_IInkStrokeInput<D>::StrokeCanceled(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkStrokeInput, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, StrokeCanceled_revoker>(this, StrokeCanceled(handler));
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkStrokeInput<D>::StrokeCanceled(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeInput)->remove_StrokeCanceled(get_abi(cookie)));
}

template <typename D> Windows::UI::Input::Inking::InkPresenter consume_Windows_UI_Input_Inking_IInkStrokeInput<D>::InkPresenter() const
{
    Windows::UI::Input::Inking::InkPresenter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeInput)->get_InkPresenter(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Input_Inking_IInkStrokeRenderingSegment<D>::Position() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeRenderingSegment)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Input_Inking_IInkStrokeRenderingSegment<D>::BezierControlPoint1() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeRenderingSegment)->get_BezierControlPoint1(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Input_Inking_IInkStrokeRenderingSegment<D>::BezierControlPoint2() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeRenderingSegment)->get_BezierControlPoint2(put_abi(value)));
    return value;
}

template <typename D> float consume_Windows_UI_Input_Inking_IInkStrokeRenderingSegment<D>::Pressure() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeRenderingSegment)->get_Pressure(&value));
    return value;
}

template <typename D> float consume_Windows_UI_Input_Inking_IInkStrokeRenderingSegment<D>::TiltX() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeRenderingSegment)->get_TiltX(&value));
    return value;
}

template <typename D> float consume_Windows_UI_Input_Inking_IInkStrokeRenderingSegment<D>::TiltY() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeRenderingSegment)->get_TiltY(&value));
    return value;
}

template <typename D> float consume_Windows_UI_Input_Inking_IInkStrokeRenderingSegment<D>::Twist() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokeRenderingSegment)->get_Twist(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkStroke> consume_Windows_UI_Input_Inking_IInkStrokesCollectedEventArgs<D>::Strokes() const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkStroke> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokesCollectedEventArgs)->get_Strokes(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkStroke> consume_Windows_UI_Input_Inking_IInkStrokesErasedEventArgs<D>::Strokes() const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkStroke> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkStrokesErasedEventArgs)->get_Strokes(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkStroke> consume_Windows_UI_Input_Inking_IInkSynchronizer<D>::BeginDry() const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkStroke> inkStrokes{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkSynchronizer)->BeginDry(put_abi(inkStrokes)));
    return inkStrokes;
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkSynchronizer<D>::EndDry() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkSynchronizer)->EndDry());
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerEntered(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkUnprocessedInput, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkUnprocessedInput)->add_PointerEntered(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerEntered_revoker consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerEntered(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkUnprocessedInput, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PointerEntered_revoker>(this, PointerEntered(handler));
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerEntered(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Inking::IInkUnprocessedInput)->remove_PointerEntered(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerHovered(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkUnprocessedInput, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkUnprocessedInput)->add_PointerHovered(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerHovered_revoker consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerHovered(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkUnprocessedInput, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PointerHovered_revoker>(this, PointerHovered(handler));
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerHovered(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Inking::IInkUnprocessedInput)->remove_PointerHovered(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerExited(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkUnprocessedInput, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkUnprocessedInput)->add_PointerExited(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerExited_revoker consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerExited(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkUnprocessedInput, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PointerExited_revoker>(this, PointerExited(handler));
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerExited(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Inking::IInkUnprocessedInput)->remove_PointerExited(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerPressed(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkUnprocessedInput, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkUnprocessedInput)->add_PointerPressed(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerPressed_revoker consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerPressed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkUnprocessedInput, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PointerPressed_revoker>(this, PointerPressed(handler));
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerPressed(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Inking::IInkUnprocessedInput)->remove_PointerPressed(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerMoved(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkUnprocessedInput, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkUnprocessedInput)->add_PointerMoved(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerMoved_revoker consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerMoved(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkUnprocessedInput, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PointerMoved_revoker>(this, PointerMoved(handler));
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerMoved(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Inking::IInkUnprocessedInput)->remove_PointerMoved(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerReleased(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkUnprocessedInput, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkUnprocessedInput)->add_PointerReleased(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerReleased_revoker consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerReleased(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkUnprocessedInput, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PointerReleased_revoker>(this, PointerReleased(handler));
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerReleased(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Inking::IInkUnprocessedInput)->remove_PointerReleased(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerLost(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkUnprocessedInput, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkUnprocessedInput)->add_PointerLost(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerLost_revoker consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerLost(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkUnprocessedInput, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PointerLost_revoker>(this, PointerLost(handler));
}

template <typename D> void consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerLost(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Inking::IInkUnprocessedInput)->remove_PointerLost(get_abi(cookie)));
}

template <typename D> Windows::UI::Input::Inking::InkPresenter consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::InkPresenter() const
{
    Windows::UI::Input::Inking::InkPresenter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IInkUnprocessedInput)->get_InkPresenter(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_Inking_IPenAndInkSettings<D>::IsHandwritingDirectlyIntoTextFieldEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IPenAndInkSettings)->get_IsHandwritingDirectlyIntoTextFieldEnabled(&value));
    return value;
}

template <typename D> Windows::UI::Input::Inking::PenHandedness consume_Windows_UI_Input_Inking_IPenAndInkSettings<D>::PenHandedness() const
{
    Windows::UI::Input::Inking::PenHandedness value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IPenAndInkSettings)->get_PenHandedness(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Inking::HandwritingLineHeight consume_Windows_UI_Input_Inking_IPenAndInkSettings<D>::HandwritingLineHeight() const
{
    Windows::UI::Input::Inking::HandwritingLineHeight value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IPenAndInkSettings)->get_HandwritingLineHeight(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Input_Inking_IPenAndInkSettings<D>::FontFamilyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IPenAndInkSettings)->get_FontFamilyName(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_Inking_IPenAndInkSettings<D>::UserConsentsToHandwritingTelemetryCollection() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IPenAndInkSettings)->get_UserConsentsToHandwritingTelemetryCollection(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_Inking_IPenAndInkSettings<D>::IsTouchHandwritingEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IPenAndInkSettings)->get_IsTouchHandwritingEnabled(&value));
    return value;
}

template <typename D> Windows::UI::Input::Inking::PenAndInkSettings consume_Windows_UI_Input_Inking_IPenAndInkSettingsStatics<D>::GetDefault() const
{
    Windows::UI::Input::Inking::PenAndInkSettings result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::IPenAndInkSettingsStatics)->GetDefault(put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkDrawingAttributes> : produce_base<D, Windows::UI::Input::Inking::IInkDrawingAttributes>
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

    int32_t WINRT_CALL get_PenTip(Windows::UI::Input::Inking::PenTipShape* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PenTip, WINRT_WRAP(Windows::UI::Input::Inking::PenTipShape));
            *value = detach_from<Windows::UI::Input::Inking::PenTipShape>(this->shim().PenTip());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PenTip(Windows::UI::Input::Inking::PenTipShape value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PenTip, WINRT_WRAP(void), Windows::UI::Input::Inking::PenTipShape const&);
            this->shim().PenTip(*reinterpret_cast<Windows::UI::Input::Inking::PenTipShape const*>(&value));
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

    int32_t WINRT_CALL get_IgnorePressure(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IgnorePressure, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IgnorePressure());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IgnorePressure(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IgnorePressure, WINRT_WRAP(void), bool);
            this->shim().IgnorePressure(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FitToCurve(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FitToCurve, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().FitToCurve());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FitToCurve(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FitToCurve, WINRT_WRAP(void), bool);
            this->shim().FitToCurve(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkDrawingAttributes2> : produce_base<D, Windows::UI::Input::Inking::IInkDrawingAttributes2>
{
    int32_t WINRT_CALL get_PenTipTransform(Windows::Foundation::Numerics::float3x2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PenTipTransform, WINRT_WRAP(Windows::Foundation::Numerics::float3x2));
            *value = detach_from<Windows::Foundation::Numerics::float3x2>(this->shim().PenTipTransform());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PenTipTransform(Windows::Foundation::Numerics::float3x2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PenTipTransform, WINRT_WRAP(void), Windows::Foundation::Numerics::float3x2 const&);
            this->shim().PenTipTransform(*reinterpret_cast<Windows::Foundation::Numerics::float3x2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DrawAsHighlighter(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DrawAsHighlighter, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().DrawAsHighlighter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DrawAsHighlighter(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DrawAsHighlighter, WINRT_WRAP(void), bool);
            this->shim().DrawAsHighlighter(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkDrawingAttributes3> : produce_base<D, Windows::UI::Input::Inking::IInkDrawingAttributes3>
{
    int32_t WINRT_CALL get_Kind(Windows::UI::Input::Inking::InkDrawingAttributesKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::UI::Input::Inking::InkDrawingAttributesKind));
            *value = detach_from<Windows::UI::Input::Inking::InkDrawingAttributesKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PencilProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PencilProperties, WINRT_WRAP(Windows::UI::Input::Inking::InkDrawingAttributesPencilProperties));
            *value = detach_from<Windows::UI::Input::Inking::InkDrawingAttributesPencilProperties>(this->shim().PencilProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkDrawingAttributes4> : produce_base<D, Windows::UI::Input::Inking::IInkDrawingAttributes4>
{
    int32_t WINRT_CALL get_IgnoreTilt(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IgnoreTilt, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IgnoreTilt());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IgnoreTilt(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IgnoreTilt, WINRT_WRAP(void), bool);
            this->shim().IgnoreTilt(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkDrawingAttributes5> : produce_base<D, Windows::UI::Input::Inking::IInkDrawingAttributes5>
{
    int32_t WINRT_CALL get_ModelerAttributes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ModelerAttributes, WINRT_WRAP(Windows::UI::Input::Inking::InkModelerAttributes));
            *value = detach_from<Windows::UI::Input::Inking::InkModelerAttributes>(this->shim().ModelerAttributes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkDrawingAttributesPencilProperties> : produce_base<D, Windows::UI::Input::Inking::IInkDrawingAttributesPencilProperties>
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
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkDrawingAttributesStatics> : produce_base<D, Windows::UI::Input::Inking::IInkDrawingAttributesStatics>
{
    int32_t WINRT_CALL CreateForPencil(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateForPencil, WINRT_WRAP(Windows::UI::Input::Inking::InkDrawingAttributes));
            *result = detach_from<Windows::UI::Input::Inking::InkDrawingAttributes>(this->shim().CreateForPencil());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkInputConfiguration> : produce_base<D, Windows::UI::Input::Inking::IInkInputConfiguration>
{
    int32_t WINRT_CALL get_IsPrimaryBarrelButtonInputEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPrimaryBarrelButtonInputEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPrimaryBarrelButtonInputEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsPrimaryBarrelButtonInputEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPrimaryBarrelButtonInputEnabled, WINRT_WRAP(void), bool);
            this->shim().IsPrimaryBarrelButtonInputEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsEraserInputEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEraserInputEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsEraserInputEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsEraserInputEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEraserInputEnabled, WINRT_WRAP(void), bool);
            this->shim().IsEraserInputEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkInputProcessingConfiguration> : produce_base<D, Windows::UI::Input::Inking::IInkInputProcessingConfiguration>
{
    int32_t WINRT_CALL get_Mode(Windows::UI::Input::Inking::InkInputProcessingMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(Windows::UI::Input::Inking::InkInputProcessingMode));
            *value = detach_from<Windows::UI::Input::Inking::InkInputProcessingMode>(this->shim().Mode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Mode(Windows::UI::Input::Inking::InkInputProcessingMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(void), Windows::UI::Input::Inking::InkInputProcessingMode const&);
            this->shim().Mode(*reinterpret_cast<Windows::UI::Input::Inking::InkInputProcessingMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RightDragAction(Windows::UI::Input::Inking::InkInputRightDragAction* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RightDragAction, WINRT_WRAP(Windows::UI::Input::Inking::InkInputRightDragAction));
            *value = detach_from<Windows::UI::Input::Inking::InkInputRightDragAction>(this->shim().RightDragAction());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RightDragAction(Windows::UI::Input::Inking::InkInputRightDragAction value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RightDragAction, WINRT_WRAP(void), Windows::UI::Input::Inking::InkInputRightDragAction const&);
            this->shim().RightDragAction(*reinterpret_cast<Windows::UI::Input::Inking::InkInputRightDragAction const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkManager> : produce_base<D, Windows::UI::Input::Inking::IInkManager>
{
    int32_t WINRT_CALL get_Mode(Windows::UI::Input::Inking::InkManipulationMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(Windows::UI::Input::Inking::InkManipulationMode));
            *value = detach_from<Windows::UI::Input::Inking::InkManipulationMode>(this->shim().Mode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Mode(Windows::UI::Input::Inking::InkManipulationMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(void), Windows::UI::Input::Inking::InkManipulationMode const&);
            this->shim().Mode(*reinterpret_cast<Windows::UI::Input::Inking::InkManipulationMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ProcessPointerDown(void* pointerPoint) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProcessPointerDown, WINRT_WRAP(void), Windows::UI::Input::PointerPoint const&);
            this->shim().ProcessPointerDown(*reinterpret_cast<Windows::UI::Input::PointerPoint const*>(&pointerPoint));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ProcessPointerUpdate(void* pointerPoint, void** updateInformation) noexcept final
    {
        try
        {
            *updateInformation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProcessPointerUpdate, WINRT_WRAP(Windows::Foundation::IInspectable), Windows::UI::Input::PointerPoint const&);
            *updateInformation = detach_from<Windows::Foundation::IInspectable>(this->shim().ProcessPointerUpdate(*reinterpret_cast<Windows::UI::Input::PointerPoint const*>(&pointerPoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ProcessPointerUp(void* pointerPoint, Windows::Foundation::Rect* updateRectangle) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProcessPointerUp, WINRT_WRAP(Windows::Foundation::Rect), Windows::UI::Input::PointerPoint const&);
            *updateRectangle = detach_from<Windows::Foundation::Rect>(this->shim().ProcessPointerUp(*reinterpret_cast<Windows::UI::Input::PointerPoint const*>(&pointerPoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetDefaultDrawingAttributes(void* drawingAttributes) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetDefaultDrawingAttributes, WINRT_WRAP(void), Windows::UI::Input::Inking::InkDrawingAttributes const&);
            this->shim().SetDefaultDrawingAttributes(*reinterpret_cast<Windows::UI::Input::Inking::InkDrawingAttributes const*>(&drawingAttributes));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RecognizeAsync2(Windows::UI::Input::Inking::InkRecognitionTarget recognitionTarget, void** recognitionResults) noexcept final
    {
        try
        {
            *recognitionResults = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecognizeAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkRecognitionResult>>), Windows::UI::Input::Inking::InkRecognitionTarget const);
            *recognitionResults = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkRecognitionResult>>>(this->shim().RecognizeAsync(*reinterpret_cast<Windows::UI::Input::Inking::InkRecognitionTarget const*>(&recognitionTarget)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkModelerAttributes> : produce_base<D, Windows::UI::Input::Inking::IInkModelerAttributes>
{
    int32_t WINRT_CALL get_PredictionTime(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PredictionTime, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().PredictionTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PredictionTime(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PredictionTime, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().PredictionTime(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScalingFactor(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScalingFactor, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().ScalingFactor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ScalingFactor(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScalingFactor, WINRT_WRAP(void), float);
            this->shim().ScalingFactor(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkPoint> : produce_base<D, Windows::UI::Input::Inking::IInkPoint>
{
    int32_t WINRT_CALL get_Position(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Pressure(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pressure, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Pressure());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkPoint2> : produce_base<D, Windows::UI::Input::Inking::IInkPoint2>
{
    int32_t WINRT_CALL get_TiltX(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TiltX, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().TiltX());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TiltY(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TiltY, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().TiltY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Timestamp(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Timestamp, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkPointFactory> : produce_base<D, Windows::UI::Input::Inking::IInkPointFactory>
{
    int32_t WINRT_CALL CreateInkPoint(Windows::Foundation::Point position, float pressure, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInkPoint, WINRT_WRAP(Windows::UI::Input::Inking::InkPoint), Windows::Foundation::Point const&, float);
            *result = detach_from<Windows::UI::Input::Inking::InkPoint>(this->shim().CreateInkPoint(*reinterpret_cast<Windows::Foundation::Point const*>(&position), pressure));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkPointFactory2> : produce_base<D, Windows::UI::Input::Inking::IInkPointFactory2>
{
    int32_t WINRT_CALL CreateInkPointWithTiltAndTimestamp(Windows::Foundation::Point position, float pressure, float tiltX, float tiltY, uint64_t timestamp, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInkPointWithTiltAndTimestamp, WINRT_WRAP(Windows::UI::Input::Inking::InkPoint), Windows::Foundation::Point const&, float, float, float, uint64_t);
            *result = detach_from<Windows::UI::Input::Inking::InkPoint>(this->shim().CreateInkPointWithTiltAndTimestamp(*reinterpret_cast<Windows::Foundation::Point const*>(&position), pressure, tiltX, tiltY, timestamp));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkPresenter> : produce_base<D, Windows::UI::Input::Inking::IInkPresenter>
{
    int32_t WINRT_CALL get_IsInputEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInputEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsInputEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsInputEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInputEnabled, WINRT_WRAP(void), bool);
            this->shim().IsInputEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InputDeviceTypes(Windows::UI::Core::CoreInputDeviceTypes* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InputDeviceTypes, WINRT_WRAP(Windows::UI::Core::CoreInputDeviceTypes));
            *value = detach_from<Windows::UI::Core::CoreInputDeviceTypes>(this->shim().InputDeviceTypes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InputDeviceTypes(Windows::UI::Core::CoreInputDeviceTypes value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InputDeviceTypes, WINRT_WRAP(void), Windows::UI::Core::CoreInputDeviceTypes const&);
            this->shim().InputDeviceTypes(*reinterpret_cast<Windows::UI::Core::CoreInputDeviceTypes const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UnprocessedInput(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnprocessedInput, WINRT_WRAP(Windows::UI::Input::Inking::InkUnprocessedInput));
            *value = detach_from<Windows::UI::Input::Inking::InkUnprocessedInput>(this->shim().UnprocessedInput());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeInput(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeInput, WINRT_WRAP(Windows::UI::Input::Inking::InkStrokeInput));
            *value = detach_from<Windows::UI::Input::Inking::InkStrokeInput>(this->shim().StrokeInput());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InputProcessingConfiguration(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InputProcessingConfiguration, WINRT_WRAP(Windows::UI::Input::Inking::InkInputProcessingConfiguration));
            *value = detach_from<Windows::UI::Input::Inking::InkInputProcessingConfiguration>(this->shim().InputProcessingConfiguration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeContainer(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeContainer, WINRT_WRAP(Windows::UI::Input::Inking::InkStrokeContainer));
            *value = detach_from<Windows::UI::Input::Inking::InkStrokeContainer>(this->shim().StrokeContainer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StrokeContainer(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeContainer, WINRT_WRAP(void), Windows::UI::Input::Inking::InkStrokeContainer const&);
            this->shim().StrokeContainer(*reinterpret_cast<Windows::UI::Input::Inking::InkStrokeContainer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CopyDefaultDrawingAttributes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CopyDefaultDrawingAttributes, WINRT_WRAP(Windows::UI::Input::Inking::InkDrawingAttributes));
            *value = detach_from<Windows::UI::Input::Inking::InkDrawingAttributes>(this->shim().CopyDefaultDrawingAttributes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateDefaultDrawingAttributes(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateDefaultDrawingAttributes, WINRT_WRAP(void), Windows::UI::Input::Inking::InkDrawingAttributes const&);
            this->shim().UpdateDefaultDrawingAttributes(*reinterpret_cast<Windows::UI::Input::Inking::InkDrawingAttributes const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ActivateCustomDrying(void** inkSynchronizer) noexcept final
    {
        try
        {
            *inkSynchronizer = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActivateCustomDrying, WINRT_WRAP(Windows::UI::Input::Inking::InkSynchronizer));
            *inkSynchronizer = detach_from<Windows::UI::Input::Inking::InkSynchronizer>(this->shim().ActivateCustomDrying());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPredefinedConfiguration(Windows::UI::Input::Inking::InkPresenterPredefinedConfiguration value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPredefinedConfiguration, WINRT_WRAP(void), Windows::UI::Input::Inking::InkPresenterPredefinedConfiguration const&);
            this->shim().SetPredefinedConfiguration(*reinterpret_cast<Windows::UI::Input::Inking::InkPresenterPredefinedConfiguration const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_StrokesCollected(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokesCollected, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkPresenter, Windows::UI::Input::Inking::InkStrokesCollectedEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().StrokesCollected(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkPresenter, Windows::UI::Input::Inking::InkStrokesCollectedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_StrokesCollected(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(StrokesCollected, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().StrokesCollected(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_StrokesErased(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokesErased, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkPresenter, Windows::UI::Input::Inking::InkStrokesErasedEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().StrokesErased(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkPresenter, Windows::UI::Input::Inking::InkStrokesErasedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_StrokesErased(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(StrokesErased, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().StrokesErased(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkPresenter2> : produce_base<D, Windows::UI::Input::Inking::IInkPresenter2>
{
    int32_t WINRT_CALL get_HighContrastAdjustment(Windows::UI::Input::Inking::InkHighContrastAdjustment* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HighContrastAdjustment, WINRT_WRAP(Windows::UI::Input::Inking::InkHighContrastAdjustment));
            *value = detach_from<Windows::UI::Input::Inking::InkHighContrastAdjustment>(this->shim().HighContrastAdjustment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_HighContrastAdjustment(Windows::UI::Input::Inking::InkHighContrastAdjustment value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HighContrastAdjustment, WINRT_WRAP(void), Windows::UI::Input::Inking::InkHighContrastAdjustment const&);
            this->shim().HighContrastAdjustment(*reinterpret_cast<Windows::UI::Input::Inking::InkHighContrastAdjustment const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkPresenter3> : produce_base<D, Windows::UI::Input::Inking::IInkPresenter3>
{
    int32_t WINRT_CALL get_InputConfiguration(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InputConfiguration, WINRT_WRAP(Windows::UI::Input::Inking::InkInputConfiguration));
            *value = detach_from<Windows::UI::Input::Inking::InkInputConfiguration>(this->shim().InputConfiguration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkPresenterProtractor> : produce_base<D, Windows::UI::Input::Inking::IInkPresenterProtractor>
{
    int32_t WINRT_CALL get_AreTickMarksVisible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AreTickMarksVisible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AreTickMarksVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AreTickMarksVisible(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AreTickMarksVisible, WINRT_WRAP(void), bool);
            this->shim().AreTickMarksVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AreRaysVisible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AreRaysVisible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AreRaysVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AreRaysVisible(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AreRaysVisible, WINRT_WRAP(void), bool);
            this->shim().AreRaysVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsCenterMarkerVisible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCenterMarkerVisible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCenterMarkerVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsCenterMarkerVisible(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCenterMarkerVisible, WINRT_WRAP(void), bool);
            this->shim().IsCenterMarkerVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsAngleReadoutVisible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAngleReadoutVisible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsAngleReadoutVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsAngleReadoutVisible(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAngleReadoutVisible, WINRT_WRAP(void), bool);
            this->shim().IsAngleReadoutVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsResizable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsResizable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsResizable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsResizable(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsResizable, WINRT_WRAP(void), bool);
            this->shim().IsResizable(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Radius(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Radius, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Radius());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Radius(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Radius, WINRT_WRAP(void), double);
            this->shim().Radius(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AccentColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccentColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().AccentColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AccentColor(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccentColor, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().AccentColor(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkPresenterProtractorFactory> : produce_base<D, Windows::UI::Input::Inking::IInkPresenterProtractorFactory>
{
    int32_t WINRT_CALL Create(void* inkPresenter, void** inkPresenterProtractor) noexcept final
    {
        try
        {
            *inkPresenterProtractor = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::UI::Input::Inking::InkPresenterProtractor), Windows::UI::Input::Inking::InkPresenter const&);
            *inkPresenterProtractor = detach_from<Windows::UI::Input::Inking::InkPresenterProtractor>(this->shim().Create(*reinterpret_cast<Windows::UI::Input::Inking::InkPresenter const*>(&inkPresenter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkPresenterRuler> : produce_base<D, Windows::UI::Input::Inking::IInkPresenterRuler>
{
    int32_t WINRT_CALL get_Length(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Length, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Length());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Length(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Length, WINRT_WRAP(void), double);
            this->shim().Length(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Width(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Width, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Width());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Width(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Width, WINRT_WRAP(void), double);
            this->shim().Width(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkPresenterRuler2> : produce_base<D, Windows::UI::Input::Inking::IInkPresenterRuler2>
{
    int32_t WINRT_CALL get_AreTickMarksVisible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AreTickMarksVisible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AreTickMarksVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AreTickMarksVisible(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AreTickMarksVisible, WINRT_WRAP(void), bool);
            this->shim().AreTickMarksVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsCompassVisible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCompassVisible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCompassVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsCompassVisible(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCompassVisible, WINRT_WRAP(void), bool);
            this->shim().IsCompassVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkPresenterRulerFactory> : produce_base<D, Windows::UI::Input::Inking::IInkPresenterRulerFactory>
{
    int32_t WINRT_CALL Create(void* inkPresenter, void** inkPresenterRuler) noexcept final
    {
        try
        {
            *inkPresenterRuler = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::UI::Input::Inking::InkPresenterRuler), Windows::UI::Input::Inking::InkPresenter const&);
            *inkPresenterRuler = detach_from<Windows::UI::Input::Inking::InkPresenterRuler>(this->shim().Create(*reinterpret_cast<Windows::UI::Input::Inking::InkPresenter const*>(&inkPresenter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkPresenterStencil> : produce_base<D, Windows::UI::Input::Inking::IInkPresenterStencil>
{
    int32_t WINRT_CALL get_Kind(Windows::UI::Input::Inking::InkPresenterStencilKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::UI::Input::Inking::InkPresenterStencilKind));
            *value = detach_from<Windows::UI::Input::Inking::InkPresenterStencilKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsVisible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsVisible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsVisible(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsVisible, WINRT_WRAP(void), bool);
            this->shim().IsVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BackgroundColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackgroundColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().BackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BackgroundColor(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackgroundColor, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().BackgroundColor(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ForegroundColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ForegroundColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().ForegroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ForegroundColor(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ForegroundColor, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().ForegroundColor(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Transform(Windows::Foundation::Numerics::float3x2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Transform, WINRT_WRAP(Windows::Foundation::Numerics::float3x2));
            *value = detach_from<Windows::Foundation::Numerics::float3x2>(this->shim().Transform());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Transform(Windows::Foundation::Numerics::float3x2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Transform, WINRT_WRAP(void), Windows::Foundation::Numerics::float3x2 const&);
            this->shim().Transform(*reinterpret_cast<Windows::Foundation::Numerics::float3x2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkRecognitionResult> : produce_base<D, Windows::UI::Input::Inking::IInkRecognitionResult>
{
    int32_t WINRT_CALL get_BoundingRect(Windows::Foundation::Rect* boundingRect) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BoundingRect, WINRT_WRAP(Windows::Foundation::Rect));
            *boundingRect = detach_from<Windows::Foundation::Rect>(this->shim().BoundingRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetTextCandidates(void** textCandidates) noexcept final
    {
        try
        {
            *textCandidates = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTextCandidates, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *textCandidates = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().GetTextCandidates());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStrokes(void** strokes) noexcept final
    {
        try
        {
            *strokes = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStrokes, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkStroke>));
            *strokes = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkStroke>>(this->shim().GetStrokes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkRecognizer> : produce_base<D, Windows::UI::Input::Inking::IInkRecognizer>
{
    int32_t WINRT_CALL get_Name(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkRecognizerContainer> : produce_base<D, Windows::UI::Input::Inking::IInkRecognizerContainer>
{
    int32_t WINRT_CALL SetDefaultRecognizer(void* recognizer) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetDefaultRecognizer, WINRT_WRAP(void), Windows::UI::Input::Inking::InkRecognizer const&);
            this->shim().SetDefaultRecognizer(*reinterpret_cast<Windows::UI::Input::Inking::InkRecognizer const*>(&recognizer));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RecognizeAsync(void* strokeCollection, Windows::UI::Input::Inking::InkRecognitionTarget recognitionTarget, void** recognitionResults) noexcept final
    {
        try
        {
            *recognitionResults = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecognizeAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkRecognitionResult>>), Windows::UI::Input::Inking::InkStrokeContainer const, Windows::UI::Input::Inking::InkRecognitionTarget const);
            *recognitionResults = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkRecognitionResult>>>(this->shim().RecognizeAsync(*reinterpret_cast<Windows::UI::Input::Inking::InkStrokeContainer const*>(&strokeCollection), *reinterpret_cast<Windows::UI::Input::Inking::InkRecognitionTarget const*>(&recognitionTarget)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetRecognizers(void** recognizerView) noexcept final
    {
        try
        {
            *recognizerView = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetRecognizers, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkRecognizer>));
            *recognizerView = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkRecognizer>>(this->shim().GetRecognizers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkStroke> : produce_base<D, Windows::UI::Input::Inking::IInkStroke>
{
    int32_t WINRT_CALL get_DrawingAttributes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DrawingAttributes, WINRT_WRAP(Windows::UI::Input::Inking::InkDrawingAttributes));
            *value = detach_from<Windows::UI::Input::Inking::InkDrawingAttributes>(this->shim().DrawingAttributes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DrawingAttributes(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DrawingAttributes, WINRT_WRAP(void), Windows::UI::Input::Inking::InkDrawingAttributes const&);
            this->shim().DrawingAttributes(*reinterpret_cast<Windows::UI::Input::Inking::InkDrawingAttributes const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BoundingRect(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BoundingRect, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().BoundingRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Selected(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Selected, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Selected());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Selected(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Selected, WINRT_WRAP(void), bool);
            this->shim().Selected(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Recognized(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Recognized, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Recognized());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetRenderingSegments(void** renderingSegments) noexcept final
    {
        try
        {
            *renderingSegments = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetRenderingSegments, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkStrokeRenderingSegment>));
            *renderingSegments = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkStrokeRenderingSegment>>(this->shim().GetRenderingSegments());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Clone(void** clonedStroke) noexcept final
    {
        try
        {
            *clonedStroke = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Clone, WINRT_WRAP(Windows::UI::Input::Inking::InkStroke));
            *clonedStroke = detach_from<Windows::UI::Input::Inking::InkStroke>(this->shim().Clone());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkStroke2> : produce_base<D, Windows::UI::Input::Inking::IInkStroke2>
{
    int32_t WINRT_CALL get_PointTransform(Windows::Foundation::Numerics::float3x2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointTransform, WINRT_WRAP(Windows::Foundation::Numerics::float3x2));
            *value = detach_from<Windows::Foundation::Numerics::float3x2>(this->shim().PointTransform());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PointTransform(Windows::Foundation::Numerics::float3x2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointTransform, WINRT_WRAP(void), Windows::Foundation::Numerics::float3x2 const&);
            this->shim().PointTransform(*reinterpret_cast<Windows::Foundation::Numerics::float3x2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetInkPoints(void** inkPoints) noexcept final
    {
        try
        {
            *inkPoints = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetInkPoints, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkPoint>));
            *inkPoints = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkPoint>>(this->shim().GetInkPoints());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkStroke3> : produce_base<D, Windows::UI::Input::Inking::IInkStroke3>
{
    int32_t WINRT_CALL get_Id(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeStartedTime(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeStartedTime, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().StrokeStartedTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StrokeStartedTime(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeStartedTime, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::DateTime> const&);
            this->shim().StrokeStartedTime(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeDuration(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeDuration, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().StrokeDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StrokeDuration(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeDuration, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const&);
            this->shim().StrokeDuration(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkStrokeBuilder> : produce_base<D, Windows::UI::Input::Inking::IInkStrokeBuilder>
{
    int32_t WINRT_CALL BeginStroke(void* pointerPoint) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BeginStroke, WINRT_WRAP(void), Windows::UI::Input::PointerPoint const&);
            this->shim().BeginStroke(*reinterpret_cast<Windows::UI::Input::PointerPoint const*>(&pointerPoint));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AppendToStroke(void* pointerPoint, void** previousPointerPoint) noexcept final
    {
        try
        {
            *previousPointerPoint = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppendToStroke, WINRT_WRAP(Windows::UI::Input::PointerPoint), Windows::UI::Input::PointerPoint const&);
            *previousPointerPoint = detach_from<Windows::UI::Input::PointerPoint>(this->shim().AppendToStroke(*reinterpret_cast<Windows::UI::Input::PointerPoint const*>(&pointerPoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EndStroke(void* pointerPoint, void** stroke) noexcept final
    {
        try
        {
            *stroke = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndStroke, WINRT_WRAP(Windows::UI::Input::Inking::InkStroke), Windows::UI::Input::PointerPoint const&);
            *stroke = detach_from<Windows::UI::Input::Inking::InkStroke>(this->shim().EndStroke(*reinterpret_cast<Windows::UI::Input::PointerPoint const*>(&pointerPoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateStroke(void* points, void** stroke) noexcept final
    {
        try
        {
            *stroke = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateStroke, WINRT_WRAP(Windows::UI::Input::Inking::InkStroke), Windows::Foundation::Collections::IIterable<Windows::Foundation::Point> const&);
            *stroke = detach_from<Windows::UI::Input::Inking::InkStroke>(this->shim().CreateStroke(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Point> const*>(&points)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetDefaultDrawingAttributes(void* drawingAttributes) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetDefaultDrawingAttributes, WINRT_WRAP(void), Windows::UI::Input::Inking::InkDrawingAttributes const&);
            this->shim().SetDefaultDrawingAttributes(*reinterpret_cast<Windows::UI::Input::Inking::InkDrawingAttributes const*>(&drawingAttributes));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkStrokeBuilder2> : produce_base<D, Windows::UI::Input::Inking::IInkStrokeBuilder2>
{
    int32_t WINRT_CALL CreateStrokeFromInkPoints(void* inkPoints, Windows::Foundation::Numerics::float3x2 transform, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateStrokeFromInkPoints, WINRT_WRAP(Windows::UI::Input::Inking::InkStroke), Windows::Foundation::Collections::IIterable<Windows::UI::Input::Inking::InkPoint> const&, Windows::Foundation::Numerics::float3x2 const&);
            *result = detach_from<Windows::UI::Input::Inking::InkStroke>(this->shim().CreateStrokeFromInkPoints(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::UI::Input::Inking::InkPoint> const*>(&inkPoints), *reinterpret_cast<Windows::Foundation::Numerics::float3x2 const*>(&transform)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkStrokeBuilder3> : produce_base<D, Windows::UI::Input::Inking::IInkStrokeBuilder3>
{
    int32_t WINRT_CALL CreateStrokeFromInkPoints(void* inkPoints, Windows::Foundation::Numerics::float3x2 transform, void* strokeStartedTime, void* strokeDuration, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateStrokeFromInkPoints, WINRT_WRAP(Windows::UI::Input::Inking::InkStroke), Windows::Foundation::Collections::IIterable<Windows::UI::Input::Inking::InkPoint> const&, Windows::Foundation::Numerics::float3x2 const&, Windows::Foundation::IReference<Windows::Foundation::DateTime> const&, Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const&);
            *result = detach_from<Windows::UI::Input::Inking::InkStroke>(this->shim().CreateStrokeFromInkPoints(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::UI::Input::Inking::InkPoint> const*>(&inkPoints), *reinterpret_cast<Windows::Foundation::Numerics::float3x2 const*>(&transform), *reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&strokeStartedTime), *reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const*>(&strokeDuration)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkStrokeContainer> : produce_base<D, Windows::UI::Input::Inking::IInkStrokeContainer>
{
    int32_t WINRT_CALL get_BoundingRect(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BoundingRect, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().BoundingRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddStroke(void* stroke) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddStroke, WINRT_WRAP(void), Windows::UI::Input::Inking::InkStroke const&);
            this->shim().AddStroke(*reinterpret_cast<Windows::UI::Input::Inking::InkStroke const*>(&stroke));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteSelected(Windows::Foundation::Rect* invalidatedRect) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteSelected, WINRT_WRAP(Windows::Foundation::Rect));
            *invalidatedRect = detach_from<Windows::Foundation::Rect>(this->shim().DeleteSelected());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MoveSelected(Windows::Foundation::Point translation, Windows::Foundation::Rect* invalidatedRectangle) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MoveSelected, WINRT_WRAP(Windows::Foundation::Rect), Windows::Foundation::Point const&);
            *invalidatedRectangle = detach_from<Windows::Foundation::Rect>(this->shim().MoveSelected(*reinterpret_cast<Windows::Foundation::Point const*>(&translation)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SelectWithPolyLine(void* polyline, Windows::Foundation::Rect* invalidatedRectangle) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectWithPolyLine, WINRT_WRAP(Windows::Foundation::Rect), Windows::Foundation::Collections::IIterable<Windows::Foundation::Point> const&);
            *invalidatedRectangle = detach_from<Windows::Foundation::Rect>(this->shim().SelectWithPolyLine(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Point> const*>(&polyline)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SelectWithLine(Windows::Foundation::Point from, Windows::Foundation::Point to, Windows::Foundation::Rect* invalidatedRectangle) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectWithLine, WINRT_WRAP(Windows::Foundation::Rect), Windows::Foundation::Point const&, Windows::Foundation::Point const&);
            *invalidatedRectangle = detach_from<Windows::Foundation::Rect>(this->shim().SelectWithLine(*reinterpret_cast<Windows::Foundation::Point const*>(&from), *reinterpret_cast<Windows::Foundation::Point const*>(&to)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CopySelectedToClipboard() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CopySelectedToClipboard, WINRT_WRAP(void));
            this->shim().CopySelectedToClipboard();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PasteFromClipboard(Windows::Foundation::Point position, Windows::Foundation::Rect* invalidatedRectangle) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PasteFromClipboard, WINRT_WRAP(Windows::Foundation::Rect), Windows::Foundation::Point const&);
            *invalidatedRectangle = detach_from<Windows::Foundation::Rect>(this->shim().PasteFromClipboard(*reinterpret_cast<Windows::Foundation::Point const*>(&position)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CanPasteFromClipboard(bool* canPaste) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanPasteFromClipboard, WINRT_WRAP(bool));
            *canPaste = detach_from<bool>(this->shim().CanPasteFromClipboard());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LoadAsync(void* inputStream, void** loadAction) noexcept final
    {
        try
        {
            *loadAction = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadAsync, WINRT_WRAP(Windows::Foundation::IAsyncActionWithProgress<uint64_t>), Windows::Storage::Streams::IInputStream const);
            *loadAction = detach_from<Windows::Foundation::IAsyncActionWithProgress<uint64_t>>(this->shim().LoadAsync(*reinterpret_cast<Windows::Storage::Streams::IInputStream const*>(&inputStream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SaveAsync(void* outputStream, void** outputStreamOperation) noexcept final
    {
        try
        {
            *outputStreamOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t>), Windows::Storage::Streams::IOutputStream const);
            *outputStreamOperation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t>>(this->shim().SaveAsync(*reinterpret_cast<Windows::Storage::Streams::IOutputStream const*>(&outputStream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateRecognitionResults(void* recognitionResults) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateRecognitionResults, WINRT_WRAP(void), Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkRecognitionResult> const&);
            this->shim().UpdateRecognitionResults(*reinterpret_cast<Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkRecognitionResult> const*>(&recognitionResults));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStrokes(void** strokeView) noexcept final
    {
        try
        {
            *strokeView = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStrokes, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkStroke>));
            *strokeView = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkStroke>>(this->shim().GetStrokes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetRecognitionResults(void** recognitionResults) noexcept final
    {
        try
        {
            *recognitionResults = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetRecognitionResults, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkRecognitionResult>));
            *recognitionResults = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkRecognitionResult>>(this->shim().GetRecognitionResults());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkStrokeContainer2> : produce_base<D, Windows::UI::Input::Inking::IInkStrokeContainer2>
{
    int32_t WINRT_CALL AddStrokes(void* strokes) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddStrokes, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<Windows::UI::Input::Inking::InkStroke> const&);
            this->shim().AddStrokes(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::UI::Input::Inking::InkStroke> const*>(&strokes));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Clear() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Clear, WINRT_WRAP(void));
            this->shim().Clear();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkStrokeContainer3> : produce_base<D, Windows::UI::Input::Inking::IInkStrokeContainer3>
{
    int32_t WINRT_CALL SaveWithFormatAsync(void* outputStream, Windows::UI::Input::Inking::InkPersistenceFormat inkPersistenceFormat, void** outputStreamOperation) noexcept final
    {
        try
        {
            *outputStreamOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t>), Windows::Storage::Streams::IOutputStream const, Windows::UI::Input::Inking::InkPersistenceFormat const);
            *outputStreamOperation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t>>(this->shim().SaveAsync(*reinterpret_cast<Windows::Storage::Streams::IOutputStream const*>(&outputStream), *reinterpret_cast<Windows::UI::Input::Inking::InkPersistenceFormat const*>(&inkPersistenceFormat)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStrokeById(uint32_t id, void** stroke) noexcept final
    {
        try
        {
            *stroke = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStrokeById, WINRT_WRAP(Windows::UI::Input::Inking::InkStroke), uint32_t);
            *stroke = detach_from<Windows::UI::Input::Inking::InkStroke>(this->shim().GetStrokeById(id));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkStrokeInput> : produce_base<D, Windows::UI::Input::Inking::IInkStrokeInput>
{
    int32_t WINRT_CALL add_StrokeStarted(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeStarted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkStrokeInput, Windows::UI::Core::PointerEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().StrokeStarted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkStrokeInput, Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_StrokeStarted(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(StrokeStarted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().StrokeStarted(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_StrokeContinued(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeContinued, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkStrokeInput, Windows::UI::Core::PointerEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().StrokeContinued(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkStrokeInput, Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_StrokeContinued(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(StrokeContinued, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().StrokeContinued(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_StrokeEnded(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeEnded, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkStrokeInput, Windows::UI::Core::PointerEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().StrokeEnded(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkStrokeInput, Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_StrokeEnded(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(StrokeEnded, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().StrokeEnded(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_StrokeCanceled(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeCanceled, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkStrokeInput, Windows::UI::Core::PointerEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().StrokeCanceled(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkStrokeInput, Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_StrokeCanceled(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(StrokeCanceled, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().StrokeCanceled(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL get_InkPresenter(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InkPresenter, WINRT_WRAP(Windows::UI::Input::Inking::InkPresenter));
            *value = detach_from<Windows::UI::Input::Inking::InkPresenter>(this->shim().InkPresenter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkStrokeRenderingSegment> : produce_base<D, Windows::UI::Input::Inking::IInkStrokeRenderingSegment>
{
    int32_t WINRT_CALL get_Position(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BezierControlPoint1(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BezierControlPoint1, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().BezierControlPoint1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BezierControlPoint2(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BezierControlPoint2, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().BezierControlPoint2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Pressure(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pressure, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Pressure());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TiltX(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TiltX, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().TiltX());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TiltY(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TiltY, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().TiltY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Twist(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Twist, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Twist());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkStrokesCollectedEventArgs> : produce_base<D, Windows::UI::Input::Inking::IInkStrokesCollectedEventArgs>
{
    int32_t WINRT_CALL get_Strokes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Strokes, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkStroke>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkStroke>>(this->shim().Strokes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkStrokesErasedEventArgs> : produce_base<D, Windows::UI::Input::Inking::IInkStrokesErasedEventArgs>
{
    int32_t WINRT_CALL get_Strokes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Strokes, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkStroke>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkStroke>>(this->shim().Strokes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkSynchronizer> : produce_base<D, Windows::UI::Input::Inking::IInkSynchronizer>
{
    int32_t WINRT_CALL BeginDry(void** inkStrokes) noexcept final
    {
        try
        {
            *inkStrokes = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BeginDry, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkStroke>));
            *inkStrokes = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::InkStroke>>(this->shim().BeginDry());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EndDry() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndDry, WINRT_WRAP(void));
            this->shim().EndDry();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IInkUnprocessedInput> : produce_base<D, Windows::UI::Input::Inking::IInkUnprocessedInput>
{
    int32_t WINRT_CALL add_PointerEntered(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerEntered, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkUnprocessedInput, Windows::UI::Core::PointerEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PointerEntered(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkUnprocessedInput, Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerEntered(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerEntered, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerEntered(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_PointerHovered(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerHovered, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkUnprocessedInput, Windows::UI::Core::PointerEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PointerHovered(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkUnprocessedInput, Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerHovered(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerHovered, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerHovered(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_PointerExited(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerExited, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkUnprocessedInput, Windows::UI::Core::PointerEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PointerExited(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkUnprocessedInput, Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerExited(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerExited, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerExited(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_PointerPressed(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerPressed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkUnprocessedInput, Windows::UI::Core::PointerEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PointerPressed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkUnprocessedInput, Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerPressed(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerPressed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerPressed(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_PointerMoved(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerMoved, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkUnprocessedInput, Windows::UI::Core::PointerEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PointerMoved(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkUnprocessedInput, Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerMoved(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerMoved, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerMoved(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_PointerReleased(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerReleased, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkUnprocessedInput, Windows::UI::Core::PointerEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PointerReleased(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkUnprocessedInput, Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerReleased(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerReleased, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerReleased(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_PointerLost(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerLost, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkUnprocessedInput, Windows::UI::Core::PointerEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PointerLost(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::InkUnprocessedInput, Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerLost(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerLost, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerLost(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL get_InkPresenter(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InkPresenter, WINRT_WRAP(Windows::UI::Input::Inking::InkPresenter));
            *value = detach_from<Windows::UI::Input::Inking::InkPresenter>(this->shim().InkPresenter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IPenAndInkSettings> : produce_base<D, Windows::UI::Input::Inking::IPenAndInkSettings>
{
    int32_t WINRT_CALL get_IsHandwritingDirectlyIntoTextFieldEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsHandwritingDirectlyIntoTextFieldEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsHandwritingDirectlyIntoTextFieldEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PenHandedness(Windows::UI::Input::Inking::PenHandedness* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PenHandedness, WINRT_WRAP(Windows::UI::Input::Inking::PenHandedness));
            *value = detach_from<Windows::UI::Input::Inking::PenHandedness>(this->shim().PenHandedness());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HandwritingLineHeight(Windows::UI::Input::Inking::HandwritingLineHeight* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HandwritingLineHeight, WINRT_WRAP(Windows::UI::Input::Inking::HandwritingLineHeight));
            *value = detach_from<Windows::UI::Input::Inking::HandwritingLineHeight>(this->shim().HandwritingLineHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FontFamilyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontFamilyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FontFamilyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UserConsentsToHandwritingTelemetryCollection(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserConsentsToHandwritingTelemetryCollection, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().UserConsentsToHandwritingTelemetryCollection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsTouchHandwritingEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTouchHandwritingEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsTouchHandwritingEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::IPenAndInkSettingsStatics> : produce_base<D, Windows::UI::Input::Inking::IPenAndInkSettingsStatics>
{
    int32_t WINRT_CALL GetDefault(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::UI::Input::Inking::PenAndInkSettings));
            *result = detach_from<Windows::UI::Input::Inking::PenAndInkSettings>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::Input::Inking {

inline InkDrawingAttributes::InkDrawingAttributes() :
    InkDrawingAttributes(impl::call_factory<InkDrawingAttributes>([](auto&& f) { return f.template ActivateInstance<InkDrawingAttributes>(); }))
{}

inline Windows::UI::Input::Inking::InkDrawingAttributes InkDrawingAttributes::CreateForPencil()
{
    return impl::call_factory<InkDrawingAttributes, Windows::UI::Input::Inking::IInkDrawingAttributesStatics>([&](auto&& f) { return f.CreateForPencil(); });
}

inline InkManager::InkManager() :
    InkManager(impl::call_factory<InkManager>([](auto&& f) { return f.template ActivateInstance<InkManager>(); }))
{}

inline InkPoint::InkPoint(Windows::Foundation::Point const& position, float pressure) :
    InkPoint(impl::call_factory<InkPoint, Windows::UI::Input::Inking::IInkPointFactory>([&](auto&& f) { return f.CreateInkPoint(position, pressure); }))
{}

inline InkPoint::InkPoint(Windows::Foundation::Point const& position, float pressure, float tiltX, float tiltY, uint64_t timestamp) :
    InkPoint(impl::call_factory<InkPoint, Windows::UI::Input::Inking::IInkPointFactory2>([&](auto&& f) { return f.CreateInkPointWithTiltAndTimestamp(position, pressure, tiltX, tiltY, timestamp); }))
{}

inline InkPresenterProtractor::InkPresenterProtractor(Windows::UI::Input::Inking::InkPresenter const& inkPresenter) :
    InkPresenterProtractor(impl::call_factory<InkPresenterProtractor, Windows::UI::Input::Inking::IInkPresenterProtractorFactory>([&](auto&& f) { return f.Create(inkPresenter); }))
{}

inline InkPresenterRuler::InkPresenterRuler(Windows::UI::Input::Inking::InkPresenter const& inkPresenter) :
    InkPresenterRuler(impl::call_factory<InkPresenterRuler, Windows::UI::Input::Inking::IInkPresenterRulerFactory>([&](auto&& f) { return f.Create(inkPresenter); }))
{}

inline InkRecognizerContainer::InkRecognizerContainer() :
    InkRecognizerContainer(impl::call_factory<InkRecognizerContainer>([](auto&& f) { return f.template ActivateInstance<InkRecognizerContainer>(); }))
{}

inline InkStrokeBuilder::InkStrokeBuilder() :
    InkStrokeBuilder(impl::call_factory<InkStrokeBuilder>([](auto&& f) { return f.template ActivateInstance<InkStrokeBuilder>(); }))
{}

inline InkStrokeContainer::InkStrokeContainer() :
    InkStrokeContainer(impl::call_factory<InkStrokeContainer>([](auto&& f) { return f.template ActivateInstance<InkStrokeContainer>(); }))
{}

inline Windows::UI::Input::Inking::PenAndInkSettings PenAndInkSettings::GetDefault()
{
    return impl::call_factory<PenAndInkSettings, Windows::UI::Input::Inking::IPenAndInkSettingsStatics>([&](auto&& f) { return f.GetDefault(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Input::Inking::IInkDrawingAttributes> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkDrawingAttributes> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkDrawingAttributes2> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkDrawingAttributes2> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkDrawingAttributes3> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkDrawingAttributes3> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkDrawingAttributes4> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkDrawingAttributes4> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkDrawingAttributes5> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkDrawingAttributes5> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkDrawingAttributesPencilProperties> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkDrawingAttributesPencilProperties> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkDrawingAttributesStatics> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkDrawingAttributesStatics> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkInputConfiguration> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkInputConfiguration> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkInputProcessingConfiguration> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkInputProcessingConfiguration> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkManager> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkManager> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkModelerAttributes> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkModelerAttributes> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkPoint> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkPoint> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkPoint2> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkPoint2> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkPointFactory> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkPointFactory> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkPointFactory2> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkPointFactory2> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkPresenter> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkPresenter> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkPresenter2> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkPresenter2> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkPresenter3> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkPresenter3> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkPresenterProtractor> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkPresenterProtractor> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkPresenterProtractorFactory> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkPresenterProtractorFactory> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkPresenterRuler> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkPresenterRuler> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkPresenterRuler2> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkPresenterRuler2> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkPresenterRulerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkPresenterRulerFactory> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkPresenterStencil> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkPresenterStencil> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkRecognitionResult> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkRecognitionResult> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkRecognizer> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkRecognizer> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkRecognizerContainer> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkRecognizerContainer> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkStroke> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkStroke> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkStroke2> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkStroke2> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkStroke3> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkStroke3> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkStrokeBuilder> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkStrokeBuilder> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkStrokeBuilder2> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkStrokeBuilder2> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkStrokeBuilder3> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkStrokeBuilder3> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkStrokeContainer> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkStrokeContainer> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkStrokeContainer2> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkStrokeContainer2> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkStrokeContainer3> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkStrokeContainer3> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkStrokeInput> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkStrokeInput> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkStrokeRenderingSegment> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkStrokeRenderingSegment> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkStrokesCollectedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkStrokesCollectedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkStrokesErasedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkStrokesErasedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkSynchronizer> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkSynchronizer> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IInkUnprocessedInput> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IInkUnprocessedInput> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IPenAndInkSettings> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IPenAndInkSettings> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::IPenAndInkSettingsStatics> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::IPenAndInkSettingsStatics> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::InkDrawingAttributes> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::InkDrawingAttributes> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::InkDrawingAttributesPencilProperties> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::InkDrawingAttributesPencilProperties> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::InkInputConfiguration> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::InkInputConfiguration> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::InkInputProcessingConfiguration> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::InkInputProcessingConfiguration> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::InkManager> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::InkManager> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::InkModelerAttributes> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::InkModelerAttributes> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::InkPoint> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::InkPoint> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::InkPresenter> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::InkPresenter> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::InkPresenterProtractor> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::InkPresenterProtractor> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::InkPresenterRuler> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::InkPresenterRuler> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::InkRecognitionResult> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::InkRecognitionResult> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::InkRecognizer> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::InkRecognizer> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::InkRecognizerContainer> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::InkRecognizerContainer> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::InkStroke> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::InkStroke> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::InkStrokeBuilder> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::InkStrokeBuilder> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::InkStrokeContainer> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::InkStrokeContainer> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::InkStrokeInput> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::InkStrokeInput> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::InkStrokeRenderingSegment> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::InkStrokeRenderingSegment> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::InkStrokesCollectedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::InkStrokesCollectedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::InkStrokesErasedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::InkStrokesErasedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::InkSynchronizer> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::InkSynchronizer> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::InkUnprocessedInput> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::InkUnprocessedInput> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::PenAndInkSettings> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::PenAndInkSettings> {};

}
