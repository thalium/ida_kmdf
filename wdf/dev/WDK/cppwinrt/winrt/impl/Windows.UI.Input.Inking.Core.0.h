// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::UI::Composition {

struct ContainerVisual;

}

WINRT_EXPORT namespace winrt::Windows::UI::Core {

struct PointerEventArgs;

}

WINRT_EXPORT namespace winrt::Windows::UI::Input::Inking {

struct InkDrawingAttributes;
struct InkPoint;
struct InkPresenter;
struct InkStroke;

}

WINRT_EXPORT namespace winrt::Windows::UI::Input::Inking::Core {

enum class CoreWetStrokeDisposition : int32_t
{
    Inking = 0,
    Completed = 1,
    Canceled = 2,
};

struct ICoreIncrementalInkStroke;
struct ICoreIncrementalInkStrokeFactory;
struct ICoreInkIndependentInputSource;
struct ICoreInkIndependentInputSourceStatics;
struct ICoreInkPresenterHost;
struct ICoreWetStrokeUpdateEventArgs;
struct ICoreWetStrokeUpdateSource;
struct ICoreWetStrokeUpdateSourceStatics;
struct CoreIncrementalInkStroke;
struct CoreInkIndependentInputSource;
struct CoreInkPresenterHost;
struct CoreWetStrokeUpdateEventArgs;
struct CoreWetStrokeUpdateSource;

}

namespace winrt::impl {

template <> struct category<Windows::UI::Input::Inking::Core::ICoreIncrementalInkStroke>{ using type = interface_category; };
template <> struct category<Windows::UI::Input::Inking::Core::ICoreIncrementalInkStrokeFactory>{ using type = interface_category; };
template <> struct category<Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource>{ using type = interface_category; };
template <> struct category<Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSourceStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Input::Inking::Core::ICoreInkPresenterHost>{ using type = interface_category; };
template <> struct category<Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource>{ using type = interface_category; };
template <> struct category<Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSourceStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Input::Inking::Core::CoreIncrementalInkStroke>{ using type = class_category; };
template <> struct category<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource>{ using type = class_category; };
template <> struct category<Windows::UI::Input::Inking::Core::CoreInkPresenterHost>{ using type = class_category; };
template <> struct category<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource>{ using type = class_category; };
template <> struct category<Windows::UI::Input::Inking::Core::CoreWetStrokeDisposition>{ using type = enum_category; };
template <> struct name<Windows::UI::Input::Inking::Core::ICoreIncrementalInkStroke>{ static constexpr auto & value{ L"Windows.UI.Input.Inking.Core.ICoreIncrementalInkStroke" }; };
template <> struct name<Windows::UI::Input::Inking::Core::ICoreIncrementalInkStrokeFactory>{ static constexpr auto & value{ L"Windows.UI.Input.Inking.Core.ICoreIncrementalInkStrokeFactory" }; };
template <> struct name<Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource>{ static constexpr auto & value{ L"Windows.UI.Input.Inking.Core.ICoreInkIndependentInputSource" }; };
template <> struct name<Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSourceStatics>{ static constexpr auto & value{ L"Windows.UI.Input.Inking.Core.ICoreInkIndependentInputSourceStatics" }; };
template <> struct name<Windows::UI::Input::Inking::Core::ICoreInkPresenterHost>{ static constexpr auto & value{ L"Windows.UI.Input.Inking.Core.ICoreInkPresenterHost" }; };
template <> struct name<Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateEventArgs>{ static constexpr auto & value{ L"Windows.UI.Input.Inking.Core.ICoreWetStrokeUpdateEventArgs" }; };
template <> struct name<Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource>{ static constexpr auto & value{ L"Windows.UI.Input.Inking.Core.ICoreWetStrokeUpdateSource" }; };
template <> struct name<Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSourceStatics>{ static constexpr auto & value{ L"Windows.UI.Input.Inking.Core.ICoreWetStrokeUpdateSourceStatics" }; };
template <> struct name<Windows::UI::Input::Inking::Core::CoreIncrementalInkStroke>{ static constexpr auto & value{ L"Windows.UI.Input.Inking.Core.CoreIncrementalInkStroke" }; };
template <> struct name<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource>{ static constexpr auto & value{ L"Windows.UI.Input.Inking.Core.CoreInkIndependentInputSource" }; };
template <> struct name<Windows::UI::Input::Inking::Core::CoreInkPresenterHost>{ static constexpr auto & value{ L"Windows.UI.Input.Inking.Core.CoreInkPresenterHost" }; };
template <> struct name<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs>{ static constexpr auto & value{ L"Windows.UI.Input.Inking.Core.CoreWetStrokeUpdateEventArgs" }; };
template <> struct name<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource>{ static constexpr auto & value{ L"Windows.UI.Input.Inking.Core.CoreWetStrokeUpdateSource" }; };
template <> struct name<Windows::UI::Input::Inking::Core::CoreWetStrokeDisposition>{ static constexpr auto & value{ L"Windows.UI.Input.Inking.Core.CoreWetStrokeDisposition" }; };
template <> struct guid_storage<Windows::UI::Input::Inking::Core::ICoreIncrementalInkStroke>{ static constexpr guid value{ 0xFDA015D3,0x9D66,0x4F7D,{ 0xA5,0x7F,0xCC,0x70,0xB9,0xCF,0xAA,0x76 } }; };
template <> struct guid_storage<Windows::UI::Input::Inking::Core::ICoreIncrementalInkStrokeFactory>{ static constexpr guid value{ 0xD7C59F46,0x8DA8,0x4F70,{ 0x97,0x51,0xE5,0x3B,0xB6,0xDF,0x45,0x96 } }; };
template <> struct guid_storage<Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource>{ static constexpr guid value{ 0x39B38DA9,0x7639,0x4499,{ 0xA5,0xB5,0x19,0x1D,0x00,0xE3,0x5B,0x16 } }; };
template <> struct guid_storage<Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSourceStatics>{ static constexpr guid value{ 0x73E6011B,0x80C0,0x4DFB,{ 0x9B,0x66,0x10,0xBA,0x7F,0x3F,0x9C,0x84 } }; };
template <> struct guid_storage<Windows::UI::Input::Inking::Core::ICoreInkPresenterHost>{ static constexpr guid value{ 0x396E89E6,0x7D55,0x4617,{ 0x9E,0x58,0x68,0xC7,0x0C,0x91,0x69,0xB9 } }; };
template <> struct guid_storage<Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateEventArgs>{ static constexpr guid value{ 0xFB07D14C,0x3380,0x457A,{ 0xA9,0x87,0x99,0x13,0x57,0x89,0x6C,0x1B } }; };
template <> struct guid_storage<Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource>{ static constexpr guid value{ 0x1F718E22,0xEE52,0x4E00,{ 0x82,0x09,0x4C,0x3E,0x5B,0x21,0xA3,0xCC } }; };
template <> struct guid_storage<Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSourceStatics>{ static constexpr guid value{ 0x3DAD9CBA,0x1D3D,0x46AE,{ 0xAB,0x9D,0x86,0x47,0x48,0x6C,0x6F,0x90 } }; };
template <> struct default_interface<Windows::UI::Input::Inking::Core::CoreIncrementalInkStroke>{ using type = Windows::UI::Input::Inking::Core::ICoreIncrementalInkStroke; };
template <> struct default_interface<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource>{ using type = Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource; };
template <> struct default_interface<Windows::UI::Input::Inking::Core::CoreInkPresenterHost>{ using type = Windows::UI::Input::Inking::Core::ICoreInkPresenterHost; };
template <> struct default_interface<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs>{ using type = Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateEventArgs; };
template <> struct default_interface<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource>{ using type = Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource; };

template <> struct abi<Windows::UI::Input::Inking::Core::ICoreIncrementalInkStroke>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL AppendInkPoints(void* inkPoints, Windows::Foundation::Rect* result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateInkStroke(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL get_DrawingAttributes(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PointTransform(Windows::Foundation::Numerics::float3x2* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BoundingRect(Windows::Foundation::Rect* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Input::Inking::Core::ICoreIncrementalInkStrokeFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* drawingAttributes, Windows::Foundation::Numerics::float3x2 pointTransform, void** result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_PointerEntering(void* handler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_PointerEntering(winrt::event_token cookie) noexcept = 0;
    virtual int32_t WINRT_CALL add_PointerHovering(void* handler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_PointerHovering(winrt::event_token cookie) noexcept = 0;
    virtual int32_t WINRT_CALL add_PointerExiting(void* handler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_PointerExiting(winrt::event_token cookie) noexcept = 0;
    virtual int32_t WINRT_CALL add_PointerPressing(void* handler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_PointerPressing(winrt::event_token cookie) noexcept = 0;
    virtual int32_t WINRT_CALL add_PointerMoving(void* handler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_PointerMoving(winrt::event_token cookie) noexcept = 0;
    virtual int32_t WINRT_CALL add_PointerReleasing(void* handler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_PointerReleasing(winrt::event_token cookie) noexcept = 0;
    virtual int32_t WINRT_CALL add_PointerLost(void* handler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_PointerLost(winrt::event_token cookie) noexcept = 0;
    virtual int32_t WINRT_CALL get_InkPresenter(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSourceStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* inkPresenter, void** inkIndependentInputSource) noexcept = 0;
};};

template <> struct abi<Windows::UI::Input::Inking::Core::ICoreInkPresenterHost>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_InkPresenter(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RootVisual(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RootVisual(void* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_NewInkPoints(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PointerId(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Disposition(Windows::UI::Input::Inking::Core::CoreWetStrokeDisposition* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Disposition(Windows::UI::Input::Inking::Core::CoreWetStrokeDisposition value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_WetStrokeStarting(void* handler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_WetStrokeStarting(winrt::event_token cookie) noexcept = 0;
    virtual int32_t WINRT_CALL add_WetStrokeContinuing(void* handler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_WetStrokeContinuing(winrt::event_token cookie) noexcept = 0;
    virtual int32_t WINRT_CALL add_WetStrokeStopping(void* handler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_WetStrokeStopping(winrt::event_token cookie) noexcept = 0;
    virtual int32_t WINRT_CALL add_WetStrokeCompleted(void* handler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_WetStrokeCompleted(winrt::event_token cookie) noexcept = 0;
    virtual int32_t WINRT_CALL add_WetStrokeCanceled(void* handler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_WetStrokeCanceled(winrt::event_token cookie) noexcept = 0;
    virtual int32_t WINRT_CALL get_InkPresenter(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSourceStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* inkPresenter, void** WetStrokeUpdateSource) noexcept = 0;
};};

template <typename D>
struct consume_Windows_UI_Input_Inking_Core_ICoreIncrementalInkStroke
{
    Windows::Foundation::Rect AppendInkPoints(param::iterable<Windows::UI::Input::Inking::InkPoint> const& inkPoints) const;
    Windows::UI::Input::Inking::InkStroke CreateInkStroke() const;
    Windows::UI::Input::Inking::InkDrawingAttributes DrawingAttributes() const;
    Windows::Foundation::Numerics::float3x2 PointTransform() const;
    Windows::Foundation::Rect BoundingRect() const;
};
template <> struct consume<Windows::UI::Input::Inking::Core::ICoreIncrementalInkStroke> { template <typename D> using type = consume_Windows_UI_Input_Inking_Core_ICoreIncrementalInkStroke<D>; };

template <typename D>
struct consume_Windows_UI_Input_Inking_Core_ICoreIncrementalInkStrokeFactory
{
    Windows::UI::Input::Inking::Core::CoreIncrementalInkStroke Create(Windows::UI::Input::Inking::InkDrawingAttributes const& drawingAttributes, Windows::Foundation::Numerics::float3x2 const& pointTransform) const;
};
template <> struct consume<Windows::UI::Input::Inking::Core::ICoreIncrementalInkStrokeFactory> { template <typename D> using type = consume_Windows_UI_Input_Inking_Core_ICoreIncrementalInkStrokeFactory<D>; };

template <typename D>
struct consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSource
{
    winrt::event_token PointerEntering(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const& handler) const;
    using PointerEntering_revoker = impl::event_revoker<Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource, &impl::abi_t<Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource>::remove_PointerEntering>;
    PointerEntering_revoker PointerEntering(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const& handler) const;
    void PointerEntering(winrt::event_token const& cookie) const noexcept;
    winrt::event_token PointerHovering(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const& handler) const;
    using PointerHovering_revoker = impl::event_revoker<Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource, &impl::abi_t<Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource>::remove_PointerHovering>;
    PointerHovering_revoker PointerHovering(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const& handler) const;
    void PointerHovering(winrt::event_token const& cookie) const noexcept;
    winrt::event_token PointerExiting(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const& handler) const;
    using PointerExiting_revoker = impl::event_revoker<Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource, &impl::abi_t<Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource>::remove_PointerExiting>;
    PointerExiting_revoker PointerExiting(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const& handler) const;
    void PointerExiting(winrt::event_token const& cookie) const noexcept;
    winrt::event_token PointerPressing(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const& handler) const;
    using PointerPressing_revoker = impl::event_revoker<Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource, &impl::abi_t<Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource>::remove_PointerPressing>;
    PointerPressing_revoker PointerPressing(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const& handler) const;
    void PointerPressing(winrt::event_token const& cookie) const noexcept;
    winrt::event_token PointerMoving(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const& handler) const;
    using PointerMoving_revoker = impl::event_revoker<Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource, &impl::abi_t<Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource>::remove_PointerMoving>;
    PointerMoving_revoker PointerMoving(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const& handler) const;
    void PointerMoving(winrt::event_token const& cookie) const noexcept;
    winrt::event_token PointerReleasing(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const& handler) const;
    using PointerReleasing_revoker = impl::event_revoker<Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource, &impl::abi_t<Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource>::remove_PointerReleasing>;
    PointerReleasing_revoker PointerReleasing(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const& handler) const;
    void PointerReleasing(winrt::event_token const& cookie) const noexcept;
    winrt::event_token PointerLost(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const& handler) const;
    using PointerLost_revoker = impl::event_revoker<Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource, &impl::abi_t<Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource>::remove_PointerLost>;
    PointerLost_revoker PointerLost(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const& handler) const;
    void PointerLost(winrt::event_token const& cookie) const noexcept;
    Windows::UI::Input::Inking::InkPresenter InkPresenter() const;
};
template <> struct consume<Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource> { template <typename D> using type = consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSource<D>; };

template <typename D>
struct consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSourceStatics
{
    Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource Create(Windows::UI::Input::Inking::InkPresenter const& inkPresenter) const;
};
template <> struct consume<Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSourceStatics> { template <typename D> using type = consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSourceStatics<D>; };

template <typename D>
struct consume_Windows_UI_Input_Inking_Core_ICoreInkPresenterHost
{
    Windows::UI::Input::Inking::InkPresenter InkPresenter() const;
    Windows::UI::Composition::ContainerVisual RootVisual() const;
    void RootVisual(Windows::UI::Composition::ContainerVisual const& value) const;
};
template <> struct consume<Windows::UI::Input::Inking::Core::ICoreInkPresenterHost> { template <typename D> using type = consume_Windows_UI_Input_Inking_Core_ICoreInkPresenterHost<D>; };

template <typename D>
struct consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateEventArgs
{
    Windows::Foundation::Collections::IVector<Windows::UI::Input::Inking::InkPoint> NewInkPoints() const;
    uint32_t PointerId() const;
    Windows::UI::Input::Inking::Core::CoreWetStrokeDisposition Disposition() const;
    void Disposition(Windows::UI::Input::Inking::Core::CoreWetStrokeDisposition const& value) const;
};
template <> struct consume<Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateEventArgs> { template <typename D> using type = consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateSource
{
    winrt::event_token WetStrokeStarting(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const& handler) const;
    using WetStrokeStarting_revoker = impl::event_revoker<Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource, &impl::abi_t<Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource>::remove_WetStrokeStarting>;
    WetStrokeStarting_revoker WetStrokeStarting(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const& handler) const;
    void WetStrokeStarting(winrt::event_token const& cookie) const noexcept;
    winrt::event_token WetStrokeContinuing(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const& handler) const;
    using WetStrokeContinuing_revoker = impl::event_revoker<Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource, &impl::abi_t<Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource>::remove_WetStrokeContinuing>;
    WetStrokeContinuing_revoker WetStrokeContinuing(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const& handler) const;
    void WetStrokeContinuing(winrt::event_token const& cookie) const noexcept;
    winrt::event_token WetStrokeStopping(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const& handler) const;
    using WetStrokeStopping_revoker = impl::event_revoker<Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource, &impl::abi_t<Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource>::remove_WetStrokeStopping>;
    WetStrokeStopping_revoker WetStrokeStopping(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const& handler) const;
    void WetStrokeStopping(winrt::event_token const& cookie) const noexcept;
    winrt::event_token WetStrokeCompleted(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const& handler) const;
    using WetStrokeCompleted_revoker = impl::event_revoker<Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource, &impl::abi_t<Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource>::remove_WetStrokeCompleted>;
    WetStrokeCompleted_revoker WetStrokeCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const& handler) const;
    void WetStrokeCompleted(winrt::event_token const& cookie) const noexcept;
    winrt::event_token WetStrokeCanceled(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const& handler) const;
    using WetStrokeCanceled_revoker = impl::event_revoker<Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource, &impl::abi_t<Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource>::remove_WetStrokeCanceled>;
    WetStrokeCanceled_revoker WetStrokeCanceled(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const& handler) const;
    void WetStrokeCanceled(winrt::event_token const& cookie) const noexcept;
    Windows::UI::Input::Inking::InkPresenter InkPresenter() const;
};
template <> struct consume<Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource> { template <typename D> using type = consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateSource<D>; };

template <typename D>
struct consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateSourceStatics
{
    Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource Create(Windows::UI::Input::Inking::InkPresenter const& inkPresenter) const;
};
template <> struct consume<Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSourceStatics> { template <typename D> using type = consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateSourceStatics<D>; };

}
