// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::UI::Input {

struct InputActivationListener;

}

WINRT_EXPORT namespace winrt::Windows::UI::WindowManagement {

struct AppWindow;

}

WINRT_EXPORT namespace winrt::Windows::UI::Input::Preview {

struct IInputActivationListenerPreviewStatics;
struct InputActivationListenerPreview;

}

namespace winrt::impl {

template <> struct category<Windows::UI::Input::Preview::IInputActivationListenerPreviewStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Input::Preview::InputActivationListenerPreview>{ using type = class_category; };
template <> struct name<Windows::UI::Input::Preview::IInputActivationListenerPreviewStatics>{ static constexpr auto & value{ L"Windows.UI.Input.Preview.IInputActivationListenerPreviewStatics" }; };
template <> struct name<Windows::UI::Input::Preview::InputActivationListenerPreview>{ static constexpr auto & value{ L"Windows.UI.Input.Preview.InputActivationListenerPreview" }; };
template <> struct guid_storage<Windows::UI::Input::Preview::IInputActivationListenerPreviewStatics>{ static constexpr guid value{ 0xF0551CE5,0x0DE6,0x5BE0,{ 0xA5,0x89,0xF7,0x37,0x20,0x1A,0x45,0x82 } }; };

template <> struct abi<Windows::UI::Input::Preview::IInputActivationListenerPreviewStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateForApplicationWindow(void* window, void** result) noexcept = 0;
};};

template <typename D>
struct consume_Windows_UI_Input_Preview_IInputActivationListenerPreviewStatics
{
    Windows::UI::Input::InputActivationListener CreateForApplicationWindow(Windows::UI::WindowManagement::AppWindow const& window) const;
};
template <> struct consume<Windows::UI::Input::Preview::IInputActivationListenerPreviewStatics> { template <typename D> using type = consume_Windows_UI_Input_Preview_IInputActivationListenerPreviewStatics<D>; };

}
