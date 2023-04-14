// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::UI::Composition {

struct CompositionPropertySet;
struct ICompositionAnimationBase;
struct Visual;

}

WINRT_EXPORT namespace winrt::Windows::UI::WindowManagement {

struct AppWindow;

}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml {

struct FrameworkElement;
struct ResourceDictionary;
struct UIElement;

}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Controls {

struct ScrollViewer;

}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Controls::Primitives {

enum class FlyoutPlacementMode;

}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Hosting {

enum class DesignerAppViewState : int32_t
{
    Visible = 0,
    Hidden = 1,
};

enum class XamlSourceFocusNavigationReason : int32_t
{
    Programmatic = 0,
    Restore = 1,
    First = 3,
    Last = 4,
    Left = 7,
    Up = 8,
    Right = 9,
    Down = 10,
};

struct IDesignerAppExitedEventArgs;
struct IDesignerAppManager;
struct IDesignerAppManagerFactory;
struct IDesignerAppView;
struct IDesktopWindowXamlSource;
struct IDesktopWindowXamlSourceFactory;
struct IDesktopWindowXamlSourceGotFocusEventArgs;
struct IDesktopWindowXamlSourceTakeFocusRequestedEventArgs;
struct IElementCompositionPreview;
struct IElementCompositionPreviewStatics;
struct IElementCompositionPreviewStatics2;
struct IElementCompositionPreviewStatics3;
struct IWindowsXamlManager;
struct IWindowsXamlManagerStatics;
struct IXamlSourceFocusNavigationRequest;
struct IXamlSourceFocusNavigationRequestFactory;
struct IXamlSourceFocusNavigationResult;
struct IXamlSourceFocusNavigationResultFactory;
struct IXamlUIPresenter;
struct IXamlUIPresenterHost;
struct IXamlUIPresenterHost2;
struct IXamlUIPresenterHost3;
struct IXamlUIPresenterStatics;
struct IXamlUIPresenterStatics2;
struct DesignerAppExitedEventArgs;
struct DesignerAppManager;
struct DesignerAppView;
struct DesktopWindowXamlSource;
struct DesktopWindowXamlSourceGotFocusEventArgs;
struct DesktopWindowXamlSourceTakeFocusRequestedEventArgs;
struct ElementCompositionPreview;
struct WindowsXamlManager;
struct XamlSourceFocusNavigationRequest;
struct XamlSourceFocusNavigationResult;
struct XamlUIPresenter;

}

namespace winrt::impl {

template <> struct category<Windows::UI::Xaml::Hosting::IDesignerAppExitedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Hosting::IDesignerAppManager>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Hosting::IDesignerAppManagerFactory>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Hosting::IDesignerAppView>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceFactory>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceGotFocusEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceTakeFocusRequestedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Hosting::IElementCompositionPreview>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics2>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics3>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Hosting::IWindowsXamlManager>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Hosting::IWindowsXamlManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequest>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequestFactory>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationResult>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationResultFactory>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Hosting::IXamlUIPresenter>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Hosting::IXamlUIPresenterHost>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Hosting::IXamlUIPresenterHost2>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Hosting::IXamlUIPresenterHost3>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics2>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Hosting::DesignerAppExitedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Hosting::DesignerAppManager>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Hosting::DesignerAppView>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Hosting::DesktopWindowXamlSource>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Hosting::DesktopWindowXamlSourceGotFocusEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Hosting::DesktopWindowXamlSourceTakeFocusRequestedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Hosting::ElementCompositionPreview>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Hosting::WindowsXamlManager>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationResult>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Hosting::XamlUIPresenter>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Hosting::DesignerAppViewState>{ using type = enum_category; };
template <> struct category<Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason>{ using type = enum_category; };
template <> struct name<Windows::UI::Xaml::Hosting::IDesignerAppExitedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.IDesignerAppExitedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Hosting::IDesignerAppManager>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.IDesignerAppManager" }; };
template <> struct name<Windows::UI::Xaml::Hosting::IDesignerAppManagerFactory>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.IDesignerAppManagerFactory" }; };
template <> struct name<Windows::UI::Xaml::Hosting::IDesignerAppView>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.IDesignerAppView" }; };
template <> struct name<Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.IDesktopWindowXamlSource" }; };
template <> struct name<Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceFactory>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.IDesktopWindowXamlSourceFactory" }; };
template <> struct name<Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceGotFocusEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.IDesktopWindowXamlSourceGotFocusEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceTakeFocusRequestedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.IDesktopWindowXamlSourceTakeFocusRequestedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Hosting::IElementCompositionPreview>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.IElementCompositionPreview" }; };
template <> struct name<Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.IElementCompositionPreviewStatics" }; };
template <> struct name<Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics2>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.IElementCompositionPreviewStatics2" }; };
template <> struct name<Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics3>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.IElementCompositionPreviewStatics3" }; };
template <> struct name<Windows::UI::Xaml::Hosting::IWindowsXamlManager>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.IWindowsXamlManager" }; };
template <> struct name<Windows::UI::Xaml::Hosting::IWindowsXamlManagerStatics>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.IWindowsXamlManagerStatics" }; };
template <> struct name<Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequest>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.IXamlSourceFocusNavigationRequest" }; };
template <> struct name<Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequestFactory>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.IXamlSourceFocusNavigationRequestFactory" }; };
template <> struct name<Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationResult>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.IXamlSourceFocusNavigationResult" }; };
template <> struct name<Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationResultFactory>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.IXamlSourceFocusNavigationResultFactory" }; };
template <> struct name<Windows::UI::Xaml::Hosting::IXamlUIPresenter>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.IXamlUIPresenter" }; };
template <> struct name<Windows::UI::Xaml::Hosting::IXamlUIPresenterHost>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.IXamlUIPresenterHost" }; };
template <> struct name<Windows::UI::Xaml::Hosting::IXamlUIPresenterHost2>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.IXamlUIPresenterHost2" }; };
template <> struct name<Windows::UI::Xaml::Hosting::IXamlUIPresenterHost3>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.IXamlUIPresenterHost3" }; };
template <> struct name<Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.IXamlUIPresenterStatics" }; };
template <> struct name<Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics2>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.IXamlUIPresenterStatics2" }; };
template <> struct name<Windows::UI::Xaml::Hosting::DesignerAppExitedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.DesignerAppExitedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Hosting::DesignerAppManager>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.DesignerAppManager" }; };
template <> struct name<Windows::UI::Xaml::Hosting::DesignerAppView>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.DesignerAppView" }; };
template <> struct name<Windows::UI::Xaml::Hosting::DesktopWindowXamlSource>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.DesktopWindowXamlSource" }; };
template <> struct name<Windows::UI::Xaml::Hosting::DesktopWindowXamlSourceGotFocusEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.DesktopWindowXamlSourceGotFocusEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Hosting::DesktopWindowXamlSourceTakeFocusRequestedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.DesktopWindowXamlSourceTakeFocusRequestedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Hosting::ElementCompositionPreview>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.ElementCompositionPreview" }; };
template <> struct name<Windows::UI::Xaml::Hosting::WindowsXamlManager>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.WindowsXamlManager" }; };
template <> struct name<Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.XamlSourceFocusNavigationRequest" }; };
template <> struct name<Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationResult>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.XamlSourceFocusNavigationResult" }; };
template <> struct name<Windows::UI::Xaml::Hosting::XamlUIPresenter>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.XamlUIPresenter" }; };
template <> struct name<Windows::UI::Xaml::Hosting::DesignerAppViewState>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.DesignerAppViewState" }; };
template <> struct name<Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason>{ static constexpr auto & value{ L"Windows.UI.Xaml.Hosting.XamlSourceFocusNavigationReason" }; };
template <> struct guid_storage<Windows::UI::Xaml::Hosting::IDesignerAppExitedEventArgs>{ static constexpr guid value{ 0xF6AAC86A,0x0CAD,0x410C,{ 0x8F,0x62,0xDC,0x29,0x36,0x15,0x1C,0x74 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Hosting::IDesignerAppManager>{ static constexpr guid value{ 0xA6272CAA,0xD5C6,0x40CB,{ 0xAB,0xD9,0x27,0xBA,0x43,0x83,0x1B,0xB7 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Hosting::IDesignerAppManagerFactory>{ static constexpr guid value{ 0x8F9D633B,0x1266,0x4C0E,{ 0x84,0x99,0x0D,0xB8,0x5B,0xBD,0x4C,0x43 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Hosting::IDesignerAppView>{ static constexpr guid value{ 0x5C777CEA,0xDD71,0x4A84,{ 0xA5,0x6F,0xDA,0xCB,0x4B,0x14,0x70,0x6F } }; };
template <> struct guid_storage<Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource>{ static constexpr guid value{ 0xD585BFE1,0x00FF,0x51BE,{ 0xBA,0x1D,0xA1,0x32,0x99,0x56,0xEA,0x0A } }; };
template <> struct guid_storage<Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceFactory>{ static constexpr guid value{ 0x5CD61DC0,0x2561,0x56E1,{ 0x8E,0x75,0x6E,0x44,0x17,0x38,0x05,0xE3 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceGotFocusEventArgs>{ static constexpr guid value{ 0x39BE4849,0xD9CC,0x5B70,{ 0x8F,0x05,0x1A,0xD9,0xA4,0xAA,0xA3,0x42 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceTakeFocusRequestedEventArgs>{ static constexpr guid value{ 0xFE61E4B9,0xA7AF,0x52B3,{ 0xBD,0xB9,0xC3,0x30,0x5C,0x0B,0x8D,0xF2 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Hosting::IElementCompositionPreview>{ static constexpr guid value{ 0xB6F1A676,0xCFE6,0x46AC,{ 0xAC,0xF6,0xC4,0x68,0x7B,0xB6,0x5E,0x60 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics>{ static constexpr guid value{ 0x08C92B38,0xEC99,0x4C55,{ 0xBC,0x85,0xA1,0xC1,0x80,0xB2,0x76,0x46 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics2>{ static constexpr guid value{ 0x24148FBB,0x23D6,0x4F37,{ 0xBA,0x0C,0x07,0x33,0xE7,0x99,0x72,0x2D } }; };
template <> struct guid_storage<Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics3>{ static constexpr guid value{ 0x843BC4C3,0xC105,0x59FE,{ 0xA3,0xD1,0x37,0x3C,0x1D,0x3E,0x6F,0xBC } }; };
template <> struct guid_storage<Windows::UI::Xaml::Hosting::IWindowsXamlManager>{ static constexpr guid value{ 0x56096C31,0x1AA0,0x5288,{ 0x88,0x18,0x6E,0x74,0xA2,0xDC,0xAF,0xF5 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Hosting::IWindowsXamlManagerStatics>{ static constexpr guid value{ 0x28258A12,0x7D82,0x505B,{ 0xB2,0x10,0x71,0x2B,0x04,0xA5,0x88,0x82 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequest>{ static constexpr guid value{ 0xFBB93BB5,0x1496,0x5A80,{ 0xAC,0x00,0xE7,0x57,0x35,0x97,0x55,0xE6 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequestFactory>{ static constexpr guid value{ 0xE746AB8F,0xB4EF,0x5390,{ 0x97,0xE5,0xCC,0x0A,0x27,0x79,0xC5,0x74 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationResult>{ static constexpr guid value{ 0x88D55A5F,0x9603,0x5D8F,{ 0x9C,0xC7,0xD1,0xC4,0x07,0x0D,0x98,0x01 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationResultFactory>{ static constexpr guid value{ 0x43BBADBF,0xF9E1,0x5527,{ 0xB8,0xC5,0x09,0x33,0x9F,0xF2,0xCA,0x76 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Hosting::IXamlUIPresenter>{ static constexpr guid value{ 0xA714944A,0x1619,0x4FC6,{ 0xB3,0x1B,0x89,0x51,0x2E,0xF0,0x22,0xA2 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Hosting::IXamlUIPresenterHost>{ static constexpr guid value{ 0xAAFB84CD,0x9F6D,0x4F80,{ 0xAC,0x2C,0x0E,0x6C,0xB9,0xF3,0x16,0x59 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Hosting::IXamlUIPresenterHost2>{ static constexpr guid value{ 0x61595672,0x7CA4,0x4A21,{ 0xB5,0x6A,0x88,0xF4,0x81,0x23,0x88,0xCA } }; };
template <> struct guid_storage<Windows::UI::Xaml::Hosting::IXamlUIPresenterHost3>{ static constexpr guid value{ 0xB14292BF,0x7320,0x41BB,{ 0x9F,0x26,0x4D,0x6F,0xD3,0x4D,0xB4,0x5A } }; };
template <> struct guid_storage<Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics>{ static constexpr guid value{ 0x71EAEAC8,0x45E1,0x4192,{ 0x85,0xAA,0x3A,0x42,0x2E,0xDD,0x23,0xCF } }; };
template <> struct guid_storage<Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics2>{ static constexpr guid value{ 0x5C6B68D2,0xCF1C,0x4F53,{ 0xBF,0x09,0x6A,0x74,0x5F,0x7A,0x97,0x03 } }; };
template <> struct default_interface<Windows::UI::Xaml::Hosting::DesignerAppExitedEventArgs>{ using type = Windows::UI::Xaml::Hosting::IDesignerAppExitedEventArgs; };
template <> struct default_interface<Windows::UI::Xaml::Hosting::DesignerAppManager>{ using type = Windows::UI::Xaml::Hosting::IDesignerAppManager; };
template <> struct default_interface<Windows::UI::Xaml::Hosting::DesignerAppView>{ using type = Windows::UI::Xaml::Hosting::IDesignerAppView; };
template <> struct default_interface<Windows::UI::Xaml::Hosting::DesktopWindowXamlSource>{ using type = Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource; };
template <> struct default_interface<Windows::UI::Xaml::Hosting::DesktopWindowXamlSourceGotFocusEventArgs>{ using type = Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceGotFocusEventArgs; };
template <> struct default_interface<Windows::UI::Xaml::Hosting::DesktopWindowXamlSourceTakeFocusRequestedEventArgs>{ using type = Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceTakeFocusRequestedEventArgs; };
template <> struct default_interface<Windows::UI::Xaml::Hosting::ElementCompositionPreview>{ using type = Windows::UI::Xaml::Hosting::IElementCompositionPreview; };
template <> struct default_interface<Windows::UI::Xaml::Hosting::WindowsXamlManager>{ using type = Windows::UI::Xaml::Hosting::IWindowsXamlManager; };
template <> struct default_interface<Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest>{ using type = Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequest; };
template <> struct default_interface<Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationResult>{ using type = Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationResult; };
template <> struct default_interface<Windows::UI::Xaml::Hosting::XamlUIPresenter>{ using type = Windows::UI::Xaml::Hosting::IXamlUIPresenter; };

template <> struct abi<Windows::UI::Xaml::Hosting::IDesignerAppExitedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ExitCode(uint32_t* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Hosting::IDesignerAppManager>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AppUserModelId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL add_DesignerAppExited(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_DesignerAppExited(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL CreateNewViewAsync(Windows::UI::Xaml::Hosting::DesignerAppViewState initialViewState, Windows::Foundation::Size initialViewSize, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL LoadObjectIntoAppAsync(void* dllName, winrt::guid classId, void* initializationData, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Hosting::IDesignerAppManagerFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* appUserModelId, void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Hosting::IDesignerAppView>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ApplicationViewId(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AppUserModelId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ViewState(Windows::UI::Xaml::Hosting::DesignerAppViewState* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ViewSize(Windows::Foundation::Size* value) noexcept = 0;
    virtual int32_t WINRT_CALL UpdateViewAsync(Windows::UI::Xaml::Hosting::DesignerAppViewState viewState, Windows::Foundation::Size viewSize, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Content(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Content(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HasFocus(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_TakeFocusRequested(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_TakeFocusRequested(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_GotFocus(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_GotFocus(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL NavigateFocus(void* request, void** result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceGotFocusEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Request(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceTakeFocusRequestedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Request(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Hosting::IElementCompositionPreview>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetElementVisual(void* element, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetElementChildVisual(void* element, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL SetElementChildVisual(void* element, void* visual) noexcept = 0;
    virtual int32_t WINRT_CALL GetScrollViewerManipulationPropertySet(void* scrollViewer, void** result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL SetImplicitShowAnimation(void* element, void* animation) noexcept = 0;
    virtual int32_t WINRT_CALL SetImplicitHideAnimation(void* element, void* animation) noexcept = 0;
    virtual int32_t WINRT_CALL SetIsTranslationEnabled(void* element, bool value) noexcept = 0;
    virtual int32_t WINRT_CALL GetPointerPositionPropertySet(void* targetElement, void** result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL SetAppWindowContent(void* appWindow, void* xamlContent) noexcept = 0;
    virtual int32_t WINRT_CALL GetAppWindowContent(void* appWindow, void** result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Hosting::IWindowsXamlManager>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Xaml::Hosting::IWindowsXamlManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL InitializeForCurrentThread(void** result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequest>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Reason(Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HintRect(Windows::Foundation::Rect* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CorrelationId(winrt::guid* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequestFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateInstance(Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason reason, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateInstanceWithHintRect(Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason reason, Windows::Foundation::Rect hintRect, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateInstanceWithHintRectAndCorrelationId(Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason reason, Windows::Foundation::Rect hintRect, winrt::guid correlationId, void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_WasFocusMoved(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationResultFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateInstance(bool focusMoved, void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Hosting::IXamlUIPresenter>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_RootElement(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RootElement(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ThemeKey(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ThemeKey(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ThemeResourcesXaml(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ThemeResourcesXaml(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL SetSize(int32_t width, int32_t height) noexcept = 0;
    virtual int32_t WINRT_CALL Render() noexcept = 0;
    virtual int32_t WINRT_CALL Present() noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Hosting::IXamlUIPresenterHost>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ResolveFileResource(void* path, void** result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Hosting::IXamlUIPresenterHost2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetGenericXamlFilePath(void** result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Hosting::IXamlUIPresenterHost3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ResolveDictionaryResource(void* dictionary, void* dictionaryKey, void* suggestedValue, void** result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CompleteTimelinesAutomatically(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CompleteTimelinesAutomatically(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL SetHost(void* host) noexcept = 0;
    virtual int32_t WINRT_CALL NotifyWindowSizeChanged() noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetFlyoutPlacementTargetInfo(void* placementTarget, Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode preferredPlacement, Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode* targetPreferredPlacement, bool* allowFallbacks, Windows::Foundation::Rect* returnValue) noexcept = 0;
    virtual int32_t WINRT_CALL GetFlyoutPlacement(Windows::Foundation::Rect placementTargetBounds, Windows::Foundation::Size controlSize, Windows::Foundation::Size minControlSize, Windows::Foundation::Rect containerRect, Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode targetPreferredPlacement, bool allowFallbacks, Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode* chosenPlacement, Windows::Foundation::Rect* returnValue) noexcept = 0;
};};

template <typename D>
struct consume_Windows_UI_Xaml_Hosting_IDesignerAppExitedEventArgs
{
    uint32_t ExitCode() const;
};
template <> struct consume<Windows::UI::Xaml::Hosting::IDesignerAppExitedEventArgs> { template <typename D> using type = consume_Windows_UI_Xaml_Hosting_IDesignerAppExitedEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Hosting_IDesignerAppManager
{
    hstring AppUserModelId() const;
    winrt::event_token DesignerAppExited(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Hosting::DesignerAppManager, Windows::UI::Xaml::Hosting::DesignerAppExitedEventArgs> const& handler) const;
    using DesignerAppExited_revoker = impl::event_revoker<Windows::UI::Xaml::Hosting::IDesignerAppManager, &impl::abi_t<Windows::UI::Xaml::Hosting::IDesignerAppManager>::remove_DesignerAppExited>;
    DesignerAppExited_revoker DesignerAppExited(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Hosting::DesignerAppManager, Windows::UI::Xaml::Hosting::DesignerAppExitedEventArgs> const& handler) const;
    void DesignerAppExited(winrt::event_token const& token) const noexcept;
    Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Hosting::DesignerAppView> CreateNewViewAsync(Windows::UI::Xaml::Hosting::DesignerAppViewState const& initialViewState, Windows::Foundation::Size const& initialViewSize) const;
    Windows::Foundation::IAsyncAction LoadObjectIntoAppAsync(param::hstring const& dllName, winrt::guid const& classId, param::hstring const& initializationData) const;
};
template <> struct consume<Windows::UI::Xaml::Hosting::IDesignerAppManager> { template <typename D> using type = consume_Windows_UI_Xaml_Hosting_IDesignerAppManager<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Hosting_IDesignerAppManagerFactory
{
    Windows::UI::Xaml::Hosting::DesignerAppManager Create(param::hstring const& appUserModelId) const;
};
template <> struct consume<Windows::UI::Xaml::Hosting::IDesignerAppManagerFactory> { template <typename D> using type = consume_Windows_UI_Xaml_Hosting_IDesignerAppManagerFactory<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Hosting_IDesignerAppView
{
    int32_t ApplicationViewId() const;
    hstring AppUserModelId() const;
    Windows::UI::Xaml::Hosting::DesignerAppViewState ViewState() const;
    Windows::Foundation::Size ViewSize() const;
    Windows::Foundation::IAsyncAction UpdateViewAsync(Windows::UI::Xaml::Hosting::DesignerAppViewState const& viewState, Windows::Foundation::Size const& viewSize) const;
};
template <> struct consume<Windows::UI::Xaml::Hosting::IDesignerAppView> { template <typename D> using type = consume_Windows_UI_Xaml_Hosting_IDesignerAppView<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSource
{
    Windows::UI::Xaml::UIElement Content() const;
    void Content(Windows::UI::Xaml::UIElement const& value) const;
    bool HasFocus() const;
    winrt::event_token TakeFocusRequested(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Hosting::DesktopWindowXamlSource, Windows::UI::Xaml::Hosting::DesktopWindowXamlSourceTakeFocusRequestedEventArgs> const& handler) const;
    using TakeFocusRequested_revoker = impl::event_revoker<Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource, &impl::abi_t<Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource>::remove_TakeFocusRequested>;
    TakeFocusRequested_revoker TakeFocusRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Hosting::DesktopWindowXamlSource, Windows::UI::Xaml::Hosting::DesktopWindowXamlSourceTakeFocusRequestedEventArgs> const& handler) const;
    void TakeFocusRequested(winrt::event_token const& token) const noexcept;
    winrt::event_token GotFocus(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Hosting::DesktopWindowXamlSource, Windows::UI::Xaml::Hosting::DesktopWindowXamlSourceGotFocusEventArgs> const& handler) const;
    using GotFocus_revoker = impl::event_revoker<Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource, &impl::abi_t<Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource>::remove_GotFocus>;
    GotFocus_revoker GotFocus(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Hosting::DesktopWindowXamlSource, Windows::UI::Xaml::Hosting::DesktopWindowXamlSourceGotFocusEventArgs> const& handler) const;
    void GotFocus(winrt::event_token const& token) const noexcept;
    Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationResult NavigateFocus(Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest const& request) const;
};
template <> struct consume<Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource> { template <typename D> using type = consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSource<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSourceFactory
{
    Windows::UI::Xaml::Hosting::DesktopWindowXamlSource CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const;
};
template <> struct consume<Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceFactory> { template <typename D> using type = consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSourceFactory<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSourceGotFocusEventArgs
{
    Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest Request() const;
};
template <> struct consume<Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceGotFocusEventArgs> { template <typename D> using type = consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSourceGotFocusEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSourceTakeFocusRequestedEventArgs
{
    Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest Request() const;
};
template <> struct consume<Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceTakeFocusRequestedEventArgs> { template <typename D> using type = consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSourceTakeFocusRequestedEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Hosting_IElementCompositionPreview
{
};
template <> struct consume<Windows::UI::Xaml::Hosting::IElementCompositionPreview> { template <typename D> using type = consume_Windows_UI_Xaml_Hosting_IElementCompositionPreview<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Hosting_IElementCompositionPreviewStatics
{
    Windows::UI::Composition::Visual GetElementVisual(Windows::UI::Xaml::UIElement const& element) const;
    Windows::UI::Composition::Visual GetElementChildVisual(Windows::UI::Xaml::UIElement const& element) const;
    void SetElementChildVisual(Windows::UI::Xaml::UIElement const& element, Windows::UI::Composition::Visual const& visual) const;
    Windows::UI::Composition::CompositionPropertySet GetScrollViewerManipulationPropertySet(Windows::UI::Xaml::Controls::ScrollViewer const& scrollViewer) const;
};
template <> struct consume<Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics> { template <typename D> using type = consume_Windows_UI_Xaml_Hosting_IElementCompositionPreviewStatics<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Hosting_IElementCompositionPreviewStatics2
{
    void SetImplicitShowAnimation(Windows::UI::Xaml::UIElement const& element, Windows::UI::Composition::ICompositionAnimationBase const& animation) const;
    void SetImplicitHideAnimation(Windows::UI::Xaml::UIElement const& element, Windows::UI::Composition::ICompositionAnimationBase const& animation) const;
    void SetIsTranslationEnabled(Windows::UI::Xaml::UIElement const& element, bool value) const;
    Windows::UI::Composition::CompositionPropertySet GetPointerPositionPropertySet(Windows::UI::Xaml::UIElement const& targetElement) const;
};
template <> struct consume<Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics2> { template <typename D> using type = consume_Windows_UI_Xaml_Hosting_IElementCompositionPreviewStatics2<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Hosting_IElementCompositionPreviewStatics3
{
    void SetAppWindowContent(Windows::UI::WindowManagement::AppWindow const& appWindow, Windows::UI::Xaml::UIElement const& xamlContent) const;
    Windows::UI::Xaml::UIElement GetAppWindowContent(Windows::UI::WindowManagement::AppWindow const& appWindow) const;
};
template <> struct consume<Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics3> { template <typename D> using type = consume_Windows_UI_Xaml_Hosting_IElementCompositionPreviewStatics3<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Hosting_IWindowsXamlManager
{
};
template <> struct consume<Windows::UI::Xaml::Hosting::IWindowsXamlManager> { template <typename D> using type = consume_Windows_UI_Xaml_Hosting_IWindowsXamlManager<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Hosting_IWindowsXamlManagerStatics
{
    Windows::UI::Xaml::Hosting::WindowsXamlManager InitializeForCurrentThread() const;
};
template <> struct consume<Windows::UI::Xaml::Hosting::IWindowsXamlManagerStatics> { template <typename D> using type = consume_Windows_UI_Xaml_Hosting_IWindowsXamlManagerStatics<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Hosting_IXamlSourceFocusNavigationRequest
{
    Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason Reason() const;
    Windows::Foundation::Rect HintRect() const;
    winrt::guid CorrelationId() const;
};
template <> struct consume<Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequest> { template <typename D> using type = consume_Windows_UI_Xaml_Hosting_IXamlSourceFocusNavigationRequest<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Hosting_IXamlSourceFocusNavigationRequestFactory
{
    Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest CreateInstance(Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason const& reason) const;
    Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest CreateInstanceWithHintRect(Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason const& reason, Windows::Foundation::Rect const& hintRect) const;
    Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest CreateInstanceWithHintRectAndCorrelationId(Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason const& reason, Windows::Foundation::Rect const& hintRect, winrt::guid const& correlationId) const;
};
template <> struct consume<Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequestFactory> { template <typename D> using type = consume_Windows_UI_Xaml_Hosting_IXamlSourceFocusNavigationRequestFactory<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Hosting_IXamlSourceFocusNavigationResult
{
    bool WasFocusMoved() const;
};
template <> struct consume<Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationResult> { template <typename D> using type = consume_Windows_UI_Xaml_Hosting_IXamlSourceFocusNavigationResult<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Hosting_IXamlSourceFocusNavigationResultFactory
{
    Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationResult CreateInstance(bool focusMoved) const;
};
template <> struct consume<Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationResultFactory> { template <typename D> using type = consume_Windows_UI_Xaml_Hosting_IXamlSourceFocusNavigationResultFactory<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Hosting_IXamlUIPresenter
{
    Windows::UI::Xaml::UIElement RootElement() const;
    void RootElement(Windows::UI::Xaml::UIElement const& value) const;
    hstring ThemeKey() const;
    void ThemeKey(param::hstring const& value) const;
    hstring ThemeResourcesXaml() const;
    void ThemeResourcesXaml(param::hstring const& value) const;
    void SetSize(int32_t width, int32_t height) const;
    void Render() const;
    void Present() const;
};
template <> struct consume<Windows::UI::Xaml::Hosting::IXamlUIPresenter> { template <typename D> using type = consume_Windows_UI_Xaml_Hosting_IXamlUIPresenter<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Hosting_IXamlUIPresenterHost
{
    hstring ResolveFileResource(param::hstring const& path) const;
};
template <> struct consume<Windows::UI::Xaml::Hosting::IXamlUIPresenterHost> { template <typename D> using type = consume_Windows_UI_Xaml_Hosting_IXamlUIPresenterHost<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Hosting_IXamlUIPresenterHost2
{
    hstring GetGenericXamlFilePath() const;
};
template <> struct consume<Windows::UI::Xaml::Hosting::IXamlUIPresenterHost2> { template <typename D> using type = consume_Windows_UI_Xaml_Hosting_IXamlUIPresenterHost2<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Hosting_IXamlUIPresenterHost3
{
    Windows::Foundation::IInspectable ResolveDictionaryResource(Windows::UI::Xaml::ResourceDictionary const& dictionary, Windows::Foundation::IInspectable const& dictionaryKey, Windows::Foundation::IInspectable const& suggestedValue) const;
};
template <> struct consume<Windows::UI::Xaml::Hosting::IXamlUIPresenterHost3> { template <typename D> using type = consume_Windows_UI_Xaml_Hosting_IXamlUIPresenterHost3<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Hosting_IXamlUIPresenterStatics
{
    bool CompleteTimelinesAutomatically() const;
    void CompleteTimelinesAutomatically(bool value) const;
    void SetHost(Windows::UI::Xaml::Hosting::IXamlUIPresenterHost const& host) const;
    void NotifyWindowSizeChanged() const;
};
template <> struct consume<Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics> { template <typename D> using type = consume_Windows_UI_Xaml_Hosting_IXamlUIPresenterStatics<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Hosting_IXamlUIPresenterStatics2
{
    Windows::Foundation::Rect GetFlyoutPlacementTargetInfo(Windows::UI::Xaml::FrameworkElement const& placementTarget, Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode const& preferredPlacement, Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode& targetPreferredPlacement, bool& allowFallbacks) const;
    Windows::Foundation::Rect GetFlyoutPlacement(Windows::Foundation::Rect const& placementTargetBounds, Windows::Foundation::Size const& controlSize, Windows::Foundation::Size const& minControlSize, Windows::Foundation::Rect const& containerRect, Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode const& targetPreferredPlacement, bool allowFallbacks, Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode& chosenPlacement) const;
};
template <> struct consume<Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics2> { template <typename D> using type = consume_Windows_UI_Xaml_Hosting_IXamlUIPresenterStatics2<D>; };

}
