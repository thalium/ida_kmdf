// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.UI.WebUI.Core.2.h"
#include "winrt/Windows.UI.WebUI.h"

namespace winrt::impl {

template <typename D> bool consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::Visible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBar)->get_Visible(&value));
    return value;
}

template <typename D> void consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::Visible(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBar)->put_Visible(value));
}

template <typename D> double consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::Opacity() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBar)->get_Opacity(&value));
    return value;
}

template <typename D> void consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::Opacity(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBar)->put_Opacity(value));
}

template <typename D> Windows::UI::Color consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::ForegroundColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBar)->get_ForegroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::ForegroundColor(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBar)->put_ForegroundColor(get_abi(value)));
}

template <typename D> Windows::UI::Color consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::BackgroundColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBar)->get_BackgroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::BackgroundColor(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBar)->put_BackgroundColor(get_abi(value)));
}

template <typename D> Windows::UI::WebUI::Core::WebUICommandBarClosedDisplayMode consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::ClosedDisplayMode() const
{
    Windows::UI::WebUI::Core::WebUICommandBarClosedDisplayMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBar)->get_ClosedDisplayMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::ClosedDisplayMode(Windows::UI::WebUI::Core::WebUICommandBarClosedDisplayMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBar)->put_ClosedDisplayMode(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::IsOpen() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBar)->get_IsOpen(&value));
    return value;
}

template <typename D> void consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::IsOpen(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBar)->put_IsOpen(value));
}

template <typename D> Windows::Foundation::Size consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::Size() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBar)->get_Size(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IObservableVector<Windows::UI::WebUI::Core::IWebUICommandBarElement> consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::PrimaryCommands() const
{
    Windows::Foundation::Collections::IObservableVector<Windows::UI::WebUI::Core::IWebUICommandBarElement> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBar)->get_PrimaryCommands(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IObservableVector<Windows::UI::WebUI::Core::IWebUICommandBarElement> consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::SecondaryCommands() const
{
    Windows::Foundation::Collections::IObservableVector<Windows::UI::WebUI::Core::IWebUICommandBarElement> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBar)->get_SecondaryCommands(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::MenuOpened(Windows::UI::WebUI::Core::MenuOpenedEventHandler const& handler) const
{
    winrt::event_token value{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBar)->add_MenuOpened(get_abi(handler), put_abi(value)));
    return value;
}

template <typename D> typename consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::MenuOpened_revoker consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::MenuOpened(auto_revoke_t, Windows::UI::WebUI::Core::MenuOpenedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, MenuOpened_revoker>(this, MenuOpened(handler));
}

template <typename D> void consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::MenuOpened(winrt::event_token const& value) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBar)->remove_MenuOpened(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::MenuClosed(Windows::UI::WebUI::Core::MenuClosedEventHandler const& handler) const
{
    winrt::event_token value{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBar)->add_MenuClosed(get_abi(handler), put_abi(value)));
    return value;
}

template <typename D> typename consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::MenuClosed_revoker consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::MenuClosed(auto_revoke_t, Windows::UI::WebUI::Core::MenuClosedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, MenuClosed_revoker>(this, MenuClosed(handler));
}

template <typename D> void consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::MenuClosed(winrt::event_token const& value) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBar)->remove_MenuClosed(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::SizeChanged(Windows::UI::WebUI::Core::SizeChangedEventHandler const& handler) const
{
    winrt::event_token value{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBar)->add_SizeChanged(get_abi(handler), put_abi(value)));
    return value;
}

template <typename D> typename consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::SizeChanged_revoker consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::SizeChanged(auto_revoke_t, Windows::UI::WebUI::Core::SizeChangedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, SizeChanged_revoker>(this, SizeChanged(handler));
}

template <typename D> void consume_Windows_UI_WebUI_Core_IWebUICommandBar<D>::SizeChanged(winrt::event_token const& value) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBar)->remove_SizeChanged(get_abi(value)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_UI_WebUI_Core_IWebUICommandBarBitmapIcon<D>::Uri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBarBitmapIcon)->get_Uri(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_WebUI_Core_IWebUICommandBarBitmapIcon<D>::Uri(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBarBitmapIcon)->put_Uri(get_abi(value)));
}

template <typename D> Windows::UI::WebUI::Core::WebUICommandBarBitmapIcon consume_Windows_UI_WebUI_Core_IWebUICommandBarBitmapIconFactory<D>::Create(Windows::Foundation::Uri const& uri) const
{
    Windows::UI::WebUI::Core::WebUICommandBarBitmapIcon instance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBarBitmapIconFactory)->Create(get_abi(uri), put_abi(instance)));
    return instance;
}

template <typename D> hstring consume_Windows_UI_WebUI_Core_IWebUICommandBarConfirmationButton<D>::Text() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBarConfirmationButton)->get_Text(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_WebUI_Core_IWebUICommandBarConfirmationButton<D>::Text(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBarConfirmationButton)->put_Text(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_UI_WebUI_Core_IWebUICommandBarConfirmationButton<D>::ItemInvoked(Windows::Foundation::TypedEventHandler<Windows::UI::WebUI::Core::WebUICommandBarConfirmationButton, Windows::UI::WebUI::Core::WebUICommandBarItemInvokedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBarConfirmationButton)->add_ItemInvoked(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_WebUI_Core_IWebUICommandBarConfirmationButton<D>::ItemInvoked_revoker consume_Windows_UI_WebUI_Core_IWebUICommandBarConfirmationButton<D>::ItemInvoked(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::WebUI::Core::WebUICommandBarConfirmationButton, Windows::UI::WebUI::Core::WebUICommandBarItemInvokedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ItemInvoked_revoker>(this, ItemInvoked(handler));
}

template <typename D> void consume_Windows_UI_WebUI_Core_IWebUICommandBarConfirmationButton<D>::ItemInvoked(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBarConfirmationButton)->remove_ItemInvoked(get_abi(token)));
}

template <typename D> bool consume_Windows_UI_WebUI_Core_IWebUICommandBarIconButton<D>::Enabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBarIconButton)->get_Enabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_WebUI_Core_IWebUICommandBarIconButton<D>::Enabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBarIconButton)->put_Enabled(value));
}

template <typename D> hstring consume_Windows_UI_WebUI_Core_IWebUICommandBarIconButton<D>::Label() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBarIconButton)->get_Label(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_WebUI_Core_IWebUICommandBarIconButton<D>::Label(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBarIconButton)->put_Label(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_WebUI_Core_IWebUICommandBarIconButton<D>::IsToggleButton() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBarIconButton)->get_IsToggleButton(&value));
    return value;
}

template <typename D> void consume_Windows_UI_WebUI_Core_IWebUICommandBarIconButton<D>::IsToggleButton(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBarIconButton)->put_IsToggleButton(value));
}

template <typename D> bool consume_Windows_UI_WebUI_Core_IWebUICommandBarIconButton<D>::IsChecked() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBarIconButton)->get_IsChecked(&value));
    return value;
}

template <typename D> void consume_Windows_UI_WebUI_Core_IWebUICommandBarIconButton<D>::IsChecked(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBarIconButton)->put_IsChecked(value));
}

template <typename D> Windows::UI::WebUI::Core::IWebUICommandBarIcon consume_Windows_UI_WebUI_Core_IWebUICommandBarIconButton<D>::Icon() const
{
    Windows::UI::WebUI::Core::IWebUICommandBarIcon value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBarIconButton)->get_Icon(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_WebUI_Core_IWebUICommandBarIconButton<D>::Icon(Windows::UI::WebUI::Core::IWebUICommandBarIcon const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBarIconButton)->put_Icon(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_UI_WebUI_Core_IWebUICommandBarIconButton<D>::ItemInvoked(Windows::Foundation::TypedEventHandler<Windows::UI::WebUI::Core::WebUICommandBarIconButton, Windows::UI::WebUI::Core::WebUICommandBarItemInvokedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBarIconButton)->add_ItemInvoked(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_WebUI_Core_IWebUICommandBarIconButton<D>::ItemInvoked_revoker consume_Windows_UI_WebUI_Core_IWebUICommandBarIconButton<D>::ItemInvoked(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::WebUI::Core::WebUICommandBarIconButton, Windows::UI::WebUI::Core::WebUICommandBarItemInvokedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ItemInvoked_revoker>(this, ItemInvoked(handler));
}

template <typename D> void consume_Windows_UI_WebUI_Core_IWebUICommandBarIconButton<D>::ItemInvoked(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBarIconButton)->remove_ItemInvoked(get_abi(token)));
}

template <typename D> bool consume_Windows_UI_WebUI_Core_IWebUICommandBarItemInvokedEventArgs<D>::IsPrimaryCommand() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBarItemInvokedEventArgs)->get_IsPrimaryCommand(&value));
    return value;
}

template <typename D> Windows::Foundation::Size consume_Windows_UI_WebUI_Core_IWebUICommandBarSizeChangedEventArgs<D>::Size() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBarSizeChangedEventArgs)->get_Size(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::WebUI::Core::WebUICommandBar consume_Windows_UI_WebUI_Core_IWebUICommandBarStatics<D>::GetForCurrentView() const
{
    Windows::UI::WebUI::Core::WebUICommandBar commandBar{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBarStatics)->GetForCurrentView(put_abi(commandBar)));
    return commandBar;
}

template <typename D> hstring consume_Windows_UI_WebUI_Core_IWebUICommandBarSymbolIcon<D>::Symbol() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBarSymbolIcon)->get_Symbol(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_WebUI_Core_IWebUICommandBarSymbolIcon<D>::Symbol(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBarSymbolIcon)->put_Symbol(get_abi(value)));
}

template <typename D> Windows::UI::WebUI::Core::WebUICommandBarSymbolIcon consume_Windows_UI_WebUI_Core_IWebUICommandBarSymbolIconFactory<D>::Create(param::hstring const& symbol) const
{
    Windows::UI::WebUI::Core::WebUICommandBarSymbolIcon instance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::Core::IWebUICommandBarSymbolIconFactory)->Create(get_abi(symbol), put_abi(instance)));
    return instance;
}

template <> struct delegate<Windows::UI::WebUI::Core::MenuClosedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::WebUI::Core::MenuClosedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::WebUI::Core::MenuClosedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke() noexcept final
        {
            try
            {
                (*this)();
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::WebUI::Core::MenuOpenedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::WebUI::Core::MenuOpenedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::WebUI::Core::MenuOpenedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke() noexcept final
        {
            try
            {
                (*this)();
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::WebUI::Core::SizeChangedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::WebUI::Core::SizeChangedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::WebUI::Core::SizeChangedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* eventArgs) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::UI::WebUI::Core::WebUICommandBarSizeChangedEventArgs const*>(&eventArgs));
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
struct produce<D, Windows::UI::WebUI::Core::IWebUICommandBar> : produce_base<D, Windows::UI::WebUI::Core::IWebUICommandBar>
{
    int32_t WINRT_CALL get_Visible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Visible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Visible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Visible(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Visible, WINRT_WRAP(void), bool);
            this->shim().Visible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL get_ClosedDisplayMode(Windows::UI::WebUI::Core::WebUICommandBarClosedDisplayMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClosedDisplayMode, WINRT_WRAP(Windows::UI::WebUI::Core::WebUICommandBarClosedDisplayMode));
            *value = detach_from<Windows::UI::WebUI::Core::WebUICommandBarClosedDisplayMode>(this->shim().ClosedDisplayMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ClosedDisplayMode(Windows::UI::WebUI::Core::WebUICommandBarClosedDisplayMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClosedDisplayMode, WINRT_WRAP(void), Windows::UI::WebUI::Core::WebUICommandBarClosedDisplayMode const&);
            this->shim().ClosedDisplayMode(*reinterpret_cast<Windows::UI::WebUI::Core::WebUICommandBarClosedDisplayMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsOpen(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOpen, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsOpen());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsOpen(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOpen, WINRT_WRAP(void), bool);
            this->shim().IsOpen(value);
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

    int32_t WINRT_CALL get_PrimaryCommands(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrimaryCommands, WINRT_WRAP(Windows::Foundation::Collections::IObservableVector<Windows::UI::WebUI::Core::IWebUICommandBarElement>));
            *value = detach_from<Windows::Foundation::Collections::IObservableVector<Windows::UI::WebUI::Core::IWebUICommandBarElement>>(this->shim().PrimaryCommands());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SecondaryCommands(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SecondaryCommands, WINRT_WRAP(Windows::Foundation::Collections::IObservableVector<Windows::UI::WebUI::Core::IWebUICommandBarElement>));
            *value = detach_from<Windows::Foundation::Collections::IObservableVector<Windows::UI::WebUI::Core::IWebUICommandBarElement>>(this->shim().SecondaryCommands());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_MenuOpened(void* handler, winrt::event_token* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MenuOpened, WINRT_WRAP(winrt::event_token), Windows::UI::WebUI::Core::MenuOpenedEventHandler const&);
            *value = detach_from<winrt::event_token>(this->shim().MenuOpened(*reinterpret_cast<Windows::UI::WebUI::Core::MenuOpenedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MenuOpened(winrt::event_token value) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MenuOpened, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MenuOpened(*reinterpret_cast<winrt::event_token const*>(&value));
        return 0;
    }

    int32_t WINRT_CALL add_MenuClosed(void* handler, winrt::event_token* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MenuClosed, WINRT_WRAP(winrt::event_token), Windows::UI::WebUI::Core::MenuClosedEventHandler const&);
            *value = detach_from<winrt::event_token>(this->shim().MenuClosed(*reinterpret_cast<Windows::UI::WebUI::Core::MenuClosedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MenuClosed(winrt::event_token value) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MenuClosed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MenuClosed(*reinterpret_cast<winrt::event_token const*>(&value));
        return 0;
    }

    int32_t WINRT_CALL add_SizeChanged(void* handler, winrt::event_token* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SizeChanged, WINRT_WRAP(winrt::event_token), Windows::UI::WebUI::Core::SizeChangedEventHandler const&);
            *value = detach_from<winrt::event_token>(this->shim().SizeChanged(*reinterpret_cast<Windows::UI::WebUI::Core::SizeChangedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SizeChanged(winrt::event_token value) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SizeChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SizeChanged(*reinterpret_cast<winrt::event_token const*>(&value));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::WebUI::Core::IWebUICommandBarBitmapIcon> : produce_base<D, Windows::UI::WebUI::Core::IWebUICommandBarBitmapIcon>
{
    int32_t WINRT_CALL get_Uri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Uri(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uri, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().Uri(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::WebUI::Core::IWebUICommandBarBitmapIconFactory> : produce_base<D, Windows::UI::WebUI::Core::IWebUICommandBarBitmapIconFactory>
{
    int32_t WINRT_CALL Create(void* uri, void** instance) noexcept final
    {
        try
        {
            *instance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::UI::WebUI::Core::WebUICommandBarBitmapIcon), Windows::Foundation::Uri const&);
            *instance = detach_from<Windows::UI::WebUI::Core::WebUICommandBarBitmapIcon>(this->shim().Create(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::WebUI::Core::IWebUICommandBarConfirmationButton> : produce_base<D, Windows::UI::WebUI::Core::IWebUICommandBarConfirmationButton>
{
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

    int32_t WINRT_CALL add_ItemInvoked(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemInvoked, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::WebUI::Core::WebUICommandBarConfirmationButton, Windows::UI::WebUI::Core::WebUICommandBarItemInvokedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ItemInvoked(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::WebUI::Core::WebUICommandBarConfirmationButton, Windows::UI::WebUI::Core::WebUICommandBarItemInvokedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ItemInvoked(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ItemInvoked, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ItemInvoked(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::WebUI::Core::IWebUICommandBarElement> : produce_base<D, Windows::UI::WebUI::Core::IWebUICommandBarElement>
{};

template <typename D>
struct produce<D, Windows::UI::WebUI::Core::IWebUICommandBarIcon> : produce_base<D, Windows::UI::WebUI::Core::IWebUICommandBarIcon>
{};

template <typename D>
struct produce<D, Windows::UI::WebUI::Core::IWebUICommandBarIconButton> : produce_base<D, Windows::UI::WebUI::Core::IWebUICommandBarIconButton>
{
    int32_t WINRT_CALL get_Enabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Enabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Enabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Enabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Enabled, WINRT_WRAP(void), bool);
            this->shim().Enabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Label(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Label, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Label());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Label(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Label, WINRT_WRAP(void), hstring const&);
            this->shim().Label(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsToggleButton(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsToggleButton, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsToggleButton());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsToggleButton(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsToggleButton, WINRT_WRAP(void), bool);
            this->shim().IsToggleButton(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsChecked(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsChecked, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsChecked());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsChecked(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsChecked, WINRT_WRAP(void), bool);
            this->shim().IsChecked(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Icon(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Icon, WINRT_WRAP(Windows::UI::WebUI::Core::IWebUICommandBarIcon));
            *value = detach_from<Windows::UI::WebUI::Core::IWebUICommandBarIcon>(this->shim().Icon());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Icon(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Icon, WINRT_WRAP(void), Windows::UI::WebUI::Core::IWebUICommandBarIcon const&);
            this->shim().Icon(*reinterpret_cast<Windows::UI::WebUI::Core::IWebUICommandBarIcon const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ItemInvoked(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemInvoked, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::WebUI::Core::WebUICommandBarIconButton, Windows::UI::WebUI::Core::WebUICommandBarItemInvokedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ItemInvoked(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::WebUI::Core::WebUICommandBarIconButton, Windows::UI::WebUI::Core::WebUICommandBarItemInvokedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ItemInvoked(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ItemInvoked, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ItemInvoked(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::WebUI::Core::IWebUICommandBarItemInvokedEventArgs> : produce_base<D, Windows::UI::WebUI::Core::IWebUICommandBarItemInvokedEventArgs>
{
    int32_t WINRT_CALL get_IsPrimaryCommand(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPrimaryCommand, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPrimaryCommand());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::WebUI::Core::IWebUICommandBarSizeChangedEventArgs> : produce_base<D, Windows::UI::WebUI::Core::IWebUICommandBarSizeChangedEventArgs>
{
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
};

template <typename D>
struct produce<D, Windows::UI::WebUI::Core::IWebUICommandBarStatics> : produce_base<D, Windows::UI::WebUI::Core::IWebUICommandBarStatics>
{
    int32_t WINRT_CALL GetForCurrentView(void** commandBar) noexcept final
    {
        try
        {
            *commandBar = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentView, WINRT_WRAP(Windows::UI::WebUI::Core::WebUICommandBar));
            *commandBar = detach_from<Windows::UI::WebUI::Core::WebUICommandBar>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::WebUI::Core::IWebUICommandBarSymbolIcon> : produce_base<D, Windows::UI::WebUI::Core::IWebUICommandBarSymbolIcon>
{
    int32_t WINRT_CALL get_Symbol(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Symbol, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Symbol());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Symbol(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Symbol, WINRT_WRAP(void), hstring const&);
            this->shim().Symbol(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::WebUI::Core::IWebUICommandBarSymbolIconFactory> : produce_base<D, Windows::UI::WebUI::Core::IWebUICommandBarSymbolIconFactory>
{
    int32_t WINRT_CALL Create(void* symbol, void** instance) noexcept final
    {
        try
        {
            *instance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::UI::WebUI::Core::WebUICommandBarSymbolIcon), hstring const&);
            *instance = detach_from<Windows::UI::WebUI::Core::WebUICommandBarSymbolIcon>(this->shim().Create(*reinterpret_cast<hstring const*>(&symbol)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::WebUI::Core {

inline Windows::UI::WebUI::Core::WebUICommandBar WebUICommandBar::GetForCurrentView()
{
    return impl::call_factory<WebUICommandBar, Windows::UI::WebUI::Core::IWebUICommandBarStatics>([&](auto&& f) { return f.GetForCurrentView(); });
}

inline WebUICommandBarBitmapIcon::WebUICommandBarBitmapIcon() :
    WebUICommandBarBitmapIcon(impl::call_factory<WebUICommandBarBitmapIcon>([](auto&& f) { return f.template ActivateInstance<WebUICommandBarBitmapIcon>(); }))
{}

inline WebUICommandBarBitmapIcon::WebUICommandBarBitmapIcon(Windows::Foundation::Uri const& uri) :
    WebUICommandBarBitmapIcon(impl::call_factory<WebUICommandBarBitmapIcon, Windows::UI::WebUI::Core::IWebUICommandBarBitmapIconFactory>([&](auto&& f) { return f.Create(uri); }))
{}

inline WebUICommandBarConfirmationButton::WebUICommandBarConfirmationButton() :
    WebUICommandBarConfirmationButton(impl::call_factory<WebUICommandBarConfirmationButton>([](auto&& f) { return f.template ActivateInstance<WebUICommandBarConfirmationButton>(); }))
{}

inline WebUICommandBarIconButton::WebUICommandBarIconButton() :
    WebUICommandBarIconButton(impl::call_factory<WebUICommandBarIconButton>([](auto&& f) { return f.template ActivateInstance<WebUICommandBarIconButton>(); }))
{}

inline WebUICommandBarSymbolIcon::WebUICommandBarSymbolIcon() :
    WebUICommandBarSymbolIcon(impl::call_factory<WebUICommandBarSymbolIcon>([](auto&& f) { return f.template ActivateInstance<WebUICommandBarSymbolIcon>(); }))
{}

inline WebUICommandBarSymbolIcon::WebUICommandBarSymbolIcon(param::hstring const& symbol) :
    WebUICommandBarSymbolIcon(impl::call_factory<WebUICommandBarSymbolIcon, Windows::UI::WebUI::Core::IWebUICommandBarSymbolIconFactory>([&](auto&& f) { return f.Create(symbol); }))
{}

template <typename L> MenuClosedEventHandler::MenuClosedEventHandler(L handler) :
    MenuClosedEventHandler(impl::make_delegate<MenuClosedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> MenuClosedEventHandler::MenuClosedEventHandler(F* handler) :
    MenuClosedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> MenuClosedEventHandler::MenuClosedEventHandler(O* object, M method) :
    MenuClosedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> MenuClosedEventHandler::MenuClosedEventHandler(com_ptr<O>&& object, M method) :
    MenuClosedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> MenuClosedEventHandler::MenuClosedEventHandler(weak_ref<O>&& object, M method) :
    MenuClosedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void MenuClosedEventHandler::operator()() const
{
    check_hresult((*(impl::abi_t<MenuClosedEventHandler>**)this)->Invoke());
}

template <typename L> MenuOpenedEventHandler::MenuOpenedEventHandler(L handler) :
    MenuOpenedEventHandler(impl::make_delegate<MenuOpenedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> MenuOpenedEventHandler::MenuOpenedEventHandler(F* handler) :
    MenuOpenedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> MenuOpenedEventHandler::MenuOpenedEventHandler(O* object, M method) :
    MenuOpenedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> MenuOpenedEventHandler::MenuOpenedEventHandler(com_ptr<O>&& object, M method) :
    MenuOpenedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> MenuOpenedEventHandler::MenuOpenedEventHandler(weak_ref<O>&& object, M method) :
    MenuOpenedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void MenuOpenedEventHandler::operator()() const
{
    check_hresult((*(impl::abi_t<MenuOpenedEventHandler>**)this)->Invoke());
}

template <typename L> SizeChangedEventHandler::SizeChangedEventHandler(L handler) :
    SizeChangedEventHandler(impl::make_delegate<SizeChangedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> SizeChangedEventHandler::SizeChangedEventHandler(F* handler) :
    SizeChangedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> SizeChangedEventHandler::SizeChangedEventHandler(O* object, M method) :
    SizeChangedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> SizeChangedEventHandler::SizeChangedEventHandler(com_ptr<O>&& object, M method) :
    SizeChangedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> SizeChangedEventHandler::SizeChangedEventHandler(weak_ref<O>&& object, M method) :
    SizeChangedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void SizeChangedEventHandler::operator()(Windows::UI::WebUI::Core::WebUICommandBarSizeChangedEventArgs const& eventArgs) const
{
    check_hresult((*(impl::abi_t<SizeChangedEventHandler>**)this)->Invoke(get_abi(eventArgs)));
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::WebUI::Core::IWebUICommandBar> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::Core::IWebUICommandBar> {};
template<> struct hash<winrt::Windows::UI::WebUI::Core::IWebUICommandBarBitmapIcon> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::Core::IWebUICommandBarBitmapIcon> {};
template<> struct hash<winrt::Windows::UI::WebUI::Core::IWebUICommandBarBitmapIconFactory> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::Core::IWebUICommandBarBitmapIconFactory> {};
template<> struct hash<winrt::Windows::UI::WebUI::Core::IWebUICommandBarConfirmationButton> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::Core::IWebUICommandBarConfirmationButton> {};
template<> struct hash<winrt::Windows::UI::WebUI::Core::IWebUICommandBarElement> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::Core::IWebUICommandBarElement> {};
template<> struct hash<winrt::Windows::UI::WebUI::Core::IWebUICommandBarIcon> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::Core::IWebUICommandBarIcon> {};
template<> struct hash<winrt::Windows::UI::WebUI::Core::IWebUICommandBarIconButton> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::Core::IWebUICommandBarIconButton> {};
template<> struct hash<winrt::Windows::UI::WebUI::Core::IWebUICommandBarItemInvokedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::Core::IWebUICommandBarItemInvokedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::Core::IWebUICommandBarSizeChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::Core::IWebUICommandBarSizeChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::Core::IWebUICommandBarStatics> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::Core::IWebUICommandBarStatics> {};
template<> struct hash<winrt::Windows::UI::WebUI::Core::IWebUICommandBarSymbolIcon> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::Core::IWebUICommandBarSymbolIcon> {};
template<> struct hash<winrt::Windows::UI::WebUI::Core::IWebUICommandBarSymbolIconFactory> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::Core::IWebUICommandBarSymbolIconFactory> {};
template<> struct hash<winrt::Windows::UI::WebUI::Core::WebUICommandBar> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::Core::WebUICommandBar> {};
template<> struct hash<winrt::Windows::UI::WebUI::Core::WebUICommandBarBitmapIcon> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::Core::WebUICommandBarBitmapIcon> {};
template<> struct hash<winrt::Windows::UI::WebUI::Core::WebUICommandBarConfirmationButton> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::Core::WebUICommandBarConfirmationButton> {};
template<> struct hash<winrt::Windows::UI::WebUI::Core::WebUICommandBarIconButton> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::Core::WebUICommandBarIconButton> {};
template<> struct hash<winrt::Windows::UI::WebUI::Core::WebUICommandBarItemInvokedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::Core::WebUICommandBarItemInvokedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::Core::WebUICommandBarSizeChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::Core::WebUICommandBarSizeChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::Core::WebUICommandBarSymbolIcon> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::Core::WebUICommandBarSymbolIcon> {};

}
