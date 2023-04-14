// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.UI.Popups.2.h"
#include "winrt/Windows.UI.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_UI_Popups_IMessageDialog<D>::Title() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Popups::IMessageDialog)->get_Title(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Popups_IMessageDialog<D>::Title(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Popups::IMessageDialog)->put_Title(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Popups::IUICommand> consume_Windows_UI_Popups_IMessageDialog<D>::Commands() const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Popups::IUICommand> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Popups::IMessageDialog)->get_Commands(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_UI_Popups_IMessageDialog<D>::DefaultCommandIndex() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Popups::IMessageDialog)->get_DefaultCommandIndex(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Popups_IMessageDialog<D>::DefaultCommandIndex(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Popups::IMessageDialog)->put_DefaultCommandIndex(value));
}

template <typename D> uint32_t consume_Windows_UI_Popups_IMessageDialog<D>::CancelCommandIndex() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Popups::IMessageDialog)->get_CancelCommandIndex(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Popups_IMessageDialog<D>::CancelCommandIndex(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Popups::IMessageDialog)->put_CancelCommandIndex(value));
}

template <typename D> hstring consume_Windows_UI_Popups_IMessageDialog<D>::Content() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Popups::IMessageDialog)->get_Content(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Popups_IMessageDialog<D>::Content(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Popups::IMessageDialog)->put_Content(get_abi(value)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::UI::Popups::IUICommand> consume_Windows_UI_Popups_IMessageDialog<D>::ShowAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::UI::Popups::IUICommand> messageDialogAsyncOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Popups::IMessageDialog)->ShowAsync(put_abi(messageDialogAsyncOperation)));
    return messageDialogAsyncOperation;
}

template <typename D> Windows::UI::Popups::MessageDialogOptions consume_Windows_UI_Popups_IMessageDialog<D>::Options() const
{
    Windows::UI::Popups::MessageDialogOptions value{};
    check_hresult(WINRT_SHIM(Windows::UI::Popups::IMessageDialog)->get_Options(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Popups_IMessageDialog<D>::Options(Windows::UI::Popups::MessageDialogOptions const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Popups::IMessageDialog)->put_Options(get_abi(value)));
}

template <typename D> Windows::UI::Popups::MessageDialog consume_Windows_UI_Popups_IMessageDialogFactory<D>::Create(param::hstring const& content) const
{
    Windows::UI::Popups::MessageDialog messageDialog{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Popups::IMessageDialogFactory)->Create(get_abi(content), put_abi(messageDialog)));
    return messageDialog;
}

template <typename D> Windows::UI::Popups::MessageDialog consume_Windows_UI_Popups_IMessageDialogFactory<D>::CreateWithTitle(param::hstring const& content, param::hstring const& title) const
{
    Windows::UI::Popups::MessageDialog messageDialog{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Popups::IMessageDialogFactory)->CreateWithTitle(get_abi(content), get_abi(title), put_abi(messageDialog)));
    return messageDialog;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Popups::IUICommand> consume_Windows_UI_Popups_IPopupMenu<D>::Commands() const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Popups::IUICommand> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Popups::IPopupMenu)->get_Commands(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::UI::Popups::IUICommand> consume_Windows_UI_Popups_IPopupMenu<D>::ShowAsync(Windows::Foundation::Point const& invocationPoint) const
{
    Windows::Foundation::IAsyncOperation<Windows::UI::Popups::IUICommand> asyncOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Popups::IPopupMenu)->ShowAsync(get_abi(invocationPoint), put_abi(asyncOperation)));
    return asyncOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::UI::Popups::IUICommand> consume_Windows_UI_Popups_IPopupMenu<D>::ShowForSelectionAsync(Windows::Foundation::Rect const& selection) const
{
    Windows::Foundation::IAsyncOperation<Windows::UI::Popups::IUICommand> asyncOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Popups::IPopupMenu)->ShowAsyncWithRect(get_abi(selection), put_abi(asyncOperation)));
    return asyncOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::UI::Popups::IUICommand> consume_Windows_UI_Popups_IPopupMenu<D>::ShowForSelectionAsync(Windows::Foundation::Rect const& selection, Windows::UI::Popups::Placement const& preferredPlacement) const
{
    Windows::Foundation::IAsyncOperation<Windows::UI::Popups::IUICommand> asyncOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Popups::IPopupMenu)->ShowAsyncWithRectAndPlacement(get_abi(selection), get_abi(preferredPlacement), put_abi(asyncOperation)));
    return asyncOperation;
}

template <typename D> hstring consume_Windows_UI_Popups_IUICommand<D>::Label() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Popups::IUICommand)->get_Label(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Popups_IUICommand<D>::Label(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Popups::IUICommand)->put_Label(get_abi(value)));
}

template <typename D> Windows::UI::Popups::UICommandInvokedHandler consume_Windows_UI_Popups_IUICommand<D>::Invoked() const
{
    Windows::UI::Popups::UICommandInvokedHandler value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Popups::IUICommand)->get_Invoked(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Popups_IUICommand<D>::Invoked(Windows::UI::Popups::UICommandInvokedHandler const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Popups::IUICommand)->put_Invoked(get_abi(value)));
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Popups_IUICommand<D>::Id() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Popups::IUICommand)->get_Id(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Popups_IUICommand<D>::Id(Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Popups::IUICommand)->put_Id(get_abi(value)));
}

template <typename D> Windows::UI::Popups::UICommand consume_Windows_UI_Popups_IUICommandFactory<D>::Create(param::hstring const& label) const
{
    Windows::UI::Popups::UICommand instance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Popups::IUICommandFactory)->Create(get_abi(label), put_abi(instance)));
    return instance;
}

template <typename D> Windows::UI::Popups::UICommand consume_Windows_UI_Popups_IUICommandFactory<D>::CreateWithHandler(param::hstring const& label, Windows::UI::Popups::UICommandInvokedHandler const& action) const
{
    Windows::UI::Popups::UICommand instance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Popups::IUICommandFactory)->CreateWithHandler(get_abi(label), get_abi(action), put_abi(instance)));
    return instance;
}

template <typename D> Windows::UI::Popups::UICommand consume_Windows_UI_Popups_IUICommandFactory<D>::CreateWithHandlerAndId(param::hstring const& label, Windows::UI::Popups::UICommandInvokedHandler const& action, Windows::Foundation::IInspectable const& commandId) const
{
    Windows::UI::Popups::UICommand instance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Popups::IUICommandFactory)->CreateWithHandlerAndId(get_abi(label), get_abi(action), get_abi(commandId), put_abi(instance)));
    return instance;
}

template <> struct delegate<Windows::UI::Popups::UICommandInvokedHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Popups::UICommandInvokedHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Popups::UICommandInvokedHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* command) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::UI::Popups::IUICommand const*>(&command));
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
struct produce<D, Windows::UI::Popups::IMessageDialog> : produce_base<D, Windows::UI::Popups::IMessageDialog>
{
    int32_t WINRT_CALL get_Title(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Title(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(void), hstring const&);
            this->shim().Title(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Commands(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Commands, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Popups::IUICommand>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Popups::IUICommand>>(this->shim().Commands());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DefaultCommandIndex(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultCommandIndex, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().DefaultCommandIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DefaultCommandIndex(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultCommandIndex, WINRT_WRAP(void), uint32_t);
            this->shim().DefaultCommandIndex(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CancelCommandIndex(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CancelCommandIndex, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().CancelCommandIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CancelCommandIndex(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CancelCommandIndex, WINRT_WRAP(void), uint32_t);
            this->shim().CancelCommandIndex(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Content(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Content, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Content());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Content(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Content, WINRT_WRAP(void), hstring const&);
            this->shim().Content(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowAsync(void** messageDialogAsyncOperation) noexcept final
    {
        try
        {
            *messageDialogAsyncOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::UI::Popups::IUICommand>));
            *messageDialogAsyncOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::UI::Popups::IUICommand>>(this->shim().ShowAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Options(Windows::UI::Popups::MessageDialogOptions* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Options, WINRT_WRAP(Windows::UI::Popups::MessageDialogOptions));
            *value = detach_from<Windows::UI::Popups::MessageDialogOptions>(this->shim().Options());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Options(Windows::UI::Popups::MessageDialogOptions value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Options, WINRT_WRAP(void), Windows::UI::Popups::MessageDialogOptions const&);
            this->shim().Options(*reinterpret_cast<Windows::UI::Popups::MessageDialogOptions const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Popups::IMessageDialogFactory> : produce_base<D, Windows::UI::Popups::IMessageDialogFactory>
{
    int32_t WINRT_CALL Create(void* content, void** messageDialog) noexcept final
    {
        try
        {
            *messageDialog = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::UI::Popups::MessageDialog), hstring const&);
            *messageDialog = detach_from<Windows::UI::Popups::MessageDialog>(this->shim().Create(*reinterpret_cast<hstring const*>(&content)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithTitle(void* content, void* title, void** messageDialog) noexcept final
    {
        try
        {
            *messageDialog = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithTitle, WINRT_WRAP(Windows::UI::Popups::MessageDialog), hstring const&, hstring const&);
            *messageDialog = detach_from<Windows::UI::Popups::MessageDialog>(this->shim().CreateWithTitle(*reinterpret_cast<hstring const*>(&content), *reinterpret_cast<hstring const*>(&title)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Popups::IPopupMenu> : produce_base<D, Windows::UI::Popups::IPopupMenu>
{
    int32_t WINRT_CALL get_Commands(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Commands, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Popups::IUICommand>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Popups::IUICommand>>(this->shim().Commands());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowAsync(Windows::Foundation::Point invocationPoint, void** asyncOperation) noexcept final
    {
        try
        {
            *asyncOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::UI::Popups::IUICommand>), Windows::Foundation::Point const);
            *asyncOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::UI::Popups::IUICommand>>(this->shim().ShowAsync(*reinterpret_cast<Windows::Foundation::Point const*>(&invocationPoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowAsyncWithRect(Windows::Foundation::Rect selection, void** asyncOperation) noexcept final
    {
        try
        {
            *asyncOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowForSelectionAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::UI::Popups::IUICommand>), Windows::Foundation::Rect const);
            *asyncOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::UI::Popups::IUICommand>>(this->shim().ShowForSelectionAsync(*reinterpret_cast<Windows::Foundation::Rect const*>(&selection)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowAsyncWithRectAndPlacement(Windows::Foundation::Rect selection, Windows::UI::Popups::Placement preferredPlacement, void** asyncOperation) noexcept final
    {
        try
        {
            *asyncOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowForSelectionAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::UI::Popups::IUICommand>), Windows::Foundation::Rect const, Windows::UI::Popups::Placement const);
            *asyncOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::UI::Popups::IUICommand>>(this->shim().ShowForSelectionAsync(*reinterpret_cast<Windows::Foundation::Rect const*>(&selection), *reinterpret_cast<Windows::UI::Popups::Placement const*>(&preferredPlacement)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Popups::IUICommand> : produce_base<D, Windows::UI::Popups::IUICommand>
{
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

    int32_t WINRT_CALL get_Invoked(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Invoked, WINRT_WRAP(Windows::UI::Popups::UICommandInvokedHandler));
            *value = detach_from<Windows::UI::Popups::UICommandInvokedHandler>(this->shim().Invoked());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Invoked(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Invoked, WINRT_WRAP(void), Windows::UI::Popups::UICommandInvokedHandler const&);
            this->shim().Invoked(*reinterpret_cast<Windows::UI::Popups::UICommandInvokedHandler const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Id(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Id(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(void), Windows::Foundation::IInspectable const&);
            this->shim().Id(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Popups::IUICommandFactory> : produce_base<D, Windows::UI::Popups::IUICommandFactory>
{
    int32_t WINRT_CALL Create(void* label, void** instance) noexcept final
    {
        try
        {
            *instance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::UI::Popups::UICommand), hstring const&);
            *instance = detach_from<Windows::UI::Popups::UICommand>(this->shim().Create(*reinterpret_cast<hstring const*>(&label)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithHandler(void* label, void* action, void** instance) noexcept final
    {
        try
        {
            *instance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithHandler, WINRT_WRAP(Windows::UI::Popups::UICommand), hstring const&, Windows::UI::Popups::UICommandInvokedHandler const&);
            *instance = detach_from<Windows::UI::Popups::UICommand>(this->shim().CreateWithHandler(*reinterpret_cast<hstring const*>(&label), *reinterpret_cast<Windows::UI::Popups::UICommandInvokedHandler const*>(&action)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithHandlerAndId(void* label, void* action, void* commandId, void** instance) noexcept final
    {
        try
        {
            *instance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithHandlerAndId, WINRT_WRAP(Windows::UI::Popups::UICommand), hstring const&, Windows::UI::Popups::UICommandInvokedHandler const&, Windows::Foundation::IInspectable const&);
            *instance = detach_from<Windows::UI::Popups::UICommand>(this->shim().CreateWithHandlerAndId(*reinterpret_cast<hstring const*>(&label), *reinterpret_cast<Windows::UI::Popups::UICommandInvokedHandler const*>(&action), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&commandId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::Popups {

inline MessageDialog::MessageDialog(param::hstring const& content) :
    MessageDialog(impl::call_factory<MessageDialog, Windows::UI::Popups::IMessageDialogFactory>([&](auto&& f) { return f.Create(content); }))
{}

inline MessageDialog::MessageDialog(param::hstring const& content, param::hstring const& title) :
    MessageDialog(impl::call_factory<MessageDialog, Windows::UI::Popups::IMessageDialogFactory>([&](auto&& f) { return f.CreateWithTitle(content, title); }))
{}

inline PopupMenu::PopupMenu() :
    PopupMenu(impl::call_factory<PopupMenu>([](auto&& f) { return f.template ActivateInstance<PopupMenu>(); }))
{}

inline UICommand::UICommand() :
    UICommand(impl::call_factory<UICommand>([](auto&& f) { return f.template ActivateInstance<UICommand>(); }))
{}

inline UICommand::UICommand(param::hstring const& label) :
    UICommand(impl::call_factory<UICommand, Windows::UI::Popups::IUICommandFactory>([&](auto&& f) { return f.Create(label); }))
{}

inline UICommand::UICommand(param::hstring const& label, Windows::UI::Popups::UICommandInvokedHandler const& action) :
    UICommand(impl::call_factory<UICommand, Windows::UI::Popups::IUICommandFactory>([&](auto&& f) { return f.CreateWithHandler(label, action); }))
{}

inline UICommand::UICommand(param::hstring const& label, Windows::UI::Popups::UICommandInvokedHandler const& action, Windows::Foundation::IInspectable const& commandId) :
    UICommand(impl::call_factory<UICommand, Windows::UI::Popups::IUICommandFactory>([&](auto&& f) { return f.CreateWithHandlerAndId(label, action, commandId); }))
{}

inline UICommandSeparator::UICommandSeparator() :
    UICommandSeparator(impl::call_factory<UICommandSeparator>([](auto&& f) { return f.template ActivateInstance<UICommandSeparator>(); }))
{}

template <typename L> UICommandInvokedHandler::UICommandInvokedHandler(L handler) :
    UICommandInvokedHandler(impl::make_delegate<UICommandInvokedHandler>(std::forward<L>(handler)))
{}

template <typename F> UICommandInvokedHandler::UICommandInvokedHandler(F* handler) :
    UICommandInvokedHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> UICommandInvokedHandler::UICommandInvokedHandler(O* object, M method) :
    UICommandInvokedHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> UICommandInvokedHandler::UICommandInvokedHandler(com_ptr<O>&& object, M method) :
    UICommandInvokedHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> UICommandInvokedHandler::UICommandInvokedHandler(weak_ref<O>&& object, M method) :
    UICommandInvokedHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void UICommandInvokedHandler::operator()(Windows::UI::Popups::IUICommand const& command) const
{
    check_hresult((*(impl::abi_t<UICommandInvokedHandler>**)this)->Invoke(get_abi(command)));
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Popups::IMessageDialog> : winrt::impl::hash_base<winrt::Windows::UI::Popups::IMessageDialog> {};
template<> struct hash<winrt::Windows::UI::Popups::IMessageDialogFactory> : winrt::impl::hash_base<winrt::Windows::UI::Popups::IMessageDialogFactory> {};
template<> struct hash<winrt::Windows::UI::Popups::IPopupMenu> : winrt::impl::hash_base<winrt::Windows::UI::Popups::IPopupMenu> {};
template<> struct hash<winrt::Windows::UI::Popups::IUICommand> : winrt::impl::hash_base<winrt::Windows::UI::Popups::IUICommand> {};
template<> struct hash<winrt::Windows::UI::Popups::IUICommandFactory> : winrt::impl::hash_base<winrt::Windows::UI::Popups::IUICommandFactory> {};
template<> struct hash<winrt::Windows::UI::Popups::MessageDialog> : winrt::impl::hash_base<winrt::Windows::UI::Popups::MessageDialog> {};
template<> struct hash<winrt::Windows::UI::Popups::PopupMenu> : winrt::impl::hash_base<winrt::Windows::UI::Popups::PopupMenu> {};
template<> struct hash<winrt::Windows::UI::Popups::UICommand> : winrt::impl::hash_base<winrt::Windows::UI::Popups::UICommand> {};
template<> struct hash<winrt::Windows::UI::Popups::UICommandSeparator> : winrt::impl::hash_base<winrt::Windows::UI::Popups::UICommandSeparator> {};

}
