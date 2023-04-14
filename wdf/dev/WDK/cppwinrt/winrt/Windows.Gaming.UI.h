// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.Activation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Gaming.UI.2.h"

namespace winrt::impl {

template <typename D> winrt::event_token consume_Windows_Gaming_UI_IGameBarStatics<D>::VisibilityChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Gaming::UI::IGameBarStatics)->add_VisibilityChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Gaming_UI_IGameBarStatics<D>::VisibilityChanged_revoker consume_Windows_Gaming_UI_IGameBarStatics<D>::VisibilityChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, VisibilityChanged_revoker>(this, VisibilityChanged(handler));
}

template <typename D> void consume_Windows_Gaming_UI_IGameBarStatics<D>::VisibilityChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Gaming::UI::IGameBarStatics)->remove_VisibilityChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Gaming_UI_IGameBarStatics<D>::IsInputRedirectedChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Gaming::UI::IGameBarStatics)->add_IsInputRedirectedChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Gaming_UI_IGameBarStatics<D>::IsInputRedirectedChanged_revoker consume_Windows_Gaming_UI_IGameBarStatics<D>::IsInputRedirectedChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, IsInputRedirectedChanged_revoker>(this, IsInputRedirectedChanged(handler));
}

template <typename D> void consume_Windows_Gaming_UI_IGameBarStatics<D>::IsInputRedirectedChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Gaming::UI::IGameBarStatics)->remove_IsInputRedirectedChanged(get_abi(token)));
}

template <typename D> bool consume_Windows_Gaming_UI_IGameBarStatics<D>::Visible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::UI::IGameBarStatics)->get_Visible(&value));
    return value;
}

template <typename D> bool consume_Windows_Gaming_UI_IGameBarStatics<D>::IsInputRedirected() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::UI::IGameBarStatics)->get_IsInputRedirected(&value));
    return value;
}

template <typename D> hstring consume_Windows_Gaming_UI_IGameChatMessageReceivedEventArgs<D>::AppId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::UI::IGameChatMessageReceivedEventArgs)->get_AppId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Gaming_UI_IGameChatMessageReceivedEventArgs<D>::AppDisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::UI::IGameChatMessageReceivedEventArgs)->get_AppDisplayName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Gaming_UI_IGameChatMessageReceivedEventArgs<D>::SenderName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::UI::IGameChatMessageReceivedEventArgs)->get_SenderName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Gaming_UI_IGameChatMessageReceivedEventArgs<D>::Message() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::UI::IGameChatMessageReceivedEventArgs)->get_Message(put_abi(value)));
    return value;
}

template <typename D> Windows::Gaming::UI::GameChatMessageOrigin consume_Windows_Gaming_UI_IGameChatMessageReceivedEventArgs<D>::Origin() const
{
    Windows::Gaming::UI::GameChatMessageOrigin value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::UI::IGameChatMessageReceivedEventArgs)->get_Origin(put_abi(value)));
    return value;
}

template <typename D> Windows::Gaming::UI::GameChatOverlayPosition consume_Windows_Gaming_UI_IGameChatOverlay<D>::DesiredPosition() const
{
    Windows::Gaming::UI::GameChatOverlayPosition value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::UI::IGameChatOverlay)->get_DesiredPosition(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Gaming_UI_IGameChatOverlay<D>::DesiredPosition(Windows::Gaming::UI::GameChatOverlayPosition const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::UI::IGameChatOverlay)->put_DesiredPosition(get_abi(value)));
}

template <typename D> void consume_Windows_Gaming_UI_IGameChatOverlay<D>::AddMessage(param::hstring const& sender, param::hstring const& message, Windows::Gaming::UI::GameChatMessageOrigin const& origin) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::UI::IGameChatOverlay)->AddMessage(get_abi(sender), get_abi(message), get_abi(origin)));
}

template <typename D> winrt::event_token consume_Windows_Gaming_UI_IGameChatOverlayMessageSource<D>::MessageReceived(Windows::Foundation::TypedEventHandler<Windows::Gaming::UI::GameChatOverlayMessageSource, Windows::Gaming::UI::GameChatMessageReceivedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Gaming::UI::IGameChatOverlayMessageSource)->add_MessageReceived(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Gaming_UI_IGameChatOverlayMessageSource<D>::MessageReceived_revoker consume_Windows_Gaming_UI_IGameChatOverlayMessageSource<D>::MessageReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Gaming::UI::GameChatOverlayMessageSource, Windows::Gaming::UI::GameChatMessageReceivedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, MessageReceived_revoker>(this, MessageReceived(handler));
}

template <typename D> void consume_Windows_Gaming_UI_IGameChatOverlayMessageSource<D>::MessageReceived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Gaming::UI::IGameChatOverlayMessageSource)->remove_MessageReceived(get_abi(token)));
}

template <typename D> void consume_Windows_Gaming_UI_IGameChatOverlayMessageSource<D>::SetDelayBeforeClosingAfterMessageReceived(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::UI::IGameChatOverlayMessageSource)->SetDelayBeforeClosingAfterMessageReceived(get_abi(value)));
}

template <typename D> Windows::Gaming::UI::GameChatOverlay consume_Windows_Gaming_UI_IGameChatOverlayStatics<D>::GetDefault() const
{
    Windows::Gaming::UI::GameChatOverlay value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::UI::IGameChatOverlayStatics)->GetDefault(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::ValueSet consume_Windows_Gaming_UI_IGameUIProviderActivatedEventArgs<D>::GameUIArgs() const
{
    Windows::Foundation::Collections::ValueSet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::UI::IGameUIProviderActivatedEventArgs)->get_GameUIArgs(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Gaming_UI_IGameUIProviderActivatedEventArgs<D>::ReportCompleted(Windows::Foundation::Collections::ValueSet const& results) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::UI::IGameUIProviderActivatedEventArgs)->ReportCompleted(get_abi(results)));
}

template <typename D>
struct produce<D, Windows::Gaming::UI::IGameBarStatics> : produce_base<D, Windows::Gaming::UI::IGameBarStatics>
{
    int32_t WINRT_CALL add_VisibilityChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VisibilityChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().VisibilityChanged(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_VisibilityChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(VisibilityChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().VisibilityChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_IsInputRedirectedChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInputRedirectedChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().IsInputRedirectedChanged(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_IsInputRedirectedChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(IsInputRedirectedChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().IsInputRedirectedChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

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

    int32_t WINRT_CALL get_IsInputRedirected(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInputRedirected, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsInputRedirected());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::UI::IGameChatMessageReceivedEventArgs> : produce_base<D, Windows::Gaming::UI::IGameChatMessageReceivedEventArgs>
{
    int32_t WINRT_CALL get_AppId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AppId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppDisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppDisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AppDisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SenderName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SenderName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SenderName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Message(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Message, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Origin(Windows::Gaming::UI::GameChatMessageOrigin* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Origin, WINRT_WRAP(Windows::Gaming::UI::GameChatMessageOrigin));
            *value = detach_from<Windows::Gaming::UI::GameChatMessageOrigin>(this->shim().Origin());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::UI::IGameChatOverlay> : produce_base<D, Windows::Gaming::UI::IGameChatOverlay>
{
    int32_t WINRT_CALL get_DesiredPosition(Windows::Gaming::UI::GameChatOverlayPosition* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredPosition, WINRT_WRAP(Windows::Gaming::UI::GameChatOverlayPosition));
            *value = detach_from<Windows::Gaming::UI::GameChatOverlayPosition>(this->shim().DesiredPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DesiredPosition(Windows::Gaming::UI::GameChatOverlayPosition value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredPosition, WINRT_WRAP(void), Windows::Gaming::UI::GameChatOverlayPosition const&);
            this->shim().DesiredPosition(*reinterpret_cast<Windows::Gaming::UI::GameChatOverlayPosition const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddMessage(void* sender, void* message, Windows::Gaming::UI::GameChatMessageOrigin origin) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddMessage, WINRT_WRAP(void), hstring const&, hstring const&, Windows::Gaming::UI::GameChatMessageOrigin const&);
            this->shim().AddMessage(*reinterpret_cast<hstring const*>(&sender), *reinterpret_cast<hstring const*>(&message), *reinterpret_cast<Windows::Gaming::UI::GameChatMessageOrigin const*>(&origin));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::UI::IGameChatOverlayMessageSource> : produce_base<D, Windows::Gaming::UI::IGameChatOverlayMessageSource>
{
    int32_t WINRT_CALL add_MessageReceived(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Gaming::UI::GameChatOverlayMessageSource, Windows::Gaming::UI::GameChatMessageReceivedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().MessageReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Gaming::UI::GameChatOverlayMessageSource, Windows::Gaming::UI::GameChatMessageReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MessageReceived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MessageReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MessageReceived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL SetDelayBeforeClosingAfterMessageReceived(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetDelayBeforeClosingAfterMessageReceived, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().SetDelayBeforeClosingAfterMessageReceived(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::UI::IGameChatOverlayStatics> : produce_base<D, Windows::Gaming::UI::IGameChatOverlayStatics>
{
    int32_t WINRT_CALL GetDefault(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Gaming::UI::GameChatOverlay));
            *value = detach_from<Windows::Gaming::UI::GameChatOverlay>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::UI::IGameUIProviderActivatedEventArgs> : produce_base<D, Windows::Gaming::UI::IGameUIProviderActivatedEventArgs>
{
    int32_t WINRT_CALL get_GameUIArgs(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GameUIArgs, WINRT_WRAP(Windows::Foundation::Collections::ValueSet));
            *value = detach_from<Windows::Foundation::Collections::ValueSet>(this->shim().GameUIArgs());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportCompleted(void* results) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCompleted, WINRT_WRAP(void), Windows::Foundation::Collections::ValueSet const&);
            this->shim().ReportCompleted(*reinterpret_cast<Windows::Foundation::Collections::ValueSet const*>(&results));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Gaming::UI {

inline winrt::event_token GameBar::VisibilityChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<GameBar, Windows::Gaming::UI::IGameBarStatics>([&](auto&& f) { return f.VisibilityChanged(handler); });
}

inline GameBar::VisibilityChanged_revoker GameBar::VisibilityChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<GameBar, Windows::Gaming::UI::IGameBarStatics>();
    return { f, f.VisibilityChanged(handler) };
}

inline void GameBar::VisibilityChanged(winrt::event_token const& token)
{
    impl::call_factory<GameBar, Windows::Gaming::UI::IGameBarStatics>([&](auto&& f) { return f.VisibilityChanged(token); });
}

inline winrt::event_token GameBar::IsInputRedirectedChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<GameBar, Windows::Gaming::UI::IGameBarStatics>([&](auto&& f) { return f.IsInputRedirectedChanged(handler); });
}

inline GameBar::IsInputRedirectedChanged_revoker GameBar::IsInputRedirectedChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<GameBar, Windows::Gaming::UI::IGameBarStatics>();
    return { f, f.IsInputRedirectedChanged(handler) };
}

inline void GameBar::IsInputRedirectedChanged(winrt::event_token const& token)
{
    impl::call_factory<GameBar, Windows::Gaming::UI::IGameBarStatics>([&](auto&& f) { return f.IsInputRedirectedChanged(token); });
}

inline bool GameBar::Visible()
{
    return impl::call_factory<GameBar, Windows::Gaming::UI::IGameBarStatics>([&](auto&& f) { return f.Visible(); });
}

inline bool GameBar::IsInputRedirected()
{
    return impl::call_factory<GameBar, Windows::Gaming::UI::IGameBarStatics>([&](auto&& f) { return f.IsInputRedirected(); });
}

inline Windows::Gaming::UI::GameChatOverlay GameChatOverlay::GetDefault()
{
    return impl::call_factory<GameChatOverlay, Windows::Gaming::UI::IGameChatOverlayStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline GameChatOverlayMessageSource::GameChatOverlayMessageSource() :
    GameChatOverlayMessageSource(impl::call_factory<GameChatOverlayMessageSource>([](auto&& f) { return f.template ActivateInstance<GameChatOverlayMessageSource>(); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Gaming::UI::IGameBarStatics> : winrt::impl::hash_base<winrt::Windows::Gaming::UI::IGameBarStatics> {};
template<> struct hash<winrt::Windows::Gaming::UI::IGameChatMessageReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Gaming::UI::IGameChatMessageReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Gaming::UI::IGameChatOverlay> : winrt::impl::hash_base<winrt::Windows::Gaming::UI::IGameChatOverlay> {};
template<> struct hash<winrt::Windows::Gaming::UI::IGameChatOverlayMessageSource> : winrt::impl::hash_base<winrt::Windows::Gaming::UI::IGameChatOverlayMessageSource> {};
template<> struct hash<winrt::Windows::Gaming::UI::IGameChatOverlayStatics> : winrt::impl::hash_base<winrt::Windows::Gaming::UI::IGameChatOverlayStatics> {};
template<> struct hash<winrt::Windows::Gaming::UI::IGameUIProviderActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::Gaming::UI::IGameUIProviderActivatedEventArgs> {};
template<> struct hash<winrt::Windows::Gaming::UI::GameBar> : winrt::impl::hash_base<winrt::Windows::Gaming::UI::GameBar> {};
template<> struct hash<winrt::Windows::Gaming::UI::GameChatMessageReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Gaming::UI::GameChatMessageReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Gaming::UI::GameChatOverlay> : winrt::impl::hash_base<winrt::Windows::Gaming::UI::GameChatOverlay> {};
template<> struct hash<winrt::Windows::Gaming::UI::GameChatOverlayMessageSource> : winrt::impl::hash_base<winrt::Windows::Gaming::UI::GameChatOverlayMessageSource> {};
template<> struct hash<winrt::Windows::Gaming::UI::GameUIProviderActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::Gaming::UI::GameUIProviderActivatedEventArgs> {};

}
