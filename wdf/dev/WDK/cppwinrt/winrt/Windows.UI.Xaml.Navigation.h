// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.UI.Xaml.2.h"
#include "winrt/impl/Windows.UI.Xaml.Interop.2.h"
#include "winrt/impl/Windows.UI.Xaml.Media.Animation.2.h"
#include "winrt/impl/Windows.UI.Xaml.Navigation.2.h"
#include "winrt/Windows.UI.Xaml.h"

namespace winrt::impl {

template <typename D> bool consume_Windows_UI_Xaml_Navigation_IFrameNavigationOptions<D>::IsNavigationStackEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Navigation::IFrameNavigationOptions)->get_IsNavigationStackEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Navigation_IFrameNavigationOptions<D>::IsNavigationStackEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Navigation::IFrameNavigationOptions)->put_IsNavigationStackEnabled(value));
}

template <typename D> Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo consume_Windows_UI_Xaml_Navigation_IFrameNavigationOptions<D>::TransitionInfoOverride() const
{
    Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Navigation::IFrameNavigationOptions)->get_TransitionInfoOverride(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Navigation_IFrameNavigationOptions<D>::TransitionInfoOverride(Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Navigation::IFrameNavigationOptions)->put_TransitionInfoOverride(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Navigation::FrameNavigationOptions consume_Windows_UI_Xaml_Navigation_IFrameNavigationOptionsFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Navigation::FrameNavigationOptions value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Navigation::IFrameNavigationOptionsFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Navigation_INavigatingCancelEventArgs<D>::Cancel() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Navigation::INavigatingCancelEventArgs)->get_Cancel(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Navigation_INavigatingCancelEventArgs<D>::Cancel(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Navigation::INavigatingCancelEventArgs)->put_Cancel(value));
}

template <typename D> Windows::UI::Xaml::Navigation::NavigationMode consume_Windows_UI_Xaml_Navigation_INavigatingCancelEventArgs<D>::NavigationMode() const
{
    Windows::UI::Xaml::Navigation::NavigationMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Navigation::INavigatingCancelEventArgs)->get_NavigationMode(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Interop::TypeName consume_Windows_UI_Xaml_Navigation_INavigatingCancelEventArgs<D>::SourcePageType() const
{
    Windows::UI::Xaml::Interop::TypeName value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Navigation::INavigatingCancelEventArgs)->get_SourcePageType(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Navigation_INavigatingCancelEventArgs2<D>::Parameter() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Navigation::INavigatingCancelEventArgs2)->get_Parameter(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo consume_Windows_UI_Xaml_Navigation_INavigatingCancelEventArgs2<D>::NavigationTransitionInfo() const
{
    Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Navigation::INavigatingCancelEventArgs2)->get_NavigationTransitionInfo(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Navigation_INavigationEventArgs<D>::Content() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Navigation::INavigationEventArgs)->get_Content(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Navigation_INavigationEventArgs<D>::Parameter() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Navigation::INavigationEventArgs)->get_Parameter(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Interop::TypeName consume_Windows_UI_Xaml_Navigation_INavigationEventArgs<D>::SourcePageType() const
{
    Windows::UI::Xaml::Interop::TypeName value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Navigation::INavigationEventArgs)->get_SourcePageType(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Navigation::NavigationMode consume_Windows_UI_Xaml_Navigation_INavigationEventArgs<D>::NavigationMode() const
{
    Windows::UI::Xaml::Navigation::NavigationMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Navigation::INavigationEventArgs)->get_NavigationMode(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_UI_Xaml_Navigation_INavigationEventArgs<D>::Uri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Navigation::INavigationEventArgs)->get_Uri(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Navigation_INavigationEventArgs<D>::Uri(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Navigation::INavigationEventArgs)->put_Uri(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo consume_Windows_UI_Xaml_Navigation_INavigationEventArgs2<D>::NavigationTransitionInfo() const
{
    Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Navigation::INavigationEventArgs2)->get_NavigationTransitionInfo(put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_UI_Xaml_Navigation_INavigationFailedEventArgs<D>::Exception() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Navigation::INavigationFailedEventArgs)->get_Exception(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Navigation_INavigationFailedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Navigation::INavigationFailedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Navigation_INavigationFailedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Navigation::INavigationFailedEventArgs)->put_Handled(value));
}

template <typename D> Windows::UI::Xaml::Interop::TypeName consume_Windows_UI_Xaml_Navigation_INavigationFailedEventArgs<D>::SourcePageType() const
{
    Windows::UI::Xaml::Interop::TypeName value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Navigation::INavigationFailedEventArgs)->get_SourcePageType(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Interop::TypeName consume_Windows_UI_Xaml_Navigation_IPageStackEntry<D>::SourcePageType() const
{
    Windows::UI::Xaml::Interop::TypeName value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Navigation::IPageStackEntry)->get_SourcePageType(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Navigation_IPageStackEntry<D>::Parameter() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Navigation::IPageStackEntry)->get_Parameter(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo consume_Windows_UI_Xaml_Navigation_IPageStackEntry<D>::NavigationTransitionInfo() const
{
    Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Navigation::IPageStackEntry)->get_NavigationTransitionInfo(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Navigation::PageStackEntry consume_Windows_UI_Xaml_Navigation_IPageStackEntryFactory<D>::CreateInstance(Windows::UI::Xaml::Interop::TypeName const& sourcePageType, Windows::Foundation::IInspectable const& parameter, Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo const& navigationTransitionInfo) const
{
    Windows::UI::Xaml::Navigation::PageStackEntry value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Navigation::IPageStackEntryFactory)->CreateInstance(get_abi(sourcePageType), get_abi(parameter), get_abi(navigationTransitionInfo), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Navigation_IPageStackEntryStatics<D>::SourcePageTypeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Navigation::IPageStackEntryStatics)->get_SourcePageTypeProperty(put_abi(value)));
    return value;
}

template <> struct delegate<Windows::UI::Xaml::Navigation::LoadCompletedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::Navigation::LoadCompletedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::Navigation::LoadCompletedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::Navigation::NavigationEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::Navigation::NavigatedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::Navigation::NavigatedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::Navigation::NavigatedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::Navigation::NavigationEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::Navigation::NavigatingCancelEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::Navigation::NavigatingCancelEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::Navigation::NavigatingCancelEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::Navigation::NavigatingCancelEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::Navigation::NavigationFailedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::Navigation::NavigationFailedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::Navigation::NavigationFailedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::Navigation::NavigationFailedEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::Navigation::NavigationStoppedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::Navigation::NavigationStoppedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::Navigation::NavigationStoppedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::Navigation::NavigationEventArgs const*>(&e));
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
struct produce<D, Windows::UI::Xaml::Navigation::IFrameNavigationOptions> : produce_base<D, Windows::UI::Xaml::Navigation::IFrameNavigationOptions>
{
    int32_t WINRT_CALL get_IsNavigationStackEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsNavigationStackEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsNavigationStackEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsNavigationStackEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsNavigationStackEnabled, WINRT_WRAP(void), bool);
            this->shim().IsNavigationStackEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransitionInfoOverride(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransitionInfoOverride, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo>(this->shim().TransitionInfoOverride());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TransitionInfoOverride(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransitionInfoOverride, WINRT_WRAP(void), Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo const&);
            this->shim().TransitionInfoOverride(*reinterpret_cast<Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Navigation::IFrameNavigationOptionsFactory> : produce_base<D, Windows::UI::Xaml::Navigation::IFrameNavigationOptionsFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Navigation::FrameNavigationOptions), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Navigation::FrameNavigationOptions>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Navigation::INavigatingCancelEventArgs> : produce_base<D, Windows::UI::Xaml::Navigation::INavigatingCancelEventArgs>
{
    int32_t WINRT_CALL get_Cancel(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cancel, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Cancel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Cancel(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cancel, WINRT_WRAP(void), bool);
            this->shim().Cancel(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NavigationMode(Windows::UI::Xaml::Navigation::NavigationMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NavigationMode, WINRT_WRAP(Windows::UI::Xaml::Navigation::NavigationMode));
            *value = detach_from<Windows::UI::Xaml::Navigation::NavigationMode>(this->shim().NavigationMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SourcePageType(struct struct_Windows_UI_Xaml_Interop_TypeName* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourcePageType, WINRT_WRAP(Windows::UI::Xaml::Interop::TypeName));
            *value = detach_from<Windows::UI::Xaml::Interop::TypeName>(this->shim().SourcePageType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Navigation::INavigatingCancelEventArgs2> : produce_base<D, Windows::UI::Xaml::Navigation::INavigatingCancelEventArgs2>
{
    int32_t WINRT_CALL get_Parameter(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parameter, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().Parameter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NavigationTransitionInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NavigationTransitionInfo, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo>(this->shim().NavigationTransitionInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Navigation::INavigationEventArgs> : produce_base<D, Windows::UI::Xaml::Navigation::INavigationEventArgs>
{
    int32_t WINRT_CALL get_Content(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Content, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().Content());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Parameter(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parameter, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().Parameter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SourcePageType(struct struct_Windows_UI_Xaml_Interop_TypeName* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourcePageType, WINRT_WRAP(Windows::UI::Xaml::Interop::TypeName));
            *value = detach_from<Windows::UI::Xaml::Interop::TypeName>(this->shim().SourcePageType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NavigationMode(Windows::UI::Xaml::Navigation::NavigationMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NavigationMode, WINRT_WRAP(Windows::UI::Xaml::Navigation::NavigationMode));
            *value = detach_from<Windows::UI::Xaml::Navigation::NavigationMode>(this->shim().NavigationMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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
struct produce<D, Windows::UI::Xaml::Navigation::INavigationEventArgs2> : produce_base<D, Windows::UI::Xaml::Navigation::INavigationEventArgs2>
{
    int32_t WINRT_CALL get_NavigationTransitionInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NavigationTransitionInfo, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo>(this->shim().NavigationTransitionInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Navigation::INavigationFailedEventArgs> : produce_base<D, Windows::UI::Xaml::Navigation::INavigationFailedEventArgs>
{
    int32_t WINRT_CALL get_Exception(winrt::hresult* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Exception, WINRT_WRAP(winrt::hresult));
            *value = detach_from<winrt::hresult>(this->shim().Exception());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Handled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Handled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Handled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(void), bool);
            this->shim().Handled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SourcePageType(struct struct_Windows_UI_Xaml_Interop_TypeName* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourcePageType, WINRT_WRAP(Windows::UI::Xaml::Interop::TypeName));
            *value = detach_from<Windows::UI::Xaml::Interop::TypeName>(this->shim().SourcePageType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Navigation::IPageStackEntry> : produce_base<D, Windows::UI::Xaml::Navigation::IPageStackEntry>
{
    int32_t WINRT_CALL get_SourcePageType(struct struct_Windows_UI_Xaml_Interop_TypeName* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourcePageType, WINRT_WRAP(Windows::UI::Xaml::Interop::TypeName));
            *value = detach_from<Windows::UI::Xaml::Interop::TypeName>(this->shim().SourcePageType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Parameter(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parameter, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().Parameter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NavigationTransitionInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NavigationTransitionInfo, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo>(this->shim().NavigationTransitionInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Navigation::IPageStackEntryFactory> : produce_base<D, Windows::UI::Xaml::Navigation::IPageStackEntryFactory>
{
    int32_t WINRT_CALL CreateInstance(struct struct_Windows_UI_Xaml_Interop_TypeName sourcePageType, void* parameter, void* navigationTransitionInfo, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Navigation::PageStackEntry), Windows::UI::Xaml::Interop::TypeName const&, Windows::Foundation::IInspectable const&, Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo const&);
            *value = detach_from<Windows::UI::Xaml::Navigation::PageStackEntry>(this->shim().CreateInstance(*reinterpret_cast<Windows::UI::Xaml::Interop::TypeName const*>(&sourcePageType), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&parameter), *reinterpret_cast<Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo const*>(&navigationTransitionInfo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Navigation::IPageStackEntryStatics> : produce_base<D, Windows::UI::Xaml::Navigation::IPageStackEntryStatics>
{
    int32_t WINRT_CALL get_SourcePageTypeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourcePageTypeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().SourcePageTypeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Navigation {

inline FrameNavigationOptions::FrameNavigationOptions()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<FrameNavigationOptions, Windows::UI::Xaml::Navigation::IFrameNavigationOptionsFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline PageStackEntry::PageStackEntry(Windows::UI::Xaml::Interop::TypeName const& sourcePageType, Windows::Foundation::IInspectable const& parameter, Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo const& navigationTransitionInfo) :
    PageStackEntry(impl::call_factory<PageStackEntry, Windows::UI::Xaml::Navigation::IPageStackEntryFactory>([&](auto&& f) { return f.CreateInstance(sourcePageType, parameter, navigationTransitionInfo); }))
{}

inline Windows::UI::Xaml::DependencyProperty PageStackEntry::SourcePageTypeProperty()
{
    return impl::call_factory<PageStackEntry, Windows::UI::Xaml::Navigation::IPageStackEntryStatics>([&](auto&& f) { return f.SourcePageTypeProperty(); });
}

template <typename L> LoadCompletedEventHandler::LoadCompletedEventHandler(L handler) :
    LoadCompletedEventHandler(impl::make_delegate<LoadCompletedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> LoadCompletedEventHandler::LoadCompletedEventHandler(F* handler) :
    LoadCompletedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> LoadCompletedEventHandler::LoadCompletedEventHandler(O* object, M method) :
    LoadCompletedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> LoadCompletedEventHandler::LoadCompletedEventHandler(com_ptr<O>&& object, M method) :
    LoadCompletedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> LoadCompletedEventHandler::LoadCompletedEventHandler(weak_ref<O>&& object, M method) :
    LoadCompletedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void LoadCompletedEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Navigation::NavigationEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<LoadCompletedEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> NavigatedEventHandler::NavigatedEventHandler(L handler) :
    NavigatedEventHandler(impl::make_delegate<NavigatedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> NavigatedEventHandler::NavigatedEventHandler(F* handler) :
    NavigatedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> NavigatedEventHandler::NavigatedEventHandler(O* object, M method) :
    NavigatedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> NavigatedEventHandler::NavigatedEventHandler(com_ptr<O>&& object, M method) :
    NavigatedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> NavigatedEventHandler::NavigatedEventHandler(weak_ref<O>&& object, M method) :
    NavigatedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void NavigatedEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Navigation::NavigationEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<NavigatedEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> NavigatingCancelEventHandler::NavigatingCancelEventHandler(L handler) :
    NavigatingCancelEventHandler(impl::make_delegate<NavigatingCancelEventHandler>(std::forward<L>(handler)))
{}

template <typename F> NavigatingCancelEventHandler::NavigatingCancelEventHandler(F* handler) :
    NavigatingCancelEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> NavigatingCancelEventHandler::NavigatingCancelEventHandler(O* object, M method) :
    NavigatingCancelEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> NavigatingCancelEventHandler::NavigatingCancelEventHandler(com_ptr<O>&& object, M method) :
    NavigatingCancelEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> NavigatingCancelEventHandler::NavigatingCancelEventHandler(weak_ref<O>&& object, M method) :
    NavigatingCancelEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void NavigatingCancelEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Navigation::NavigatingCancelEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<NavigatingCancelEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> NavigationFailedEventHandler::NavigationFailedEventHandler(L handler) :
    NavigationFailedEventHandler(impl::make_delegate<NavigationFailedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> NavigationFailedEventHandler::NavigationFailedEventHandler(F* handler) :
    NavigationFailedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> NavigationFailedEventHandler::NavigationFailedEventHandler(O* object, M method) :
    NavigationFailedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> NavigationFailedEventHandler::NavigationFailedEventHandler(com_ptr<O>&& object, M method) :
    NavigationFailedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> NavigationFailedEventHandler::NavigationFailedEventHandler(weak_ref<O>&& object, M method) :
    NavigationFailedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void NavigationFailedEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Navigation::NavigationFailedEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<NavigationFailedEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> NavigationStoppedEventHandler::NavigationStoppedEventHandler(L handler) :
    NavigationStoppedEventHandler(impl::make_delegate<NavigationStoppedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> NavigationStoppedEventHandler::NavigationStoppedEventHandler(F* handler) :
    NavigationStoppedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> NavigationStoppedEventHandler::NavigationStoppedEventHandler(O* object, M method) :
    NavigationStoppedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> NavigationStoppedEventHandler::NavigationStoppedEventHandler(com_ptr<O>&& object, M method) :
    NavigationStoppedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> NavigationStoppedEventHandler::NavigationStoppedEventHandler(weak_ref<O>&& object, M method) :
    NavigationStoppedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void NavigationStoppedEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Navigation::NavigationEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<NavigationStoppedEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename D, typename... Interfaces>
struct FrameNavigationOptionsT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Navigation::IFrameNavigationOptions>,
    impl::base<D, Windows::UI::Xaml::Navigation::FrameNavigationOptions>
{
    using composable = FrameNavigationOptions;

protected:
    FrameNavigationOptionsT()
    {
        impl::call_factory<Windows::UI::Xaml::Navigation::FrameNavigationOptions, Windows::UI::Xaml::Navigation::IFrameNavigationOptionsFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Xaml::Navigation::IFrameNavigationOptions> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Navigation::IFrameNavigationOptions> {};
template<> struct hash<winrt::Windows::UI::Xaml::Navigation::IFrameNavigationOptionsFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Navigation::IFrameNavigationOptionsFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Navigation::INavigatingCancelEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Navigation::INavigatingCancelEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Navigation::INavigatingCancelEventArgs2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Navigation::INavigatingCancelEventArgs2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Navigation::INavigationEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Navigation::INavigationEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Navigation::INavigationEventArgs2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Navigation::INavigationEventArgs2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Navigation::INavigationFailedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Navigation::INavigationFailedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Navigation::IPageStackEntry> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Navigation::IPageStackEntry> {};
template<> struct hash<winrt::Windows::UI::Xaml::Navigation::IPageStackEntryFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Navigation::IPageStackEntryFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Navigation::IPageStackEntryStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Navigation::IPageStackEntryStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Navigation::FrameNavigationOptions> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Navigation::FrameNavigationOptions> {};
template<> struct hash<winrt::Windows::UI::Xaml::Navigation::NavigatingCancelEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Navigation::NavigatingCancelEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Navigation::NavigationEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Navigation::NavigationEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Navigation::NavigationFailedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Navigation::NavigationFailedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Navigation::PageStackEntry> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Navigation::PageStackEntry> {};

}
