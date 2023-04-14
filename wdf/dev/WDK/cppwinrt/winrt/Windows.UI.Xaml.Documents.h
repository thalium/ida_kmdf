// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.UI.Core.2.h"
#include "winrt/impl/Windows.UI.Text.2.h"
#include "winrt/impl/Windows.UI.Xaml.2.h"
#include "winrt/impl/Windows.UI.Xaml.Input.2.h"
#include "winrt/impl/Windows.UI.Xaml.Media.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.UI.Composition.2.h"
#include "winrt/impl/Windows.UI.Xaml.Documents.2.h"
#include "winrt/Windows.UI.Xaml.h"

namespace winrt::impl {

template <typename D> Windows::UI::Xaml::TextAlignment consume_Windows_UI_Xaml_Documents_IBlock<D>::TextAlignment() const
{
    Windows::UI::Xaml::TextAlignment value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IBlock)->get_TextAlignment(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IBlock<D>::TextAlignment(Windows::UI::Xaml::TextAlignment const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IBlock)->put_TextAlignment(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_Documents_IBlock<D>::LineHeight() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IBlock)->get_LineHeight(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IBlock<D>::LineHeight(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IBlock)->put_LineHeight(value));
}

template <typename D> Windows::UI::Xaml::LineStackingStrategy consume_Windows_UI_Xaml_Documents_IBlock<D>::LineStackingStrategy() const
{
    Windows::UI::Xaml::LineStackingStrategy value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IBlock)->get_LineStackingStrategy(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IBlock<D>::LineStackingStrategy(Windows::UI::Xaml::LineStackingStrategy const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IBlock)->put_LineStackingStrategy(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Thickness consume_Windows_UI_Xaml_Documents_IBlock<D>::Margin() const
{
    Windows::UI::Xaml::Thickness value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IBlock)->get_Margin(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IBlock<D>::Margin(Windows::UI::Xaml::Thickness const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IBlock)->put_Margin(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::TextAlignment consume_Windows_UI_Xaml_Documents_IBlock2<D>::HorizontalTextAlignment() const
{
    Windows::UI::Xaml::TextAlignment value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IBlock2)->get_HorizontalTextAlignment(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IBlock2<D>::HorizontalTextAlignment(Windows::UI::Xaml::TextAlignment const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IBlock2)->put_HorizontalTextAlignment(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Documents::Block consume_Windows_UI_Xaml_Documents_IBlockFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Documents::Block value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IBlockFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IBlockStatics<D>::TextAlignmentProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IBlockStatics)->get_TextAlignmentProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IBlockStatics<D>::LineHeightProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IBlockStatics)->get_LineHeightProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IBlockStatics<D>::LineStackingStrategyProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IBlockStatics)->get_LineStackingStrategyProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IBlockStatics<D>::MarginProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IBlockStatics)->get_MarginProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IBlockStatics2<D>::HorizontalTextAlignmentProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IBlockStatics2)->get_HorizontalTextAlignmentProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Text::ContentLinkInfo consume_Windows_UI_Xaml_Documents_IContentLink<D>::Info() const
{
    Windows::UI::Text::ContentLinkInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->get_Info(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IContentLink<D>::Info(Windows::UI::Text::ContentLinkInfo const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->put_Info(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Documents_IContentLink<D>::Background() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->get_Background(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IContentLink<D>::Background(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->put_Background(get_abi(value)));
}

template <typename D> Windows::UI::Core::CoreCursorType consume_Windows_UI_Xaml_Documents_IContentLink<D>::Cursor() const
{
    Windows::UI::Core::CoreCursorType value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->get_Cursor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IContentLink<D>::Cursor(Windows::UI::Core::CoreCursorType const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->put_Cursor(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Documents_IContentLink<D>::XYFocusLeft() const
{
    Windows::UI::Xaml::DependencyObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->get_XYFocusLeft(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IContentLink<D>::XYFocusLeft(Windows::UI::Xaml::DependencyObject const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->put_XYFocusLeft(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Documents_IContentLink<D>::XYFocusRight() const
{
    Windows::UI::Xaml::DependencyObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->get_XYFocusRight(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IContentLink<D>::XYFocusRight(Windows::UI::Xaml::DependencyObject const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->put_XYFocusRight(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Documents_IContentLink<D>::XYFocusUp() const
{
    Windows::UI::Xaml::DependencyObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->get_XYFocusUp(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IContentLink<D>::XYFocusUp(Windows::UI::Xaml::DependencyObject const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->put_XYFocusUp(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Documents_IContentLink<D>::XYFocusDown() const
{
    Windows::UI::Xaml::DependencyObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->get_XYFocusDown(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IContentLink<D>::XYFocusDown(Windows::UI::Xaml::DependencyObject const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->put_XYFocusDown(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::ElementSoundMode consume_Windows_UI_Xaml_Documents_IContentLink<D>::ElementSoundMode() const
{
    Windows::UI::Xaml::ElementSoundMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->get_ElementSoundMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IContentLink<D>::ElementSoundMode(Windows::UI::Xaml::ElementSoundMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->put_ElementSoundMode(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::FocusState consume_Windows_UI_Xaml_Documents_IContentLink<D>::FocusState() const
{
    Windows::UI::Xaml::FocusState value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->get_FocusState(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Input::XYFocusNavigationStrategy consume_Windows_UI_Xaml_Documents_IContentLink<D>::XYFocusUpNavigationStrategy() const
{
    Windows::UI::Xaml::Input::XYFocusNavigationStrategy value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->get_XYFocusUpNavigationStrategy(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IContentLink<D>::XYFocusUpNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->put_XYFocusUpNavigationStrategy(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Input::XYFocusNavigationStrategy consume_Windows_UI_Xaml_Documents_IContentLink<D>::XYFocusDownNavigationStrategy() const
{
    Windows::UI::Xaml::Input::XYFocusNavigationStrategy value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->get_XYFocusDownNavigationStrategy(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IContentLink<D>::XYFocusDownNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->put_XYFocusDownNavigationStrategy(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Input::XYFocusNavigationStrategy consume_Windows_UI_Xaml_Documents_IContentLink<D>::XYFocusLeftNavigationStrategy() const
{
    Windows::UI::Xaml::Input::XYFocusNavigationStrategy value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->get_XYFocusLeftNavigationStrategy(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IContentLink<D>::XYFocusLeftNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->put_XYFocusLeftNavigationStrategy(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Input::XYFocusNavigationStrategy consume_Windows_UI_Xaml_Documents_IContentLink<D>::XYFocusRightNavigationStrategy() const
{
    Windows::UI::Xaml::Input::XYFocusNavigationStrategy value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->get_XYFocusRightNavigationStrategy(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IContentLink<D>::XYFocusRightNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->put_XYFocusRightNavigationStrategy(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_IContentLink<D>::IsTabStop() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->get_IsTabStop(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IContentLink<D>::IsTabStop(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->put_IsTabStop(value));
}

template <typename D> int32_t consume_Windows_UI_Xaml_Documents_IContentLink<D>::TabIndex() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->get_TabIndex(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IContentLink<D>::TabIndex(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->put_TabIndex(value));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Documents_IContentLink<D>::Invoked(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Documents::ContentLink, Windows::UI::Xaml::Documents::ContentLinkInvokedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->add_Invoked(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Documents_IContentLink<D>::Invoked_revoker consume_Windows_UI_Xaml_Documents_IContentLink<D>::Invoked(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Documents::ContentLink, Windows::UI::Xaml::Documents::ContentLinkInvokedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Invoked_revoker>(this, Invoked(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IContentLink<D>::Invoked(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->remove_Invoked(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Documents_IContentLink<D>::GotFocus(Windows::UI::Xaml::RoutedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->add_GotFocus(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Documents_IContentLink<D>::GotFocus_revoker consume_Windows_UI_Xaml_Documents_IContentLink<D>::GotFocus(auto_revoke_t, Windows::UI::Xaml::RoutedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, GotFocus_revoker>(this, GotFocus(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IContentLink<D>::GotFocus(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->remove_GotFocus(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Documents_IContentLink<D>::LostFocus(Windows::UI::Xaml::RoutedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->add_LostFocus(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Documents_IContentLink<D>::LostFocus_revoker consume_Windows_UI_Xaml_Documents_IContentLink<D>::LostFocus(auto_revoke_t, Windows::UI::Xaml::RoutedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, LostFocus_revoker>(this, LostFocus(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IContentLink<D>::LostFocus(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->remove_LostFocus(get_abi(token)));
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_IContentLink<D>::Focus(Windows::UI::Xaml::FocusState const& value) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLink)->Focus(get_abi(value), &result));
    return result;
}

template <typename D> Windows::UI::Text::ContentLinkInfo consume_Windows_UI_Xaml_Documents_IContentLinkInvokedEventArgs<D>::ContentLinkInfo() const
{
    Windows::UI::Text::ContentLinkInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLinkInvokedEventArgs)->get_ContentLinkInfo(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_IContentLinkInvokedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLinkInvokedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IContentLinkInvokedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLinkInvokedEventArgs)->put_Handled(value));
}

template <typename D> Windows::UI::Xaml::Documents::ContentLinkProvider consume_Windows_UI_Xaml_Documents_IContentLinkProviderFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Documents::ContentLinkProvider value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLinkProviderFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IContentLinkStatics<D>::BackgroundProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLinkStatics)->get_BackgroundProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IContentLinkStatics<D>::CursorProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLinkStatics)->get_CursorProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IContentLinkStatics<D>::XYFocusLeftProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLinkStatics)->get_XYFocusLeftProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IContentLinkStatics<D>::XYFocusRightProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLinkStatics)->get_XYFocusRightProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IContentLinkStatics<D>::XYFocusUpProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLinkStatics)->get_XYFocusUpProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IContentLinkStatics<D>::XYFocusDownProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLinkStatics)->get_XYFocusDownProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IContentLinkStatics<D>::ElementSoundModeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLinkStatics)->get_ElementSoundModeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IContentLinkStatics<D>::FocusStateProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLinkStatics)->get_FocusStateProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IContentLinkStatics<D>::XYFocusUpNavigationStrategyProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLinkStatics)->get_XYFocusUpNavigationStrategyProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IContentLinkStatics<D>::XYFocusDownNavigationStrategyProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLinkStatics)->get_XYFocusDownNavigationStrategyProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IContentLinkStatics<D>::XYFocusLeftNavigationStrategyProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLinkStatics)->get_XYFocusLeftNavigationStrategyProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IContentLinkStatics<D>::XYFocusRightNavigationStrategyProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLinkStatics)->get_XYFocusRightNavigationStrategyProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IContentLinkStatics<D>::IsTabStopProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLinkStatics)->get_IsTabStopProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IContentLinkStatics<D>::TabIndexProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IContentLinkStatics)->get_TabIndexProperty(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Documents_IGlyphs<D>::UnicodeString() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IGlyphs)->get_UnicodeString(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IGlyphs<D>::UnicodeString(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IGlyphs)->put_UnicodeString(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Xaml_Documents_IGlyphs<D>::Indices() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IGlyphs)->get_Indices(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IGlyphs<D>::Indices(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IGlyphs)->put_Indices(get_abi(value)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_UI_Xaml_Documents_IGlyphs<D>::FontUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IGlyphs)->get_FontUri(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IGlyphs<D>::FontUri(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IGlyphs)->put_FontUri(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::StyleSimulations consume_Windows_UI_Xaml_Documents_IGlyphs<D>::StyleSimulations() const
{
    Windows::UI::Xaml::Media::StyleSimulations value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IGlyphs)->get_StyleSimulations(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IGlyphs<D>::StyleSimulations(Windows::UI::Xaml::Media::StyleSimulations const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IGlyphs)->put_StyleSimulations(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_Documents_IGlyphs<D>::FontRenderingEmSize() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IGlyphs)->get_FontRenderingEmSize(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IGlyphs<D>::FontRenderingEmSize(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IGlyphs)->put_FontRenderingEmSize(value));
}

template <typename D> double consume_Windows_UI_Xaml_Documents_IGlyphs<D>::OriginX() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IGlyphs)->get_OriginX(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IGlyphs<D>::OriginX(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IGlyphs)->put_OriginX(value));
}

template <typename D> double consume_Windows_UI_Xaml_Documents_IGlyphs<D>::OriginY() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IGlyphs)->get_OriginY(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IGlyphs<D>::OriginY(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IGlyphs)->put_OriginY(value));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Documents_IGlyphs<D>::Fill() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IGlyphs)->get_Fill(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IGlyphs<D>::Fill(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IGlyphs)->put_Fill(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_IGlyphs2<D>::IsColorFontEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IGlyphs2)->get_IsColorFontEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IGlyphs2<D>::IsColorFontEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IGlyphs2)->put_IsColorFontEnabled(value));
}

template <typename D> int32_t consume_Windows_UI_Xaml_Documents_IGlyphs2<D>::ColorFontPaletteIndex() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IGlyphs2)->get_ColorFontPaletteIndex(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IGlyphs2<D>::ColorFontPaletteIndex(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IGlyphs2)->put_ColorFontPaletteIndex(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IGlyphsStatics<D>::UnicodeStringProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IGlyphsStatics)->get_UnicodeStringProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IGlyphsStatics<D>::IndicesProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IGlyphsStatics)->get_IndicesProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IGlyphsStatics<D>::FontUriProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IGlyphsStatics)->get_FontUriProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IGlyphsStatics<D>::StyleSimulationsProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IGlyphsStatics)->get_StyleSimulationsProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IGlyphsStatics<D>::FontRenderingEmSizeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IGlyphsStatics)->get_FontRenderingEmSizeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IGlyphsStatics<D>::OriginXProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IGlyphsStatics)->get_OriginXProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IGlyphsStatics<D>::OriginYProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IGlyphsStatics)->get_OriginYProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IGlyphsStatics<D>::FillProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IGlyphsStatics)->get_FillProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IGlyphsStatics2<D>::IsColorFontEnabledProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IGlyphsStatics2)->get_IsColorFontEnabledProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IGlyphsStatics2<D>::ColorFontPaletteIndexProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IGlyphsStatics2)->get_ColorFontPaletteIndexProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_UI_Xaml_Documents_IHyperlink<D>::NavigateUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlink)->get_NavigateUri(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IHyperlink<D>::NavigateUri(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlink)->put_NavigateUri(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Documents_IHyperlink<D>::Click(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Documents::Hyperlink, Windows::UI::Xaml::Documents::HyperlinkClickEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlink)->add_Click(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Documents_IHyperlink<D>::Click_revoker consume_Windows_UI_Xaml_Documents_IHyperlink<D>::Click(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Documents::Hyperlink, Windows::UI::Xaml::Documents::HyperlinkClickEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Click_revoker>(this, Click(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IHyperlink<D>::Click(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlink)->remove_Click(get_abi(token)));
}

template <typename D> Windows::UI::Xaml::Documents::UnderlineStyle consume_Windows_UI_Xaml_Documents_IHyperlink2<D>::UnderlineStyle() const
{
    Windows::UI::Xaml::Documents::UnderlineStyle value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlink2)->get_UnderlineStyle(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IHyperlink2<D>::UnderlineStyle(Windows::UI::Xaml::Documents::UnderlineStyle const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlink2)->put_UnderlineStyle(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Documents_IHyperlink3<D>::XYFocusLeft() const
{
    Windows::UI::Xaml::DependencyObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlink3)->get_XYFocusLeft(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IHyperlink3<D>::XYFocusLeft(Windows::UI::Xaml::DependencyObject const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlink3)->put_XYFocusLeft(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Documents_IHyperlink3<D>::XYFocusRight() const
{
    Windows::UI::Xaml::DependencyObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlink3)->get_XYFocusRight(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IHyperlink3<D>::XYFocusRight(Windows::UI::Xaml::DependencyObject const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlink3)->put_XYFocusRight(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Documents_IHyperlink3<D>::XYFocusUp() const
{
    Windows::UI::Xaml::DependencyObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlink3)->get_XYFocusUp(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IHyperlink3<D>::XYFocusUp(Windows::UI::Xaml::DependencyObject const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlink3)->put_XYFocusUp(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Documents_IHyperlink3<D>::XYFocusDown() const
{
    Windows::UI::Xaml::DependencyObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlink3)->get_XYFocusDown(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IHyperlink3<D>::XYFocusDown(Windows::UI::Xaml::DependencyObject const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlink3)->put_XYFocusDown(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::ElementSoundMode consume_Windows_UI_Xaml_Documents_IHyperlink3<D>::ElementSoundMode() const
{
    Windows::UI::Xaml::ElementSoundMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlink3)->get_ElementSoundMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IHyperlink3<D>::ElementSoundMode(Windows::UI::Xaml::ElementSoundMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlink3)->put_ElementSoundMode(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::FocusState consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::FocusState() const
{
    Windows::UI::Xaml::FocusState value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlink4)->get_FocusState(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Input::XYFocusNavigationStrategy consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::XYFocusUpNavigationStrategy() const
{
    Windows::UI::Xaml::Input::XYFocusNavigationStrategy value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlink4)->get_XYFocusUpNavigationStrategy(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::XYFocusUpNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlink4)->put_XYFocusUpNavigationStrategy(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Input::XYFocusNavigationStrategy consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::XYFocusDownNavigationStrategy() const
{
    Windows::UI::Xaml::Input::XYFocusNavigationStrategy value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlink4)->get_XYFocusDownNavigationStrategy(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::XYFocusDownNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlink4)->put_XYFocusDownNavigationStrategy(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Input::XYFocusNavigationStrategy consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::XYFocusLeftNavigationStrategy() const
{
    Windows::UI::Xaml::Input::XYFocusNavigationStrategy value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlink4)->get_XYFocusLeftNavigationStrategy(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::XYFocusLeftNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlink4)->put_XYFocusLeftNavigationStrategy(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Input::XYFocusNavigationStrategy consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::XYFocusRightNavigationStrategy() const
{
    Windows::UI::Xaml::Input::XYFocusNavigationStrategy value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlink4)->get_XYFocusRightNavigationStrategy(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::XYFocusRightNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlink4)->put_XYFocusRightNavigationStrategy(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::GotFocus(Windows::UI::Xaml::RoutedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlink4)->add_GotFocus(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::GotFocus_revoker consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::GotFocus(auto_revoke_t, Windows::UI::Xaml::RoutedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, GotFocus_revoker>(this, GotFocus(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::GotFocus(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlink4)->remove_GotFocus(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::LostFocus(Windows::UI::Xaml::RoutedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlink4)->add_LostFocus(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::LostFocus_revoker consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::LostFocus(auto_revoke_t, Windows::UI::Xaml::RoutedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, LostFocus_revoker>(this, LostFocus(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::LostFocus(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlink4)->remove_LostFocus(get_abi(token)));
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_IHyperlink4<D>::Focus(Windows::UI::Xaml::FocusState const& value) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlink4)->Focus(get_abi(value), &result));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_IHyperlink5<D>::IsTabStop() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlink5)->get_IsTabStop(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IHyperlink5<D>::IsTabStop(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlink5)->put_IsTabStop(value));
}

template <typename D> int32_t consume_Windows_UI_Xaml_Documents_IHyperlink5<D>::TabIndex() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlink5)->get_TabIndex(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IHyperlink5<D>::TabIndex(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlink5)->put_TabIndex(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IHyperlinkStatics<D>::NavigateUriProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlinkStatics)->get_NavigateUriProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IHyperlinkStatics2<D>::UnderlineStyleProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlinkStatics2)->get_UnderlineStyleProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IHyperlinkStatics3<D>::XYFocusLeftProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlinkStatics3)->get_XYFocusLeftProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IHyperlinkStatics3<D>::XYFocusRightProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlinkStatics3)->get_XYFocusRightProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IHyperlinkStatics3<D>::XYFocusUpProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlinkStatics3)->get_XYFocusUpProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IHyperlinkStatics3<D>::XYFocusDownProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlinkStatics3)->get_XYFocusDownProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IHyperlinkStatics3<D>::ElementSoundModeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlinkStatics3)->get_ElementSoundModeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IHyperlinkStatics4<D>::FocusStateProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlinkStatics4)->get_FocusStateProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IHyperlinkStatics4<D>::XYFocusUpNavigationStrategyProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlinkStatics4)->get_XYFocusUpNavigationStrategyProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IHyperlinkStatics4<D>::XYFocusDownNavigationStrategyProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlinkStatics4)->get_XYFocusDownNavigationStrategyProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IHyperlinkStatics4<D>::XYFocusLeftNavigationStrategyProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlinkStatics4)->get_XYFocusLeftNavigationStrategyProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IHyperlinkStatics4<D>::XYFocusRightNavigationStrategyProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlinkStatics4)->get_XYFocusRightNavigationStrategyProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IHyperlinkStatics5<D>::IsTabStopProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlinkStatics5)->get_IsTabStopProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IHyperlinkStatics5<D>::TabIndexProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IHyperlinkStatics5)->get_TabIndexProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Documents::Inline consume_Windows_UI_Xaml_Documents_IInlineFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Documents::Inline value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IInlineFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::UIElement consume_Windows_UI_Xaml_Documents_IInlineUIContainer<D>::Child() const
{
    Windows::UI::Xaml::UIElement value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IInlineUIContainer)->get_Child(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IInlineUIContainer<D>::Child(Windows::UI::Xaml::UIElement const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IInlineUIContainer)->put_Child(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Documents::InlineCollection consume_Windows_UI_Xaml_Documents_IParagraph<D>::Inlines() const
{
    Windows::UI::Xaml::Documents::InlineCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IParagraph)->get_Inlines(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Documents_IParagraph<D>::TextIndent() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IParagraph)->get_TextIndent(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IParagraph<D>::TextIndent(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IParagraph)->put_TextIndent(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IParagraphStatics<D>::TextIndentProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IParagraphStatics)->get_TextIndentProperty(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Documents_IRun<D>::Text() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IRun)->get_Text(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IRun<D>::Text(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IRun)->put_Text(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::FlowDirection consume_Windows_UI_Xaml_Documents_IRun<D>::FlowDirection() const
{
    Windows::UI::Xaml::FlowDirection value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IRun)->get_FlowDirection(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_IRun<D>::FlowDirection(Windows::UI::Xaml::FlowDirection const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IRun)->put_FlowDirection(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_IRunStatics<D>::FlowDirectionProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::IRunStatics)->get_FlowDirectionProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Documents::InlineCollection consume_Windows_UI_Xaml_Documents_ISpan<D>::Inlines() const
{
    Windows::UI::Xaml::Documents::InlineCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ISpan)->get_Inlines(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ISpan<D>::Inlines(Windows::UI::Xaml::Documents::InlineCollection const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ISpan)->put_Inlines(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Documents::Span consume_Windows_UI_Xaml_Documents_ISpanFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Documents::Span value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ISpanFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Documents_ITextElement<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement)->get_Name(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Documents_ITextElement<D>::FontSize() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement)->get_FontSize(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITextElement<D>::FontSize(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement)->put_FontSize(value));
}

template <typename D> Windows::UI::Xaml::Media::FontFamily consume_Windows_UI_Xaml_Documents_ITextElement<D>::FontFamily() const
{
    Windows::UI::Xaml::Media::FontFamily value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement)->get_FontFamily(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITextElement<D>::FontFamily(Windows::UI::Xaml::Media::FontFamily const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement)->put_FontFamily(get_abi(value)));
}

template <typename D> Windows::UI::Text::FontWeight consume_Windows_UI_Xaml_Documents_ITextElement<D>::FontWeight() const
{
    Windows::UI::Text::FontWeight value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement)->get_FontWeight(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITextElement<D>::FontWeight(Windows::UI::Text::FontWeight const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement)->put_FontWeight(get_abi(value)));
}

template <typename D> Windows::UI::Text::FontStyle consume_Windows_UI_Xaml_Documents_ITextElement<D>::FontStyle() const
{
    Windows::UI::Text::FontStyle value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement)->get_FontStyle(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITextElement<D>::FontStyle(Windows::UI::Text::FontStyle const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement)->put_FontStyle(get_abi(value)));
}

template <typename D> Windows::UI::Text::FontStretch consume_Windows_UI_Xaml_Documents_ITextElement<D>::FontStretch() const
{
    Windows::UI::Text::FontStretch value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement)->get_FontStretch(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITextElement<D>::FontStretch(Windows::UI::Text::FontStretch const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement)->put_FontStretch(get_abi(value)));
}

template <typename D> int32_t consume_Windows_UI_Xaml_Documents_ITextElement<D>::CharacterSpacing() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement)->get_CharacterSpacing(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITextElement<D>::CharacterSpacing(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement)->put_CharacterSpacing(value));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Documents_ITextElement<D>::Foreground() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement)->get_Foreground(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITextElement<D>::Foreground(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement)->put_Foreground(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Xaml_Documents_ITextElement<D>::Language() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement)->get_Language(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITextElement<D>::Language(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement)->put_Language(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Documents::TextPointer consume_Windows_UI_Xaml_Documents_ITextElement<D>::ContentStart() const
{
    Windows::UI::Xaml::Documents::TextPointer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement)->get_ContentStart(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Documents::TextPointer consume_Windows_UI_Xaml_Documents_ITextElement<D>::ContentEnd() const
{
    Windows::UI::Xaml::Documents::TextPointer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement)->get_ContentEnd(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Documents::TextPointer consume_Windows_UI_Xaml_Documents_ITextElement<D>::ElementStart() const
{
    Windows::UI::Xaml::Documents::TextPointer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement)->get_ElementStart(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Documents::TextPointer consume_Windows_UI_Xaml_Documents_ITextElement<D>::ElementEnd() const
{
    Windows::UI::Xaml::Documents::TextPointer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement)->get_ElementEnd(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Documents_ITextElement<D>::FindName(param::hstring const& name) const
{
    Windows::Foundation::IInspectable result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement)->FindName(get_abi(name), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITextElement2<D>::IsTextScaleFactorEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement2)->get_IsTextScaleFactorEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITextElement2<D>::IsTextScaleFactorEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement2)->put_IsTextScaleFactorEnabled(value));
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITextElement3<D>::AllowFocusOnInteraction() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement3)->get_AllowFocusOnInteraction(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITextElement3<D>::AllowFocusOnInteraction(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement3)->put_AllowFocusOnInteraction(value));
}

template <typename D> hstring consume_Windows_UI_Xaml_Documents_ITextElement3<D>::AccessKey() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement3)->get_AccessKey(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITextElement3<D>::AccessKey(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement3)->put_AccessKey(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITextElement3<D>::ExitDisplayModeOnAccessKeyInvoked() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement3)->get_ExitDisplayModeOnAccessKeyInvoked(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITextElement3<D>::ExitDisplayModeOnAccessKeyInvoked(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement3)->put_ExitDisplayModeOnAccessKeyInvoked(value));
}

template <typename D> Windows::UI::Text::TextDecorations consume_Windows_UI_Xaml_Documents_ITextElement4<D>::TextDecorations() const
{
    Windows::UI::Text::TextDecorations value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement4)->get_TextDecorations(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITextElement4<D>::TextDecorations(Windows::UI::Text::TextDecorations const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement4)->put_TextDecorations(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITextElement4<D>::IsAccessKeyScope() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement4)->get_IsAccessKeyScope(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITextElement4<D>::IsAccessKeyScope(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement4)->put_IsAccessKeyScope(value));
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Documents_ITextElement4<D>::AccessKeyScopeOwner() const
{
    Windows::UI::Xaml::DependencyObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement4)->get_AccessKeyScopeOwner(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITextElement4<D>::AccessKeyScopeOwner(Windows::UI::Xaml::DependencyObject const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement4)->put_AccessKeyScopeOwner(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Input::KeyTipPlacementMode consume_Windows_UI_Xaml_Documents_ITextElement4<D>::KeyTipPlacementMode() const
{
    Windows::UI::Xaml::Input::KeyTipPlacementMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement4)->get_KeyTipPlacementMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITextElement4<D>::KeyTipPlacementMode(Windows::UI::Xaml::Input::KeyTipPlacementMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement4)->put_KeyTipPlacementMode(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_Documents_ITextElement4<D>::KeyTipHorizontalOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement4)->get_KeyTipHorizontalOffset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITextElement4<D>::KeyTipHorizontalOffset(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement4)->put_KeyTipHorizontalOffset(value));
}

template <typename D> double consume_Windows_UI_Xaml_Documents_ITextElement4<D>::KeyTipVerticalOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement4)->get_KeyTipVerticalOffset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITextElement4<D>::KeyTipVerticalOffset(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement4)->put_KeyTipVerticalOffset(value));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Documents_ITextElement4<D>::AccessKeyDisplayRequested(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Documents::TextElement, Windows::UI::Xaml::Input::AccessKeyDisplayRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement4)->add_AccessKeyDisplayRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Documents_ITextElement4<D>::AccessKeyDisplayRequested_revoker consume_Windows_UI_Xaml_Documents_ITextElement4<D>::AccessKeyDisplayRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Documents::TextElement, Windows::UI::Xaml::Input::AccessKeyDisplayRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, AccessKeyDisplayRequested_revoker>(this, AccessKeyDisplayRequested(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITextElement4<D>::AccessKeyDisplayRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement4)->remove_AccessKeyDisplayRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Documents_ITextElement4<D>::AccessKeyDisplayDismissed(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Documents::TextElement, Windows::UI::Xaml::Input::AccessKeyDisplayDismissedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement4)->add_AccessKeyDisplayDismissed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Documents_ITextElement4<D>::AccessKeyDisplayDismissed_revoker consume_Windows_UI_Xaml_Documents_ITextElement4<D>::AccessKeyDisplayDismissed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Documents::TextElement, Windows::UI::Xaml::Input::AccessKeyDisplayDismissedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, AccessKeyDisplayDismissed_revoker>(this, AccessKeyDisplayDismissed(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITextElement4<D>::AccessKeyDisplayDismissed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement4)->remove_AccessKeyDisplayDismissed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Documents_ITextElement4<D>::AccessKeyInvoked(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Documents::TextElement, Windows::UI::Xaml::Input::AccessKeyInvokedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement4)->add_AccessKeyInvoked(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Documents_ITextElement4<D>::AccessKeyInvoked_revoker consume_Windows_UI_Xaml_Documents_ITextElement4<D>::AccessKeyInvoked(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Documents::TextElement, Windows::UI::Xaml::Input::AccessKeyInvokedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, AccessKeyInvoked_revoker>(this, AccessKeyInvoked(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITextElement4<D>::AccessKeyInvoked(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement4)->remove_AccessKeyInvoked(get_abi(token)));
}

template <typename D> Windows::UI::Xaml::XamlRoot consume_Windows_UI_Xaml_Documents_ITextElement5<D>::XamlRoot() const
{
    Windows::UI::Xaml::XamlRoot value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement5)->get_XamlRoot(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITextElement5<D>::XamlRoot(Windows::UI::Xaml::XamlRoot const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElement5)->put_XamlRoot(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITextElementOverrides<D>::OnDisconnectVisualChildren() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElementOverrides)->OnDisconnectVisualChildren());
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITextElementStatics<D>::FontSizeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElementStatics)->get_FontSizeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITextElementStatics<D>::FontFamilyProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElementStatics)->get_FontFamilyProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITextElementStatics<D>::FontWeightProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElementStatics)->get_FontWeightProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITextElementStatics<D>::FontStyleProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElementStatics)->get_FontStyleProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITextElementStatics<D>::FontStretchProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElementStatics)->get_FontStretchProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITextElementStatics<D>::CharacterSpacingProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElementStatics)->get_CharacterSpacingProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITextElementStatics<D>::ForegroundProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElementStatics)->get_ForegroundProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITextElementStatics<D>::LanguageProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElementStatics)->get_LanguageProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITextElementStatics2<D>::IsTextScaleFactorEnabledProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElementStatics2)->get_IsTextScaleFactorEnabledProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITextElementStatics3<D>::AllowFocusOnInteractionProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElementStatics3)->get_AllowFocusOnInteractionProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITextElementStatics3<D>::AccessKeyProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElementStatics3)->get_AccessKeyProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITextElementStatics3<D>::ExitDisplayModeOnAccessKeyInvokedProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElementStatics3)->get_ExitDisplayModeOnAccessKeyInvokedProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITextElementStatics4<D>::TextDecorationsProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElementStatics4)->get_TextDecorationsProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITextElementStatics4<D>::IsAccessKeyScopeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElementStatics4)->get_IsAccessKeyScopeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITextElementStatics4<D>::AccessKeyScopeOwnerProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElementStatics4)->get_AccessKeyScopeOwnerProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITextElementStatics4<D>::KeyTipPlacementModeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElementStatics4)->get_KeyTipPlacementModeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITextElementStatics4<D>::KeyTipHorizontalOffsetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElementStatics4)->get_KeyTipHorizontalOffsetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITextElementStatics4<D>::KeyTipVerticalOffsetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextElementStatics4)->get_KeyTipVerticalOffsetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Documents::TextRange> consume_Windows_UI_Xaml_Documents_ITextHighlighter<D>::Ranges() const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Documents::TextRange> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextHighlighter)->get_Ranges(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Documents_ITextHighlighter<D>::Foreground() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextHighlighter)->get_Foreground(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITextHighlighter<D>::Foreground(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextHighlighter)->put_Foreground(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_Documents_ITextHighlighter<D>::Background() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextHighlighter)->get_Background(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITextHighlighter<D>::Background(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextHighlighter)->put_Background(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Documents::TextHighlighter consume_Windows_UI_Xaml_Documents_ITextHighlighterFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Documents::TextHighlighter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextHighlighterFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITextHighlighterStatics<D>::ForegroundProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextHighlighterStatics)->get_ForegroundProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITextHighlighterStatics<D>::BackgroundProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextHighlighterStatics)->get_BackgroundProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Documents_ITextPointer<D>::Parent() const
{
    Windows::UI::Xaml::DependencyObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextPointer)->get_Parent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::FrameworkElement consume_Windows_UI_Xaml_Documents_ITextPointer<D>::VisualParent() const
{
    Windows::UI::Xaml::FrameworkElement value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextPointer)->get_VisualParent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Documents::LogicalDirection consume_Windows_UI_Xaml_Documents_ITextPointer<D>::LogicalDirection() const
{
    Windows::UI::Xaml::Documents::LogicalDirection value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextPointer)->get_LogicalDirection(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Documents_ITextPointer<D>::Offset() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextPointer)->get_Offset(&value));
    return value;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Xaml_Documents_ITextPointer<D>::GetCharacterRect(Windows::UI::Xaml::Documents::LogicalDirection const& direction) const
{
    Windows::Foundation::Rect result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextPointer)->GetCharacterRect(get_abi(direction), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Documents::TextPointer consume_Windows_UI_Xaml_Documents_ITextPointer<D>::GetPositionAtOffset(int32_t offset, Windows::UI::Xaml::Documents::LogicalDirection const& direction) const
{
    Windows::UI::Xaml::Documents::TextPointer result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITextPointer)->GetPositionAtOffset(offset, get_abi(direction), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::AnnotationAlternatesProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_AnnotationAlternatesProperty(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetAnnotationAlternates(Windows::UI::Xaml::DependencyObject const& element) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetAnnotationAlternates(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetAnnotationAlternates(Windows::UI::Xaml::DependencyObject const& element, int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetAnnotationAlternates(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::EastAsianExpertFormsProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_EastAsianExpertFormsProperty(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetEastAsianExpertForms(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetEastAsianExpertForms(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetEastAsianExpertForms(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetEastAsianExpertForms(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::EastAsianLanguageProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_EastAsianLanguageProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::FontEastAsianLanguage consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetEastAsianLanguage(Windows::UI::Xaml::DependencyObject const& element) const
{
    Windows::UI::Xaml::FontEastAsianLanguage result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetEastAsianLanguage(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetEastAsianLanguage(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::FontEastAsianLanguage const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetEastAsianLanguage(get_abi(element), get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::EastAsianWidthsProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_EastAsianWidthsProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::FontEastAsianWidths consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetEastAsianWidths(Windows::UI::Xaml::DependencyObject const& element) const
{
    Windows::UI::Xaml::FontEastAsianWidths result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetEastAsianWidths(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetEastAsianWidths(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::FontEastAsianWidths const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetEastAsianWidths(get_abi(element), get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StandardLigaturesProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_StandardLigaturesProperty(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStandardLigatures(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetStandardLigatures(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStandardLigatures(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetStandardLigatures(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::ContextualLigaturesProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_ContextualLigaturesProperty(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetContextualLigatures(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetContextualLigatures(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetContextualLigatures(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetContextualLigatures(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::DiscretionaryLigaturesProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_DiscretionaryLigaturesProperty(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetDiscretionaryLigatures(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetDiscretionaryLigatures(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetDiscretionaryLigatures(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetDiscretionaryLigatures(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::HistoricalLigaturesProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_HistoricalLigaturesProperty(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetHistoricalLigatures(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetHistoricalLigatures(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetHistoricalLigatures(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetHistoricalLigatures(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StandardSwashesProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_StandardSwashesProperty(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStandardSwashes(Windows::UI::Xaml::DependencyObject const& element) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetStandardSwashes(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStandardSwashes(Windows::UI::Xaml::DependencyObject const& element, int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetStandardSwashes(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::ContextualSwashesProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_ContextualSwashesProperty(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetContextualSwashes(Windows::UI::Xaml::DependencyObject const& element) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetContextualSwashes(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetContextualSwashes(Windows::UI::Xaml::DependencyObject const& element, int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetContextualSwashes(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::ContextualAlternatesProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_ContextualAlternatesProperty(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetContextualAlternates(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetContextualAlternates(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetContextualAlternates(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetContextualAlternates(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticAlternatesProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticAlternatesProperty(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticAlternates(Windows::UI::Xaml::DependencyObject const& element) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticAlternates(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticAlternates(Windows::UI::Xaml::DependencyObject const& element, int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticAlternates(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet1Property() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet1Property(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet1(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet1(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet1(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet1(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet2Property() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet2Property(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet2(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet2(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet2(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet2(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet3Property() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet3Property(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet3(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet3(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet3(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet3(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet4Property() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet4Property(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet4(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet4(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet4(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet4(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet5Property() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet5Property(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet5(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet5(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet5(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet5(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet6Property() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet6Property(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet6(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet6(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet6(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet6(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet7Property() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet7Property(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet7(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet7(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet7(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet7(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet8Property() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet8Property(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet8(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet8(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet8(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet8(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet9Property() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet9Property(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet9(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet9(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet9(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet9(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet10Property() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet10Property(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet10(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet10(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet10(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet10(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet11Property() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet11Property(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet11(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet11(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet11(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet11(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet12Property() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet12Property(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet12(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet12(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet12(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet12(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet13Property() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet13Property(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet13(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet13(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet13(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet13(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet14Property() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet14Property(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet14(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet14(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet14(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet14(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet15Property() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet15Property(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet15(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet15(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet15(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet15(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet16Property() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet16Property(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet16(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet16(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet16(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet16(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet17Property() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet17Property(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet17(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet17(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet17(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet17(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet18Property() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet18Property(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet18(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet18(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet18(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet18(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet19Property() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet19Property(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet19(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet19(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet19(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet19(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::StylisticSet20Property() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_StylisticSet20Property(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetStylisticSet20(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetStylisticSet20(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetStylisticSet20(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetStylisticSet20(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::CapitalsProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_CapitalsProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::FontCapitals consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetCapitals(Windows::UI::Xaml::DependencyObject const& element) const
{
    Windows::UI::Xaml::FontCapitals result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetCapitals(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetCapitals(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::FontCapitals const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetCapitals(get_abi(element), get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::CapitalSpacingProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_CapitalSpacingProperty(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetCapitalSpacing(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetCapitalSpacing(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetCapitalSpacing(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetCapitalSpacing(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::KerningProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_KerningProperty(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetKerning(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetKerning(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetKerning(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetKerning(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::CaseSensitiveFormsProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_CaseSensitiveFormsProperty(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetCaseSensitiveForms(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetCaseSensitiveForms(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetCaseSensitiveForms(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetCaseSensitiveForms(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::HistoricalFormsProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_HistoricalFormsProperty(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetHistoricalForms(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetHistoricalForms(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetHistoricalForms(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetHistoricalForms(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::FractionProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_FractionProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::FontFraction consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetFraction(Windows::UI::Xaml::DependencyObject const& element) const
{
    Windows::UI::Xaml::FontFraction result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetFraction(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetFraction(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::FontFraction const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetFraction(get_abi(element), get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::NumeralStyleProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_NumeralStyleProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::FontNumeralStyle consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetNumeralStyle(Windows::UI::Xaml::DependencyObject const& element) const
{
    Windows::UI::Xaml::FontNumeralStyle result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetNumeralStyle(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetNumeralStyle(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::FontNumeralStyle const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetNumeralStyle(get_abi(element), get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::NumeralAlignmentProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_NumeralAlignmentProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::FontNumeralAlignment consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetNumeralAlignment(Windows::UI::Xaml::DependencyObject const& element) const
{
    Windows::UI::Xaml::FontNumeralAlignment result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetNumeralAlignment(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetNumeralAlignment(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::FontNumeralAlignment const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetNumeralAlignment(get_abi(element), get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SlashedZeroProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_SlashedZeroProperty(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetSlashedZero(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetSlashedZero(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetSlashedZero(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetSlashedZero(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::MathematicalGreekProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_MathematicalGreekProperty(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetMathematicalGreek(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetMathematicalGreek(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetMathematicalGreek(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetMathematicalGreek(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::VariantsProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->get_VariantsProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::FontVariants consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::GetVariants(Windows::UI::Xaml::DependencyObject const& element) const
{
    Windows::UI::Xaml::FontVariants result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->GetVariants(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>::SetVariants(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::FontVariants const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Documents::ITypographyStatics)->SetVariants(get_abi(element), get_abi(value)));
}

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IBlock> : produce_base<D, Windows::UI::Xaml::Documents::IBlock>
{
    int32_t WINRT_CALL get_TextAlignment(Windows::UI::Xaml::TextAlignment* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TextAlignment, WINRT_WRAP(Windows::UI::Xaml::TextAlignment));
            *value = detach_from<Windows::UI::Xaml::TextAlignment>(this->shim().TextAlignment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TextAlignment(Windows::UI::Xaml::TextAlignment value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TextAlignment, WINRT_WRAP(void), Windows::UI::Xaml::TextAlignment const&);
            this->shim().TextAlignment(*reinterpret_cast<Windows::UI::Xaml::TextAlignment const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LineHeight(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineHeight, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().LineHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LineHeight(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineHeight, WINRT_WRAP(void), double);
            this->shim().LineHeight(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LineStackingStrategy(Windows::UI::Xaml::LineStackingStrategy* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineStackingStrategy, WINRT_WRAP(Windows::UI::Xaml::LineStackingStrategy));
            *value = detach_from<Windows::UI::Xaml::LineStackingStrategy>(this->shim().LineStackingStrategy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LineStackingStrategy(Windows::UI::Xaml::LineStackingStrategy value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineStackingStrategy, WINRT_WRAP(void), Windows::UI::Xaml::LineStackingStrategy const&);
            this->shim().LineStackingStrategy(*reinterpret_cast<Windows::UI::Xaml::LineStackingStrategy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Margin(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Margin, WINRT_WRAP(Windows::UI::Xaml::Thickness));
            *value = detach_from<Windows::UI::Xaml::Thickness>(this->shim().Margin());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Margin(struct struct_Windows_UI_Xaml_Thickness value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Margin, WINRT_WRAP(void), Windows::UI::Xaml::Thickness const&);
            this->shim().Margin(*reinterpret_cast<Windows::UI::Xaml::Thickness const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IBlock2> : produce_base<D, Windows::UI::Xaml::Documents::IBlock2>
{
    int32_t WINRT_CALL get_HorizontalTextAlignment(Windows::UI::Xaml::TextAlignment* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontalTextAlignment, WINRT_WRAP(Windows::UI::Xaml::TextAlignment));
            *value = detach_from<Windows::UI::Xaml::TextAlignment>(this->shim().HorizontalTextAlignment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_HorizontalTextAlignment(Windows::UI::Xaml::TextAlignment value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontalTextAlignment, WINRT_WRAP(void), Windows::UI::Xaml::TextAlignment const&);
            this->shim().HorizontalTextAlignment(*reinterpret_cast<Windows::UI::Xaml::TextAlignment const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IBlockFactory> : produce_base<D, Windows::UI::Xaml::Documents::IBlockFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Documents::Block), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Documents::Block>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IBlockStatics> : produce_base<D, Windows::UI::Xaml::Documents::IBlockStatics>
{
    int32_t WINRT_CALL get_TextAlignmentProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TextAlignmentProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TextAlignmentProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LineHeightProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineHeightProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().LineHeightProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LineStackingStrategyProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineStackingStrategyProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().LineStackingStrategyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MarginProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MarginProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().MarginProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IBlockStatics2> : produce_base<D, Windows::UI::Xaml::Documents::IBlockStatics2>
{
    int32_t WINRT_CALL get_HorizontalTextAlignmentProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontalTextAlignmentProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().HorizontalTextAlignmentProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IBold> : produce_base<D, Windows::UI::Xaml::Documents::IBold>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IContactContentLinkProvider> : produce_base<D, Windows::UI::Xaml::Documents::IContactContentLinkProvider>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IContentLink> : produce_base<D, Windows::UI::Xaml::Documents::IContentLink>
{
    int32_t WINRT_CALL get_Info(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Info, WINRT_WRAP(Windows::UI::Text::ContentLinkInfo));
            *value = detach_from<Windows::UI::Text::ContentLinkInfo>(this->shim().Info());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Info(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Info, WINRT_WRAP(void), Windows::UI::Text::ContentLinkInfo const&);
            this->shim().Info(*reinterpret_cast<Windows::UI::Text::ContentLinkInfo const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Background(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Background, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().Background());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Background(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Background, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().Background(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Cursor(Windows::UI::Core::CoreCursorType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cursor, WINRT_WRAP(Windows::UI::Core::CoreCursorType));
            *value = detach_from<Windows::UI::Core::CoreCursorType>(this->shim().Cursor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Cursor(Windows::UI::Core::CoreCursorType value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cursor, WINRT_WRAP(void), Windows::UI::Core::CoreCursorType const&);
            this->shim().Cursor(*reinterpret_cast<Windows::UI::Core::CoreCursorType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusLeft(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusLeft, WINRT_WRAP(Windows::UI::Xaml::DependencyObject));
            *value = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().XYFocusLeft());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_XYFocusLeft(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusLeft, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&);
            this->shim().XYFocusLeft(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusRight(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusRight, WINRT_WRAP(Windows::UI::Xaml::DependencyObject));
            *value = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().XYFocusRight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_XYFocusRight(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusRight, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&);
            this->shim().XYFocusRight(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusUp(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusUp, WINRT_WRAP(Windows::UI::Xaml::DependencyObject));
            *value = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().XYFocusUp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_XYFocusUp(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusUp, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&);
            this->shim().XYFocusUp(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusDown(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusDown, WINRT_WRAP(Windows::UI::Xaml::DependencyObject));
            *value = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().XYFocusDown());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_XYFocusDown(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusDown, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&);
            this->shim().XYFocusDown(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ElementSoundMode(Windows::UI::Xaml::ElementSoundMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ElementSoundMode, WINRT_WRAP(Windows::UI::Xaml::ElementSoundMode));
            *value = detach_from<Windows::UI::Xaml::ElementSoundMode>(this->shim().ElementSoundMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ElementSoundMode(Windows::UI::Xaml::ElementSoundMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ElementSoundMode, WINRT_WRAP(void), Windows::UI::Xaml::ElementSoundMode const&);
            this->shim().ElementSoundMode(*reinterpret_cast<Windows::UI::Xaml::ElementSoundMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FocusState(Windows::UI::Xaml::FocusState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusState, WINRT_WRAP(Windows::UI::Xaml::FocusState));
            *value = detach_from<Windows::UI::Xaml::FocusState>(this->shim().FocusState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusUpNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusUpNavigationStrategy, WINRT_WRAP(Windows::UI::Xaml::Input::XYFocusNavigationStrategy));
            *value = detach_from<Windows::UI::Xaml::Input::XYFocusNavigationStrategy>(this->shim().XYFocusUpNavigationStrategy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_XYFocusUpNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusUpNavigationStrategy, WINRT_WRAP(void), Windows::UI::Xaml::Input::XYFocusNavigationStrategy const&);
            this->shim().XYFocusUpNavigationStrategy(*reinterpret_cast<Windows::UI::Xaml::Input::XYFocusNavigationStrategy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusDownNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusDownNavigationStrategy, WINRT_WRAP(Windows::UI::Xaml::Input::XYFocusNavigationStrategy));
            *value = detach_from<Windows::UI::Xaml::Input::XYFocusNavigationStrategy>(this->shim().XYFocusDownNavigationStrategy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_XYFocusDownNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusDownNavigationStrategy, WINRT_WRAP(void), Windows::UI::Xaml::Input::XYFocusNavigationStrategy const&);
            this->shim().XYFocusDownNavigationStrategy(*reinterpret_cast<Windows::UI::Xaml::Input::XYFocusNavigationStrategy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusLeftNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusLeftNavigationStrategy, WINRT_WRAP(Windows::UI::Xaml::Input::XYFocusNavigationStrategy));
            *value = detach_from<Windows::UI::Xaml::Input::XYFocusNavigationStrategy>(this->shim().XYFocusLeftNavigationStrategy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_XYFocusLeftNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusLeftNavigationStrategy, WINRT_WRAP(void), Windows::UI::Xaml::Input::XYFocusNavigationStrategy const&);
            this->shim().XYFocusLeftNavigationStrategy(*reinterpret_cast<Windows::UI::Xaml::Input::XYFocusNavigationStrategy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusRightNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusRightNavigationStrategy, WINRT_WRAP(Windows::UI::Xaml::Input::XYFocusNavigationStrategy));
            *value = detach_from<Windows::UI::Xaml::Input::XYFocusNavigationStrategy>(this->shim().XYFocusRightNavigationStrategy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_XYFocusRightNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusRightNavigationStrategy, WINRT_WRAP(void), Windows::UI::Xaml::Input::XYFocusNavigationStrategy const&);
            this->shim().XYFocusRightNavigationStrategy(*reinterpret_cast<Windows::UI::Xaml::Input::XYFocusNavigationStrategy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsTabStop(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTabStop, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsTabStop());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsTabStop(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTabStop, WINRT_WRAP(void), bool);
            this->shim().IsTabStop(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TabIndex(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TabIndex, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().TabIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TabIndex(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TabIndex, WINRT_WRAP(void), int32_t);
            this->shim().TabIndex(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Invoked(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Invoked, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Documents::ContentLink, Windows::UI::Xaml::Documents::ContentLinkInvokedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Invoked(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Documents::ContentLink, Windows::UI::Xaml::Documents::ContentLinkInvokedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Invoked(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Invoked, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Invoked(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_GotFocus(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GotFocus, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::RoutedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().GotFocus(*reinterpret_cast<Windows::UI::Xaml::RoutedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_GotFocus(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(GotFocus, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().GotFocus(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_LostFocus(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LostFocus, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::RoutedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().LostFocus(*reinterpret_cast<Windows::UI::Xaml::RoutedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_LostFocus(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(LostFocus, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().LostFocus(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL Focus(Windows::UI::Xaml::FocusState value, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Focus, WINRT_WRAP(bool), Windows::UI::Xaml::FocusState const&);
            *result = detach_from<bool>(this->shim().Focus(*reinterpret_cast<Windows::UI::Xaml::FocusState const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IContentLinkInvokedEventArgs> : produce_base<D, Windows::UI::Xaml::Documents::IContentLinkInvokedEventArgs>
{
    int32_t WINRT_CALL get_ContentLinkInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentLinkInfo, WINRT_WRAP(Windows::UI::Text::ContentLinkInfo));
            *value = detach_from<Windows::UI::Text::ContentLinkInfo>(this->shim().ContentLinkInfo());
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
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IContentLinkProvider> : produce_base<D, Windows::UI::Xaml::Documents::IContentLinkProvider>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IContentLinkProviderCollection> : produce_base<D, Windows::UI::Xaml::Documents::IContentLinkProviderCollection>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IContentLinkProviderFactory> : produce_base<D, Windows::UI::Xaml::Documents::IContentLinkProviderFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Documents::ContentLinkProvider), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Documents::ContentLinkProvider>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IContentLinkStatics> : produce_base<D, Windows::UI::Xaml::Documents::IContentLinkStatics>
{
    int32_t WINRT_CALL get_BackgroundProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackgroundProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().BackgroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CursorProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CursorProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CursorProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusLeftProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusLeftProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusLeftProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusRightProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusRightProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusRightProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusUpProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusUpProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusUpProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusDownProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusDownProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusDownProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ElementSoundModeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ElementSoundModeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ElementSoundModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FocusStateProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusStateProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FocusStateProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusUpNavigationStrategyProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusUpNavigationStrategyProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusUpNavigationStrategyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusDownNavigationStrategyProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusDownNavigationStrategyProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusDownNavigationStrategyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusLeftNavigationStrategyProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusLeftNavigationStrategyProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusLeftNavigationStrategyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusRightNavigationStrategyProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusRightNavigationStrategyProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusRightNavigationStrategyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsTabStopProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTabStopProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsTabStopProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TabIndexProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TabIndexProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TabIndexProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IGlyphs> : produce_base<D, Windows::UI::Xaml::Documents::IGlyphs>
{
    int32_t WINRT_CALL get_UnicodeString(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnicodeString, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UnicodeString());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_UnicodeString(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnicodeString, WINRT_WRAP(void), hstring const&);
            this->shim().UnicodeString(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Indices(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Indices, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Indices());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Indices(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Indices, WINRT_WRAP(void), hstring const&);
            this->shim().Indices(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FontUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().FontUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FontUri(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontUri, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().FontUri(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StyleSimulations(Windows::UI::Xaml::Media::StyleSimulations* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StyleSimulations, WINRT_WRAP(Windows::UI::Xaml::Media::StyleSimulations));
            *value = detach_from<Windows::UI::Xaml::Media::StyleSimulations>(this->shim().StyleSimulations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StyleSimulations(Windows::UI::Xaml::Media::StyleSimulations value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StyleSimulations, WINRT_WRAP(void), Windows::UI::Xaml::Media::StyleSimulations const&);
            this->shim().StyleSimulations(*reinterpret_cast<Windows::UI::Xaml::Media::StyleSimulations const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FontRenderingEmSize(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontRenderingEmSize, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().FontRenderingEmSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FontRenderingEmSize(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontRenderingEmSize, WINRT_WRAP(void), double);
            this->shim().FontRenderingEmSize(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OriginX(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OriginX, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().OriginX());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OriginX(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OriginX, WINRT_WRAP(void), double);
            this->shim().OriginX(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OriginY(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OriginY, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().OriginY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OriginY(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OriginY, WINRT_WRAP(void), double);
            this->shim().OriginY(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IGlyphs2> : produce_base<D, Windows::UI::Xaml::Documents::IGlyphs2>
{
    int32_t WINRT_CALL get_IsColorFontEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsColorFontEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsColorFontEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsColorFontEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsColorFontEnabled, WINRT_WRAP(void), bool);
            this->shim().IsColorFontEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ColorFontPaletteIndex(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColorFontPaletteIndex, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ColorFontPaletteIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ColorFontPaletteIndex(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColorFontPaletteIndex, WINRT_WRAP(void), int32_t);
            this->shim().ColorFontPaletteIndex(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IGlyphsStatics> : produce_base<D, Windows::UI::Xaml::Documents::IGlyphsStatics>
{
    int32_t WINRT_CALL get_UnicodeStringProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnicodeStringProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().UnicodeStringProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IndicesProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IndicesProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IndicesProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FontUriProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontUriProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FontUriProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StyleSimulationsProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StyleSimulationsProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StyleSimulationsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FontRenderingEmSizeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontRenderingEmSizeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FontRenderingEmSizeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OriginXProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OriginXProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().OriginXProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OriginYProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OriginYProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().OriginYProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IGlyphsStatics2> : produce_base<D, Windows::UI::Xaml::Documents::IGlyphsStatics2>
{
    int32_t WINRT_CALL get_IsColorFontEnabledProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsColorFontEnabledProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsColorFontEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ColorFontPaletteIndexProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColorFontPaletteIndexProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ColorFontPaletteIndexProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IHyperlink> : produce_base<D, Windows::UI::Xaml::Documents::IHyperlink>
{
    int32_t WINRT_CALL get_NavigateUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NavigateUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().NavigateUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_NavigateUri(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NavigateUri, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().NavigateUri(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Click(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Click, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Documents::Hyperlink, Windows::UI::Xaml::Documents::HyperlinkClickEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Click(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Documents::Hyperlink, Windows::UI::Xaml::Documents::HyperlinkClickEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Click(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Click, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Click(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IHyperlink2> : produce_base<D, Windows::UI::Xaml::Documents::IHyperlink2>
{
    int32_t WINRT_CALL get_UnderlineStyle(Windows::UI::Xaml::Documents::UnderlineStyle* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnderlineStyle, WINRT_WRAP(Windows::UI::Xaml::Documents::UnderlineStyle));
            *value = detach_from<Windows::UI::Xaml::Documents::UnderlineStyle>(this->shim().UnderlineStyle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_UnderlineStyle(Windows::UI::Xaml::Documents::UnderlineStyle value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnderlineStyle, WINRT_WRAP(void), Windows::UI::Xaml::Documents::UnderlineStyle const&);
            this->shim().UnderlineStyle(*reinterpret_cast<Windows::UI::Xaml::Documents::UnderlineStyle const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IHyperlink3> : produce_base<D, Windows::UI::Xaml::Documents::IHyperlink3>
{
    int32_t WINRT_CALL get_XYFocusLeft(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusLeft, WINRT_WRAP(Windows::UI::Xaml::DependencyObject));
            *value = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().XYFocusLeft());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_XYFocusLeft(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusLeft, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&);
            this->shim().XYFocusLeft(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusRight(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusRight, WINRT_WRAP(Windows::UI::Xaml::DependencyObject));
            *value = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().XYFocusRight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_XYFocusRight(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusRight, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&);
            this->shim().XYFocusRight(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusUp(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusUp, WINRT_WRAP(Windows::UI::Xaml::DependencyObject));
            *value = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().XYFocusUp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_XYFocusUp(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusUp, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&);
            this->shim().XYFocusUp(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusDown(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusDown, WINRT_WRAP(Windows::UI::Xaml::DependencyObject));
            *value = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().XYFocusDown());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_XYFocusDown(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusDown, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&);
            this->shim().XYFocusDown(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ElementSoundMode(Windows::UI::Xaml::ElementSoundMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ElementSoundMode, WINRT_WRAP(Windows::UI::Xaml::ElementSoundMode));
            *value = detach_from<Windows::UI::Xaml::ElementSoundMode>(this->shim().ElementSoundMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ElementSoundMode(Windows::UI::Xaml::ElementSoundMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ElementSoundMode, WINRT_WRAP(void), Windows::UI::Xaml::ElementSoundMode const&);
            this->shim().ElementSoundMode(*reinterpret_cast<Windows::UI::Xaml::ElementSoundMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IHyperlink4> : produce_base<D, Windows::UI::Xaml::Documents::IHyperlink4>
{
    int32_t WINRT_CALL get_FocusState(Windows::UI::Xaml::FocusState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusState, WINRT_WRAP(Windows::UI::Xaml::FocusState));
            *value = detach_from<Windows::UI::Xaml::FocusState>(this->shim().FocusState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusUpNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusUpNavigationStrategy, WINRT_WRAP(Windows::UI::Xaml::Input::XYFocusNavigationStrategy));
            *value = detach_from<Windows::UI::Xaml::Input::XYFocusNavigationStrategy>(this->shim().XYFocusUpNavigationStrategy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_XYFocusUpNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusUpNavigationStrategy, WINRT_WRAP(void), Windows::UI::Xaml::Input::XYFocusNavigationStrategy const&);
            this->shim().XYFocusUpNavigationStrategy(*reinterpret_cast<Windows::UI::Xaml::Input::XYFocusNavigationStrategy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusDownNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusDownNavigationStrategy, WINRT_WRAP(Windows::UI::Xaml::Input::XYFocusNavigationStrategy));
            *value = detach_from<Windows::UI::Xaml::Input::XYFocusNavigationStrategy>(this->shim().XYFocusDownNavigationStrategy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_XYFocusDownNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusDownNavigationStrategy, WINRT_WRAP(void), Windows::UI::Xaml::Input::XYFocusNavigationStrategy const&);
            this->shim().XYFocusDownNavigationStrategy(*reinterpret_cast<Windows::UI::Xaml::Input::XYFocusNavigationStrategy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusLeftNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusLeftNavigationStrategy, WINRT_WRAP(Windows::UI::Xaml::Input::XYFocusNavigationStrategy));
            *value = detach_from<Windows::UI::Xaml::Input::XYFocusNavigationStrategy>(this->shim().XYFocusLeftNavigationStrategy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_XYFocusLeftNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusLeftNavigationStrategy, WINRT_WRAP(void), Windows::UI::Xaml::Input::XYFocusNavigationStrategy const&);
            this->shim().XYFocusLeftNavigationStrategy(*reinterpret_cast<Windows::UI::Xaml::Input::XYFocusNavigationStrategy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusRightNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusRightNavigationStrategy, WINRT_WRAP(Windows::UI::Xaml::Input::XYFocusNavigationStrategy));
            *value = detach_from<Windows::UI::Xaml::Input::XYFocusNavigationStrategy>(this->shim().XYFocusRightNavigationStrategy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_XYFocusRightNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusRightNavigationStrategy, WINRT_WRAP(void), Windows::UI::Xaml::Input::XYFocusNavigationStrategy const&);
            this->shim().XYFocusRightNavigationStrategy(*reinterpret_cast<Windows::UI::Xaml::Input::XYFocusNavigationStrategy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_GotFocus(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GotFocus, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::RoutedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().GotFocus(*reinterpret_cast<Windows::UI::Xaml::RoutedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_GotFocus(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(GotFocus, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().GotFocus(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_LostFocus(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LostFocus, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::RoutedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().LostFocus(*reinterpret_cast<Windows::UI::Xaml::RoutedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_LostFocus(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(LostFocus, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().LostFocus(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL Focus(Windows::UI::Xaml::FocusState value, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Focus, WINRT_WRAP(bool), Windows::UI::Xaml::FocusState const&);
            *result = detach_from<bool>(this->shim().Focus(*reinterpret_cast<Windows::UI::Xaml::FocusState const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IHyperlink5> : produce_base<D, Windows::UI::Xaml::Documents::IHyperlink5>
{
    int32_t WINRT_CALL get_IsTabStop(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTabStop, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsTabStop());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsTabStop(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTabStop, WINRT_WRAP(void), bool);
            this->shim().IsTabStop(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TabIndex(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TabIndex, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().TabIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TabIndex(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TabIndex, WINRT_WRAP(void), int32_t);
            this->shim().TabIndex(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IHyperlinkClickEventArgs> : produce_base<D, Windows::UI::Xaml::Documents::IHyperlinkClickEventArgs>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IHyperlinkStatics> : produce_base<D, Windows::UI::Xaml::Documents::IHyperlinkStatics>
{
    int32_t WINRT_CALL get_NavigateUriProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NavigateUriProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().NavigateUriProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IHyperlinkStatics2> : produce_base<D, Windows::UI::Xaml::Documents::IHyperlinkStatics2>
{
    int32_t WINRT_CALL get_UnderlineStyleProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnderlineStyleProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().UnderlineStyleProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IHyperlinkStatics3> : produce_base<D, Windows::UI::Xaml::Documents::IHyperlinkStatics3>
{
    int32_t WINRT_CALL get_XYFocusLeftProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusLeftProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusLeftProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusRightProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusRightProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusRightProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusUpProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusUpProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusUpProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusDownProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusDownProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusDownProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ElementSoundModeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ElementSoundModeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ElementSoundModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IHyperlinkStatics4> : produce_base<D, Windows::UI::Xaml::Documents::IHyperlinkStatics4>
{
    int32_t WINRT_CALL get_FocusStateProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusStateProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FocusStateProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusUpNavigationStrategyProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusUpNavigationStrategyProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusUpNavigationStrategyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusDownNavigationStrategyProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusDownNavigationStrategyProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusDownNavigationStrategyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusLeftNavigationStrategyProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusLeftNavigationStrategyProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusLeftNavigationStrategyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusRightNavigationStrategyProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusRightNavigationStrategyProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusRightNavigationStrategyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IHyperlinkStatics5> : produce_base<D, Windows::UI::Xaml::Documents::IHyperlinkStatics5>
{
    int32_t WINRT_CALL get_IsTabStopProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTabStopProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsTabStopProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TabIndexProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TabIndexProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TabIndexProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IInline> : produce_base<D, Windows::UI::Xaml::Documents::IInline>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IInlineFactory> : produce_base<D, Windows::UI::Xaml::Documents::IInlineFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Documents::Inline), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Documents::Inline>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IInlineUIContainer> : produce_base<D, Windows::UI::Xaml::Documents::IInlineUIContainer>
{
    int32_t WINRT_CALL get_Child(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Child, WINRT_WRAP(Windows::UI::Xaml::UIElement));
            *value = detach_from<Windows::UI::Xaml::UIElement>(this->shim().Child());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Child(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Child, WINRT_WRAP(void), Windows::UI::Xaml::UIElement const&);
            this->shim().Child(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IItalic> : produce_base<D, Windows::UI::Xaml::Documents::IItalic>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::ILineBreak> : produce_base<D, Windows::UI::Xaml::Documents::ILineBreak>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IParagraph> : produce_base<D, Windows::UI::Xaml::Documents::IParagraph>
{
    int32_t WINRT_CALL get_Inlines(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Inlines, WINRT_WRAP(Windows::UI::Xaml::Documents::InlineCollection));
            *value = detach_from<Windows::UI::Xaml::Documents::InlineCollection>(this->shim().Inlines());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TextIndent(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TextIndent, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().TextIndent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TextIndent(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TextIndent, WINRT_WRAP(void), double);
            this->shim().TextIndent(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IParagraphStatics> : produce_base<D, Windows::UI::Xaml::Documents::IParagraphStatics>
{
    int32_t WINRT_CALL get_TextIndentProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TextIndentProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TextIndentProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IPlaceContentLinkProvider> : produce_base<D, Windows::UI::Xaml::Documents::IPlaceContentLinkProvider>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IRun> : produce_base<D, Windows::UI::Xaml::Documents::IRun>
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

    int32_t WINRT_CALL get_FlowDirection(Windows::UI::Xaml::FlowDirection* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FlowDirection, WINRT_WRAP(Windows::UI::Xaml::FlowDirection));
            *value = detach_from<Windows::UI::Xaml::FlowDirection>(this->shim().FlowDirection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FlowDirection(Windows::UI::Xaml::FlowDirection value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FlowDirection, WINRT_WRAP(void), Windows::UI::Xaml::FlowDirection const&);
            this->shim().FlowDirection(*reinterpret_cast<Windows::UI::Xaml::FlowDirection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IRunStatics> : produce_base<D, Windows::UI::Xaml::Documents::IRunStatics>
{
    int32_t WINRT_CALL get_FlowDirectionProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FlowDirectionProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FlowDirectionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::ISpan> : produce_base<D, Windows::UI::Xaml::Documents::ISpan>
{
    int32_t WINRT_CALL get_Inlines(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Inlines, WINRT_WRAP(Windows::UI::Xaml::Documents::InlineCollection));
            *value = detach_from<Windows::UI::Xaml::Documents::InlineCollection>(this->shim().Inlines());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Inlines(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Inlines, WINRT_WRAP(void), Windows::UI::Xaml::Documents::InlineCollection const&);
            this->shim().Inlines(*reinterpret_cast<Windows::UI::Xaml::Documents::InlineCollection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::ISpanFactory> : produce_base<D, Windows::UI::Xaml::Documents::ISpanFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Documents::Span), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Documents::Span>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::ITextElement> : produce_base<D, Windows::UI::Xaml::Documents::ITextElement>
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

    int32_t WINRT_CALL get_FontSize(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontSize, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().FontSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FontSize(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontSize, WINRT_WRAP(void), double);
            this->shim().FontSize(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FontFamily(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontFamily, WINRT_WRAP(Windows::UI::Xaml::Media::FontFamily));
            *value = detach_from<Windows::UI::Xaml::Media::FontFamily>(this->shim().FontFamily());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FontFamily(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontFamily, WINRT_WRAP(void), Windows::UI::Xaml::Media::FontFamily const&);
            this->shim().FontFamily(*reinterpret_cast<Windows::UI::Xaml::Media::FontFamily const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FontWeight(struct struct_Windows_UI_Text_FontWeight* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontWeight, WINRT_WRAP(Windows::UI::Text::FontWeight));
            *value = detach_from<Windows::UI::Text::FontWeight>(this->shim().FontWeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FontWeight(struct struct_Windows_UI_Text_FontWeight value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontWeight, WINRT_WRAP(void), Windows::UI::Text::FontWeight const&);
            this->shim().FontWeight(*reinterpret_cast<Windows::UI::Text::FontWeight const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FontStyle(Windows::UI::Text::FontStyle* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontStyle, WINRT_WRAP(Windows::UI::Text::FontStyle));
            *value = detach_from<Windows::UI::Text::FontStyle>(this->shim().FontStyle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FontStyle(Windows::UI::Text::FontStyle value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontStyle, WINRT_WRAP(void), Windows::UI::Text::FontStyle const&);
            this->shim().FontStyle(*reinterpret_cast<Windows::UI::Text::FontStyle const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FontStretch(Windows::UI::Text::FontStretch* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontStretch, WINRT_WRAP(Windows::UI::Text::FontStretch));
            *value = detach_from<Windows::UI::Text::FontStretch>(this->shim().FontStretch());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FontStretch(Windows::UI::Text::FontStretch value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontStretch, WINRT_WRAP(void), Windows::UI::Text::FontStretch const&);
            this->shim().FontStretch(*reinterpret_cast<Windows::UI::Text::FontStretch const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CharacterSpacing(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CharacterSpacing, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().CharacterSpacing());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CharacterSpacing(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CharacterSpacing, WINRT_WRAP(void), int32_t);
            this->shim().CharacterSpacing(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Foreground(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Foreground, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().Foreground());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Foreground(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Foreground, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().Foreground(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Language(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Language, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Language());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Language(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Language, WINRT_WRAP(void), hstring const&);
            this->shim().Language(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentStart(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentStart, WINRT_WRAP(Windows::UI::Xaml::Documents::TextPointer));
            *value = detach_from<Windows::UI::Xaml::Documents::TextPointer>(this->shim().ContentStart());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentEnd(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentEnd, WINRT_WRAP(Windows::UI::Xaml::Documents::TextPointer));
            *value = detach_from<Windows::UI::Xaml::Documents::TextPointer>(this->shim().ContentEnd());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ElementStart(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ElementStart, WINRT_WRAP(Windows::UI::Xaml::Documents::TextPointer));
            *value = detach_from<Windows::UI::Xaml::Documents::TextPointer>(this->shim().ElementStart());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ElementEnd(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ElementEnd, WINRT_WRAP(Windows::UI::Xaml::Documents::TextPointer));
            *value = detach_from<Windows::UI::Xaml::Documents::TextPointer>(this->shim().ElementEnd());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindName(void* name, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindName, WINRT_WRAP(Windows::Foundation::IInspectable), hstring const&);
            *result = detach_from<Windows::Foundation::IInspectable>(this->shim().FindName(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::ITextElement2> : produce_base<D, Windows::UI::Xaml::Documents::ITextElement2>
{
    int32_t WINRT_CALL get_IsTextScaleFactorEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTextScaleFactorEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsTextScaleFactorEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsTextScaleFactorEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTextScaleFactorEnabled, WINRT_WRAP(void), bool);
            this->shim().IsTextScaleFactorEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::ITextElement3> : produce_base<D, Windows::UI::Xaml::Documents::ITextElement3>
{
    int32_t WINRT_CALL get_AllowFocusOnInteraction(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowFocusOnInteraction, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AllowFocusOnInteraction());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AllowFocusOnInteraction(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowFocusOnInteraction, WINRT_WRAP(void), bool);
            this->shim().AllowFocusOnInteraction(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AccessKey(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccessKey, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AccessKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AccessKey(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccessKey, WINRT_WRAP(void), hstring const&);
            this->shim().AccessKey(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExitDisplayModeOnAccessKeyInvoked(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExitDisplayModeOnAccessKeyInvoked, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ExitDisplayModeOnAccessKeyInvoked());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ExitDisplayModeOnAccessKeyInvoked(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExitDisplayModeOnAccessKeyInvoked, WINRT_WRAP(void), bool);
            this->shim().ExitDisplayModeOnAccessKeyInvoked(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::ITextElement4> : produce_base<D, Windows::UI::Xaml::Documents::ITextElement4>
{
    int32_t WINRT_CALL get_TextDecorations(Windows::UI::Text::TextDecorations* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TextDecorations, WINRT_WRAP(Windows::UI::Text::TextDecorations));
            *value = detach_from<Windows::UI::Text::TextDecorations>(this->shim().TextDecorations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TextDecorations(Windows::UI::Text::TextDecorations value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TextDecorations, WINRT_WRAP(void), Windows::UI::Text::TextDecorations const&);
            this->shim().TextDecorations(*reinterpret_cast<Windows::UI::Text::TextDecorations const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsAccessKeyScope(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAccessKeyScope, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsAccessKeyScope());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsAccessKeyScope(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAccessKeyScope, WINRT_WRAP(void), bool);
            this->shim().IsAccessKeyScope(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AccessKeyScopeOwner(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccessKeyScopeOwner, WINRT_WRAP(Windows::UI::Xaml::DependencyObject));
            *value = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().AccessKeyScopeOwner());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AccessKeyScopeOwner(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccessKeyScopeOwner, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&);
            this->shim().AccessKeyScopeOwner(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyTipPlacementMode(Windows::UI::Xaml::Input::KeyTipPlacementMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyTipPlacementMode, WINRT_WRAP(Windows::UI::Xaml::Input::KeyTipPlacementMode));
            *value = detach_from<Windows::UI::Xaml::Input::KeyTipPlacementMode>(this->shim().KeyTipPlacementMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_KeyTipPlacementMode(Windows::UI::Xaml::Input::KeyTipPlacementMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyTipPlacementMode, WINRT_WRAP(void), Windows::UI::Xaml::Input::KeyTipPlacementMode const&);
            this->shim().KeyTipPlacementMode(*reinterpret_cast<Windows::UI::Xaml::Input::KeyTipPlacementMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyTipHorizontalOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyTipHorizontalOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().KeyTipHorizontalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_KeyTipHorizontalOffset(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyTipHorizontalOffset, WINRT_WRAP(void), double);
            this->shim().KeyTipHorizontalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyTipVerticalOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyTipVerticalOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().KeyTipVerticalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_KeyTipVerticalOffset(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyTipVerticalOffset, WINRT_WRAP(void), double);
            this->shim().KeyTipVerticalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_AccessKeyDisplayRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccessKeyDisplayRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Documents::TextElement, Windows::UI::Xaml::Input::AccessKeyDisplayRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().AccessKeyDisplayRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Documents::TextElement, Windows::UI::Xaml::Input::AccessKeyDisplayRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AccessKeyDisplayRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AccessKeyDisplayRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AccessKeyDisplayRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_AccessKeyDisplayDismissed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccessKeyDisplayDismissed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Documents::TextElement, Windows::UI::Xaml::Input::AccessKeyDisplayDismissedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().AccessKeyDisplayDismissed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Documents::TextElement, Windows::UI::Xaml::Input::AccessKeyDisplayDismissedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AccessKeyDisplayDismissed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AccessKeyDisplayDismissed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AccessKeyDisplayDismissed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_AccessKeyInvoked(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccessKeyInvoked, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Documents::TextElement, Windows::UI::Xaml::Input::AccessKeyInvokedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().AccessKeyInvoked(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Documents::TextElement, Windows::UI::Xaml::Input::AccessKeyInvokedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AccessKeyInvoked(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AccessKeyInvoked, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AccessKeyInvoked(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::ITextElement5> : produce_base<D, Windows::UI::Xaml::Documents::ITextElement5>
{
    int32_t WINRT_CALL get_XamlRoot(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XamlRoot, WINRT_WRAP(Windows::UI::Xaml::XamlRoot));
            *value = detach_from<Windows::UI::Xaml::XamlRoot>(this->shim().XamlRoot());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_XamlRoot(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XamlRoot, WINRT_WRAP(void), Windows::UI::Xaml::XamlRoot const&);
            this->shim().XamlRoot(*reinterpret_cast<Windows::UI::Xaml::XamlRoot const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::ITextElementFactory> : produce_base<D, Windows::UI::Xaml::Documents::ITextElementFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::ITextElementOverrides> : produce_base<D, Windows::UI::Xaml::Documents::ITextElementOverrides>
{
    int32_t WINRT_CALL OnDisconnectVisualChildren() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnDisconnectVisualChildren, WINRT_WRAP(void));
            this->shim().OnDisconnectVisualChildren();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::ITextElementStatics> : produce_base<D, Windows::UI::Xaml::Documents::ITextElementStatics>
{
    int32_t WINRT_CALL get_FontSizeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontSizeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FontSizeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FontFamilyProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontFamilyProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FontFamilyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FontWeightProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontWeightProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FontWeightProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FontStyleProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontStyleProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FontStyleProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FontStretchProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontStretchProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FontStretchProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CharacterSpacingProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CharacterSpacingProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CharacterSpacingProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ForegroundProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ForegroundProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ForegroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LanguageProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LanguageProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().LanguageProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::ITextElementStatics2> : produce_base<D, Windows::UI::Xaml::Documents::ITextElementStatics2>
{
    int32_t WINRT_CALL get_IsTextScaleFactorEnabledProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTextScaleFactorEnabledProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsTextScaleFactorEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::ITextElementStatics3> : produce_base<D, Windows::UI::Xaml::Documents::ITextElementStatics3>
{
    int32_t WINRT_CALL get_AllowFocusOnInteractionProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowFocusOnInteractionProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().AllowFocusOnInteractionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AccessKeyProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccessKeyProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().AccessKeyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExitDisplayModeOnAccessKeyInvokedProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExitDisplayModeOnAccessKeyInvokedProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ExitDisplayModeOnAccessKeyInvokedProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::ITextElementStatics4> : produce_base<D, Windows::UI::Xaml::Documents::ITextElementStatics4>
{
    int32_t WINRT_CALL get_TextDecorationsProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TextDecorationsProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TextDecorationsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsAccessKeyScopeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAccessKeyScopeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsAccessKeyScopeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AccessKeyScopeOwnerProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccessKeyScopeOwnerProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().AccessKeyScopeOwnerProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyTipPlacementModeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyTipPlacementModeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().KeyTipPlacementModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyTipHorizontalOffsetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyTipHorizontalOffsetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().KeyTipHorizontalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyTipVerticalOffsetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyTipVerticalOffsetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().KeyTipVerticalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::ITextHighlighter> : produce_base<D, Windows::UI::Xaml::Documents::ITextHighlighter>
{
    int32_t WINRT_CALL get_Ranges(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Ranges, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Documents::TextRange>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Documents::TextRange>>(this->shim().Ranges());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Foreground(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Foreground, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().Foreground());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Foreground(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Foreground, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().Foreground(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Background(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Background, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().Background());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Background(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Background, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().Background(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::ITextHighlighterBase> : produce_base<D, Windows::UI::Xaml::Documents::ITextHighlighterBase>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::ITextHighlighterBaseFactory> : produce_base<D, Windows::UI::Xaml::Documents::ITextHighlighterBaseFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::ITextHighlighterFactory> : produce_base<D, Windows::UI::Xaml::Documents::ITextHighlighterFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Documents::TextHighlighter), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Documents::TextHighlighter>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::ITextHighlighterStatics> : produce_base<D, Windows::UI::Xaml::Documents::ITextHighlighterStatics>
{
    int32_t WINRT_CALL get_ForegroundProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ForegroundProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ForegroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BackgroundProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackgroundProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().BackgroundProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::ITextPointer> : produce_base<D, Windows::UI::Xaml::Documents::ITextPointer>
{
    int32_t WINRT_CALL get_Parent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parent, WINRT_WRAP(Windows::UI::Xaml::DependencyObject));
            *value = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().Parent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VisualParent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VisualParent, WINRT_WRAP(Windows::UI::Xaml::FrameworkElement));
            *value = detach_from<Windows::UI::Xaml::FrameworkElement>(this->shim().VisualParent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LogicalDirection(Windows::UI::Xaml::Documents::LogicalDirection* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LogicalDirection, WINRT_WRAP(Windows::UI::Xaml::Documents::LogicalDirection));
            *value = detach_from<Windows::UI::Xaml::Documents::LogicalDirection>(this->shim().LogicalDirection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Offset(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Offset, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Offset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCharacterRect(Windows::UI::Xaml::Documents::LogicalDirection direction, Windows::Foundation::Rect* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCharacterRect, WINRT_WRAP(Windows::Foundation::Rect), Windows::UI::Xaml::Documents::LogicalDirection const&);
            *result = detach_from<Windows::Foundation::Rect>(this->shim().GetCharacterRect(*reinterpret_cast<Windows::UI::Xaml::Documents::LogicalDirection const*>(&direction)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPositionAtOffset(int32_t offset, Windows::UI::Xaml::Documents::LogicalDirection direction, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPositionAtOffset, WINRT_WRAP(Windows::UI::Xaml::Documents::TextPointer), int32_t, Windows::UI::Xaml::Documents::LogicalDirection const&);
            *result = detach_from<Windows::UI::Xaml::Documents::TextPointer>(this->shim().GetPositionAtOffset(offset, *reinterpret_cast<Windows::UI::Xaml::Documents::LogicalDirection const*>(&direction)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::ITypography> : produce_base<D, Windows::UI::Xaml::Documents::ITypography>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::ITypographyStatics> : produce_base<D, Windows::UI::Xaml::Documents::ITypographyStatics>
{
    int32_t WINRT_CALL get_AnnotationAlternatesProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AnnotationAlternatesProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().AnnotationAlternatesProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAnnotationAlternates(void* element, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAnnotationAlternates, WINRT_WRAP(int32_t), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<int32_t>(this->shim().GetAnnotationAlternates(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetAnnotationAlternates(void* element, int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetAnnotationAlternates, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, int32_t);
            this->shim().SetAnnotationAlternates(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EastAsianExpertFormsProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EastAsianExpertFormsProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().EastAsianExpertFormsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetEastAsianExpertForms(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetEastAsianExpertForms, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetEastAsianExpertForms(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetEastAsianExpertForms(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetEastAsianExpertForms, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetEastAsianExpertForms(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EastAsianLanguageProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EastAsianLanguageProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().EastAsianLanguageProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetEastAsianLanguage(void* element, Windows::UI::Xaml::FontEastAsianLanguage* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetEastAsianLanguage, WINRT_WRAP(Windows::UI::Xaml::FontEastAsianLanguage), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<Windows::UI::Xaml::FontEastAsianLanguage>(this->shim().GetEastAsianLanguage(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetEastAsianLanguage(void* element, Windows::UI::Xaml::FontEastAsianLanguage value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetEastAsianLanguage, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, Windows::UI::Xaml::FontEastAsianLanguage const&);
            this->shim().SetEastAsianLanguage(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<Windows::UI::Xaml::FontEastAsianLanguage const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EastAsianWidthsProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EastAsianWidthsProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().EastAsianWidthsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetEastAsianWidths(void* element, Windows::UI::Xaml::FontEastAsianWidths* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetEastAsianWidths, WINRT_WRAP(Windows::UI::Xaml::FontEastAsianWidths), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<Windows::UI::Xaml::FontEastAsianWidths>(this->shim().GetEastAsianWidths(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetEastAsianWidths(void* element, Windows::UI::Xaml::FontEastAsianWidths value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetEastAsianWidths, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, Windows::UI::Xaml::FontEastAsianWidths const&);
            this->shim().SetEastAsianWidths(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<Windows::UI::Xaml::FontEastAsianWidths const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StandardLigaturesProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StandardLigaturesProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StandardLigaturesProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStandardLigatures(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStandardLigatures, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetStandardLigatures(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetStandardLigatures(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetStandardLigatures, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetStandardLigatures(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContextualLigaturesProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContextualLigaturesProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ContextualLigaturesProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetContextualLigatures(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetContextualLigatures, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetContextualLigatures(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetContextualLigatures(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetContextualLigatures, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetContextualLigatures(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DiscretionaryLigaturesProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DiscretionaryLigaturesProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().DiscretionaryLigaturesProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDiscretionaryLigatures(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDiscretionaryLigatures, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetDiscretionaryLigatures(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetDiscretionaryLigatures(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetDiscretionaryLigatures, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetDiscretionaryLigatures(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HistoricalLigaturesProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HistoricalLigaturesProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().HistoricalLigaturesProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetHistoricalLigatures(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetHistoricalLigatures, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetHistoricalLigatures(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetHistoricalLigatures(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetHistoricalLigatures, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetHistoricalLigatures(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StandardSwashesProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StandardSwashesProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StandardSwashesProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStandardSwashes(void* element, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStandardSwashes, WINRT_WRAP(int32_t), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<int32_t>(this->shim().GetStandardSwashes(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetStandardSwashes(void* element, int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetStandardSwashes, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, int32_t);
            this->shim().SetStandardSwashes(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContextualSwashesProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContextualSwashesProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ContextualSwashesProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetContextualSwashes(void* element, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetContextualSwashes, WINRT_WRAP(int32_t), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<int32_t>(this->shim().GetContextualSwashes(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetContextualSwashes(void* element, int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetContextualSwashes, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, int32_t);
            this->shim().SetContextualSwashes(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContextualAlternatesProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContextualAlternatesProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ContextualAlternatesProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetContextualAlternates(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetContextualAlternates, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetContextualAlternates(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetContextualAlternates(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetContextualAlternates, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetContextualAlternates(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StylisticAlternatesProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StylisticAlternatesProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticAlternatesProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStylisticAlternates(void* element, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStylisticAlternates, WINRT_WRAP(int32_t), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<int32_t>(this->shim().GetStylisticAlternates(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetStylisticAlternates(void* element, int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetStylisticAlternates, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, int32_t);
            this->shim().SetStylisticAlternates(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StylisticSet1Property(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StylisticSet1Property, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet1Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStylisticSet1(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStylisticSet1, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetStylisticSet1(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetStylisticSet1(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetStylisticSet1, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetStylisticSet1(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StylisticSet2Property(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StylisticSet2Property, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet2Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStylisticSet2(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStylisticSet2, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetStylisticSet2(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetStylisticSet2(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetStylisticSet2, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetStylisticSet2(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StylisticSet3Property(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StylisticSet3Property, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet3Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStylisticSet3(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStylisticSet3, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetStylisticSet3(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetStylisticSet3(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetStylisticSet3, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetStylisticSet3(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StylisticSet4Property(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StylisticSet4Property, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet4Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStylisticSet4(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStylisticSet4, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetStylisticSet4(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetStylisticSet4(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetStylisticSet4, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetStylisticSet4(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StylisticSet5Property(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StylisticSet5Property, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet5Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStylisticSet5(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStylisticSet5, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetStylisticSet5(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetStylisticSet5(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetStylisticSet5, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetStylisticSet5(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StylisticSet6Property(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StylisticSet6Property, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet6Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStylisticSet6(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStylisticSet6, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetStylisticSet6(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetStylisticSet6(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetStylisticSet6, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetStylisticSet6(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StylisticSet7Property(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StylisticSet7Property, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet7Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStylisticSet7(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStylisticSet7, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetStylisticSet7(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetStylisticSet7(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetStylisticSet7, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetStylisticSet7(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StylisticSet8Property(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StylisticSet8Property, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet8Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStylisticSet8(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStylisticSet8, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetStylisticSet8(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetStylisticSet8(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetStylisticSet8, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetStylisticSet8(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StylisticSet9Property(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StylisticSet9Property, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet9Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStylisticSet9(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStylisticSet9, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetStylisticSet9(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetStylisticSet9(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetStylisticSet9, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetStylisticSet9(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StylisticSet10Property(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StylisticSet10Property, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet10Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStylisticSet10(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStylisticSet10, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetStylisticSet10(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetStylisticSet10(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetStylisticSet10, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetStylisticSet10(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StylisticSet11Property(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StylisticSet11Property, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet11Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStylisticSet11(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStylisticSet11, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetStylisticSet11(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetStylisticSet11(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetStylisticSet11, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetStylisticSet11(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StylisticSet12Property(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StylisticSet12Property, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet12Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStylisticSet12(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStylisticSet12, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetStylisticSet12(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetStylisticSet12(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetStylisticSet12, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetStylisticSet12(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StylisticSet13Property(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StylisticSet13Property, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet13Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStylisticSet13(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStylisticSet13, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetStylisticSet13(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetStylisticSet13(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetStylisticSet13, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetStylisticSet13(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StylisticSet14Property(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StylisticSet14Property, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet14Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStylisticSet14(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStylisticSet14, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetStylisticSet14(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetStylisticSet14(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetStylisticSet14, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetStylisticSet14(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StylisticSet15Property(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StylisticSet15Property, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet15Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStylisticSet15(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStylisticSet15, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetStylisticSet15(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetStylisticSet15(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetStylisticSet15, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetStylisticSet15(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StylisticSet16Property(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StylisticSet16Property, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet16Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStylisticSet16(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStylisticSet16, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetStylisticSet16(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetStylisticSet16(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetStylisticSet16, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetStylisticSet16(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StylisticSet17Property(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StylisticSet17Property, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet17Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStylisticSet17(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStylisticSet17, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetStylisticSet17(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetStylisticSet17(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetStylisticSet17, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetStylisticSet17(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StylisticSet18Property(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StylisticSet18Property, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet18Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStylisticSet18(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStylisticSet18, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetStylisticSet18(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetStylisticSet18(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetStylisticSet18, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetStylisticSet18(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StylisticSet19Property(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StylisticSet19Property, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet19Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStylisticSet19(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStylisticSet19, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetStylisticSet19(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetStylisticSet19(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetStylisticSet19, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetStylisticSet19(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StylisticSet20Property(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StylisticSet20Property, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StylisticSet20Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStylisticSet20(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStylisticSet20, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetStylisticSet20(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetStylisticSet20(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetStylisticSet20, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetStylisticSet20(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CapitalsProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CapitalsProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CapitalsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCapitals(void* element, Windows::UI::Xaml::FontCapitals* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCapitals, WINRT_WRAP(Windows::UI::Xaml::FontCapitals), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<Windows::UI::Xaml::FontCapitals>(this->shim().GetCapitals(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetCapitals(void* element, Windows::UI::Xaml::FontCapitals value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetCapitals, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, Windows::UI::Xaml::FontCapitals const&);
            this->shim().SetCapitals(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<Windows::UI::Xaml::FontCapitals const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CapitalSpacingProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CapitalSpacingProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CapitalSpacingProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCapitalSpacing(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCapitalSpacing, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetCapitalSpacing(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetCapitalSpacing(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetCapitalSpacing, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetCapitalSpacing(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KerningProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KerningProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().KerningProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetKerning(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetKerning, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetKerning(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetKerning(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetKerning, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetKerning(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CaseSensitiveFormsProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CaseSensitiveFormsProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CaseSensitiveFormsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCaseSensitiveForms(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCaseSensitiveForms, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetCaseSensitiveForms(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetCaseSensitiveForms(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetCaseSensitiveForms, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetCaseSensitiveForms(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HistoricalFormsProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HistoricalFormsProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().HistoricalFormsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetHistoricalForms(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetHistoricalForms, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetHistoricalForms(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetHistoricalForms(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetHistoricalForms, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetHistoricalForms(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FractionProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FractionProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FractionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFraction(void* element, Windows::UI::Xaml::FontFraction* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFraction, WINRT_WRAP(Windows::UI::Xaml::FontFraction), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<Windows::UI::Xaml::FontFraction>(this->shim().GetFraction(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetFraction(void* element, Windows::UI::Xaml::FontFraction value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetFraction, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, Windows::UI::Xaml::FontFraction const&);
            this->shim().SetFraction(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<Windows::UI::Xaml::FontFraction const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NumeralStyleProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NumeralStyleProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().NumeralStyleProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNumeralStyle(void* element, Windows::UI::Xaml::FontNumeralStyle* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNumeralStyle, WINRT_WRAP(Windows::UI::Xaml::FontNumeralStyle), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<Windows::UI::Xaml::FontNumeralStyle>(this->shim().GetNumeralStyle(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetNumeralStyle(void* element, Windows::UI::Xaml::FontNumeralStyle value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetNumeralStyle, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, Windows::UI::Xaml::FontNumeralStyle const&);
            this->shim().SetNumeralStyle(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<Windows::UI::Xaml::FontNumeralStyle const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NumeralAlignmentProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NumeralAlignmentProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().NumeralAlignmentProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNumeralAlignment(void* element, Windows::UI::Xaml::FontNumeralAlignment* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNumeralAlignment, WINRT_WRAP(Windows::UI::Xaml::FontNumeralAlignment), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<Windows::UI::Xaml::FontNumeralAlignment>(this->shim().GetNumeralAlignment(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetNumeralAlignment(void* element, Windows::UI::Xaml::FontNumeralAlignment value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetNumeralAlignment, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, Windows::UI::Xaml::FontNumeralAlignment const&);
            this->shim().SetNumeralAlignment(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<Windows::UI::Xaml::FontNumeralAlignment const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SlashedZeroProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SlashedZeroProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().SlashedZeroProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSlashedZero(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSlashedZero, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetSlashedZero(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetSlashedZero(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetSlashedZero, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetSlashedZero(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MathematicalGreekProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MathematicalGreekProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().MathematicalGreekProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetMathematicalGreek(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetMathematicalGreek, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetMathematicalGreek(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetMathematicalGreek(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetMathematicalGreek, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetMathematicalGreek(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VariantsProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VariantsProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().VariantsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetVariants(void* element, Windows::UI::Xaml::FontVariants* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetVariants, WINRT_WRAP(Windows::UI::Xaml::FontVariants), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<Windows::UI::Xaml::FontVariants>(this->shim().GetVariants(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetVariants(void* element, Windows::UI::Xaml::FontVariants value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetVariants, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, Windows::UI::Xaml::FontVariants const&);
            this->shim().SetVariants(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<Windows::UI::Xaml::FontVariants const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Documents::IUnderline> : produce_base<D, Windows::UI::Xaml::Documents::IUnderline>
{};

template <typename T, typename D>
struct WINRT_EBO produce_dispatch_to_overridable<T, D, Windows::UI::Xaml::Documents::ITextElementOverrides>
    : produce_dispatch_to_overridable_base<T, D, Windows::UI::Xaml::Documents::ITextElementOverrides>
{
    void OnDisconnectVisualChildren()
    {
        Windows::UI::Xaml::Documents::ITextElementOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.OnDisconnectVisualChildren();
        }
        return this->shim().OnDisconnectVisualChildren();
    }
};
}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Documents {

inline Windows::UI::Xaml::DependencyProperty Block::TextAlignmentProperty()
{
    return impl::call_factory<Block, Windows::UI::Xaml::Documents::IBlockStatics>([&](auto&& f) { return f.TextAlignmentProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Block::LineHeightProperty()
{
    return impl::call_factory<Block, Windows::UI::Xaml::Documents::IBlockStatics>([&](auto&& f) { return f.LineHeightProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Block::LineStackingStrategyProperty()
{
    return impl::call_factory<Block, Windows::UI::Xaml::Documents::IBlockStatics>([&](auto&& f) { return f.LineStackingStrategyProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Block::MarginProperty()
{
    return impl::call_factory<Block, Windows::UI::Xaml::Documents::IBlockStatics>([&](auto&& f) { return f.MarginProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Block::HorizontalTextAlignmentProperty()
{
    return impl::call_factory<Block, Windows::UI::Xaml::Documents::IBlockStatics2>([&](auto&& f) { return f.HorizontalTextAlignmentProperty(); });
}

inline Bold::Bold() :
    Bold(impl::call_factory<Bold>([](auto&& f) { return f.template ActivateInstance<Bold>(); }))
{}

inline ContactContentLinkProvider::ContactContentLinkProvider() :
    ContactContentLinkProvider(impl::call_factory<ContactContentLinkProvider>([](auto&& f) { return f.template ActivateInstance<ContactContentLinkProvider>(); }))
{}

inline ContentLink::ContentLink() :
    ContentLink(impl::call_factory<ContentLink>([](auto&& f) { return f.template ActivateInstance<ContentLink>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty ContentLink::BackgroundProperty()
{
    return impl::call_factory<ContentLink, Windows::UI::Xaml::Documents::IContentLinkStatics>([&](auto&& f) { return f.BackgroundProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ContentLink::CursorProperty()
{
    return impl::call_factory<ContentLink, Windows::UI::Xaml::Documents::IContentLinkStatics>([&](auto&& f) { return f.CursorProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ContentLink::XYFocusLeftProperty()
{
    return impl::call_factory<ContentLink, Windows::UI::Xaml::Documents::IContentLinkStatics>([&](auto&& f) { return f.XYFocusLeftProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ContentLink::XYFocusRightProperty()
{
    return impl::call_factory<ContentLink, Windows::UI::Xaml::Documents::IContentLinkStatics>([&](auto&& f) { return f.XYFocusRightProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ContentLink::XYFocusUpProperty()
{
    return impl::call_factory<ContentLink, Windows::UI::Xaml::Documents::IContentLinkStatics>([&](auto&& f) { return f.XYFocusUpProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ContentLink::XYFocusDownProperty()
{
    return impl::call_factory<ContentLink, Windows::UI::Xaml::Documents::IContentLinkStatics>([&](auto&& f) { return f.XYFocusDownProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ContentLink::ElementSoundModeProperty()
{
    return impl::call_factory<ContentLink, Windows::UI::Xaml::Documents::IContentLinkStatics>([&](auto&& f) { return f.ElementSoundModeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ContentLink::FocusStateProperty()
{
    return impl::call_factory<ContentLink, Windows::UI::Xaml::Documents::IContentLinkStatics>([&](auto&& f) { return f.FocusStateProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ContentLink::XYFocusUpNavigationStrategyProperty()
{
    return impl::call_factory<ContentLink, Windows::UI::Xaml::Documents::IContentLinkStatics>([&](auto&& f) { return f.XYFocusUpNavigationStrategyProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ContentLink::XYFocusDownNavigationStrategyProperty()
{
    return impl::call_factory<ContentLink, Windows::UI::Xaml::Documents::IContentLinkStatics>([&](auto&& f) { return f.XYFocusDownNavigationStrategyProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ContentLink::XYFocusLeftNavigationStrategyProperty()
{
    return impl::call_factory<ContentLink, Windows::UI::Xaml::Documents::IContentLinkStatics>([&](auto&& f) { return f.XYFocusLeftNavigationStrategyProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ContentLink::XYFocusRightNavigationStrategyProperty()
{
    return impl::call_factory<ContentLink, Windows::UI::Xaml::Documents::IContentLinkStatics>([&](auto&& f) { return f.XYFocusRightNavigationStrategyProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ContentLink::IsTabStopProperty()
{
    return impl::call_factory<ContentLink, Windows::UI::Xaml::Documents::IContentLinkStatics>([&](auto&& f) { return f.IsTabStopProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ContentLink::TabIndexProperty()
{
    return impl::call_factory<ContentLink, Windows::UI::Xaml::Documents::IContentLinkStatics>([&](auto&& f) { return f.TabIndexProperty(); });
}

inline ContentLinkProviderCollection::ContentLinkProviderCollection() :
    ContentLinkProviderCollection(impl::call_factory<ContentLinkProviderCollection>([](auto&& f) { return f.template ActivateInstance<ContentLinkProviderCollection>(); }))
{}

inline Glyphs::Glyphs() :
    Glyphs(impl::call_factory<Glyphs>([](auto&& f) { return f.template ActivateInstance<Glyphs>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty Glyphs::UnicodeStringProperty()
{
    return impl::call_factory<Glyphs, Windows::UI::Xaml::Documents::IGlyphsStatics>([&](auto&& f) { return f.UnicodeStringProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Glyphs::IndicesProperty()
{
    return impl::call_factory<Glyphs, Windows::UI::Xaml::Documents::IGlyphsStatics>([&](auto&& f) { return f.IndicesProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Glyphs::FontUriProperty()
{
    return impl::call_factory<Glyphs, Windows::UI::Xaml::Documents::IGlyphsStatics>([&](auto&& f) { return f.FontUriProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Glyphs::StyleSimulationsProperty()
{
    return impl::call_factory<Glyphs, Windows::UI::Xaml::Documents::IGlyphsStatics>([&](auto&& f) { return f.StyleSimulationsProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Glyphs::FontRenderingEmSizeProperty()
{
    return impl::call_factory<Glyphs, Windows::UI::Xaml::Documents::IGlyphsStatics>([&](auto&& f) { return f.FontRenderingEmSizeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Glyphs::OriginXProperty()
{
    return impl::call_factory<Glyphs, Windows::UI::Xaml::Documents::IGlyphsStatics>([&](auto&& f) { return f.OriginXProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Glyphs::OriginYProperty()
{
    return impl::call_factory<Glyphs, Windows::UI::Xaml::Documents::IGlyphsStatics>([&](auto&& f) { return f.OriginYProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Glyphs::FillProperty()
{
    return impl::call_factory<Glyphs, Windows::UI::Xaml::Documents::IGlyphsStatics>([&](auto&& f) { return f.FillProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Glyphs::IsColorFontEnabledProperty()
{
    return impl::call_factory<Glyphs, Windows::UI::Xaml::Documents::IGlyphsStatics2>([&](auto&& f) { return f.IsColorFontEnabledProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Glyphs::ColorFontPaletteIndexProperty()
{
    return impl::call_factory<Glyphs, Windows::UI::Xaml::Documents::IGlyphsStatics2>([&](auto&& f) { return f.ColorFontPaletteIndexProperty(); });
}

inline Hyperlink::Hyperlink() :
    Hyperlink(impl::call_factory<Hyperlink>([](auto&& f) { return f.template ActivateInstance<Hyperlink>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty Hyperlink::NavigateUriProperty()
{
    return impl::call_factory<Hyperlink, Windows::UI::Xaml::Documents::IHyperlinkStatics>([&](auto&& f) { return f.NavigateUriProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Hyperlink::UnderlineStyleProperty()
{
    return impl::call_factory<Hyperlink, Windows::UI::Xaml::Documents::IHyperlinkStatics2>([&](auto&& f) { return f.UnderlineStyleProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Hyperlink::XYFocusLeftProperty()
{
    return impl::call_factory<Hyperlink, Windows::UI::Xaml::Documents::IHyperlinkStatics3>([&](auto&& f) { return f.XYFocusLeftProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Hyperlink::XYFocusRightProperty()
{
    return impl::call_factory<Hyperlink, Windows::UI::Xaml::Documents::IHyperlinkStatics3>([&](auto&& f) { return f.XYFocusRightProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Hyperlink::XYFocusUpProperty()
{
    return impl::call_factory<Hyperlink, Windows::UI::Xaml::Documents::IHyperlinkStatics3>([&](auto&& f) { return f.XYFocusUpProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Hyperlink::XYFocusDownProperty()
{
    return impl::call_factory<Hyperlink, Windows::UI::Xaml::Documents::IHyperlinkStatics3>([&](auto&& f) { return f.XYFocusDownProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Hyperlink::ElementSoundModeProperty()
{
    return impl::call_factory<Hyperlink, Windows::UI::Xaml::Documents::IHyperlinkStatics3>([&](auto&& f) { return f.ElementSoundModeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Hyperlink::FocusStateProperty()
{
    return impl::call_factory<Hyperlink, Windows::UI::Xaml::Documents::IHyperlinkStatics4>([&](auto&& f) { return f.FocusStateProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Hyperlink::XYFocusUpNavigationStrategyProperty()
{
    return impl::call_factory<Hyperlink, Windows::UI::Xaml::Documents::IHyperlinkStatics4>([&](auto&& f) { return f.XYFocusUpNavigationStrategyProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Hyperlink::XYFocusDownNavigationStrategyProperty()
{
    return impl::call_factory<Hyperlink, Windows::UI::Xaml::Documents::IHyperlinkStatics4>([&](auto&& f) { return f.XYFocusDownNavigationStrategyProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Hyperlink::XYFocusLeftNavigationStrategyProperty()
{
    return impl::call_factory<Hyperlink, Windows::UI::Xaml::Documents::IHyperlinkStatics4>([&](auto&& f) { return f.XYFocusLeftNavigationStrategyProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Hyperlink::XYFocusRightNavigationStrategyProperty()
{
    return impl::call_factory<Hyperlink, Windows::UI::Xaml::Documents::IHyperlinkStatics4>([&](auto&& f) { return f.XYFocusRightNavigationStrategyProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Hyperlink::IsTabStopProperty()
{
    return impl::call_factory<Hyperlink, Windows::UI::Xaml::Documents::IHyperlinkStatics5>([&](auto&& f) { return f.IsTabStopProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Hyperlink::TabIndexProperty()
{
    return impl::call_factory<Hyperlink, Windows::UI::Xaml::Documents::IHyperlinkStatics5>([&](auto&& f) { return f.TabIndexProperty(); });
}

inline InlineUIContainer::InlineUIContainer() :
    InlineUIContainer(impl::call_factory<InlineUIContainer>([](auto&& f) { return f.template ActivateInstance<InlineUIContainer>(); }))
{}

inline Italic::Italic() :
    Italic(impl::call_factory<Italic>([](auto&& f) { return f.template ActivateInstance<Italic>(); }))
{}

inline LineBreak::LineBreak() :
    LineBreak(impl::call_factory<LineBreak>([](auto&& f) { return f.template ActivateInstance<LineBreak>(); }))
{}

inline Paragraph::Paragraph() :
    Paragraph(impl::call_factory<Paragraph>([](auto&& f) { return f.template ActivateInstance<Paragraph>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty Paragraph::TextIndentProperty()
{
    return impl::call_factory<Paragraph, Windows::UI::Xaml::Documents::IParagraphStatics>([&](auto&& f) { return f.TextIndentProperty(); });
}

inline PlaceContentLinkProvider::PlaceContentLinkProvider() :
    PlaceContentLinkProvider(impl::call_factory<PlaceContentLinkProvider>([](auto&& f) { return f.template ActivateInstance<PlaceContentLinkProvider>(); }))
{}

inline Run::Run() :
    Run(impl::call_factory<Run>([](auto&& f) { return f.template ActivateInstance<Run>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty Run::FlowDirectionProperty()
{
    return impl::call_factory<Run, Windows::UI::Xaml::Documents::IRunStatics>([&](auto&& f) { return f.FlowDirectionProperty(); });
}

inline Span::Span()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<Span, Windows::UI::Xaml::Documents::ISpanFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline Windows::UI::Xaml::DependencyProperty TextElement::FontSizeProperty()
{
    return impl::call_factory<TextElement, Windows::UI::Xaml::Documents::ITextElementStatics>([&](auto&& f) { return f.FontSizeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty TextElement::FontFamilyProperty()
{
    return impl::call_factory<TextElement, Windows::UI::Xaml::Documents::ITextElementStatics>([&](auto&& f) { return f.FontFamilyProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty TextElement::FontWeightProperty()
{
    return impl::call_factory<TextElement, Windows::UI::Xaml::Documents::ITextElementStatics>([&](auto&& f) { return f.FontWeightProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty TextElement::FontStyleProperty()
{
    return impl::call_factory<TextElement, Windows::UI::Xaml::Documents::ITextElementStatics>([&](auto&& f) { return f.FontStyleProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty TextElement::FontStretchProperty()
{
    return impl::call_factory<TextElement, Windows::UI::Xaml::Documents::ITextElementStatics>([&](auto&& f) { return f.FontStretchProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty TextElement::CharacterSpacingProperty()
{
    return impl::call_factory<TextElement, Windows::UI::Xaml::Documents::ITextElementStatics>([&](auto&& f) { return f.CharacterSpacingProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty TextElement::ForegroundProperty()
{
    return impl::call_factory<TextElement, Windows::UI::Xaml::Documents::ITextElementStatics>([&](auto&& f) { return f.ForegroundProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty TextElement::LanguageProperty()
{
    return impl::call_factory<TextElement, Windows::UI::Xaml::Documents::ITextElementStatics>([&](auto&& f) { return f.LanguageProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty TextElement::IsTextScaleFactorEnabledProperty()
{
    return impl::call_factory<TextElement, Windows::UI::Xaml::Documents::ITextElementStatics2>([&](auto&& f) { return f.IsTextScaleFactorEnabledProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty TextElement::AllowFocusOnInteractionProperty()
{
    return impl::call_factory<TextElement, Windows::UI::Xaml::Documents::ITextElementStatics3>([&](auto&& f) { return f.AllowFocusOnInteractionProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty TextElement::AccessKeyProperty()
{
    return impl::call_factory<TextElement, Windows::UI::Xaml::Documents::ITextElementStatics3>([&](auto&& f) { return f.AccessKeyProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty TextElement::ExitDisplayModeOnAccessKeyInvokedProperty()
{
    return impl::call_factory<TextElement, Windows::UI::Xaml::Documents::ITextElementStatics3>([&](auto&& f) { return f.ExitDisplayModeOnAccessKeyInvokedProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty TextElement::TextDecorationsProperty()
{
    return impl::call_factory<TextElement, Windows::UI::Xaml::Documents::ITextElementStatics4>([&](auto&& f) { return f.TextDecorationsProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty TextElement::IsAccessKeyScopeProperty()
{
    return impl::call_factory<TextElement, Windows::UI::Xaml::Documents::ITextElementStatics4>([&](auto&& f) { return f.IsAccessKeyScopeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty TextElement::AccessKeyScopeOwnerProperty()
{
    return impl::call_factory<TextElement, Windows::UI::Xaml::Documents::ITextElementStatics4>([&](auto&& f) { return f.AccessKeyScopeOwnerProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty TextElement::KeyTipPlacementModeProperty()
{
    return impl::call_factory<TextElement, Windows::UI::Xaml::Documents::ITextElementStatics4>([&](auto&& f) { return f.KeyTipPlacementModeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty TextElement::KeyTipHorizontalOffsetProperty()
{
    return impl::call_factory<TextElement, Windows::UI::Xaml::Documents::ITextElementStatics4>([&](auto&& f) { return f.KeyTipHorizontalOffsetProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty TextElement::KeyTipVerticalOffsetProperty()
{
    return impl::call_factory<TextElement, Windows::UI::Xaml::Documents::ITextElementStatics4>([&](auto&& f) { return f.KeyTipVerticalOffsetProperty(); });
}

inline TextHighlighter::TextHighlighter()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<TextHighlighter, Windows::UI::Xaml::Documents::ITextHighlighterFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline Windows::UI::Xaml::DependencyProperty TextHighlighter::ForegroundProperty()
{
    return impl::call_factory<TextHighlighter, Windows::UI::Xaml::Documents::ITextHighlighterStatics>([&](auto&& f) { return f.ForegroundProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty TextHighlighter::BackgroundProperty()
{
    return impl::call_factory<TextHighlighter, Windows::UI::Xaml::Documents::ITextHighlighterStatics>([&](auto&& f) { return f.BackgroundProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::AnnotationAlternatesProperty()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.AnnotationAlternatesProperty(); });
}

inline int32_t Typography::GetAnnotationAlternates(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetAnnotationAlternates(element); });
}

inline void Typography::SetAnnotationAlternates(Windows::UI::Xaml::DependencyObject const& element, int32_t value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetAnnotationAlternates(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::EastAsianExpertFormsProperty()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.EastAsianExpertFormsProperty(); });
}

inline bool Typography::GetEastAsianExpertForms(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetEastAsianExpertForms(element); });
}

inline void Typography::SetEastAsianExpertForms(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetEastAsianExpertForms(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::EastAsianLanguageProperty()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.EastAsianLanguageProperty(); });
}

inline Windows::UI::Xaml::FontEastAsianLanguage Typography::GetEastAsianLanguage(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetEastAsianLanguage(element); });
}

inline void Typography::SetEastAsianLanguage(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::FontEastAsianLanguage const& value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetEastAsianLanguage(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::EastAsianWidthsProperty()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.EastAsianWidthsProperty(); });
}

inline Windows::UI::Xaml::FontEastAsianWidths Typography::GetEastAsianWidths(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetEastAsianWidths(element); });
}

inline void Typography::SetEastAsianWidths(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::FontEastAsianWidths const& value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetEastAsianWidths(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::StandardLigaturesProperty()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.StandardLigaturesProperty(); });
}

inline bool Typography::GetStandardLigatures(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetStandardLigatures(element); });
}

inline void Typography::SetStandardLigatures(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetStandardLigatures(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::ContextualLigaturesProperty()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.ContextualLigaturesProperty(); });
}

inline bool Typography::GetContextualLigatures(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetContextualLigatures(element); });
}

inline void Typography::SetContextualLigatures(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetContextualLigatures(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::DiscretionaryLigaturesProperty()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.DiscretionaryLigaturesProperty(); });
}

inline bool Typography::GetDiscretionaryLigatures(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetDiscretionaryLigatures(element); });
}

inline void Typography::SetDiscretionaryLigatures(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetDiscretionaryLigatures(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::HistoricalLigaturesProperty()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.HistoricalLigaturesProperty(); });
}

inline bool Typography::GetHistoricalLigatures(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetHistoricalLigatures(element); });
}

inline void Typography::SetHistoricalLigatures(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetHistoricalLigatures(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::StandardSwashesProperty()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.StandardSwashesProperty(); });
}

inline int32_t Typography::GetStandardSwashes(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetStandardSwashes(element); });
}

inline void Typography::SetStandardSwashes(Windows::UI::Xaml::DependencyObject const& element, int32_t value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetStandardSwashes(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::ContextualSwashesProperty()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.ContextualSwashesProperty(); });
}

inline int32_t Typography::GetContextualSwashes(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetContextualSwashes(element); });
}

inline void Typography::SetContextualSwashes(Windows::UI::Xaml::DependencyObject const& element, int32_t value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetContextualSwashes(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::ContextualAlternatesProperty()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.ContextualAlternatesProperty(); });
}

inline bool Typography::GetContextualAlternates(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetContextualAlternates(element); });
}

inline void Typography::SetContextualAlternates(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetContextualAlternates(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::StylisticAlternatesProperty()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.StylisticAlternatesProperty(); });
}

inline int32_t Typography::GetStylisticAlternates(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetStylisticAlternates(element); });
}

inline void Typography::SetStylisticAlternates(Windows::UI::Xaml::DependencyObject const& element, int32_t value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetStylisticAlternates(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::StylisticSet1Property()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.StylisticSet1Property(); });
}

inline bool Typography::GetStylisticSet1(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetStylisticSet1(element); });
}

inline void Typography::SetStylisticSet1(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetStylisticSet1(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::StylisticSet2Property()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.StylisticSet2Property(); });
}

inline bool Typography::GetStylisticSet2(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetStylisticSet2(element); });
}

inline void Typography::SetStylisticSet2(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetStylisticSet2(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::StylisticSet3Property()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.StylisticSet3Property(); });
}

inline bool Typography::GetStylisticSet3(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetStylisticSet3(element); });
}

inline void Typography::SetStylisticSet3(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetStylisticSet3(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::StylisticSet4Property()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.StylisticSet4Property(); });
}

inline bool Typography::GetStylisticSet4(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetStylisticSet4(element); });
}

inline void Typography::SetStylisticSet4(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetStylisticSet4(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::StylisticSet5Property()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.StylisticSet5Property(); });
}

inline bool Typography::GetStylisticSet5(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetStylisticSet5(element); });
}

inline void Typography::SetStylisticSet5(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetStylisticSet5(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::StylisticSet6Property()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.StylisticSet6Property(); });
}

inline bool Typography::GetStylisticSet6(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetStylisticSet6(element); });
}

inline void Typography::SetStylisticSet6(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetStylisticSet6(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::StylisticSet7Property()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.StylisticSet7Property(); });
}

inline bool Typography::GetStylisticSet7(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetStylisticSet7(element); });
}

inline void Typography::SetStylisticSet7(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetStylisticSet7(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::StylisticSet8Property()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.StylisticSet8Property(); });
}

inline bool Typography::GetStylisticSet8(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetStylisticSet8(element); });
}

inline void Typography::SetStylisticSet8(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetStylisticSet8(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::StylisticSet9Property()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.StylisticSet9Property(); });
}

inline bool Typography::GetStylisticSet9(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetStylisticSet9(element); });
}

inline void Typography::SetStylisticSet9(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetStylisticSet9(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::StylisticSet10Property()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.StylisticSet10Property(); });
}

inline bool Typography::GetStylisticSet10(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetStylisticSet10(element); });
}

inline void Typography::SetStylisticSet10(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetStylisticSet10(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::StylisticSet11Property()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.StylisticSet11Property(); });
}

inline bool Typography::GetStylisticSet11(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetStylisticSet11(element); });
}

inline void Typography::SetStylisticSet11(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetStylisticSet11(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::StylisticSet12Property()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.StylisticSet12Property(); });
}

inline bool Typography::GetStylisticSet12(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetStylisticSet12(element); });
}

inline void Typography::SetStylisticSet12(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetStylisticSet12(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::StylisticSet13Property()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.StylisticSet13Property(); });
}

inline bool Typography::GetStylisticSet13(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetStylisticSet13(element); });
}

inline void Typography::SetStylisticSet13(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetStylisticSet13(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::StylisticSet14Property()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.StylisticSet14Property(); });
}

inline bool Typography::GetStylisticSet14(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetStylisticSet14(element); });
}

inline void Typography::SetStylisticSet14(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetStylisticSet14(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::StylisticSet15Property()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.StylisticSet15Property(); });
}

inline bool Typography::GetStylisticSet15(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetStylisticSet15(element); });
}

inline void Typography::SetStylisticSet15(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetStylisticSet15(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::StylisticSet16Property()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.StylisticSet16Property(); });
}

inline bool Typography::GetStylisticSet16(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetStylisticSet16(element); });
}

inline void Typography::SetStylisticSet16(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetStylisticSet16(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::StylisticSet17Property()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.StylisticSet17Property(); });
}

inline bool Typography::GetStylisticSet17(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetStylisticSet17(element); });
}

inline void Typography::SetStylisticSet17(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetStylisticSet17(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::StylisticSet18Property()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.StylisticSet18Property(); });
}

inline bool Typography::GetStylisticSet18(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetStylisticSet18(element); });
}

inline void Typography::SetStylisticSet18(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetStylisticSet18(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::StylisticSet19Property()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.StylisticSet19Property(); });
}

inline bool Typography::GetStylisticSet19(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetStylisticSet19(element); });
}

inline void Typography::SetStylisticSet19(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetStylisticSet19(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::StylisticSet20Property()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.StylisticSet20Property(); });
}

inline bool Typography::GetStylisticSet20(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetStylisticSet20(element); });
}

inline void Typography::SetStylisticSet20(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetStylisticSet20(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::CapitalsProperty()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.CapitalsProperty(); });
}

inline Windows::UI::Xaml::FontCapitals Typography::GetCapitals(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetCapitals(element); });
}

inline void Typography::SetCapitals(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::FontCapitals const& value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetCapitals(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::CapitalSpacingProperty()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.CapitalSpacingProperty(); });
}

inline bool Typography::GetCapitalSpacing(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetCapitalSpacing(element); });
}

inline void Typography::SetCapitalSpacing(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetCapitalSpacing(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::KerningProperty()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.KerningProperty(); });
}

inline bool Typography::GetKerning(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetKerning(element); });
}

inline void Typography::SetKerning(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetKerning(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::CaseSensitiveFormsProperty()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.CaseSensitiveFormsProperty(); });
}

inline bool Typography::GetCaseSensitiveForms(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetCaseSensitiveForms(element); });
}

inline void Typography::SetCaseSensitiveForms(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetCaseSensitiveForms(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::HistoricalFormsProperty()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.HistoricalFormsProperty(); });
}

inline bool Typography::GetHistoricalForms(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetHistoricalForms(element); });
}

inline void Typography::SetHistoricalForms(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetHistoricalForms(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::FractionProperty()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.FractionProperty(); });
}

inline Windows::UI::Xaml::FontFraction Typography::GetFraction(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetFraction(element); });
}

inline void Typography::SetFraction(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::FontFraction const& value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetFraction(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::NumeralStyleProperty()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.NumeralStyleProperty(); });
}

inline Windows::UI::Xaml::FontNumeralStyle Typography::GetNumeralStyle(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetNumeralStyle(element); });
}

inline void Typography::SetNumeralStyle(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::FontNumeralStyle const& value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetNumeralStyle(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::NumeralAlignmentProperty()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.NumeralAlignmentProperty(); });
}

inline Windows::UI::Xaml::FontNumeralAlignment Typography::GetNumeralAlignment(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetNumeralAlignment(element); });
}

inline void Typography::SetNumeralAlignment(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::FontNumeralAlignment const& value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetNumeralAlignment(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::SlashedZeroProperty()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SlashedZeroProperty(); });
}

inline bool Typography::GetSlashedZero(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetSlashedZero(element); });
}

inline void Typography::SetSlashedZero(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetSlashedZero(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::MathematicalGreekProperty()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.MathematicalGreekProperty(); });
}

inline bool Typography::GetMathematicalGreek(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetMathematicalGreek(element); });
}

inline void Typography::SetMathematicalGreek(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetMathematicalGreek(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty Typography::VariantsProperty()
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.VariantsProperty(); });
}

inline Windows::UI::Xaml::FontVariants Typography::GetVariants(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.GetVariants(element); });
}

inline void Typography::SetVariants(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::FontVariants const& value)
{
    impl::call_factory<Typography, Windows::UI::Xaml::Documents::ITypographyStatics>([&](auto&& f) { return f.SetVariants(element, value); });
}

inline Underline::Underline() :
    Underline(impl::call_factory<Underline>([](auto&& f) { return f.template ActivateInstance<Underline>(); }))
{}

template <typename D> void ITextElementOverridesT<D>::OnDisconnectVisualChildren() const
{
    return shim().template try_as<ITextElementOverrides>().OnDisconnectVisualChildren();
}

template <typename D, typename... Interfaces>
struct BlockT :
    implements<D, Windows::UI::Xaml::Documents::ITextElementOverrides, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Documents::IBlock, Windows::UI::Xaml::Documents::IBlock2, Windows::UI::Xaml::Documents::ITextElement, Windows::UI::Xaml::Documents::ITextElement2, Windows::UI::Xaml::Documents::ITextElement3, Windows::UI::Xaml::Documents::ITextElement4, Windows::UI::Xaml::Documents::ITextElement5, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Documents::Block, Windows::UI::Xaml::Documents::TextElement, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Documents::ITextElementOverridesT<D>
{
    using composable = Block;

protected:
    BlockT()
    {
        impl::call_factory<Windows::UI::Xaml::Documents::Block, Windows::UI::Xaml::Documents::IBlockFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ContentLinkProviderT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Documents::IContentLinkProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Documents::ContentLinkProvider, Windows::UI::Xaml::DependencyObject>
{
    using composable = ContentLinkProvider;

protected:
    ContentLinkProviderT()
    {
        impl::call_factory<Windows::UI::Xaml::Documents::ContentLinkProvider, Windows::UI::Xaml::Documents::IContentLinkProviderFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct InlineT :
    implements<D, Windows::UI::Xaml::Documents::ITextElementOverrides, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Documents::IInline, Windows::UI::Xaml::Documents::ITextElement, Windows::UI::Xaml::Documents::ITextElement2, Windows::UI::Xaml::Documents::ITextElement3, Windows::UI::Xaml::Documents::ITextElement4, Windows::UI::Xaml::Documents::ITextElement5, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Documents::Inline, Windows::UI::Xaml::Documents::TextElement, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Documents::ITextElementOverridesT<D>
{
    using composable = Inline;

protected:
    InlineT()
    {
        impl::call_factory<Windows::UI::Xaml::Documents::Inline, Windows::UI::Xaml::Documents::IInlineFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct SpanT :
    implements<D, Windows::UI::Xaml::Documents::ITextElementOverrides, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Documents::ISpan, Windows::UI::Xaml::Documents::IInline, Windows::UI::Xaml::Documents::ITextElement, Windows::UI::Xaml::Documents::ITextElement2, Windows::UI::Xaml::Documents::ITextElement3, Windows::UI::Xaml::Documents::ITextElement4, Windows::UI::Xaml::Documents::ITextElement5, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Documents::Span, Windows::UI::Xaml::Documents::Inline, Windows::UI::Xaml::Documents::TextElement, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Documents::ITextElementOverridesT<D>
{
    using composable = Span;

protected:
    SpanT()
    {
        impl::call_factory<Windows::UI::Xaml::Documents::Span, Windows::UI::Xaml::Documents::ISpanFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct TextHighlighterT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Documents::ITextHighlighter>,
    impl::base<D, Windows::UI::Xaml::Documents::TextHighlighter>
{
    using composable = TextHighlighter;

protected:
    TextHighlighterT()
    {
        impl::call_factory<Windows::UI::Xaml::Documents::TextHighlighter, Windows::UI::Xaml::Documents::ITextHighlighterFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Xaml::Documents::IBlock> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IBlock> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IBlock2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IBlock2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IBlockFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IBlockFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IBlockStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IBlockStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IBlockStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IBlockStatics2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IBold> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IBold> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IContactContentLinkProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IContactContentLinkProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IContentLink> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IContentLink> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IContentLinkInvokedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IContentLinkInvokedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IContentLinkProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IContentLinkProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IContentLinkProviderCollection> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IContentLinkProviderCollection> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IContentLinkProviderFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IContentLinkProviderFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IContentLinkStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IContentLinkStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IGlyphs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IGlyphs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IGlyphs2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IGlyphs2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IGlyphsStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IGlyphsStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IGlyphsStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IGlyphsStatics2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IHyperlink> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IHyperlink> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IHyperlink2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IHyperlink2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IHyperlink3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IHyperlink3> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IHyperlink4> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IHyperlink4> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IHyperlink5> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IHyperlink5> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IHyperlinkClickEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IHyperlinkClickEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics3> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics4> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics4> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics5> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics5> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IInline> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IInline> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IInlineFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IInlineFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IInlineUIContainer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IInlineUIContainer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IItalic> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IItalic> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::ILineBreak> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::ILineBreak> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IParagraph> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IParagraph> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IParagraphStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IParagraphStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IPlaceContentLinkProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IPlaceContentLinkProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IRun> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IRun> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IRunStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IRunStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::ISpan> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::ISpan> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::ISpanFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::ISpanFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITextElement> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::ITextElement> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITextElement2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::ITextElement2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITextElement3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::ITextElement3> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITextElement4> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::ITextElement4> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITextElement5> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::ITextElement5> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITextElementFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::ITextElementFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITextElementOverrides> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::ITextElementOverrides> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITextElementStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::ITextElementStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITextElementStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::ITextElementStatics2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITextElementStatics3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::ITextElementStatics3> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITextElementStatics4> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::ITextElementStatics4> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITextHighlighter> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::ITextHighlighter> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITextHighlighterBase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::ITextHighlighterBase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITextHighlighterBaseFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::ITextHighlighterBaseFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITextHighlighterFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::ITextHighlighterFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITextHighlighterStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::ITextHighlighterStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITextPointer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::ITextPointer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITypography> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::ITypography> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::ITypographyStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::ITypographyStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::IUnderline> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::IUnderline> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::Block> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::Block> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::BlockCollection> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::BlockCollection> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::Bold> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::Bold> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::ContactContentLinkProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::ContactContentLinkProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::ContentLink> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::ContentLink> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::ContentLinkInvokedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::ContentLinkInvokedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::ContentLinkProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::ContentLinkProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::ContentLinkProviderCollection> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::ContentLinkProviderCollection> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::Glyphs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::Glyphs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::Hyperlink> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::Hyperlink> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::HyperlinkClickEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::HyperlinkClickEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::Inline> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::Inline> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::InlineCollection> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::InlineCollection> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::InlineUIContainer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::InlineUIContainer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::Italic> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::Italic> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::LineBreak> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::LineBreak> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::Paragraph> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::Paragraph> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::PlaceContentLinkProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::PlaceContentLinkProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::Run> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::Run> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::Span> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::Span> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::TextElement> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::TextElement> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::TextHighlighter> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::TextHighlighter> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::TextHighlighterBase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::TextHighlighterBase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::TextPointer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::TextPointer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::Typography> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::Typography> {};
template<> struct hash<winrt::Windows::UI::Xaml::Documents::Underline> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Documents::Underline> {};

}
