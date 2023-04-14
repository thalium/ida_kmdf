// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::UI::Composition {

struct Compositor;

}

WINRT_EXPORT namespace winrt::Windows::UI::Composition::Core {

struct ICompositorController;
struct CompositorController;

}

namespace winrt::impl {

template <> struct category<Windows::UI::Composition::Core::ICompositorController>{ using type = interface_category; };
template <> struct category<Windows::UI::Composition::Core::CompositorController>{ using type = class_category; };
template <> struct name<Windows::UI::Composition::Core::ICompositorController>{ static constexpr auto & value{ L"Windows.UI.Composition.Core.ICompositorController" }; };
template <> struct name<Windows::UI::Composition::Core::CompositorController>{ static constexpr auto & value{ L"Windows.UI.Composition.Core.CompositorController" }; };
template <> struct guid_storage<Windows::UI::Composition::Core::ICompositorController>{ static constexpr guid value{ 0x2D75F35A,0x70A7,0x4395,{ 0xBA,0x2D,0xCE,0xF0,0xB1,0x83,0x99,0xF9 } }; };
template <> struct default_interface<Windows::UI::Composition::Core::CompositorController>{ using type = Windows::UI::Composition::Core::ICompositorController; };

template <> struct abi<Windows::UI::Composition::Core::ICompositorController>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Compositor(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL Commit() noexcept = 0;
    virtual int32_t WINRT_CALL EnsurePreviousCommitCompletedAsync(void** action) noexcept = 0;
    virtual int32_t WINRT_CALL add_CommitNeeded(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_CommitNeeded(winrt::event_token token) noexcept = 0;
};};

template <typename D>
struct consume_Windows_UI_Composition_Core_ICompositorController
{
    Windows::UI::Composition::Compositor Compositor() const;
    void Commit() const;
    Windows::Foundation::IAsyncAction EnsurePreviousCommitCompletedAsync() const;
    winrt::event_token CommitNeeded(Windows::Foundation::TypedEventHandler<Windows::UI::Composition::Core::CompositorController, Windows::Foundation::IInspectable> const& handler) const;
    using CommitNeeded_revoker = impl::event_revoker<Windows::UI::Composition::Core::ICompositorController, &impl::abi_t<Windows::UI::Composition::Core::ICompositorController>::remove_CommitNeeded>;
    CommitNeeded_revoker CommitNeeded(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Composition::Core::CompositorController, Windows::Foundation::IInspectable> const& handler) const;
    void CommitNeeded(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::UI::Composition::Core::ICompositorController> { template <typename D> using type = consume_Windows_UI_Composition_Core_ICompositorController<D>; };

}
