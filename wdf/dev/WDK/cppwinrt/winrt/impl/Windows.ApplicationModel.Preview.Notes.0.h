// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Graphics::Imaging {

struct SoftwareBitmap;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IBuffer;

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Preview::Notes {

struct INotePlacementChangedPreviewEventArgs;
struct INoteVisibilityChangedPreviewEventArgs;
struct INotesWindowManagerPreview;
struct INotesWindowManagerPreview2;
struct INotesWindowManagerPreviewShowNoteOptions;
struct INotesWindowManagerPreviewStatics;
struct NotePlacementChangedPreviewEventArgs;
struct NoteVisibilityChangedPreviewEventArgs;
struct NotesWindowManagerPreview;
struct NotesWindowManagerPreviewShowNoteOptions;

}

namespace winrt::impl {

template <> struct category<Windows::ApplicationModel::Preview::Notes::INotePlacementChangedPreviewEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Preview::Notes::INoteVisibilityChangedPreviewEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreviewShowNoteOptions>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreviewStatics>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Preview::Notes::NotePlacementChangedPreviewEventArgs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Preview::Notes::NoteVisibilityChangedPreviewEventArgs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreview>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreviewShowNoteOptions>{ using type = class_category; };
template <> struct name<Windows::ApplicationModel::Preview::Notes::INotePlacementChangedPreviewEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.Preview.Notes.INotePlacementChangedPreviewEventArgs" }; };
template <> struct name<Windows::ApplicationModel::Preview::Notes::INoteVisibilityChangedPreviewEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.Preview.Notes.INoteVisibilityChangedPreviewEventArgs" }; };
template <> struct name<Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview>{ static constexpr auto & value{ L"Windows.ApplicationModel.Preview.Notes.INotesWindowManagerPreview" }; };
template <> struct name<Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview2>{ static constexpr auto & value{ L"Windows.ApplicationModel.Preview.Notes.INotesWindowManagerPreview2" }; };
template <> struct name<Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreviewShowNoteOptions>{ static constexpr auto & value{ L"Windows.ApplicationModel.Preview.Notes.INotesWindowManagerPreviewShowNoteOptions" }; };
template <> struct name<Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreviewStatics>{ static constexpr auto & value{ L"Windows.ApplicationModel.Preview.Notes.INotesWindowManagerPreviewStatics" }; };
template <> struct name<Windows::ApplicationModel::Preview::Notes::NotePlacementChangedPreviewEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.Preview.Notes.NotePlacementChangedPreviewEventArgs" }; };
template <> struct name<Windows::ApplicationModel::Preview::Notes::NoteVisibilityChangedPreviewEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.Preview.Notes.NoteVisibilityChangedPreviewEventArgs" }; };
template <> struct name<Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreview>{ static constexpr auto & value{ L"Windows.ApplicationModel.Preview.Notes.NotesWindowManagerPreview" }; };
template <> struct name<Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreviewShowNoteOptions>{ static constexpr auto & value{ L"Windows.ApplicationModel.Preview.Notes.NotesWindowManagerPreviewShowNoteOptions" }; };
template <> struct guid_storage<Windows::ApplicationModel::Preview::Notes::INotePlacementChangedPreviewEventArgs>{ static constexpr guid value{ 0x491D57B7,0xF780,0x4E7F,{ 0xA9,0x39,0x9A,0x4C,0xAF,0x96,0x52,0x14 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Preview::Notes::INoteVisibilityChangedPreviewEventArgs>{ static constexpr guid value{ 0x0E34649E,0x3815,0x4FF6,{ 0x83,0xB3,0xA1,0x4D,0x17,0x12,0x0E,0x24 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview>{ static constexpr guid value{ 0xDC2AC23E,0x4850,0x4F13,{ 0x9C,0xC7,0xFF,0x48,0x7E,0xFD,0xFC,0xDE } }; };
template <> struct guid_storage<Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview2>{ static constexpr guid value{ 0xEDFE864A,0x1F54,0x4B09,{ 0x98,0x23,0xFF,0x47,0x7F,0x6F,0xA3,0xBC } }; };
template <> struct guid_storage<Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreviewShowNoteOptions>{ static constexpr guid value{ 0x886B09D6,0xA6AE,0x4007,{ 0xA5,0x6D,0x1C,0xA7,0x0C,0x84,0xC0,0xD2 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreviewStatics>{ static constexpr guid value{ 0x6668CC88,0x0A8E,0x4127,{ 0xA3,0x8E,0x99,0x54,0x45,0x86,0x8A,0x78 } }; };
template <> struct default_interface<Windows::ApplicationModel::Preview::Notes::NotePlacementChangedPreviewEventArgs>{ using type = Windows::ApplicationModel::Preview::Notes::INotePlacementChangedPreviewEventArgs; };
template <> struct default_interface<Windows::ApplicationModel::Preview::Notes::NoteVisibilityChangedPreviewEventArgs>{ using type = Windows::ApplicationModel::Preview::Notes::INoteVisibilityChangedPreviewEventArgs; };
template <> struct default_interface<Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreview>{ using type = Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview; };
template <> struct default_interface<Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreviewShowNoteOptions>{ using type = Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreviewShowNoteOptions; };

template <> struct abi<Windows::ApplicationModel::Preview::Notes::INotePlacementChangedPreviewEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ViewId(int32_t* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Preview::Notes::INoteVisibilityChangedPreviewEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ViewId(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsVisible(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsScreenLocked(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL ShowNote(int32_t noteViewId) noexcept = 0;
    virtual int32_t WINRT_CALL ShowNoteRelativeTo(int32_t noteViewId, int32_t anchorNoteViewId) noexcept = 0;
    virtual int32_t WINRT_CALL ShowNoteWithPlacement(int32_t noteViewId, void* data) noexcept = 0;
    virtual int32_t WINRT_CALL HideNote(int32_t noteViewId) noexcept = 0;
    virtual int32_t WINRT_CALL GetNotePlacement(int32_t noteViewId, void** data) noexcept = 0;
    virtual int32_t WINRT_CALL TrySetNoteSize(int32_t noteViewId, Windows::Foundation::Size size, bool* succeeded) noexcept = 0;
    virtual int32_t WINRT_CALL SetFocusToNextView() noexcept = 0;
    virtual int32_t WINRT_CALL SetNotesThumbnailAsync(void* thumbnail, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL add_SystemLockStateChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_SystemLockStateChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_NotePlacementChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_NotePlacementChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_NoteVisibilityChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_NoteVisibilityChanged(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ShowNoteRelativeToWithOptions(int32_t noteViewId, int32_t anchorNoteViewId, void* options) noexcept = 0;
    virtual int32_t WINRT_CALL ShowNoteWithPlacementWithOptions(int32_t noteViewId, void* data, void* options) noexcept = 0;
    virtual int32_t WINRT_CALL SetFocusToPreviousView() noexcept = 0;
    virtual int32_t WINRT_CALL SetThumbnailImageForTaskSwitcherAsync(void* bitmap, void** action) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreviewShowNoteOptions>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ShowWithFocus(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ShowWithFocus(bool value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreviewStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetForCurrentApp(void** current) noexcept = 0;
};};

template <typename D>
struct consume_Windows_ApplicationModel_Preview_Notes_INotePlacementChangedPreviewEventArgs
{
    int32_t ViewId() const;
};
template <> struct consume<Windows::ApplicationModel::Preview::Notes::INotePlacementChangedPreviewEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_Preview_Notes_INotePlacementChangedPreviewEventArgs<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Preview_Notes_INoteVisibilityChangedPreviewEventArgs
{
    int32_t ViewId() const;
    bool IsVisible() const;
};
template <> struct consume<Windows::ApplicationModel::Preview::Notes::INoteVisibilityChangedPreviewEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_Preview_Notes_INoteVisibilityChangedPreviewEventArgs<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreview
{
    bool IsScreenLocked() const;
    void ShowNote(int32_t noteViewId) const;
    void ShowNoteRelativeTo(int32_t noteViewId, int32_t anchorNoteViewId) const;
    void ShowNoteWithPlacement(int32_t noteViewId, Windows::Storage::Streams::IBuffer const& data) const;
    void HideNote(int32_t noteViewId) const;
    Windows::Storage::Streams::IBuffer GetNotePlacement(int32_t noteViewId) const;
    bool TrySetNoteSize(int32_t noteViewId, Windows::Foundation::Size const& size) const;
    void SetFocusToNextView() const;
    Windows::Foundation::IAsyncAction SetNotesThumbnailAsync(Windows::Storage::Streams::IBuffer const& thumbnail) const;
    winrt::event_token SystemLockStateChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreview, Windows::Foundation::IInspectable> const& handler) const;
    using SystemLockStateChanged_revoker = impl::event_revoker<Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview, &impl::abi_t<Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview>::remove_SystemLockStateChanged>;
    SystemLockStateChanged_revoker SystemLockStateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreview, Windows::Foundation::IInspectable> const& handler) const;
    void SystemLockStateChanged(winrt::event_token const& token) const noexcept;
    winrt::event_token NotePlacementChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreview, Windows::ApplicationModel::Preview::Notes::NotePlacementChangedPreviewEventArgs> const& handler) const;
    using NotePlacementChanged_revoker = impl::event_revoker<Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview, &impl::abi_t<Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview>::remove_NotePlacementChanged>;
    NotePlacementChanged_revoker NotePlacementChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreview, Windows::ApplicationModel::Preview::Notes::NotePlacementChangedPreviewEventArgs> const& handler) const;
    void NotePlacementChanged(winrt::event_token const& token) const noexcept;
    winrt::event_token NoteVisibilityChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreview, Windows::ApplicationModel::Preview::Notes::NoteVisibilityChangedPreviewEventArgs> const& handler) const;
    using NoteVisibilityChanged_revoker = impl::event_revoker<Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview, &impl::abi_t<Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview>::remove_NoteVisibilityChanged>;
    NoteVisibilityChanged_revoker NoteVisibilityChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreview, Windows::ApplicationModel::Preview::Notes::NoteVisibilityChangedPreviewEventArgs> const& handler) const;
    void NoteVisibilityChanged(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview> { template <typename D> using type = consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreview<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreview2
{
    void ShowNoteRelativeTo(int32_t noteViewId, int32_t anchorNoteViewId, Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreviewShowNoteOptions const& options) const;
    void ShowNoteWithPlacement(int32_t noteViewId, Windows::Storage::Streams::IBuffer const& data, Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreviewShowNoteOptions const& options) const;
    void SetFocusToPreviousView() const;
    Windows::Foundation::IAsyncAction SetThumbnailImageForTaskSwitcherAsync(Windows::Graphics::Imaging::SoftwareBitmap const& bitmap) const;
};
template <> struct consume<Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview2> { template <typename D> using type = consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreview2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreviewShowNoteOptions
{
    bool ShowWithFocus() const;
    void ShowWithFocus(bool value) const;
};
template <> struct consume<Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreviewShowNoteOptions> { template <typename D> using type = consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreviewShowNoteOptions<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreviewStatics
{
    Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreview GetForCurrentApp() const;
};
template <> struct consume<Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreviewStatics> { template <typename D> using type = consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreviewStatics<D>; };

}
