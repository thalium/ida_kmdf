// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.System.Update.2.h"
#include "winrt/Windows.System.h"

namespace winrt::impl {

template <typename D> Windows::System::Update::SystemUpdateItemState consume_Windows_System_Update_ISystemUpdateItem<D>::State() const
{
    Windows::System::Update::SystemUpdateItemState value{};
    check_hresult(WINRT_SHIM(Windows::System::Update::ISystemUpdateItem)->get_State(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Update_ISystemUpdateItem<D>::Title() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Update::ISystemUpdateItem)->get_Title(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Update_ISystemUpdateItem<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Update::ISystemUpdateItem)->get_Description(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Update_ISystemUpdateItem<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Update::ISystemUpdateItem)->get_Id(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_System_Update_ISystemUpdateItem<D>::Revision() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Update::ISystemUpdateItem)->get_Revision(&value));
    return value;
}

template <typename D> double consume_Windows_System_Update_ISystemUpdateItem<D>::DownloadProgress() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::System::Update::ISystemUpdateItem)->get_DownloadProgress(&value));
    return value;
}

template <typename D> double consume_Windows_System_Update_ISystemUpdateItem<D>::InstallProgress() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::System::Update::ISystemUpdateItem)->get_InstallProgress(&value));
    return value;
}

template <typename D> winrt::hresult consume_Windows_System_Update_ISystemUpdateItem<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::System::Update::ISystemUpdateItem)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> Windows::System::Update::SystemUpdateManagerState consume_Windows_System_Update_ISystemUpdateLastErrorInfo<D>::State() const
{
    Windows::System::Update::SystemUpdateManagerState value{};
    check_hresult(WINRT_SHIM(Windows::System::Update::ISystemUpdateLastErrorInfo)->get_State(put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_System_Update_ISystemUpdateLastErrorInfo<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::System::Update::ISystemUpdateLastErrorInfo)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_System_Update_ISystemUpdateLastErrorInfo<D>::IsInteractive() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::Update::ISystemUpdateLastErrorInfo)->get_IsInteractive(&value));
    return value;
}

template <typename D> bool consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::IsSupported() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::System::Update::ISystemUpdateManagerStatics)->IsSupported(&result));
    return result;
}

template <typename D> Windows::System::Update::SystemUpdateManagerState consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::State() const
{
    Windows::System::Update::SystemUpdateManagerState value{};
    check_hresult(WINRT_SHIM(Windows::System::Update::ISystemUpdateManagerStatics)->get_State(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::StateChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::Update::ISystemUpdateManagerStatics)->add_StateChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::StateChanged_revoker consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::StateChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, StateChanged_revoker>(this, StateChanged(handler));
}

template <typename D> void consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::StateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::Update::ISystemUpdateManagerStatics)->remove_StateChanged(get_abi(token)));
}

template <typename D> double consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::DownloadProgress() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::System::Update::ISystemUpdateManagerStatics)->get_DownloadProgress(&value));
    return value;
}

template <typename D> double consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::InstallProgress() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::System::Update::ISystemUpdateManagerStatics)->get_InstallProgress(&value));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::UserActiveHoursStart() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::System::Update::ISystemUpdateManagerStatics)->get_UserActiveHoursStart(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::UserActiveHoursEnd() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::System::Update::ISystemUpdateManagerStatics)->get_UserActiveHoursEnd(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::UserActiveHoursMax() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Update::ISystemUpdateManagerStatics)->get_UserActiveHoursMax(&value));
    return value;
}

template <typename D> bool consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::TrySetUserActiveHours(Windows::Foundation::TimeSpan const& start, Windows::Foundation::TimeSpan const& end) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::System::Update::ISystemUpdateManagerStatics)->TrySetUserActiveHours(get_abi(start), get_abi(end), &result));
    return result;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::LastUpdateCheckTime() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::System::Update::ISystemUpdateManagerStatics)->get_LastUpdateCheckTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::LastUpdateInstallTime() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::System::Update::ISystemUpdateManagerStatics)->get_LastUpdateInstallTime(put_abi(value)));
    return value;
}

template <typename D> Windows::System::Update::SystemUpdateLastErrorInfo consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::LastErrorInfo() const
{
    Windows::System::Update::SystemUpdateLastErrorInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Update::ISystemUpdateManagerStatics)->get_LastErrorInfo(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::GetAutomaticRebootBlockIds() const
{
    Windows::Foundation::Collections::IVectorView<hstring> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Update::ISystemUpdateManagerStatics)->GetAutomaticRebootBlockIds(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::BlockAutomaticRebootAsync(param::hstring const& lockId) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Update::ISystemUpdateManagerStatics)->BlockAutomaticRebootAsync(get_abi(lockId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::UnblockAutomaticRebootAsync(param::hstring const& lockId) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Update::ISystemUpdateManagerStatics)->UnblockAutomaticRebootAsync(get_abi(lockId), put_abi(operation)));
    return operation;
}

template <typename D> winrt::hresult consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::System::Update::ISystemUpdateManagerStatics)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::System::Update::SystemUpdateItem> consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::GetUpdateItems() const
{
    Windows::Foundation::Collections::IVectorView<Windows::System::Update::SystemUpdateItem> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Update::ISystemUpdateManagerStatics)->GetUpdateItems(put_abi(result)));
    return result;
}

template <typename D> Windows::System::Update::SystemUpdateAttentionRequiredReason consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::AttentionRequiredReason() const
{
    Windows::System::Update::SystemUpdateAttentionRequiredReason value{};
    check_hresult(WINRT_SHIM(Windows::System::Update::ISystemUpdateManagerStatics)->get_AttentionRequiredReason(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::SetFlightRing(param::hstring const& flightRing) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::System::Update::ISystemUpdateManagerStatics)->SetFlightRing(get_abi(flightRing), &result));
    return result;
}

template <typename D> hstring consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::GetFlightRing() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::System::Update::ISystemUpdateManagerStatics)->GetFlightRing(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::StartInstall(Windows::System::Update::SystemUpdateStartInstallAction const& action) const
{
    check_hresult(WINRT_SHIM(Windows::System::Update::ISystemUpdateManagerStatics)->StartInstall(get_abi(action)));
}

template <typename D> void consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::RebootToCompleteInstall() const
{
    check_hresult(WINRT_SHIM(Windows::System::Update::ISystemUpdateManagerStatics)->RebootToCompleteInstall());
}

template <typename D> void consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::StartCancelUpdates() const
{
    check_hresult(WINRT_SHIM(Windows::System::Update::ISystemUpdateManagerStatics)->StartCancelUpdates());
}

template <typename D>
struct produce<D, Windows::System::Update::ISystemUpdateItem> : produce_base<D, Windows::System::Update::ISystemUpdateItem>
{
    int32_t WINRT_CALL get_State(Windows::System::Update::SystemUpdateItemState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::System::Update::SystemUpdateItemState));
            *value = detach_from<Windows::System::Update::SystemUpdateItemState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL get_Description(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Description());
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
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Revision(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Revision, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Revision());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DownloadProgress(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DownloadProgress, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().DownloadProgress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InstallProgress(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InstallProgress, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().InstallProgress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedError, WINRT_WRAP(winrt::hresult));
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Update::ISystemUpdateLastErrorInfo> : produce_base<D, Windows::System::Update::ISystemUpdateLastErrorInfo>
{
    int32_t WINRT_CALL get_State(Windows::System::Update::SystemUpdateManagerState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::System::Update::SystemUpdateManagerState));
            *value = detach_from<Windows::System::Update::SystemUpdateManagerState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedError, WINRT_WRAP(winrt::hresult));
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsInteractive(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInteractive, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsInteractive());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Update::ISystemUpdateManagerStatics> : produce_base<D, Windows::System::Update::ISystemUpdateManagerStatics>
{
    int32_t WINRT_CALL IsSupported(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSupported, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_State(Windows::System::Update::SystemUpdateManagerState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::System::Update::SystemUpdateManagerState));
            *value = detach_from<Windows::System::Update::SystemUpdateManagerState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_StateChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().StateChanged(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_StateChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(StateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().StateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_DownloadProgress(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DownloadProgress, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().DownloadProgress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InstallProgress(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InstallProgress, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().InstallProgress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UserActiveHoursStart(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserActiveHoursStart, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().UserActiveHoursStart());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UserActiveHoursEnd(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserActiveHoursEnd, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().UserActiveHoursEnd());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UserActiveHoursMax(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserActiveHoursMax, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().UserActiveHoursMax());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySetUserActiveHours(Windows::Foundation::TimeSpan start, Windows::Foundation::TimeSpan end, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySetUserActiveHours, WINRT_WRAP(bool), Windows::Foundation::TimeSpan const&, Windows::Foundation::TimeSpan const&);
            *result = detach_from<bool>(this->shim().TrySetUserActiveHours(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&start), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&end)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LastUpdateCheckTime(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastUpdateCheckTime, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().LastUpdateCheckTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LastUpdateInstallTime(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastUpdateInstallTime, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().LastUpdateInstallTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LastErrorInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastErrorInfo, WINRT_WRAP(Windows::System::Update::SystemUpdateLastErrorInfo));
            *value = detach_from<Windows::System::Update::SystemUpdateLastErrorInfo>(this->shim().LastErrorInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAutomaticRebootBlockIds(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAutomaticRebootBlockIds, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().GetAutomaticRebootBlockIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL BlockAutomaticRebootAsync(void* lockId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BlockAutomaticRebootAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().BlockAutomaticRebootAsync(*reinterpret_cast<hstring const*>(&lockId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UnblockAutomaticRebootAsync(void* lockId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnblockAutomaticRebootAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().UnblockAutomaticRebootAsync(*reinterpret_cast<hstring const*>(&lockId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedError, WINRT_WRAP(winrt::hresult));
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetUpdateItems(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetUpdateItems, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::System::Update::SystemUpdateItem>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::System::Update::SystemUpdateItem>>(this->shim().GetUpdateItems());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AttentionRequiredReason(Windows::System::Update::SystemUpdateAttentionRequiredReason* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AttentionRequiredReason, WINRT_WRAP(Windows::System::Update::SystemUpdateAttentionRequiredReason));
            *value = detach_from<Windows::System::Update::SystemUpdateAttentionRequiredReason>(this->shim().AttentionRequiredReason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetFlightRing(void* flightRing, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetFlightRing, WINRT_WRAP(bool), hstring const&);
            *result = detach_from<bool>(this->shim().SetFlightRing(*reinterpret_cast<hstring const*>(&flightRing)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFlightRing(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFlightRing, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetFlightRing());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartInstall(Windows::System::Update::SystemUpdateStartInstallAction action) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartInstall, WINRT_WRAP(void), Windows::System::Update::SystemUpdateStartInstallAction const&);
            this->shim().StartInstall(*reinterpret_cast<Windows::System::Update::SystemUpdateStartInstallAction const*>(&action));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RebootToCompleteInstall() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RebootToCompleteInstall, WINRT_WRAP(void));
            this->shim().RebootToCompleteInstall();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartCancelUpdates() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartCancelUpdates, WINRT_WRAP(void));
            this->shim().StartCancelUpdates();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::System::Update {

inline bool SystemUpdateManager::IsSupported()
{
    return impl::call_factory<SystemUpdateManager, Windows::System::Update::ISystemUpdateManagerStatics>([&](auto&& f) { return f.IsSupported(); });
}

inline Windows::System::Update::SystemUpdateManagerState SystemUpdateManager::State()
{
    return impl::call_factory<SystemUpdateManager, Windows::System::Update::ISystemUpdateManagerStatics>([&](auto&& f) { return f.State(); });
}

inline winrt::event_token SystemUpdateManager::StateChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<SystemUpdateManager, Windows::System::Update::ISystemUpdateManagerStatics>([&](auto&& f) { return f.StateChanged(handler); });
}

inline SystemUpdateManager::StateChanged_revoker SystemUpdateManager::StateChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<SystemUpdateManager, Windows::System::Update::ISystemUpdateManagerStatics>();
    return { f, f.StateChanged(handler) };
}

inline void SystemUpdateManager::StateChanged(winrt::event_token const& token)
{
    impl::call_factory<SystemUpdateManager, Windows::System::Update::ISystemUpdateManagerStatics>([&](auto&& f) { return f.StateChanged(token); });
}

inline double SystemUpdateManager::DownloadProgress()
{
    return impl::call_factory<SystemUpdateManager, Windows::System::Update::ISystemUpdateManagerStatics>([&](auto&& f) { return f.DownloadProgress(); });
}

inline double SystemUpdateManager::InstallProgress()
{
    return impl::call_factory<SystemUpdateManager, Windows::System::Update::ISystemUpdateManagerStatics>([&](auto&& f) { return f.InstallProgress(); });
}

inline Windows::Foundation::TimeSpan SystemUpdateManager::UserActiveHoursStart()
{
    return impl::call_factory<SystemUpdateManager, Windows::System::Update::ISystemUpdateManagerStatics>([&](auto&& f) { return f.UserActiveHoursStart(); });
}

inline Windows::Foundation::TimeSpan SystemUpdateManager::UserActiveHoursEnd()
{
    return impl::call_factory<SystemUpdateManager, Windows::System::Update::ISystemUpdateManagerStatics>([&](auto&& f) { return f.UserActiveHoursEnd(); });
}

inline int32_t SystemUpdateManager::UserActiveHoursMax()
{
    return impl::call_factory<SystemUpdateManager, Windows::System::Update::ISystemUpdateManagerStatics>([&](auto&& f) { return f.UserActiveHoursMax(); });
}

inline bool SystemUpdateManager::TrySetUserActiveHours(Windows::Foundation::TimeSpan const& start, Windows::Foundation::TimeSpan const& end)
{
    return impl::call_factory<SystemUpdateManager, Windows::System::Update::ISystemUpdateManagerStatics>([&](auto&& f) { return f.TrySetUserActiveHours(start, end); });
}

inline Windows::Foundation::DateTime SystemUpdateManager::LastUpdateCheckTime()
{
    return impl::call_factory<SystemUpdateManager, Windows::System::Update::ISystemUpdateManagerStatics>([&](auto&& f) { return f.LastUpdateCheckTime(); });
}

inline Windows::Foundation::DateTime SystemUpdateManager::LastUpdateInstallTime()
{
    return impl::call_factory<SystemUpdateManager, Windows::System::Update::ISystemUpdateManagerStatics>([&](auto&& f) { return f.LastUpdateInstallTime(); });
}

inline Windows::System::Update::SystemUpdateLastErrorInfo SystemUpdateManager::LastErrorInfo()
{
    return impl::call_factory<SystemUpdateManager, Windows::System::Update::ISystemUpdateManagerStatics>([&](auto&& f) { return f.LastErrorInfo(); });
}

inline Windows::Foundation::Collections::IVectorView<hstring> SystemUpdateManager::GetAutomaticRebootBlockIds()
{
    return impl::call_factory<SystemUpdateManager, Windows::System::Update::ISystemUpdateManagerStatics>([&](auto&& f) { return f.GetAutomaticRebootBlockIds(); });
}

inline Windows::Foundation::IAsyncOperation<bool> SystemUpdateManager::BlockAutomaticRebootAsync(param::hstring const& lockId)
{
    return impl::call_factory<SystemUpdateManager, Windows::System::Update::ISystemUpdateManagerStatics>([&](auto&& f) { return f.BlockAutomaticRebootAsync(lockId); });
}

inline Windows::Foundation::IAsyncOperation<bool> SystemUpdateManager::UnblockAutomaticRebootAsync(param::hstring const& lockId)
{
    return impl::call_factory<SystemUpdateManager, Windows::System::Update::ISystemUpdateManagerStatics>([&](auto&& f) { return f.UnblockAutomaticRebootAsync(lockId); });
}

inline winrt::hresult SystemUpdateManager::ExtendedError()
{
    return impl::call_factory<SystemUpdateManager, Windows::System::Update::ISystemUpdateManagerStatics>([&](auto&& f) { return f.ExtendedError(); });
}

inline Windows::Foundation::Collections::IVectorView<Windows::System::Update::SystemUpdateItem> SystemUpdateManager::GetUpdateItems()
{
    return impl::call_factory<SystemUpdateManager, Windows::System::Update::ISystemUpdateManagerStatics>([&](auto&& f) { return f.GetUpdateItems(); });
}

inline Windows::System::Update::SystemUpdateAttentionRequiredReason SystemUpdateManager::AttentionRequiredReason()
{
    return impl::call_factory<SystemUpdateManager, Windows::System::Update::ISystemUpdateManagerStatics>([&](auto&& f) { return f.AttentionRequiredReason(); });
}

inline bool SystemUpdateManager::SetFlightRing(param::hstring const& flightRing)
{
    return impl::call_factory<SystemUpdateManager, Windows::System::Update::ISystemUpdateManagerStatics>([&](auto&& f) { return f.SetFlightRing(flightRing); });
}

inline hstring SystemUpdateManager::GetFlightRing()
{
    return impl::call_factory<SystemUpdateManager, Windows::System::Update::ISystemUpdateManagerStatics>([&](auto&& f) { return f.GetFlightRing(); });
}

inline void SystemUpdateManager::StartInstall(Windows::System::Update::SystemUpdateStartInstallAction const& action)
{
    impl::call_factory<SystemUpdateManager, Windows::System::Update::ISystemUpdateManagerStatics>([&](auto&& f) { return f.StartInstall(action); });
}

inline void SystemUpdateManager::RebootToCompleteInstall()
{
    impl::call_factory<SystemUpdateManager, Windows::System::Update::ISystemUpdateManagerStatics>([&](auto&& f) { return f.RebootToCompleteInstall(); });
}

inline void SystemUpdateManager::StartCancelUpdates()
{
    impl::call_factory<SystemUpdateManager, Windows::System::Update::ISystemUpdateManagerStatics>([&](auto&& f) { return f.StartCancelUpdates(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::System::Update::ISystemUpdateItem> : winrt::impl::hash_base<winrt::Windows::System::Update::ISystemUpdateItem> {};
template<> struct hash<winrt::Windows::System::Update::ISystemUpdateLastErrorInfo> : winrt::impl::hash_base<winrt::Windows::System::Update::ISystemUpdateLastErrorInfo> {};
template<> struct hash<winrt::Windows::System::Update::ISystemUpdateManagerStatics> : winrt::impl::hash_base<winrt::Windows::System::Update::ISystemUpdateManagerStatics> {};
template<> struct hash<winrt::Windows::System::Update::SystemUpdateItem> : winrt::impl::hash_base<winrt::Windows::System::Update::SystemUpdateItem> {};
template<> struct hash<winrt::Windows::System::Update::SystemUpdateLastErrorInfo> : winrt::impl::hash_base<winrt::Windows::System::Update::SystemUpdateLastErrorInfo> {};
template<> struct hash<winrt::Windows::System::Update::SystemUpdateManager> : winrt::impl::hash_base<winrt::Windows::System::Update::SystemUpdateManager> {};

}
