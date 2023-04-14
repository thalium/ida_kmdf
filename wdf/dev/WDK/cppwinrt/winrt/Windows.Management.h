// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Management.2.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_Management_IMdmAlert<D>::Data() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Management::IMdmAlert)->get_Data(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Management_IMdmAlert<D>::Data(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Management::IMdmAlert)->put_Data(get_abi(value)));
}

template <typename D> Windows::Management::MdmAlertDataType consume_Windows_Management_IMdmAlert<D>::Format() const
{
    Windows::Management::MdmAlertDataType value{};
    check_hresult(WINRT_SHIM(Windows::Management::IMdmAlert)->get_Format(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Management_IMdmAlert<D>::Format(Windows::Management::MdmAlertDataType const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Management::IMdmAlert)->put_Format(get_abi(value)));
}

template <typename D> Windows::Management::MdmAlertMark consume_Windows_Management_IMdmAlert<D>::Mark() const
{
    Windows::Management::MdmAlertMark value{};
    check_hresult(WINRT_SHIM(Windows::Management::IMdmAlert)->get_Mark(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Management_IMdmAlert<D>::Mark(Windows::Management::MdmAlertMark const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Management::IMdmAlert)->put_Mark(get_abi(value)));
}

template <typename D> hstring consume_Windows_Management_IMdmAlert<D>::Source() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Management::IMdmAlert)->get_Source(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Management_IMdmAlert<D>::Source(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Management::IMdmAlert)->put_Source(get_abi(value)));
}

template <typename D> uint32_t consume_Windows_Management_IMdmAlert<D>::Status() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Management::IMdmAlert)->get_Status(&value));
    return value;
}

template <typename D> hstring consume_Windows_Management_IMdmAlert<D>::Target() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Management::IMdmAlert)->get_Target(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Management_IMdmAlert<D>::Target(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Management::IMdmAlert)->put_Target(get_abi(value)));
}

template <typename D> hstring consume_Windows_Management_IMdmAlert<D>::Type() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Management::IMdmAlert)->get_Type(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Management_IMdmAlert<D>::Type(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Management::IMdmAlert)->put_Type(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Management::MdmAlert> consume_Windows_Management_IMdmSession<D>::Alerts() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Management::MdmAlert> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::IMdmSession)->get_Alerts(put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_Management_IMdmSession<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::Management::IMdmSession)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Management_IMdmSession<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Management::IMdmSession)->get_Id(put_abi(value)));
    return value;
}

template <typename D> Windows::Management::MdmSessionState consume_Windows_Management_IMdmSession<D>::State() const
{
    Windows::Management::MdmSessionState value{};
    check_hresult(WINRT_SHIM(Windows::Management::IMdmSession)->get_State(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Management_IMdmSession<D>::AttachAsync() const
{
    Windows::Foundation::IAsyncAction action{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::IMdmSession)->AttachAsync(put_abi(action)));
    return action;
}

template <typename D> void consume_Windows_Management_IMdmSession<D>::Delete() const
{
    check_hresult(WINRT_SHIM(Windows::Management::IMdmSession)->Delete());
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Management_IMdmSession<D>::StartAsync() const
{
    Windows::Foundation::IAsyncAction action{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::IMdmSession)->StartAsync(put_abi(action)));
    return action;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Management_IMdmSession<D>::StartAsync(param::async_iterable<Windows::Management::MdmAlert> const& alerts) const
{
    Windows::Foundation::IAsyncAction action{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::IMdmSession)->StartWithAlertsAsync(get_abi(alerts), put_abi(action)));
    return action;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_Management_IMdmSessionManagerStatics<D>::SessionIds() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::IMdmSessionManagerStatics)->get_SessionIds(put_abi(value)));
    return value;
}

template <typename D> Windows::Management::MdmSession consume_Windows_Management_IMdmSessionManagerStatics<D>::TryCreateSession() const
{
    Windows::Management::MdmSession result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::IMdmSessionManagerStatics)->TryCreateSession(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Management_IMdmSessionManagerStatics<D>::DeleteSessionById(param::hstring const& sessionId) const
{
    check_hresult(WINRT_SHIM(Windows::Management::IMdmSessionManagerStatics)->DeleteSessionById(get_abi(sessionId)));
}

template <typename D> Windows::Management::MdmSession consume_Windows_Management_IMdmSessionManagerStatics<D>::GetSessionById(param::hstring const& sessionId) const
{
    Windows::Management::MdmSession result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::IMdmSessionManagerStatics)->GetSessionById(get_abi(sessionId), put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::Management::IMdmAlert> : produce_base<D, Windows::Management::IMdmAlert>
{
    int32_t WINRT_CALL get_Data(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Data, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Data());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Data(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Data, WINRT_WRAP(void), hstring const&);
            this->shim().Data(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Format(Windows::Management::MdmAlertDataType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Format, WINRT_WRAP(Windows::Management::MdmAlertDataType));
            *value = detach_from<Windows::Management::MdmAlertDataType>(this->shim().Format());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Format(Windows::Management::MdmAlertDataType value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Format, WINRT_WRAP(void), Windows::Management::MdmAlertDataType const&);
            this->shim().Format(*reinterpret_cast<Windows::Management::MdmAlertDataType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Mark(Windows::Management::MdmAlertMark* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mark, WINRT_WRAP(Windows::Management::MdmAlertMark));
            *value = detach_from<Windows::Management::MdmAlertMark>(this->shim().Mark());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Mark(Windows::Management::MdmAlertMark value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mark, WINRT_WRAP(void), Windows::Management::MdmAlertMark const&);
            this->shim().Mark(*reinterpret_cast<Windows::Management::MdmAlertMark const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Source(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Source, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Source());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Source(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Source, WINRT_WRAP(void), hstring const&);
            this->shim().Source(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Target(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Target, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Target());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Target(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Target, WINRT_WRAP(void), hstring const&);
            this->shim().Target(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Type(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Type(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(void), hstring const&);
            this->shim().Type(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Management::IMdmSession> : produce_base<D, Windows::Management::IMdmSession>
{
    int32_t WINRT_CALL get_Alerts(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Alerts, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Management::MdmAlert>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Management::MdmAlert>>(this->shim().Alerts());
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

    int32_t WINRT_CALL get_State(Windows::Management::MdmSessionState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::Management::MdmSessionState));
            *value = detach_from<Windows::Management::MdmSessionState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AttachAsync(void** action) noexcept final
    {
        try
        {
            *action = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AttachAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *action = detach_from<Windows::Foundation::IAsyncAction>(this->shim().AttachAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Delete() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Delete, WINRT_WRAP(void));
            this->shim().Delete();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartAsync(void** action) noexcept final
    {
        try
        {
            *action = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *action = detach_from<Windows::Foundation::IAsyncAction>(this->shim().StartAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartWithAlertsAsync(void* alerts, void** action) noexcept final
    {
        try
        {
            *action = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Foundation::Collections::IIterable<Windows::Management::MdmAlert> const);
            *action = detach_from<Windows::Foundation::IAsyncAction>(this->shim().StartAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Management::MdmAlert> const*>(&alerts)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Management::IMdmSessionManagerStatics> : produce_base<D, Windows::Management::IMdmSessionManagerStatics>
{
    int32_t WINRT_CALL get_SessionIds(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SessionIds, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().SessionIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryCreateSession(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryCreateSession, WINRT_WRAP(Windows::Management::MdmSession));
            *result = detach_from<Windows::Management::MdmSession>(this->shim().TryCreateSession());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteSessionById(void* sessionId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteSessionById, WINRT_WRAP(void), hstring const&);
            this->shim().DeleteSessionById(*reinterpret_cast<hstring const*>(&sessionId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSessionById(void* sessionId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSessionById, WINRT_WRAP(Windows::Management::MdmSession), hstring const&);
            *result = detach_from<Windows::Management::MdmSession>(this->shim().GetSessionById(*reinterpret_cast<hstring const*>(&sessionId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Management {

inline MdmAlert::MdmAlert() :
    MdmAlert(impl::call_factory<MdmAlert>([](auto&& f) { return f.template ActivateInstance<MdmAlert>(); }))
{}

inline Windows::Foundation::Collections::IVectorView<hstring> MdmSessionManager::SessionIds()
{
    return impl::call_factory<MdmSessionManager, Windows::Management::IMdmSessionManagerStatics>([&](auto&& f) { return f.SessionIds(); });
}

inline Windows::Management::MdmSession MdmSessionManager::TryCreateSession()
{
    return impl::call_factory<MdmSessionManager, Windows::Management::IMdmSessionManagerStatics>([&](auto&& f) { return f.TryCreateSession(); });
}

inline void MdmSessionManager::DeleteSessionById(param::hstring const& sessionId)
{
    impl::call_factory<MdmSessionManager, Windows::Management::IMdmSessionManagerStatics>([&](auto&& f) { return f.DeleteSessionById(sessionId); });
}

inline Windows::Management::MdmSession MdmSessionManager::GetSessionById(param::hstring const& sessionId)
{
    return impl::call_factory<MdmSessionManager, Windows::Management::IMdmSessionManagerStatics>([&](auto&& f) { return f.GetSessionById(sessionId); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Management::IMdmAlert> : winrt::impl::hash_base<winrt::Windows::Management::IMdmAlert> {};
template<> struct hash<winrt::Windows::Management::IMdmSession> : winrt::impl::hash_base<winrt::Windows::Management::IMdmSession> {};
template<> struct hash<winrt::Windows::Management::IMdmSessionManagerStatics> : winrt::impl::hash_base<winrt::Windows::Management::IMdmSessionManagerStatics> {};
template<> struct hash<winrt::Windows::Management::MdmAlert> : winrt::impl::hash_base<winrt::Windows::Management::MdmAlert> {};
template<> struct hash<winrt::Windows::Management::MdmSession> : winrt::impl::hash_base<winrt::Windows::Management::MdmSession> {};
template<> struct hash<winrt::Windows::Management::MdmSessionManager> : winrt::impl::hash_base<winrt::Windows::Management::MdmSessionManager> {};

}
