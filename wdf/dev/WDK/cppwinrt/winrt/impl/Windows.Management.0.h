// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Management {

enum class MdmAlertDataType : int32_t
{
    String = 0,
    Base64 = 1,
    Boolean = 2,
    Integer = 3,
};

enum class MdmAlertMark : int32_t
{
    None = 0,
    Fatal = 1,
    Critical = 2,
    Warning = 3,
    Informational = 4,
};

enum class MdmSessionState : int32_t
{
    NotStarted = 0,
    Starting = 1,
    Connecting = 2,
    Communicating = 3,
    AlertStatusAvailable = 4,
    Retrying = 5,
    Completed = 6,
};

struct IMdmAlert;
struct IMdmSession;
struct IMdmSessionManagerStatics;
struct MdmAlert;
struct MdmSession;
struct MdmSessionManager;

}

namespace winrt::impl {

template <> struct category<Windows::Management::IMdmAlert>{ using type = interface_category; };
template <> struct category<Windows::Management::IMdmSession>{ using type = interface_category; };
template <> struct category<Windows::Management::IMdmSessionManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::Management::MdmAlert>{ using type = class_category; };
template <> struct category<Windows::Management::MdmSession>{ using type = class_category; };
template <> struct category<Windows::Management::MdmSessionManager>{ using type = class_category; };
template <> struct category<Windows::Management::MdmAlertDataType>{ using type = enum_category; };
template <> struct category<Windows::Management::MdmAlertMark>{ using type = enum_category; };
template <> struct category<Windows::Management::MdmSessionState>{ using type = enum_category; };
template <> struct name<Windows::Management::IMdmAlert>{ static constexpr auto & value{ L"Windows.Management.IMdmAlert" }; };
template <> struct name<Windows::Management::IMdmSession>{ static constexpr auto & value{ L"Windows.Management.IMdmSession" }; };
template <> struct name<Windows::Management::IMdmSessionManagerStatics>{ static constexpr auto & value{ L"Windows.Management.IMdmSessionManagerStatics" }; };
template <> struct name<Windows::Management::MdmAlert>{ static constexpr auto & value{ L"Windows.Management.MdmAlert" }; };
template <> struct name<Windows::Management::MdmSession>{ static constexpr auto & value{ L"Windows.Management.MdmSession" }; };
template <> struct name<Windows::Management::MdmSessionManager>{ static constexpr auto & value{ L"Windows.Management.MdmSessionManager" }; };
template <> struct name<Windows::Management::MdmAlertDataType>{ static constexpr auto & value{ L"Windows.Management.MdmAlertDataType" }; };
template <> struct name<Windows::Management::MdmAlertMark>{ static constexpr auto & value{ L"Windows.Management.MdmAlertMark" }; };
template <> struct name<Windows::Management::MdmSessionState>{ static constexpr auto & value{ L"Windows.Management.MdmSessionState" }; };
template <> struct guid_storage<Windows::Management::IMdmAlert>{ static constexpr guid value{ 0xB0FBC327,0x28C1,0x4B52,{ 0xA5,0x48,0xC5,0x80,0x7C,0xAF,0x70,0xB6 } }; };
template <> struct guid_storage<Windows::Management::IMdmSession>{ static constexpr guid value{ 0xFE89314C,0x8F64,0x4797,{ 0xA9,0xD7,0x9D,0x88,0xF8,0x6A,0xE1,0x66 } }; };
template <> struct guid_storage<Windows::Management::IMdmSessionManagerStatics>{ static constexpr guid value{ 0xCF4AD959,0xF745,0x4B79,{ 0x9B,0x5C,0xDE,0x0B,0xF8,0xEF,0xE4,0x4B } }; };
template <> struct default_interface<Windows::Management::MdmAlert>{ using type = Windows::Management::IMdmAlert; };
template <> struct default_interface<Windows::Management::MdmSession>{ using type = Windows::Management::IMdmSession; };

template <> struct abi<Windows::Management::IMdmAlert>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Data(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Data(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Format(Windows::Management::MdmAlertDataType* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Format(Windows::Management::MdmAlertDataType value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Mark(Windows::Management::MdmAlertMark* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Mark(Windows::Management::MdmAlertMark value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Source(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Source(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Status(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Target(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Target(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Type(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Type(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Management::IMdmSession>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Alerts(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Id(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_State(Windows::Management::MdmSessionState* value) noexcept = 0;
    virtual int32_t WINRT_CALL AttachAsync(void** action) noexcept = 0;
    virtual int32_t WINRT_CALL Delete() noexcept = 0;
    virtual int32_t WINRT_CALL StartAsync(void** action) noexcept = 0;
    virtual int32_t WINRT_CALL StartWithAlertsAsync(void* alerts, void** action) noexcept = 0;
};};

template <> struct abi<Windows::Management::IMdmSessionManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SessionIds(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL TryCreateSession(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL DeleteSessionById(void* sessionId) noexcept = 0;
    virtual int32_t WINRT_CALL GetSessionById(void* sessionId, void** result) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Management_IMdmAlert
{
    hstring Data() const;
    void Data(param::hstring const& value) const;
    Windows::Management::MdmAlertDataType Format() const;
    void Format(Windows::Management::MdmAlertDataType const& value) const;
    Windows::Management::MdmAlertMark Mark() const;
    void Mark(Windows::Management::MdmAlertMark const& value) const;
    hstring Source() const;
    void Source(param::hstring const& value) const;
    uint32_t Status() const;
    hstring Target() const;
    void Target(param::hstring const& value) const;
    hstring Type() const;
    void Type(param::hstring const& value) const;
};
template <> struct consume<Windows::Management::IMdmAlert> { template <typename D> using type = consume_Windows_Management_IMdmAlert<D>; };

template <typename D>
struct consume_Windows_Management_IMdmSession
{
    Windows::Foundation::Collections::IVectorView<Windows::Management::MdmAlert> Alerts() const;
    winrt::hresult ExtendedError() const;
    hstring Id() const;
    Windows::Management::MdmSessionState State() const;
    Windows::Foundation::IAsyncAction AttachAsync() const;
    void Delete() const;
    Windows::Foundation::IAsyncAction StartAsync() const;
    Windows::Foundation::IAsyncAction StartAsync(param::async_iterable<Windows::Management::MdmAlert> const& alerts) const;
};
template <> struct consume<Windows::Management::IMdmSession> { template <typename D> using type = consume_Windows_Management_IMdmSession<D>; };

template <typename D>
struct consume_Windows_Management_IMdmSessionManagerStatics
{
    Windows::Foundation::Collections::IVectorView<hstring> SessionIds() const;
    Windows::Management::MdmSession TryCreateSession() const;
    void DeleteSessionById(param::hstring const& sessionId) const;
    Windows::Management::MdmSession GetSessionById(param::hstring const& sessionId) const;
};
template <> struct consume<Windows::Management::IMdmSessionManagerStatics> { template <typename D> using type = consume_Windows_Management_IMdmSessionManagerStatics<D>; };

}
