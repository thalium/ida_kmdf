// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Activation {

enum class ActivationKind;
enum class ApplicationExecutionState;
struct SplashScreen;

}

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct Deferral;

}

WINRT_EXPORT namespace winrt::Windows::Graphics::Printing::PrintTicket {

struct WorkflowPrintTicket;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IInputStream;
struct IOutputStream;

}

WINRT_EXPORT namespace winrt::Windows::System {

struct User;

}

WINRT_EXPORT namespace winrt::Windows::Graphics::Printing::Workflow {

enum class PrintWorkflowSessionStatus : int32_t
{
    Started = 0,
    Completed = 1,
    Aborted = 2,
    Closed = 3,
};

enum class PrintWorkflowSubmittedStatus : int32_t
{
    Succeeded = 0,
    Canceled = 1,
    Failed = 2,
};

struct IPrintWorkflowBackgroundSession;
struct IPrintWorkflowBackgroundSetupRequestedEventArgs;
struct IPrintWorkflowConfiguration;
struct IPrintWorkflowForegroundSession;
struct IPrintWorkflowForegroundSetupRequestedEventArgs;
struct IPrintWorkflowObjectModelSourceFileContent;
struct IPrintWorkflowObjectModelTargetPackage;
struct IPrintWorkflowSourceContent;
struct IPrintWorkflowSpoolStreamContent;
struct IPrintWorkflowStreamTarget;
struct IPrintWorkflowSubmittedEventArgs;
struct IPrintWorkflowSubmittedOperation;
struct IPrintWorkflowTarget;
struct IPrintWorkflowTriggerDetails;
struct IPrintWorkflowUIActivatedEventArgs;
struct IPrintWorkflowXpsDataAvailableEventArgs;
struct PrintWorkflowBackgroundSession;
struct PrintWorkflowBackgroundSetupRequestedEventArgs;
struct PrintWorkflowConfiguration;
struct PrintWorkflowForegroundSession;
struct PrintWorkflowForegroundSetupRequestedEventArgs;
struct PrintWorkflowObjectModelSourceFileContent;
struct PrintWorkflowObjectModelTargetPackage;
struct PrintWorkflowSourceContent;
struct PrintWorkflowSpoolStreamContent;
struct PrintWorkflowStreamTarget;
struct PrintWorkflowSubmittedEventArgs;
struct PrintWorkflowSubmittedOperation;
struct PrintWorkflowTarget;
struct PrintWorkflowTriggerDetails;
struct PrintWorkflowUIActivatedEventArgs;
struct PrintWorkflowXpsDataAvailableEventArgs;

}

namespace winrt::impl {

template <> struct category<Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSession>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSetupRequestedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Printing::Workflow::IPrintWorkflowConfiguration>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSession>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSetupRequestedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelSourceFileContent>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelTargetPackage>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Printing::Workflow::IPrintWorkflowSourceContent>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Printing::Workflow::IPrintWorkflowSpoolStreamContent>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Printing::Workflow::IPrintWorkflowStreamTarget>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedOperation>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Printing::Workflow::IPrintWorkflowTarget>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Printing::Workflow::IPrintWorkflowTriggerDetails>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Printing::Workflow::IPrintWorkflowUIActivatedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Printing::Workflow::IPrintWorkflowXpsDataAvailableEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSession>{ using type = class_category; };
template <> struct category<Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSetupRequestedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Graphics::Printing::Workflow::PrintWorkflowConfiguration>{ using type = class_category; };
template <> struct category<Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSession>{ using type = class_category; };
template <> struct category<Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSetupRequestedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Graphics::Printing::Workflow::PrintWorkflowObjectModelSourceFileContent>{ using type = class_category; };
template <> struct category<Windows::Graphics::Printing::Workflow::PrintWorkflowObjectModelTargetPackage>{ using type = class_category; };
template <> struct category<Windows::Graphics::Printing::Workflow::PrintWorkflowSourceContent>{ using type = class_category; };
template <> struct category<Windows::Graphics::Printing::Workflow::PrintWorkflowSpoolStreamContent>{ using type = class_category; };
template <> struct category<Windows::Graphics::Printing::Workflow::PrintWorkflowStreamTarget>{ using type = class_category; };
template <> struct category<Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedOperation>{ using type = class_category; };
template <> struct category<Windows::Graphics::Printing::Workflow::PrintWorkflowTarget>{ using type = class_category; };
template <> struct category<Windows::Graphics::Printing::Workflow::PrintWorkflowTriggerDetails>{ using type = class_category; };
template <> struct category<Windows::Graphics::Printing::Workflow::PrintWorkflowUIActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Graphics::Printing::Workflow::PrintWorkflowXpsDataAvailableEventArgs>{ using type = class_category; };
template <> struct category<Windows::Graphics::Printing::Workflow::PrintWorkflowSessionStatus>{ using type = enum_category; };
template <> struct category<Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedStatus>{ using type = enum_category; };
template <> struct name<Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSession>{ static constexpr auto & value{ L"Windows.Graphics.Printing.Workflow.IPrintWorkflowBackgroundSession" }; };
template <> struct name<Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSetupRequestedEventArgs>{ static constexpr auto & value{ L"Windows.Graphics.Printing.Workflow.IPrintWorkflowBackgroundSetupRequestedEventArgs" }; };
template <> struct name<Windows::Graphics::Printing::Workflow::IPrintWorkflowConfiguration>{ static constexpr auto & value{ L"Windows.Graphics.Printing.Workflow.IPrintWorkflowConfiguration" }; };
template <> struct name<Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSession>{ static constexpr auto & value{ L"Windows.Graphics.Printing.Workflow.IPrintWorkflowForegroundSession" }; };
template <> struct name<Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSetupRequestedEventArgs>{ static constexpr auto & value{ L"Windows.Graphics.Printing.Workflow.IPrintWorkflowForegroundSetupRequestedEventArgs" }; };
template <> struct name<Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelSourceFileContent>{ static constexpr auto & value{ L"Windows.Graphics.Printing.Workflow.IPrintWorkflowObjectModelSourceFileContent" }; };
template <> struct name<Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelTargetPackage>{ static constexpr auto & value{ L"Windows.Graphics.Printing.Workflow.IPrintWorkflowObjectModelTargetPackage" }; };
template <> struct name<Windows::Graphics::Printing::Workflow::IPrintWorkflowSourceContent>{ static constexpr auto & value{ L"Windows.Graphics.Printing.Workflow.IPrintWorkflowSourceContent" }; };
template <> struct name<Windows::Graphics::Printing::Workflow::IPrintWorkflowSpoolStreamContent>{ static constexpr auto & value{ L"Windows.Graphics.Printing.Workflow.IPrintWorkflowSpoolStreamContent" }; };
template <> struct name<Windows::Graphics::Printing::Workflow::IPrintWorkflowStreamTarget>{ static constexpr auto & value{ L"Windows.Graphics.Printing.Workflow.IPrintWorkflowStreamTarget" }; };
template <> struct name<Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedEventArgs>{ static constexpr auto & value{ L"Windows.Graphics.Printing.Workflow.IPrintWorkflowSubmittedEventArgs" }; };
template <> struct name<Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedOperation>{ static constexpr auto & value{ L"Windows.Graphics.Printing.Workflow.IPrintWorkflowSubmittedOperation" }; };
template <> struct name<Windows::Graphics::Printing::Workflow::IPrintWorkflowTarget>{ static constexpr auto & value{ L"Windows.Graphics.Printing.Workflow.IPrintWorkflowTarget" }; };
template <> struct name<Windows::Graphics::Printing::Workflow::IPrintWorkflowTriggerDetails>{ static constexpr auto & value{ L"Windows.Graphics.Printing.Workflow.IPrintWorkflowTriggerDetails" }; };
template <> struct name<Windows::Graphics::Printing::Workflow::IPrintWorkflowUIActivatedEventArgs>{ static constexpr auto & value{ L"Windows.Graphics.Printing.Workflow.IPrintWorkflowUIActivatedEventArgs" }; };
template <> struct name<Windows::Graphics::Printing::Workflow::IPrintWorkflowXpsDataAvailableEventArgs>{ static constexpr auto & value{ L"Windows.Graphics.Printing.Workflow.IPrintWorkflowXpsDataAvailableEventArgs" }; };
template <> struct name<Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSession>{ static constexpr auto & value{ L"Windows.Graphics.Printing.Workflow.PrintWorkflowBackgroundSession" }; };
template <> struct name<Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSetupRequestedEventArgs>{ static constexpr auto & value{ L"Windows.Graphics.Printing.Workflow.PrintWorkflowBackgroundSetupRequestedEventArgs" }; };
template <> struct name<Windows::Graphics::Printing::Workflow::PrintWorkflowConfiguration>{ static constexpr auto & value{ L"Windows.Graphics.Printing.Workflow.PrintWorkflowConfiguration" }; };
template <> struct name<Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSession>{ static constexpr auto & value{ L"Windows.Graphics.Printing.Workflow.PrintWorkflowForegroundSession" }; };
template <> struct name<Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSetupRequestedEventArgs>{ static constexpr auto & value{ L"Windows.Graphics.Printing.Workflow.PrintWorkflowForegroundSetupRequestedEventArgs" }; };
template <> struct name<Windows::Graphics::Printing::Workflow::PrintWorkflowObjectModelSourceFileContent>{ static constexpr auto & value{ L"Windows.Graphics.Printing.Workflow.PrintWorkflowObjectModelSourceFileContent" }; };
template <> struct name<Windows::Graphics::Printing::Workflow::PrintWorkflowObjectModelTargetPackage>{ static constexpr auto & value{ L"Windows.Graphics.Printing.Workflow.PrintWorkflowObjectModelTargetPackage" }; };
template <> struct name<Windows::Graphics::Printing::Workflow::PrintWorkflowSourceContent>{ static constexpr auto & value{ L"Windows.Graphics.Printing.Workflow.PrintWorkflowSourceContent" }; };
template <> struct name<Windows::Graphics::Printing::Workflow::PrintWorkflowSpoolStreamContent>{ static constexpr auto & value{ L"Windows.Graphics.Printing.Workflow.PrintWorkflowSpoolStreamContent" }; };
template <> struct name<Windows::Graphics::Printing::Workflow::PrintWorkflowStreamTarget>{ static constexpr auto & value{ L"Windows.Graphics.Printing.Workflow.PrintWorkflowStreamTarget" }; };
template <> struct name<Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedEventArgs>{ static constexpr auto & value{ L"Windows.Graphics.Printing.Workflow.PrintWorkflowSubmittedEventArgs" }; };
template <> struct name<Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedOperation>{ static constexpr auto & value{ L"Windows.Graphics.Printing.Workflow.PrintWorkflowSubmittedOperation" }; };
template <> struct name<Windows::Graphics::Printing::Workflow::PrintWorkflowTarget>{ static constexpr auto & value{ L"Windows.Graphics.Printing.Workflow.PrintWorkflowTarget" }; };
template <> struct name<Windows::Graphics::Printing::Workflow::PrintWorkflowTriggerDetails>{ static constexpr auto & value{ L"Windows.Graphics.Printing.Workflow.PrintWorkflowTriggerDetails" }; };
template <> struct name<Windows::Graphics::Printing::Workflow::PrintWorkflowUIActivatedEventArgs>{ static constexpr auto & value{ L"Windows.Graphics.Printing.Workflow.PrintWorkflowUIActivatedEventArgs" }; };
template <> struct name<Windows::Graphics::Printing::Workflow::PrintWorkflowXpsDataAvailableEventArgs>{ static constexpr auto & value{ L"Windows.Graphics.Printing.Workflow.PrintWorkflowXpsDataAvailableEventArgs" }; };
template <> struct name<Windows::Graphics::Printing::Workflow::PrintWorkflowSessionStatus>{ static constexpr auto & value{ L"Windows.Graphics.Printing.Workflow.PrintWorkflowSessionStatus" }; };
template <> struct name<Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedStatus>{ static constexpr auto & value{ L"Windows.Graphics.Printing.Workflow.PrintWorkflowSubmittedStatus" }; };
template <> struct guid_storage<Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSession>{ static constexpr guid value{ 0x5B7913BA,0x0C5E,0x528A,{ 0x74,0x58,0x86,0xA4,0x6C,0xBD,0xDC,0x45 } }; };
template <> struct guid_storage<Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSetupRequestedEventArgs>{ static constexpr guid value{ 0x43E97342,0x1750,0x59C9,{ 0x61,0xFB,0x38,0x37,0x48,0xA2,0x03,0x62 } }; };
template <> struct guid_storage<Windows::Graphics::Printing::Workflow::IPrintWorkflowConfiguration>{ static constexpr guid value{ 0xD0AAC4ED,0xFD4B,0x5DF5,{ 0x4B,0xB6,0x8D,0x0D,0x15,0x9E,0xBE,0x3F } }; };
template <> struct guid_storage<Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSession>{ static constexpr guid value{ 0xC79B63D0,0xF8EC,0x4CEB,{ 0x95,0x3A,0xC8,0x87,0x61,0x57,0xDD,0x33 } }; };
template <> struct guid_storage<Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSetupRequestedEventArgs>{ static constexpr guid value{ 0xBBE38247,0x9C1B,0x4DD3,{ 0x9B,0x2B,0xC8,0x04,0x68,0xD9,0x41,0xB3 } }; };
template <> struct guid_storage<Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelSourceFileContent>{ static constexpr guid value{ 0xC36C8A6A,0x8A2A,0x419A,{ 0xB3,0xC3,0x20,0x90,0xE6,0xBF,0xAB,0x2F } }; };
template <> struct guid_storage<Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelTargetPackage>{ static constexpr guid value{ 0x7D96BC74,0x9B54,0x4CA1,{ 0xAD,0x3A,0x97,0x9C,0x3D,0x44,0xDD,0xAC } }; };
template <> struct guid_storage<Windows::Graphics::Printing::Workflow::IPrintWorkflowSourceContent>{ static constexpr guid value{ 0x1A28C641,0xCEB1,0x4533,{ 0xBB,0x73,0xFB,0xE6,0x3E,0xEF,0xDB,0x18 } }; };
template <> struct guid_storage<Windows::Graphics::Printing::Workflow::IPrintWorkflowSpoolStreamContent>{ static constexpr guid value{ 0x72E55ECE,0xE406,0x4B74,{ 0x84,0xE1,0x3F,0xF3,0xFD,0xCD,0xAF,0x70 } }; };
template <> struct guid_storage<Windows::Graphics::Printing::Workflow::IPrintWorkflowStreamTarget>{ static constexpr guid value{ 0xB23BBA84,0x8565,0x488B,{ 0x98,0x39,0x1C,0x9E,0x7C,0x7A,0xA9,0x16 } }; };
template <> struct guid_storage<Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedEventArgs>{ static constexpr guid value{ 0x3ADD0A41,0x3794,0x5569,{ 0x5C,0x87,0x40,0xE8,0xFF,0x72,0x0F,0x83 } }; };
template <> struct guid_storage<Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedOperation>{ static constexpr guid value{ 0x2E4E6216,0x3BE1,0x5F0F,{ 0x5C,0x81,0xA5,0xA2,0xBD,0x4E,0xAB,0x0E } }; };
template <> struct guid_storage<Windows::Graphics::Printing::Workflow::IPrintWorkflowTarget>{ static constexpr guid value{ 0x29DA276C,0x0A73,0x5AED,{ 0x4F,0x3D,0x97,0x0D,0x32,0x51,0xF0,0x57 } }; };
template <> struct guid_storage<Windows::Graphics::Printing::Workflow::IPrintWorkflowTriggerDetails>{ static constexpr guid value{ 0x5739D868,0x9D86,0x4052,{ 0xB0,0xCB,0xF3,0x10,0xBE,0xCD,0x59,0xBB } }; };
template <> struct guid_storage<Windows::Graphics::Printing::Workflow::IPrintWorkflowUIActivatedEventArgs>{ static constexpr guid value{ 0xBC8A844D,0x09EB,0x5746,{ 0x72,0xA6,0x8D,0xC8,0xB5,0xED,0xBE,0x9B } }; };
template <> struct guid_storage<Windows::Graphics::Printing::Workflow::IPrintWorkflowXpsDataAvailableEventArgs>{ static constexpr guid value{ 0x4D11C331,0x54D1,0x434E,{ 0xBE,0x0E,0x82,0xC5,0xFA,0x58,0xE5,0xB2 } }; };
template <> struct default_interface<Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSession>{ using type = Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSession; };
template <> struct default_interface<Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSetupRequestedEventArgs>{ using type = Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSetupRequestedEventArgs; };
template <> struct default_interface<Windows::Graphics::Printing::Workflow::PrintWorkflowConfiguration>{ using type = Windows::Graphics::Printing::Workflow::IPrintWorkflowConfiguration; };
template <> struct default_interface<Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSession>{ using type = Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSession; };
template <> struct default_interface<Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSetupRequestedEventArgs>{ using type = Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSetupRequestedEventArgs; };
template <> struct default_interface<Windows::Graphics::Printing::Workflow::PrintWorkflowObjectModelSourceFileContent>{ using type = Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelSourceFileContent; };
template <> struct default_interface<Windows::Graphics::Printing::Workflow::PrintWorkflowObjectModelTargetPackage>{ using type = Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelTargetPackage; };
template <> struct default_interface<Windows::Graphics::Printing::Workflow::PrintWorkflowSourceContent>{ using type = Windows::Graphics::Printing::Workflow::IPrintWorkflowSourceContent; };
template <> struct default_interface<Windows::Graphics::Printing::Workflow::PrintWorkflowSpoolStreamContent>{ using type = Windows::Graphics::Printing::Workflow::IPrintWorkflowSpoolStreamContent; };
template <> struct default_interface<Windows::Graphics::Printing::Workflow::PrintWorkflowStreamTarget>{ using type = Windows::Graphics::Printing::Workflow::IPrintWorkflowStreamTarget; };
template <> struct default_interface<Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedEventArgs>{ using type = Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedEventArgs; };
template <> struct default_interface<Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedOperation>{ using type = Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedOperation; };
template <> struct default_interface<Windows::Graphics::Printing::Workflow::PrintWorkflowTarget>{ using type = Windows::Graphics::Printing::Workflow::IPrintWorkflowTarget; };
template <> struct default_interface<Windows::Graphics::Printing::Workflow::PrintWorkflowTriggerDetails>{ using type = Windows::Graphics::Printing::Workflow::IPrintWorkflowTriggerDetails; };
template <> struct default_interface<Windows::Graphics::Printing::Workflow::PrintWorkflowUIActivatedEventArgs>{ using type = Windows::Graphics::Printing::Workflow::IPrintWorkflowUIActivatedEventArgs; };
template <> struct default_interface<Windows::Graphics::Printing::Workflow::PrintWorkflowXpsDataAvailableEventArgs>{ using type = Windows::Graphics::Printing::Workflow::IPrintWorkflowXpsDataAvailableEventArgs; };

template <> struct abi<Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSession>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_SetupRequested(void* setupEventHandler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_SetupRequested(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_Submitted(void* submittedEventHandler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Submitted(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL get_Status(Windows::Graphics::Printing::Workflow::PrintWorkflowSessionStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL Start() noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSetupRequestedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetUserPrintTicketAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL get_Configuration(void** configuration) noexcept = 0;
    virtual int32_t WINRT_CALL SetRequiresUI() noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Printing::Workflow::IPrintWorkflowConfiguration>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SourceAppDisplayName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_JobTitle(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SessionId(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSession>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_SetupRequested(void* setupEventHandler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_SetupRequested(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_XpsDataAvailable(void* xpsDataAvailableEventHandler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_XpsDataAvailable(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL get_Status(Windows::Graphics::Printing::Workflow::PrintWorkflowSessionStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL Start() noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSetupRequestedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetUserPrintTicketAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL get_Configuration(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelSourceFileContent>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelTargetPackage>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::Graphics::Printing::Workflow::IPrintWorkflowSourceContent>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetJobPrintTicketAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetSourceSpoolDataAsStreamContent(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetSourceSpoolDataAsXpsObjectModel(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Printing::Workflow::IPrintWorkflowSpoolStreamContent>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetInputStream(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Printing::Workflow::IPrintWorkflowStreamTarget>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetOutputStream(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Operation(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetTarget(void* jobPrintTicket, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedOperation>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Complete(Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedStatus status) noexcept = 0;
    virtual int32_t WINRT_CALL get_Configuration(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XpsContent(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Printing::Workflow::IPrintWorkflowTarget>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_TargetAsStream(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TargetAsXpsObjectModelPackage(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Printing::Workflow::IPrintWorkflowTriggerDetails>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_PrintWorkflowSession(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Printing::Workflow::IPrintWorkflowUIActivatedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_PrintWorkflowSession(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Printing::Workflow::IPrintWorkflowXpsDataAvailableEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Operation(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** result) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowBackgroundSession
{
    winrt::event_token SetupRequested(Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSession, Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSetupRequestedEventArgs> const& setupEventHandler) const;
    using SetupRequested_revoker = impl::event_revoker<Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSession, &impl::abi_t<Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSession>::remove_SetupRequested>;
    SetupRequested_revoker SetupRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSession, Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSetupRequestedEventArgs> const& setupEventHandler) const;
    void SetupRequested(winrt::event_token const& token) const noexcept;
    winrt::event_token Submitted(Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSession, Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedEventArgs> const& submittedEventHandler) const;
    using Submitted_revoker = impl::event_revoker<Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSession, &impl::abi_t<Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSession>::remove_Submitted>;
    Submitted_revoker Submitted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSession, Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedEventArgs> const& submittedEventHandler) const;
    void Submitted(winrt::event_token const& token) const noexcept;
    Windows::Graphics::Printing::Workflow::PrintWorkflowSessionStatus Status() const;
    void Start() const;
};
template <> struct consume<Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSession> { template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowBackgroundSession<D>; };

template <typename D>
struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowBackgroundSetupRequestedEventArgs
{
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket> GetUserPrintTicketAsync() const;
    Windows::Graphics::Printing::Workflow::PrintWorkflowConfiguration Configuration() const;
    void SetRequiresUI() const;
    Windows::Foundation::Deferral GetDeferral() const;
};
template <> struct consume<Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSetupRequestedEventArgs> { template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowBackgroundSetupRequestedEventArgs<D>; };

template <typename D>
struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowConfiguration
{
    hstring SourceAppDisplayName() const;
    hstring JobTitle() const;
    hstring SessionId() const;
};
template <> struct consume<Windows::Graphics::Printing::Workflow::IPrintWorkflowConfiguration> { template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowConfiguration<D>; };

template <typename D>
struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowForegroundSession
{
    winrt::event_token SetupRequested(Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSession, Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSetupRequestedEventArgs> const& setupEventHandler) const;
    using SetupRequested_revoker = impl::event_revoker<Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSession, &impl::abi_t<Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSession>::remove_SetupRequested>;
    SetupRequested_revoker SetupRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSession, Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSetupRequestedEventArgs> const& setupEventHandler) const;
    void SetupRequested(winrt::event_token const& token) const noexcept;
    winrt::event_token XpsDataAvailable(Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSession, Windows::Graphics::Printing::Workflow::PrintWorkflowXpsDataAvailableEventArgs> const& xpsDataAvailableEventHandler) const;
    using XpsDataAvailable_revoker = impl::event_revoker<Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSession, &impl::abi_t<Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSession>::remove_XpsDataAvailable>;
    XpsDataAvailable_revoker XpsDataAvailable(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSession, Windows::Graphics::Printing::Workflow::PrintWorkflowXpsDataAvailableEventArgs> const& xpsDataAvailableEventHandler) const;
    void XpsDataAvailable(winrt::event_token const& token) const noexcept;
    Windows::Graphics::Printing::Workflow::PrintWorkflowSessionStatus Status() const;
    void Start() const;
};
template <> struct consume<Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSession> { template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowForegroundSession<D>; };

template <typename D>
struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowForegroundSetupRequestedEventArgs
{
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket> GetUserPrintTicketAsync() const;
    Windows::Graphics::Printing::Workflow::PrintWorkflowConfiguration Configuration() const;
    Windows::Foundation::Deferral GetDeferral() const;
};
template <> struct consume<Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSetupRequestedEventArgs> { template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowForegroundSetupRequestedEventArgs<D>; };

template <typename D>
struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowObjectModelSourceFileContent
{
};
template <> struct consume<Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelSourceFileContent> { template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowObjectModelSourceFileContent<D>; };

template <typename D>
struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowObjectModelTargetPackage
{
};
template <> struct consume<Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelTargetPackage> { template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowObjectModelTargetPackage<D>; };

template <typename D>
struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowSourceContent
{
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket> GetJobPrintTicketAsync() const;
    Windows::Graphics::Printing::Workflow::PrintWorkflowSpoolStreamContent GetSourceSpoolDataAsStreamContent() const;
    Windows::Graphics::Printing::Workflow::PrintWorkflowObjectModelSourceFileContent GetSourceSpoolDataAsXpsObjectModel() const;
};
template <> struct consume<Windows::Graphics::Printing::Workflow::IPrintWorkflowSourceContent> { template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowSourceContent<D>; };

template <typename D>
struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowSpoolStreamContent
{
    Windows::Storage::Streams::IInputStream GetInputStream() const;
};
template <> struct consume<Windows::Graphics::Printing::Workflow::IPrintWorkflowSpoolStreamContent> { template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowSpoolStreamContent<D>; };

template <typename D>
struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowStreamTarget
{
    Windows::Storage::Streams::IOutputStream GetOutputStream() const;
};
template <> struct consume<Windows::Graphics::Printing::Workflow::IPrintWorkflowStreamTarget> { template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowStreamTarget<D>; };

template <typename D>
struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowSubmittedEventArgs
{
    Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedOperation Operation() const;
    Windows::Graphics::Printing::Workflow::PrintWorkflowTarget GetTarget(Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket const& jobPrintTicket) const;
    Windows::Foundation::Deferral GetDeferral() const;
};
template <> struct consume<Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedEventArgs> { template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowSubmittedEventArgs<D>; };

template <typename D>
struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowSubmittedOperation
{
    void Complete(Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedStatus const& status) const;
    Windows::Graphics::Printing::Workflow::PrintWorkflowConfiguration Configuration() const;
    Windows::Graphics::Printing::Workflow::PrintWorkflowSourceContent XpsContent() const;
};
template <> struct consume<Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedOperation> { template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowSubmittedOperation<D>; };

template <typename D>
struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowTarget
{
    Windows::Graphics::Printing::Workflow::PrintWorkflowStreamTarget TargetAsStream() const;
    Windows::Graphics::Printing::Workflow::PrintWorkflowObjectModelTargetPackage TargetAsXpsObjectModelPackage() const;
};
template <> struct consume<Windows::Graphics::Printing::Workflow::IPrintWorkflowTarget> { template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowTarget<D>; };

template <typename D>
struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowTriggerDetails
{
    Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSession PrintWorkflowSession() const;
};
template <> struct consume<Windows::Graphics::Printing::Workflow::IPrintWorkflowTriggerDetails> { template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowTriggerDetails<D>; };

template <typename D>
struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowUIActivatedEventArgs
{
    Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSession PrintWorkflowSession() const;
};
template <> struct consume<Windows::Graphics::Printing::Workflow::IPrintWorkflowUIActivatedEventArgs> { template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowUIActivatedEventArgs<D>; };

template <typename D>
struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowXpsDataAvailableEventArgs
{
    Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedOperation Operation() const;
    Windows::Foundation::Deferral GetDeferral() const;
};
template <> struct consume<Windows::Graphics::Printing::Workflow::IPrintWorkflowXpsDataAvailableEventArgs> { template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowXpsDataAvailableEventArgs<D>; };

}
