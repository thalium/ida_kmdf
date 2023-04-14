// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Foundation::Collections {

struct IPropertySet;

}

WINRT_EXPORT namespace winrt::Windows::Media::Playback {

struct MediaPlaybackItem;

}

WINRT_EXPORT namespace winrt::Windows::Media::Protection {

enum class GraphicsTrustStatus : int32_t
{
    TrustNotRequired = 0,
    TrustEstablished = 1,
    EnvironmentNotSupported = 2,
    DriverNotSupported = 3,
    DriverSigningFailure = 4,
    UnknownFailure = 5,
};

enum class HdcpProtection : int32_t
{
    Off = 0,
    On = 1,
    OnWithTypeEnforcement = 2,
};

enum class HdcpSetProtectionResult : int32_t
{
    Success = 0,
    TimedOut = 1,
    NotSupported = 2,
    UnknownFailure = 3,
};

enum class ProtectionCapabilityResult : int32_t
{
    NotSupported = 0,
    Maybe = 1,
    Probably = 2,
};

enum class RenewalStatus : int32_t
{
    NotStarted = 0,
    UpdatesInProgress = 1,
    UserCancelled = 2,
    AppComponentsMayNeedUpdating = 3,
    NoComponentsFound = 4,
};

enum class RevocationAndRenewalReasons : uint32_t
{
    UserModeComponentLoad = 0x1,
    KernelModeComponentLoad = 0x2,
    AppComponent = 0x4,
    GlobalRevocationListLoadFailed = 0x10,
    InvalidGlobalRevocationListSignature = 0x20,
    GlobalRevocationListAbsent = 0x1000,
    ComponentRevoked = 0x2000,
    InvalidComponentCertificateExtendedKeyUse = 0x4000,
    ComponentCertificateRevoked = 0x8000,
    InvalidComponentCertificateRoot = 0x10000,
    ComponentHighSecurityCertificateRevoked = 0x20000,
    ComponentLowSecurityCertificateRevoked = 0x40000,
    BootDriverVerificationFailed = 0x100000,
    ComponentSignedWithTestCertificate = 0x1000000,
    EncryptionFailure = 0x10000000,
};

struct IComponentLoadFailedEventArgs;
struct IComponentRenewalStatics;
struct IHdcpSession;
struct IMediaProtectionManager;
struct IMediaProtectionPMPServer;
struct IMediaProtectionPMPServerFactory;
struct IMediaProtectionServiceCompletion;
struct IMediaProtectionServiceRequest;
struct IProtectionCapabilities;
struct IRevocationAndRenewalInformation;
struct IRevocationAndRenewalItem;
struct IServiceRequestedEventArgs;
struct IServiceRequestedEventArgs2;
struct ComponentLoadFailedEventArgs;
struct ComponentRenewal;
struct HdcpSession;
struct MediaProtectionManager;
struct MediaProtectionPMPServer;
struct MediaProtectionServiceCompletion;
struct ProtectionCapabilities;
struct RevocationAndRenewalInformation;
struct RevocationAndRenewalItem;
struct ServiceRequestedEventArgs;
struct ComponentLoadFailedEventHandler;
struct RebootNeededEventHandler;
struct ServiceRequestedEventHandler;

}

namespace winrt::impl {

template<> struct is_enum_flag<Windows::Media::Protection::RevocationAndRenewalReasons> : std::true_type {};
template <> struct category<Windows::Media::Protection::IComponentLoadFailedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Protection::IComponentRenewalStatics>{ using type = interface_category; };
template <> struct category<Windows::Media::Protection::IHdcpSession>{ using type = interface_category; };
template <> struct category<Windows::Media::Protection::IMediaProtectionManager>{ using type = interface_category; };
template <> struct category<Windows::Media::Protection::IMediaProtectionPMPServer>{ using type = interface_category; };
template <> struct category<Windows::Media::Protection::IMediaProtectionPMPServerFactory>{ using type = interface_category; };
template <> struct category<Windows::Media::Protection::IMediaProtectionServiceCompletion>{ using type = interface_category; };
template <> struct category<Windows::Media::Protection::IMediaProtectionServiceRequest>{ using type = interface_category; };
template <> struct category<Windows::Media::Protection::IProtectionCapabilities>{ using type = interface_category; };
template <> struct category<Windows::Media::Protection::IRevocationAndRenewalInformation>{ using type = interface_category; };
template <> struct category<Windows::Media::Protection::IRevocationAndRenewalItem>{ using type = interface_category; };
template <> struct category<Windows::Media::Protection::IServiceRequestedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Protection::IServiceRequestedEventArgs2>{ using type = interface_category; };
template <> struct category<Windows::Media::Protection::ComponentLoadFailedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Protection::ComponentRenewal>{ using type = class_category; };
template <> struct category<Windows::Media::Protection::HdcpSession>{ using type = class_category; };
template <> struct category<Windows::Media::Protection::MediaProtectionManager>{ using type = class_category; };
template <> struct category<Windows::Media::Protection::MediaProtectionPMPServer>{ using type = class_category; };
template <> struct category<Windows::Media::Protection::MediaProtectionServiceCompletion>{ using type = class_category; };
template <> struct category<Windows::Media::Protection::ProtectionCapabilities>{ using type = class_category; };
template <> struct category<Windows::Media::Protection::RevocationAndRenewalInformation>{ using type = class_category; };
template <> struct category<Windows::Media::Protection::RevocationAndRenewalItem>{ using type = class_category; };
template <> struct category<Windows::Media::Protection::ServiceRequestedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Protection::GraphicsTrustStatus>{ using type = enum_category; };
template <> struct category<Windows::Media::Protection::HdcpProtection>{ using type = enum_category; };
template <> struct category<Windows::Media::Protection::HdcpSetProtectionResult>{ using type = enum_category; };
template <> struct category<Windows::Media::Protection::ProtectionCapabilityResult>{ using type = enum_category; };
template <> struct category<Windows::Media::Protection::RenewalStatus>{ using type = enum_category; };
template <> struct category<Windows::Media::Protection::RevocationAndRenewalReasons>{ using type = enum_category; };
template <> struct category<Windows::Media::Protection::ComponentLoadFailedEventHandler>{ using type = delegate_category; };
template <> struct category<Windows::Media::Protection::RebootNeededEventHandler>{ using type = delegate_category; };
template <> struct category<Windows::Media::Protection::ServiceRequestedEventHandler>{ using type = delegate_category; };
template <> struct name<Windows::Media::Protection::IComponentLoadFailedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Protection.IComponentLoadFailedEventArgs" }; };
template <> struct name<Windows::Media::Protection::IComponentRenewalStatics>{ static constexpr auto & value{ L"Windows.Media.Protection.IComponentRenewalStatics" }; };
template <> struct name<Windows::Media::Protection::IHdcpSession>{ static constexpr auto & value{ L"Windows.Media.Protection.IHdcpSession" }; };
template <> struct name<Windows::Media::Protection::IMediaProtectionManager>{ static constexpr auto & value{ L"Windows.Media.Protection.IMediaProtectionManager" }; };
template <> struct name<Windows::Media::Protection::IMediaProtectionPMPServer>{ static constexpr auto & value{ L"Windows.Media.Protection.IMediaProtectionPMPServer" }; };
template <> struct name<Windows::Media::Protection::IMediaProtectionPMPServerFactory>{ static constexpr auto & value{ L"Windows.Media.Protection.IMediaProtectionPMPServerFactory" }; };
template <> struct name<Windows::Media::Protection::IMediaProtectionServiceCompletion>{ static constexpr auto & value{ L"Windows.Media.Protection.IMediaProtectionServiceCompletion" }; };
template <> struct name<Windows::Media::Protection::IMediaProtectionServiceRequest>{ static constexpr auto & value{ L"Windows.Media.Protection.IMediaProtectionServiceRequest" }; };
template <> struct name<Windows::Media::Protection::IProtectionCapabilities>{ static constexpr auto & value{ L"Windows.Media.Protection.IProtectionCapabilities" }; };
template <> struct name<Windows::Media::Protection::IRevocationAndRenewalInformation>{ static constexpr auto & value{ L"Windows.Media.Protection.IRevocationAndRenewalInformation" }; };
template <> struct name<Windows::Media::Protection::IRevocationAndRenewalItem>{ static constexpr auto & value{ L"Windows.Media.Protection.IRevocationAndRenewalItem" }; };
template <> struct name<Windows::Media::Protection::IServiceRequestedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Protection.IServiceRequestedEventArgs" }; };
template <> struct name<Windows::Media::Protection::IServiceRequestedEventArgs2>{ static constexpr auto & value{ L"Windows.Media.Protection.IServiceRequestedEventArgs2" }; };
template <> struct name<Windows::Media::Protection::ComponentLoadFailedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Protection.ComponentLoadFailedEventArgs" }; };
template <> struct name<Windows::Media::Protection::ComponentRenewal>{ static constexpr auto & value{ L"Windows.Media.Protection.ComponentRenewal" }; };
template <> struct name<Windows::Media::Protection::HdcpSession>{ static constexpr auto & value{ L"Windows.Media.Protection.HdcpSession" }; };
template <> struct name<Windows::Media::Protection::MediaProtectionManager>{ static constexpr auto & value{ L"Windows.Media.Protection.MediaProtectionManager" }; };
template <> struct name<Windows::Media::Protection::MediaProtectionPMPServer>{ static constexpr auto & value{ L"Windows.Media.Protection.MediaProtectionPMPServer" }; };
template <> struct name<Windows::Media::Protection::MediaProtectionServiceCompletion>{ static constexpr auto & value{ L"Windows.Media.Protection.MediaProtectionServiceCompletion" }; };
template <> struct name<Windows::Media::Protection::ProtectionCapabilities>{ static constexpr auto & value{ L"Windows.Media.Protection.ProtectionCapabilities" }; };
template <> struct name<Windows::Media::Protection::RevocationAndRenewalInformation>{ static constexpr auto & value{ L"Windows.Media.Protection.RevocationAndRenewalInformation" }; };
template <> struct name<Windows::Media::Protection::RevocationAndRenewalItem>{ static constexpr auto & value{ L"Windows.Media.Protection.RevocationAndRenewalItem" }; };
template <> struct name<Windows::Media::Protection::ServiceRequestedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Protection.ServiceRequestedEventArgs" }; };
template <> struct name<Windows::Media::Protection::GraphicsTrustStatus>{ static constexpr auto & value{ L"Windows.Media.Protection.GraphicsTrustStatus" }; };
template <> struct name<Windows::Media::Protection::HdcpProtection>{ static constexpr auto & value{ L"Windows.Media.Protection.HdcpProtection" }; };
template <> struct name<Windows::Media::Protection::HdcpSetProtectionResult>{ static constexpr auto & value{ L"Windows.Media.Protection.HdcpSetProtectionResult" }; };
template <> struct name<Windows::Media::Protection::ProtectionCapabilityResult>{ static constexpr auto & value{ L"Windows.Media.Protection.ProtectionCapabilityResult" }; };
template <> struct name<Windows::Media::Protection::RenewalStatus>{ static constexpr auto & value{ L"Windows.Media.Protection.RenewalStatus" }; };
template <> struct name<Windows::Media::Protection::RevocationAndRenewalReasons>{ static constexpr auto & value{ L"Windows.Media.Protection.RevocationAndRenewalReasons" }; };
template <> struct name<Windows::Media::Protection::ComponentLoadFailedEventHandler>{ static constexpr auto & value{ L"Windows.Media.Protection.ComponentLoadFailedEventHandler" }; };
template <> struct name<Windows::Media::Protection::RebootNeededEventHandler>{ static constexpr auto & value{ L"Windows.Media.Protection.RebootNeededEventHandler" }; };
template <> struct name<Windows::Media::Protection::ServiceRequestedEventHandler>{ static constexpr auto & value{ L"Windows.Media.Protection.ServiceRequestedEventHandler" }; };
template <> struct guid_storage<Windows::Media::Protection::IComponentLoadFailedEventArgs>{ static constexpr guid value{ 0x95972E93,0x7746,0x417E,{ 0x84,0x95,0xF0,0x31,0xBB,0xC5,0x86,0x2C } }; };
template <> struct guid_storage<Windows::Media::Protection::IComponentRenewalStatics>{ static constexpr guid value{ 0x6FFBCD67,0xB795,0x48C5,{ 0x8B,0x7B,0xA7,0xC4,0xEF,0xE2,0x02,0xE3 } }; };
template <> struct guid_storage<Windows::Media::Protection::IHdcpSession>{ static constexpr guid value{ 0x718845E9,0x64D7,0x426D,{ 0x80,0x9B,0x1B,0xE4,0x61,0x94,0x1A,0x2A } }; };
template <> struct guid_storage<Windows::Media::Protection::IMediaProtectionManager>{ static constexpr guid value{ 0x45694947,0xC741,0x434B,{ 0xA7,0x9E,0x47,0x4C,0x12,0xD9,0x3D,0x2F } }; };
template <> struct guid_storage<Windows::Media::Protection::IMediaProtectionPMPServer>{ static constexpr guid value{ 0x0C111226,0x7B26,0x4D31,{ 0x95,0xBB,0x9C,0x1B,0x08,0xEF,0x7F,0xC0 } }; };
template <> struct guid_storage<Windows::Media::Protection::IMediaProtectionPMPServerFactory>{ static constexpr guid value{ 0x602C8E5E,0xF7D2,0x487E,{ 0xAF,0x91,0xDB,0xC4,0x25,0x2B,0x21,0x82 } }; };
template <> struct guid_storage<Windows::Media::Protection::IMediaProtectionServiceCompletion>{ static constexpr guid value{ 0x8B5CCA18,0xCFD5,0x44EE,{ 0xA2,0xED,0xDF,0x76,0x01,0x0C,0x14,0xB5 } }; };
template <> struct guid_storage<Windows::Media::Protection::IMediaProtectionServiceRequest>{ static constexpr guid value{ 0xB1DE0EA6,0x2094,0x478D,{ 0x87,0xA4,0x8B,0x95,0x20,0x0F,0x85,0xC6 } }; };
template <> struct guid_storage<Windows::Media::Protection::IProtectionCapabilities>{ static constexpr guid value{ 0xC7AC5D7E,0x7480,0x4D29,{ 0xA4,0x64,0x7B,0xCD,0x91,0x3D,0xD8,0xE4 } }; };
template <> struct guid_storage<Windows::Media::Protection::IRevocationAndRenewalInformation>{ static constexpr guid value{ 0xF3A1937B,0x2501,0x439E,{ 0xA6,0xE7,0x6F,0xC9,0x5E,0x17,0x5F,0xCF } }; };
template <> struct guid_storage<Windows::Media::Protection::IRevocationAndRenewalItem>{ static constexpr guid value{ 0x3099C20C,0x3CF0,0x49EA,{ 0x90,0x2D,0xCA,0xF3,0x2D,0x2D,0xDE,0x2C } }; };
template <> struct guid_storage<Windows::Media::Protection::IServiceRequestedEventArgs>{ static constexpr guid value{ 0x34283BAF,0xABB4,0x4FC1,{ 0xBD,0x89,0x93,0xF1,0x06,0x57,0x3A,0x49 } }; };
template <> struct guid_storage<Windows::Media::Protection::IServiceRequestedEventArgs2>{ static constexpr guid value{ 0x553C69D6,0xFAFE,0x4128,{ 0x8D,0xFA,0x13,0x0E,0x39,0x8A,0x13,0xA7 } }; };
template <> struct guid_storage<Windows::Media::Protection::ComponentLoadFailedEventHandler>{ static constexpr guid value{ 0x95DA643C,0x6DB9,0x424B,{ 0x86,0xCA,0x09,0x1A,0xF4,0x32,0x08,0x1C } }; };
template <> struct guid_storage<Windows::Media::Protection::RebootNeededEventHandler>{ static constexpr guid value{ 0x64E12A45,0x973B,0x4A3A,{ 0xB2,0x60,0x91,0x89,0x8A,0x49,0xA8,0x2C } }; };
template <> struct guid_storage<Windows::Media::Protection::ServiceRequestedEventHandler>{ static constexpr guid value{ 0xD2D690BA,0xCAC9,0x48E1,{ 0x95,0xC0,0xD3,0x84,0x95,0xA8,0x40,0x55 } }; };
template <> struct default_interface<Windows::Media::Protection::ComponentLoadFailedEventArgs>{ using type = Windows::Media::Protection::IComponentLoadFailedEventArgs; };
template <> struct default_interface<Windows::Media::Protection::HdcpSession>{ using type = Windows::Media::Protection::IHdcpSession; };
template <> struct default_interface<Windows::Media::Protection::MediaProtectionManager>{ using type = Windows::Media::Protection::IMediaProtectionManager; };
template <> struct default_interface<Windows::Media::Protection::MediaProtectionPMPServer>{ using type = Windows::Media::Protection::IMediaProtectionPMPServer; };
template <> struct default_interface<Windows::Media::Protection::MediaProtectionServiceCompletion>{ using type = Windows::Media::Protection::IMediaProtectionServiceCompletion; };
template <> struct default_interface<Windows::Media::Protection::ProtectionCapabilities>{ using type = Windows::Media::Protection::IProtectionCapabilities; };
template <> struct default_interface<Windows::Media::Protection::RevocationAndRenewalInformation>{ using type = Windows::Media::Protection::IRevocationAndRenewalInformation; };
template <> struct default_interface<Windows::Media::Protection::RevocationAndRenewalItem>{ using type = Windows::Media::Protection::IRevocationAndRenewalItem; };
template <> struct default_interface<Windows::Media::Protection::ServiceRequestedEventArgs>{ using type = Windows::Media::Protection::IServiceRequestedEventArgs; };

template <> struct abi<Windows::Media::Protection::IComponentLoadFailedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Information(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Completion(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Protection::IComponentRenewalStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL RenewSystemComponentsAsync(void* information, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Media::Protection::IHdcpSession>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL IsEffectiveProtectionAtLeast(Windows::Media::Protection::HdcpProtection protection, bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetEffectiveProtection(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL SetDesiredMinProtectionAsync(Windows::Media::Protection::HdcpProtection protection, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL add_ProtectionChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ProtectionChanged(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Media::Protection::IMediaProtectionManager>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_ServiceRequested(void* handler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ServiceRequested(winrt::event_token cookie) noexcept = 0;
    virtual int32_t WINRT_CALL add_RebootNeeded(void* handler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_RebootNeeded(winrt::event_token cookie) noexcept = 0;
    virtual int32_t WINRT_CALL add_ComponentLoadFailed(void* handler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ComponentLoadFailed(winrt::event_token cookie) noexcept = 0;
    virtual int32_t WINRT_CALL get_Properties(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Protection::IMediaProtectionPMPServer>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Properties(void** ppProperties) noexcept = 0;
};};

template <> struct abi<Windows::Media::Protection::IMediaProtectionPMPServerFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreatePMPServer(void* pProperties, void** ppObject) noexcept = 0;
};};

template <> struct abi<Windows::Media::Protection::IMediaProtectionServiceCompletion>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Complete(bool success) noexcept = 0;
};};

template <> struct abi<Windows::Media::Protection::IMediaProtectionServiceRequest>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ProtectionSystem(winrt::guid* system) noexcept = 0;
    virtual int32_t WINRT_CALL get_Type(winrt::guid* type) noexcept = 0;
};};

template <> struct abi<Windows::Media::Protection::IProtectionCapabilities>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL IsTypeSupported(void* type, void* keySystem, Windows::Media::Protection::ProtectionCapabilityResult* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Protection::IRevocationAndRenewalInformation>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Items(void** items) noexcept = 0;
};};

template <> struct abi<Windows::Media::Protection::IRevocationAndRenewalItem>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Reasons(Windows::Media::Protection::RevocationAndRenewalReasons* reasons) noexcept = 0;
    virtual int32_t WINRT_CALL get_HeaderHash(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PublicKeyHash(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Name(void** name) noexcept = 0;
    virtual int32_t WINRT_CALL get_RenewalId(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Protection::IServiceRequestedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Request(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Completion(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Protection::IServiceRequestedEventArgs2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_MediaPlaybackItem(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Protection::ComponentLoadFailedEventHandler>{ struct type : IUnknown
{
    virtual int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept = 0;
};};

template <> struct abi<Windows::Media::Protection::RebootNeededEventHandler>{ struct type : IUnknown
{
    virtual int32_t WINRT_CALL Invoke(void* sender) noexcept = 0;
};};

template <> struct abi<Windows::Media::Protection::ServiceRequestedEventHandler>{ struct type : IUnknown
{
    virtual int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Media_Protection_IComponentLoadFailedEventArgs
{
    Windows::Media::Protection::RevocationAndRenewalInformation Information() const;
    Windows::Media::Protection::MediaProtectionServiceCompletion Completion() const;
};
template <> struct consume<Windows::Media::Protection::IComponentLoadFailedEventArgs> { template <typename D> using type = consume_Windows_Media_Protection_IComponentLoadFailedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Protection_IComponentRenewalStatics
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Protection::RenewalStatus, uint32_t> RenewSystemComponentsAsync(Windows::Media::Protection::RevocationAndRenewalInformation const& information) const;
};
template <> struct consume<Windows::Media::Protection::IComponentRenewalStatics> { template <typename D> using type = consume_Windows_Media_Protection_IComponentRenewalStatics<D>; };

template <typename D>
struct consume_Windows_Media_Protection_IHdcpSession
{
    bool IsEffectiveProtectionAtLeast(Windows::Media::Protection::HdcpProtection const& protection) const;
    Windows::Foundation::IReference<Windows::Media::Protection::HdcpProtection> GetEffectiveProtection() const;
    Windows::Foundation::IAsyncOperation<Windows::Media::Protection::HdcpSetProtectionResult> SetDesiredMinProtectionAsync(Windows::Media::Protection::HdcpProtection const& protection) const;
    winrt::event_token ProtectionChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Protection::HdcpSession, Windows::Foundation::IInspectable> const& handler) const;
    using ProtectionChanged_revoker = impl::event_revoker<Windows::Media::Protection::IHdcpSession, &impl::abi_t<Windows::Media::Protection::IHdcpSession>::remove_ProtectionChanged>;
    ProtectionChanged_revoker ProtectionChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Protection::HdcpSession, Windows::Foundation::IInspectable> const& handler) const;
    void ProtectionChanged(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Media::Protection::IHdcpSession> { template <typename D> using type = consume_Windows_Media_Protection_IHdcpSession<D>; };

template <typename D>
struct consume_Windows_Media_Protection_IMediaProtectionManager
{
    winrt::event_token ServiceRequested(Windows::Media::Protection::ServiceRequestedEventHandler const& handler) const;
    using ServiceRequested_revoker = impl::event_revoker<Windows::Media::Protection::IMediaProtectionManager, &impl::abi_t<Windows::Media::Protection::IMediaProtectionManager>::remove_ServiceRequested>;
    ServiceRequested_revoker ServiceRequested(auto_revoke_t, Windows::Media::Protection::ServiceRequestedEventHandler const& handler) const;
    void ServiceRequested(winrt::event_token const& cookie) const noexcept;
    winrt::event_token RebootNeeded(Windows::Media::Protection::RebootNeededEventHandler const& handler) const;
    using RebootNeeded_revoker = impl::event_revoker<Windows::Media::Protection::IMediaProtectionManager, &impl::abi_t<Windows::Media::Protection::IMediaProtectionManager>::remove_RebootNeeded>;
    RebootNeeded_revoker RebootNeeded(auto_revoke_t, Windows::Media::Protection::RebootNeededEventHandler const& handler) const;
    void RebootNeeded(winrt::event_token const& cookie) const noexcept;
    winrt::event_token ComponentLoadFailed(Windows::Media::Protection::ComponentLoadFailedEventHandler const& handler) const;
    using ComponentLoadFailed_revoker = impl::event_revoker<Windows::Media::Protection::IMediaProtectionManager, &impl::abi_t<Windows::Media::Protection::IMediaProtectionManager>::remove_ComponentLoadFailed>;
    ComponentLoadFailed_revoker ComponentLoadFailed(auto_revoke_t, Windows::Media::Protection::ComponentLoadFailedEventHandler const& handler) const;
    void ComponentLoadFailed(winrt::event_token const& cookie) const noexcept;
    Windows::Foundation::Collections::IPropertySet Properties() const;
};
template <> struct consume<Windows::Media::Protection::IMediaProtectionManager> { template <typename D> using type = consume_Windows_Media_Protection_IMediaProtectionManager<D>; };

template <typename D>
struct consume_Windows_Media_Protection_IMediaProtectionPMPServer
{
    Windows::Foundation::Collections::IPropertySet Properties() const;
};
template <> struct consume<Windows::Media::Protection::IMediaProtectionPMPServer> { template <typename D> using type = consume_Windows_Media_Protection_IMediaProtectionPMPServer<D>; };

template <typename D>
struct consume_Windows_Media_Protection_IMediaProtectionPMPServerFactory
{
    Windows::Media::Protection::MediaProtectionPMPServer CreatePMPServer(Windows::Foundation::Collections::IPropertySet const& pProperties) const;
};
template <> struct consume<Windows::Media::Protection::IMediaProtectionPMPServerFactory> { template <typename D> using type = consume_Windows_Media_Protection_IMediaProtectionPMPServerFactory<D>; };

template <typename D>
struct consume_Windows_Media_Protection_IMediaProtectionServiceCompletion
{
    void Complete(bool success) const;
};
template <> struct consume<Windows::Media::Protection::IMediaProtectionServiceCompletion> { template <typename D> using type = consume_Windows_Media_Protection_IMediaProtectionServiceCompletion<D>; };

template <typename D>
struct consume_Windows_Media_Protection_IMediaProtectionServiceRequest
{
    winrt::guid ProtectionSystem() const;
    winrt::guid Type() const;
};
template <> struct consume<Windows::Media::Protection::IMediaProtectionServiceRequest> { template <typename D> using type = consume_Windows_Media_Protection_IMediaProtectionServiceRequest<D>; };

template <typename D>
struct consume_Windows_Media_Protection_IProtectionCapabilities
{
    Windows::Media::Protection::ProtectionCapabilityResult IsTypeSupported(param::hstring const& type, param::hstring const& keySystem) const;
};
template <> struct consume<Windows::Media::Protection::IProtectionCapabilities> { template <typename D> using type = consume_Windows_Media_Protection_IProtectionCapabilities<D>; };

template <typename D>
struct consume_Windows_Media_Protection_IRevocationAndRenewalInformation
{
    Windows::Foundation::Collections::IVector<Windows::Media::Protection::RevocationAndRenewalItem> Items() const;
};
template <> struct consume<Windows::Media::Protection::IRevocationAndRenewalInformation> { template <typename D> using type = consume_Windows_Media_Protection_IRevocationAndRenewalInformation<D>; };

template <typename D>
struct consume_Windows_Media_Protection_IRevocationAndRenewalItem
{
    Windows::Media::Protection::RevocationAndRenewalReasons Reasons() const;
    hstring HeaderHash() const;
    hstring PublicKeyHash() const;
    hstring Name() const;
    hstring RenewalId() const;
};
template <> struct consume<Windows::Media::Protection::IRevocationAndRenewalItem> { template <typename D> using type = consume_Windows_Media_Protection_IRevocationAndRenewalItem<D>; };

template <typename D>
struct consume_Windows_Media_Protection_IServiceRequestedEventArgs
{
    Windows::Media::Protection::IMediaProtectionServiceRequest Request() const;
    Windows::Media::Protection::MediaProtectionServiceCompletion Completion() const;
};
template <> struct consume<Windows::Media::Protection::IServiceRequestedEventArgs> { template <typename D> using type = consume_Windows_Media_Protection_IServiceRequestedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Protection_IServiceRequestedEventArgs2
{
    Windows::Media::Playback::MediaPlaybackItem MediaPlaybackItem() const;
};
template <> struct consume<Windows::Media::Protection::IServiceRequestedEventArgs2> { template <typename D> using type = consume_Windows_Media_Protection_IServiceRequestedEventArgs2<D>; };

}
