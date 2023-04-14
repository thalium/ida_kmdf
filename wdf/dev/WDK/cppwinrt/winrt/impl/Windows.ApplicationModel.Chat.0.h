// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Media::MediaProperties {

struct MediaEncodingProfile;

}

WINRT_EXPORT namespace winrt::Windows::Security::Credentials {

struct WebAccount;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IRandomAccessStreamReference;

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Chat {

enum class ChatConversationThreadingKind : int32_t
{
    Participants = 0,
    ContactId = 1,
    ConversationId = 2,
    Custom = 3,
};

enum class ChatItemKind : int32_t
{
    Message = 0,
    Conversation = 1,
};

enum class ChatMessageChangeType : int32_t
{
    MessageCreated = 0,
    MessageModified = 1,
    MessageDeleted = 2,
    ChangeTrackingLost = 3,
};

enum class ChatMessageKind : int32_t
{
    Standard = 0,
    FileTransferRequest = 1,
    TransportCustom = 2,
    JoinedConversation = 3,
    LeftConversation = 4,
    OtherParticipantJoinedConversation = 5,
    OtherParticipantLeftConversation = 6,
};

enum class ChatMessageOperatorKind : int32_t
{
    Unspecified = 0,
    Sms = 1,
    Mms = 2,
    Rcs = 3,
};

enum class ChatMessageStatus : int32_t
{
    Draft = 0,
    Sending = 1,
    Sent = 2,
    SendRetryNeeded = 3,
    SendFailed = 4,
    Received = 5,
    ReceiveDownloadNeeded = 6,
    ReceiveDownloadFailed = 7,
    ReceiveDownloading = 8,
    Deleted = 9,
    Declined = 10,
    Cancelled = 11,
    Recalled = 12,
    ReceiveRetryNeeded = 13,
};

enum class ChatMessageTransportKind : int32_t
{
    Text = 0,
    Untriaged = 1,
    Blocked = 2,
    Custom = 3,
};

enum class ChatMessageValidationStatus : int32_t
{
    Valid = 0,
    NoRecipients = 1,
    InvalidData = 2,
    MessageTooLarge = 3,
    TooManyRecipients = 4,
    TransportInactive = 5,
    TransportNotFound = 6,
    TooManyAttachments = 7,
    InvalidRecipients = 8,
    InvalidBody = 9,
    InvalidOther = 10,
    ValidWithLargeMessage = 11,
    VoiceRoamingRestriction = 12,
    DataRoamingRestriction = 13,
};

enum class ChatRestoreHistorySpan : int32_t
{
    LastMonth = 0,
    LastYear = 1,
    AnyTime = 2,
};

enum class ChatStoreChangedEventKind : int32_t
{
    NotificationsMissed = 0,
    StoreModified = 1,
    MessageCreated = 2,
    MessageModified = 3,
    MessageDeleted = 4,
    ConversationModified = 5,
    ConversationDeleted = 6,
    ConversationTransportDeleted = 7,
};

enum class ChatTransportErrorCodeCategory : int32_t
{
    None = 0,
    Http = 1,
    Network = 2,
    MmsServer = 3,
};

enum class ChatTransportInterpretedErrorCode : int32_t
{
    None = 0,
    Unknown = 1,
    InvalidRecipientAddress = 2,
    NetworkConnectivity = 3,
    ServiceDenied = 4,
    Timeout = 5,
};

enum class RcsServiceKind : int32_t
{
    Chat = 0,
    GroupChat = 1,
    FileTransfer = 2,
    Capability = 3,
};

struct IChatCapabilities;
struct IChatCapabilitiesManagerStatics;
struct IChatCapabilitiesManagerStatics2;
struct IChatConversation;
struct IChatConversation2;
struct IChatConversationReader;
struct IChatConversationThreadingInfo;
struct IChatItem;
struct IChatMessage;
struct IChatMessage2;
struct IChatMessage3;
struct IChatMessage4;
struct IChatMessageAttachment;
struct IChatMessageAttachment2;
struct IChatMessageAttachmentFactory;
struct IChatMessageBlockingStatic;
struct IChatMessageChange;
struct IChatMessageChangeReader;
struct IChatMessageChangeTracker;
struct IChatMessageChangedDeferral;
struct IChatMessageChangedEventArgs;
struct IChatMessageManager2Statics;
struct IChatMessageManagerStatic;
struct IChatMessageManagerStatics3;
struct IChatMessageNotificationTriggerDetails;
struct IChatMessageNotificationTriggerDetails2;
struct IChatMessageReader;
struct IChatMessageReader2;
struct IChatMessageStore;
struct IChatMessageStore2;
struct IChatMessageStore3;
struct IChatMessageStoreChangedEventArgs;
struct IChatMessageTransport;
struct IChatMessageTransport2;
struct IChatMessageTransportConfiguration;
struct IChatMessageValidationResult;
struct IChatQueryOptions;
struct IChatRecipientDeliveryInfo;
struct IChatSearchReader;
struct IChatSyncConfiguration;
struct IChatSyncManager;
struct IRcsEndUserMessage;
struct IRcsEndUserMessageAction;
struct IRcsEndUserMessageAvailableEventArgs;
struct IRcsEndUserMessageAvailableTriggerDetails;
struct IRcsEndUserMessageManager;
struct IRcsManagerStatics;
struct IRcsManagerStatics2;
struct IRcsServiceKindSupportedChangedEventArgs;
struct IRcsTransport;
struct IRcsTransportConfiguration;
struct IRemoteParticipantComposingChangedEventArgs;
struct ChatCapabilities;
struct ChatCapabilitiesManager;
struct ChatConversation;
struct ChatConversationReader;
struct ChatConversationThreadingInfo;
struct ChatMessage;
struct ChatMessageAttachment;
struct ChatMessageBlocking;
struct ChatMessageChange;
struct ChatMessageChangeReader;
struct ChatMessageChangeTracker;
struct ChatMessageChangedDeferral;
struct ChatMessageChangedEventArgs;
struct ChatMessageManager;
struct ChatMessageNotificationTriggerDetails;
struct ChatMessageReader;
struct ChatMessageStore;
struct ChatMessageStoreChangedEventArgs;
struct ChatMessageTransport;
struct ChatMessageTransportConfiguration;
struct ChatMessageValidationResult;
struct ChatQueryOptions;
struct ChatRecipientDeliveryInfo;
struct ChatSearchReader;
struct ChatSyncConfiguration;
struct ChatSyncManager;
struct RcsEndUserMessage;
struct RcsEndUserMessageAction;
struct RcsEndUserMessageAvailableEventArgs;
struct RcsEndUserMessageAvailableTriggerDetails;
struct RcsEndUserMessageManager;
struct RcsManager;
struct RcsServiceKindSupportedChangedEventArgs;
struct RcsTransport;
struct RcsTransportConfiguration;
struct RemoteParticipantComposingChangedEventArgs;

}

namespace winrt::impl {

template <> struct category<Windows::ApplicationModel::Chat::IChatCapabilities>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatConversation>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatConversation2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatConversationReader>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatConversationThreadingInfo>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatItem>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatMessage>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatMessage2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatMessage3>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatMessage4>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatMessageAttachment>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatMessageAttachment2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatMessageAttachmentFactory>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatMessageBlockingStatic>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatMessageChange>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatMessageChangeReader>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatMessageChangeTracker>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatMessageChangedDeferral>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatMessageChangedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatMessageManager2Statics>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatMessageManagerStatic>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatMessageManagerStatics3>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatMessageNotificationTriggerDetails>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatMessageNotificationTriggerDetails2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatMessageReader>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatMessageReader2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatMessageStore>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatMessageStore2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatMessageStore3>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatMessageStoreChangedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatMessageTransport>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatMessageTransport2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatMessageTransportConfiguration>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatMessageValidationResult>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatQueryOptions>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatRecipientDeliveryInfo>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatSearchReader>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatSyncConfiguration>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IChatSyncManager>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IRcsEndUserMessage>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IRcsEndUserMessageAction>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IRcsEndUserMessageAvailableEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IRcsEndUserMessageAvailableTriggerDetails>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IRcsEndUserMessageManager>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IRcsManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IRcsManagerStatics2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IRcsServiceKindSupportedChangedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IRcsTransport>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IRcsTransportConfiguration>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::IRemoteParticipantComposingChangedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatCapabilities>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatCapabilitiesManager>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatConversation>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatConversationReader>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatConversationThreadingInfo>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatMessage>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatMessageAttachment>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatMessageBlocking>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatMessageChange>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatMessageChangeReader>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatMessageChangeTracker>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatMessageChangedDeferral>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatMessageChangedEventArgs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatMessageManager>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatMessageNotificationTriggerDetails>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatMessageReader>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatMessageStore>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatMessageStoreChangedEventArgs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatMessageTransport>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatMessageTransportConfiguration>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatMessageValidationResult>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatQueryOptions>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatRecipientDeliveryInfo>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatSearchReader>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatSyncConfiguration>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatSyncManager>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::RcsEndUserMessage>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::RcsEndUserMessageAction>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::RcsEndUserMessageAvailableEventArgs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::RcsEndUserMessageAvailableTriggerDetails>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::RcsEndUserMessageManager>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::RcsManager>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::RcsServiceKindSupportedChangedEventArgs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::RcsTransport>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::RcsTransportConfiguration>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::RemoteParticipantComposingChangedEventArgs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatConversationThreadingKind>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatItemKind>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatMessageChangeType>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatMessageKind>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatMessageOperatorKind>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatMessageStatus>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatMessageTransportKind>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatMessageValidationStatus>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatRestoreHistorySpan>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatStoreChangedEventKind>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatTransportErrorCodeCategory>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Chat::ChatTransportInterpretedErrorCode>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Chat::RcsServiceKind>{ using type = enum_category; };
template <> struct name<Windows::ApplicationModel::Chat::IChatCapabilities>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatCapabilities" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatCapabilitiesManagerStatics" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics2>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatCapabilitiesManagerStatics2" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatConversation>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatConversation" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatConversation2>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatConversation2" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatConversationReader>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatConversationReader" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatConversationThreadingInfo>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatConversationThreadingInfo" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatItem>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatItem" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatMessage>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatMessage" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatMessage2>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatMessage2" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatMessage3>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatMessage3" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatMessage4>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatMessage4" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatMessageAttachment>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatMessageAttachment" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatMessageAttachment2>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatMessageAttachment2" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatMessageAttachmentFactory>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatMessageAttachmentFactory" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatMessageBlockingStatic>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatMessageBlockingStatic" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatMessageChange>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatMessageChange" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatMessageChangeReader>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatMessageChangeReader" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatMessageChangeTracker>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatMessageChangeTracker" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatMessageChangedDeferral>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatMessageChangedDeferral" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatMessageChangedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatMessageChangedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatMessageManager2Statics>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatMessageManager2Statics" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatMessageManagerStatic>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatMessageManagerStatic" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatMessageManagerStatics3>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatMessageManagerStatics3" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatMessageNotificationTriggerDetails>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatMessageNotificationTriggerDetails" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatMessageNotificationTriggerDetails2>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatMessageNotificationTriggerDetails2" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatMessageReader>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatMessageReader" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatMessageReader2>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatMessageReader2" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatMessageStore>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatMessageStore" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatMessageStore2>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatMessageStore2" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatMessageStore3>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatMessageStore3" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatMessageStoreChangedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatMessageStoreChangedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatMessageTransport>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatMessageTransport" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatMessageTransport2>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatMessageTransport2" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatMessageTransportConfiguration>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatMessageTransportConfiguration" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatMessageValidationResult>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatMessageValidationResult" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatQueryOptions>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatQueryOptions" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatRecipientDeliveryInfo>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatRecipientDeliveryInfo" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatSearchReader>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatSearchReader" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatSyncConfiguration>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatSyncConfiguration" }; };
template <> struct name<Windows::ApplicationModel::Chat::IChatSyncManager>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IChatSyncManager" }; };
template <> struct name<Windows::ApplicationModel::Chat::IRcsEndUserMessage>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IRcsEndUserMessage" }; };
template <> struct name<Windows::ApplicationModel::Chat::IRcsEndUserMessageAction>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IRcsEndUserMessageAction" }; };
template <> struct name<Windows::ApplicationModel::Chat::IRcsEndUserMessageAvailableEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IRcsEndUserMessageAvailableEventArgs" }; };
template <> struct name<Windows::ApplicationModel::Chat::IRcsEndUserMessageAvailableTriggerDetails>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IRcsEndUserMessageAvailableTriggerDetails" }; };
template <> struct name<Windows::ApplicationModel::Chat::IRcsEndUserMessageManager>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IRcsEndUserMessageManager" }; };
template <> struct name<Windows::ApplicationModel::Chat::IRcsManagerStatics>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IRcsManagerStatics" }; };
template <> struct name<Windows::ApplicationModel::Chat::IRcsManagerStatics2>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IRcsManagerStatics2" }; };
template <> struct name<Windows::ApplicationModel::Chat::IRcsServiceKindSupportedChangedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IRcsServiceKindSupportedChangedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::Chat::IRcsTransport>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IRcsTransport" }; };
template <> struct name<Windows::ApplicationModel::Chat::IRcsTransportConfiguration>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IRcsTransportConfiguration" }; };
template <> struct name<Windows::ApplicationModel::Chat::IRemoteParticipantComposingChangedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.IRemoteParticipantComposingChangedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatCapabilities>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatCapabilities" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatCapabilitiesManager>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatCapabilitiesManager" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatConversation>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatConversation" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatConversationReader>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatConversationReader" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatConversationThreadingInfo>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatConversationThreadingInfo" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatMessage>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatMessage" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatMessageAttachment>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatMessageAttachment" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatMessageBlocking>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatMessageBlocking" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatMessageChange>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatMessageChange" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatMessageChangeReader>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatMessageChangeReader" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatMessageChangeTracker>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatMessageChangeTracker" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatMessageChangedDeferral>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatMessageChangedDeferral" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatMessageChangedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatMessageChangedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatMessageManager>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatMessageManager" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatMessageNotificationTriggerDetails>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatMessageNotificationTriggerDetails" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatMessageReader>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatMessageReader" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatMessageStore>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatMessageStore" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatMessageStoreChangedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatMessageStoreChangedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatMessageTransport>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatMessageTransport" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatMessageTransportConfiguration>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatMessageTransportConfiguration" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatMessageValidationResult>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatMessageValidationResult" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatQueryOptions>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatQueryOptions" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatRecipientDeliveryInfo>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatRecipientDeliveryInfo" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatSearchReader>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatSearchReader" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatSyncConfiguration>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatSyncConfiguration" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatSyncManager>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatSyncManager" }; };
template <> struct name<Windows::ApplicationModel::Chat::RcsEndUserMessage>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.RcsEndUserMessage" }; };
template <> struct name<Windows::ApplicationModel::Chat::RcsEndUserMessageAction>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.RcsEndUserMessageAction" }; };
template <> struct name<Windows::ApplicationModel::Chat::RcsEndUserMessageAvailableEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.RcsEndUserMessageAvailableEventArgs" }; };
template <> struct name<Windows::ApplicationModel::Chat::RcsEndUserMessageAvailableTriggerDetails>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.RcsEndUserMessageAvailableTriggerDetails" }; };
template <> struct name<Windows::ApplicationModel::Chat::RcsEndUserMessageManager>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.RcsEndUserMessageManager" }; };
template <> struct name<Windows::ApplicationModel::Chat::RcsManager>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.RcsManager" }; };
template <> struct name<Windows::ApplicationModel::Chat::RcsServiceKindSupportedChangedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.RcsServiceKindSupportedChangedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::Chat::RcsTransport>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.RcsTransport" }; };
template <> struct name<Windows::ApplicationModel::Chat::RcsTransportConfiguration>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.RcsTransportConfiguration" }; };
template <> struct name<Windows::ApplicationModel::Chat::RemoteParticipantComposingChangedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.RemoteParticipantComposingChangedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatConversationThreadingKind>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatConversationThreadingKind" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatItemKind>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatItemKind" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatMessageChangeType>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatMessageChangeType" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatMessageKind>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatMessageKind" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatMessageOperatorKind>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatMessageOperatorKind" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatMessageStatus>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatMessageStatus" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatMessageTransportKind>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatMessageTransportKind" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatMessageValidationStatus>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatMessageValidationStatus" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatRestoreHistorySpan>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatRestoreHistorySpan" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatStoreChangedEventKind>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatStoreChangedEventKind" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatTransportErrorCodeCategory>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatTransportErrorCodeCategory" }; };
template <> struct name<Windows::ApplicationModel::Chat::ChatTransportInterpretedErrorCode>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.ChatTransportInterpretedErrorCode" }; };
template <> struct name<Windows::ApplicationModel::Chat::RcsServiceKind>{ static constexpr auto & value{ L"Windows.ApplicationModel.Chat.RcsServiceKind" }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatCapabilities>{ static constexpr guid value{ 0x3AFF77BC,0x39C9,0x4DD1,{ 0xAD,0x2D,0x39,0x64,0xDD,0x9D,0x40,0x3F } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics>{ static constexpr guid value{ 0xB57A2F30,0x7041,0x458E,{ 0xB0,0xCF,0x7C,0x0D,0x9F,0xEA,0x33,0x3A } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics2>{ static constexpr guid value{ 0xE30D4274,0xD5C1,0x4AC9,{ 0x9F,0xFC,0x40,0xE6,0x91,0x84,0xFE,0xC8 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatConversation>{ static constexpr guid value{ 0xA58C080D,0x1A6F,0x46DC,{ 0x8F,0x3D,0xF5,0x02,0x86,0x60,0xB6,0xEE } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatConversation2>{ static constexpr guid value{ 0x0A030CD1,0x983A,0x47AA,{ 0x9A,0x90,0xEE,0x48,0xEE,0x99,0x7B,0x59 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatConversationReader>{ static constexpr guid value{ 0x055136D2,0xDE32,0x4A47,{ 0xA9,0x3A,0xB3,0xDC,0x08,0x33,0x85,0x2B } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatConversationThreadingInfo>{ static constexpr guid value{ 0x331C21DC,0x7A07,0x4422,{ 0xA3,0x2C,0x24,0xBE,0x7C,0x6D,0xAB,0x24 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatItem>{ static constexpr guid value{ 0x8751D000,0xCEB1,0x4243,{ 0xB8,0x03,0x15,0xD4,0x5A,0x1D,0xD4,0x28 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatMessage>{ static constexpr guid value{ 0x4B39052A,0x1142,0x5089,{ 0x76,0xDA,0xF2,0xDB,0x3D,0x17,0xCD,0x05 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatMessage2>{ static constexpr guid value{ 0x86668332,0x543F,0x49F5,{ 0xAC,0x71,0x6C,0x2A,0xFC,0x65,0x65,0xFD } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatMessage3>{ static constexpr guid value{ 0x74EB2FB0,0x3BA7,0x459F,{ 0x8E,0x0B,0xE8,0xAF,0x0F,0xEB,0xD9,0xAD } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatMessage4>{ static constexpr guid value{ 0x2D144B0F,0xD2BF,0x460C,{ 0xAA,0x68,0x6D,0x3F,0x84,0x83,0xC9,0xBF } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatMessageAttachment>{ static constexpr guid value{ 0xC7C4FD74,0xBF63,0x58EB,{ 0x50,0x8C,0x8B,0x86,0x3F,0xF1,0x6B,0x67 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatMessageAttachment2>{ static constexpr guid value{ 0x5ED99270,0x7DD1,0x4A87,{ 0xA8,0xCE,0xAC,0xDD,0x87,0xD8,0x0D,0xC8 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatMessageAttachmentFactory>{ static constexpr guid value{ 0x205852A2,0xA356,0x5B71,{ 0x6C,0xA9,0x66,0xC9,0x85,0xB7,0xD0,0xD5 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatMessageBlockingStatic>{ static constexpr guid value{ 0xF6B9A380,0xCDEA,0x11E4,{ 0x88,0x30,0x08,0x00,0x20,0x0C,0x9A,0x66 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatMessageChange>{ static constexpr guid value{ 0x1C18C355,0x421E,0x54B8,{ 0x6D,0x38,0x6B,0x3A,0x6C,0x82,0xFC,0xCC } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatMessageChangeReader>{ static constexpr guid value{ 0x14267020,0x28CE,0x5F26,{ 0x7B,0x05,0x9A,0x5C,0x7C,0xCE,0x87,0xCA } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatMessageChangeTracker>{ static constexpr guid value{ 0x60B7F066,0x70A0,0x5224,{ 0x50,0x8C,0x24,0x2E,0xF7,0xC1,0xD0,0x6F } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatMessageChangedDeferral>{ static constexpr guid value{ 0xFBC6B30C,0x788C,0x4DCC,{ 0xAC,0xE7,0x62,0x82,0x38,0x29,0x68,0xCF } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatMessageChangedEventArgs>{ static constexpr guid value{ 0xB6B73E2D,0x691C,0x4EDF,{ 0x86,0x60,0x6E,0xB9,0x89,0x68,0x92,0xE3 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatMessageManager2Statics>{ static constexpr guid value{ 0x1D45390F,0x9F4F,0x4E35,{ 0x96,0x4E,0x1B,0x9C,0xA6,0x1A,0xC0,0x44 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatMessageManagerStatic>{ static constexpr guid value{ 0xF15C60F7,0xD5E8,0x5E92,{ 0x55,0x6D,0xE0,0x3B,0x60,0x25,0x31,0x04 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatMessageManagerStatics3>{ static constexpr guid value{ 0x208B830D,0x6755,0x48CC,{ 0x9A,0xB3,0xFD,0x03,0xC4,0x63,0xFC,0x92 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatMessageNotificationTriggerDetails>{ static constexpr guid value{ 0xFD344DFB,0x3063,0x4E17,{ 0x85,0x86,0xC6,0xC0,0x82,0x62,0xE6,0xC0 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatMessageNotificationTriggerDetails2>{ static constexpr guid value{ 0x6BB522E0,0xAA07,0x4FD1,{ 0x94,0x71,0x77,0x93,0x4F,0xB7,0x5E,0xE6 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatMessageReader>{ static constexpr guid value{ 0xB6EA78CE,0x4489,0x56F9,{ 0x76,0xAA,0xE2,0x04,0x68,0x25,0x14,0xCF } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatMessageReader2>{ static constexpr guid value{ 0x89643683,0x64BB,0x470D,{ 0x9D,0xF4,0x0D,0xE8,0xBE,0x1A,0x05,0xBF } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatMessageStore>{ static constexpr guid value{ 0x31F2FD01,0xCCF6,0x580B,{ 0x49,0x76,0x0A,0x07,0xDD,0x5D,0x3B,0x47 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatMessageStore2>{ static constexpr guid value{ 0xAD4DC4EE,0x3AD4,0x491B,{ 0xB3,0x11,0xAB,0xDF,0x9B,0xB2,0x27,0x68 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatMessageStore3>{ static constexpr guid value{ 0x9ADBBB09,0x4345,0x4EC1,{ 0x8B,0x74,0xB7,0x33,0x82,0x43,0x71,0x9C } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatMessageStoreChangedEventArgs>{ static constexpr guid value{ 0x65C66FAC,0xFE8C,0x46D4,{ 0x91,0x19,0x57,0xB8,0x41,0x03,0x11,0xD5 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatMessageTransport>{ static constexpr guid value{ 0x63A9DBF8,0xE6B3,0x5C9A,{ 0x5F,0x85,0xD4,0x79,0x25,0xB9,0xBD,0x18 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatMessageTransport2>{ static constexpr guid value{ 0x90A75622,0xD84A,0x4C22,{ 0xA9,0x4D,0x54,0x44,0x44,0xED,0xC8,0xA1 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatMessageTransportConfiguration>{ static constexpr guid value{ 0x879FF725,0x1A08,0x4ACA,{ 0xA0,0x75,0x33,0x55,0x12,0x63,0x12,0xE6 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatMessageValidationResult>{ static constexpr guid value{ 0x25E93A03,0x28EC,0x5889,{ 0x56,0x9B,0x7E,0x48,0x6B,0x12,0x6F,0x18 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatQueryOptions>{ static constexpr guid value{ 0x2FD364A6,0xBF36,0x42F7,{ 0xB7,0xE7,0x92,0x3C,0x0A,0xAB,0xFE,0x16 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatRecipientDeliveryInfo>{ static constexpr guid value{ 0xFFC7B2A2,0x283C,0x4C0A,{ 0x8A,0x0E,0x8C,0x33,0xBD,0xBF,0x05,0x45 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatSearchReader>{ static constexpr guid value{ 0x4665FE49,0x9020,0x4752,{ 0x98,0x0D,0x39,0x61,0x23,0x25,0xF5,0x89 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatSyncConfiguration>{ static constexpr guid value{ 0x09F869B2,0x69F4,0x4AFF,{ 0x82,0xB6,0x06,0x99,0x2F,0xF4,0x02,0xD2 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IChatSyncManager>{ static constexpr guid value{ 0x7BA52C63,0x2650,0x486F,{ 0xB4,0xB4,0x6B,0xD9,0xD3,0xD6,0x3C,0x84 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IRcsEndUserMessage>{ static constexpr guid value{ 0xD7CDA5EB,0xCBD7,0x4F3B,{ 0x85,0x26,0xB5,0x06,0xDE,0xC3,0x5C,0x53 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IRcsEndUserMessageAction>{ static constexpr guid value{ 0x92378737,0x9B42,0x46D3,{ 0x9D,0x5E,0x3C,0x1B,0x2D,0xAE,0x7C,0xB8 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IRcsEndUserMessageAvailableEventArgs>{ static constexpr guid value{ 0x2D45AE01,0x3F89,0x41EA,{ 0x97,0x02,0x9E,0x9E,0xD4,0x11,0xAA,0x98 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IRcsEndUserMessageAvailableTriggerDetails>{ static constexpr guid value{ 0x5B97742D,0x351F,0x4692,{ 0xB4,0x1E,0x1B,0x03,0x5D,0xC1,0x89,0x86 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IRcsEndUserMessageManager>{ static constexpr guid value{ 0x3054AE5A,0x4D1F,0x4B59,{ 0x94,0x33,0x12,0x6C,0x73,0x4E,0x86,0xA6 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IRcsManagerStatics>{ static constexpr guid value{ 0x7D270AC5,0x0ABD,0x4F31,{ 0x9B,0x99,0xA5,0x9E,0x71,0xA7,0xB7,0x31 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IRcsManagerStatics2>{ static constexpr guid value{ 0xCD49AD18,0xAD8A,0x42AA,{ 0x8E,0xEB,0xA7,0x98,0xA8,0x80,0x89,0x59 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IRcsServiceKindSupportedChangedEventArgs>{ static constexpr guid value{ 0xF47EA244,0xE783,0x4866,{ 0xB3,0xA7,0x4E,0x5C,0xCF,0x02,0x30,0x70 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IRcsTransport>{ static constexpr guid value{ 0xFEA34759,0xF37C,0x4319,{ 0x85,0x46,0xEC,0x84,0xD2,0x1D,0x30,0xFF } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IRcsTransportConfiguration>{ static constexpr guid value{ 0x1FCCB102,0x2472,0x4BB9,{ 0x99,0x88,0xC1,0x21,0x1C,0x83,0xE8,0xA9 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Chat::IRemoteParticipantComposingChangedEventArgs>{ static constexpr guid value{ 0x1EC045A7,0xCFC9,0x45C9,{ 0x98,0x76,0x44,0x9F,0x2B,0xC1,0x80,0xF5 } }; };
template <> struct default_interface<Windows::ApplicationModel::Chat::ChatCapabilities>{ using type = Windows::ApplicationModel::Chat::IChatCapabilities; };
template <> struct default_interface<Windows::ApplicationModel::Chat::ChatConversation>{ using type = Windows::ApplicationModel::Chat::IChatConversation; };
template <> struct default_interface<Windows::ApplicationModel::Chat::ChatConversationReader>{ using type = Windows::ApplicationModel::Chat::IChatConversationReader; };
template <> struct default_interface<Windows::ApplicationModel::Chat::ChatConversationThreadingInfo>{ using type = Windows::ApplicationModel::Chat::IChatConversationThreadingInfo; };
template <> struct default_interface<Windows::ApplicationModel::Chat::ChatMessage>{ using type = Windows::ApplicationModel::Chat::IChatMessage; };
template <> struct default_interface<Windows::ApplicationModel::Chat::ChatMessageAttachment>{ using type = Windows::ApplicationModel::Chat::IChatMessageAttachment; };
template <> struct default_interface<Windows::ApplicationModel::Chat::ChatMessageChange>{ using type = Windows::ApplicationModel::Chat::IChatMessageChange; };
template <> struct default_interface<Windows::ApplicationModel::Chat::ChatMessageChangeReader>{ using type = Windows::ApplicationModel::Chat::IChatMessageChangeReader; };
template <> struct default_interface<Windows::ApplicationModel::Chat::ChatMessageChangeTracker>{ using type = Windows::ApplicationModel::Chat::IChatMessageChangeTracker; };
template <> struct default_interface<Windows::ApplicationModel::Chat::ChatMessageChangedDeferral>{ using type = Windows::ApplicationModel::Chat::IChatMessageChangedDeferral; };
template <> struct default_interface<Windows::ApplicationModel::Chat::ChatMessageChangedEventArgs>{ using type = Windows::ApplicationModel::Chat::IChatMessageChangedEventArgs; };
template <> struct default_interface<Windows::ApplicationModel::Chat::ChatMessageNotificationTriggerDetails>{ using type = Windows::ApplicationModel::Chat::IChatMessageNotificationTriggerDetails; };
template <> struct default_interface<Windows::ApplicationModel::Chat::ChatMessageReader>{ using type = Windows::ApplicationModel::Chat::IChatMessageReader; };
template <> struct default_interface<Windows::ApplicationModel::Chat::ChatMessageStore>{ using type = Windows::ApplicationModel::Chat::IChatMessageStore; };
template <> struct default_interface<Windows::ApplicationModel::Chat::ChatMessageStoreChangedEventArgs>{ using type = Windows::ApplicationModel::Chat::IChatMessageStoreChangedEventArgs; };
template <> struct default_interface<Windows::ApplicationModel::Chat::ChatMessageTransport>{ using type = Windows::ApplicationModel::Chat::IChatMessageTransport; };
template <> struct default_interface<Windows::ApplicationModel::Chat::ChatMessageTransportConfiguration>{ using type = Windows::ApplicationModel::Chat::IChatMessageTransportConfiguration; };
template <> struct default_interface<Windows::ApplicationModel::Chat::ChatMessageValidationResult>{ using type = Windows::ApplicationModel::Chat::IChatMessageValidationResult; };
template <> struct default_interface<Windows::ApplicationModel::Chat::ChatQueryOptions>{ using type = Windows::ApplicationModel::Chat::IChatQueryOptions; };
template <> struct default_interface<Windows::ApplicationModel::Chat::ChatRecipientDeliveryInfo>{ using type = Windows::ApplicationModel::Chat::IChatRecipientDeliveryInfo; };
template <> struct default_interface<Windows::ApplicationModel::Chat::ChatSearchReader>{ using type = Windows::ApplicationModel::Chat::IChatSearchReader; };
template <> struct default_interface<Windows::ApplicationModel::Chat::ChatSyncConfiguration>{ using type = Windows::ApplicationModel::Chat::IChatSyncConfiguration; };
template <> struct default_interface<Windows::ApplicationModel::Chat::ChatSyncManager>{ using type = Windows::ApplicationModel::Chat::IChatSyncManager; };
template <> struct default_interface<Windows::ApplicationModel::Chat::RcsEndUserMessage>{ using type = Windows::ApplicationModel::Chat::IRcsEndUserMessage; };
template <> struct default_interface<Windows::ApplicationModel::Chat::RcsEndUserMessageAction>{ using type = Windows::ApplicationModel::Chat::IRcsEndUserMessageAction; };
template <> struct default_interface<Windows::ApplicationModel::Chat::RcsEndUserMessageAvailableEventArgs>{ using type = Windows::ApplicationModel::Chat::IRcsEndUserMessageAvailableEventArgs; };
template <> struct default_interface<Windows::ApplicationModel::Chat::RcsEndUserMessageAvailableTriggerDetails>{ using type = Windows::ApplicationModel::Chat::IRcsEndUserMessageAvailableTriggerDetails; };
template <> struct default_interface<Windows::ApplicationModel::Chat::RcsEndUserMessageManager>{ using type = Windows::ApplicationModel::Chat::IRcsEndUserMessageManager; };
template <> struct default_interface<Windows::ApplicationModel::Chat::RcsServiceKindSupportedChangedEventArgs>{ using type = Windows::ApplicationModel::Chat::IRcsServiceKindSupportedChangedEventArgs; };
template <> struct default_interface<Windows::ApplicationModel::Chat::RcsTransport>{ using type = Windows::ApplicationModel::Chat::IRcsTransport; };
template <> struct default_interface<Windows::ApplicationModel::Chat::RcsTransportConfiguration>{ using type = Windows::ApplicationModel::Chat::IRcsTransportConfiguration; };
template <> struct default_interface<Windows::ApplicationModel::Chat::RemoteParticipantComposingChangedEventArgs>{ using type = Windows::ApplicationModel::Chat::IRemoteParticipantComposingChangedEventArgs; };

template <> struct abi<Windows::ApplicationModel::Chat::IChatCapabilities>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsOnline(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsChatCapable(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsFileTransferCapable(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsGeoLocationPushCapable(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsIntegratedMessagingCapable(bool* result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetCachedCapabilitiesAsync(void* address, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetCapabilitiesFromNetworkAsync(void* address, void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetCachedCapabilitiesForTransportAsync(void* address, void* transportId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetCapabilitiesFromNetworkForTransportAsync(void* address, void* transportId, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatConversation>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_HasUnreadMessages(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL get_Id(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL get_Subject(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL put_Subject(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsConversationMuted(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsConversationMuted(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MostRecentMessageId(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL get_Participants(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL get_ThreadingInfo(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL DeleteAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetMessageReader(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL MarkAllMessagesAsReadAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL MarkMessagesAsReadAsync(Windows::Foundation::DateTime value, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL SaveAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL NotifyLocalParticipantComposing(void* transportId, void* participantAddress, bool isComposing) noexcept = 0;
    virtual int32_t WINRT_CALL NotifyRemoteParticipantComposing(void* transportId, void* participantAddress, bool isComposing) noexcept = 0;
    virtual int32_t WINRT_CALL add_RemoteParticipantComposingChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_RemoteParticipantComposingChanged(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatConversation2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CanModifyParticipants(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL put_CanModifyParticipants(bool value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatConversationReader>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ReadBatchAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL ReadBatchWithCountAsync(int32_t count, void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatConversationThreadingInfo>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ContactId(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL put_ContactId(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Custom(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL put_Custom(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ConversationId(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL put_ConversationId(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Participants(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL get_Kind(Windows::ApplicationModel::Chat::ChatConversationThreadingKind* result) noexcept = 0;
    virtual int32_t WINRT_CALL put_Kind(Windows::ApplicationModel::Chat::ChatConversationThreadingKind value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatItem>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ItemKind(Windows::ApplicationModel::Chat::ChatItemKind* result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatMessage>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Attachments(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Body(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Body(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_From(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Id(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsForwardingDisabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsIncoming(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsRead(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LocalTimestamp(Windows::Foundation::DateTime* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NetworkTimestamp(Windows::Foundation::DateTime* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Recipients(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RecipientSendStatuses(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Status(Windows::ApplicationModel::Chat::ChatMessageStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Subject(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TransportFriendlyName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TransportId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_TransportId(void* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatMessage2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_EstimatedDownloadSize(uint64_t* result) noexcept = 0;
    virtual int32_t WINRT_CALL put_EstimatedDownloadSize(uint64_t value) noexcept = 0;
    virtual int32_t WINRT_CALL put_From(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsAutoReply(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsAutoReply(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsForwardingDisabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsReplyDisabled(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsIncoming(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsRead(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsSeen(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsSeen(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsSimMessage(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL put_LocalTimestamp(Windows::Foundation::DateTime value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MessageKind(Windows::ApplicationModel::Chat::ChatMessageKind* result) noexcept = 0;
    virtual int32_t WINRT_CALL put_MessageKind(Windows::ApplicationModel::Chat::ChatMessageKind value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MessageOperatorKind(Windows::ApplicationModel::Chat::ChatMessageOperatorKind* result) noexcept = 0;
    virtual int32_t WINRT_CALL put_MessageOperatorKind(Windows::ApplicationModel::Chat::ChatMessageOperatorKind value) noexcept = 0;
    virtual int32_t WINRT_CALL put_NetworkTimestamp(Windows::Foundation::DateTime value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsReceivedDuringQuietHours(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsReceivedDuringQuietHours(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RemoteId(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Status(Windows::ApplicationModel::Chat::ChatMessageStatus value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Subject(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ShouldSuppressNotification(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL put_ShouldSuppressNotification(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ThreadingInfo(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL put_ThreadingInfo(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RecipientsDeliveryInfos(void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatMessage3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_RemoteId(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatMessage4>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SyncId(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL put_SyncId(void* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatMessageAttachment>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DataStreamReference(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DataStreamReference(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_GroupId(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_GroupId(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MimeType(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MimeType(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Text(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Text(void* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatMessageAttachment2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Thumbnail(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL put_Thumbnail(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TransferProgress(double* result) noexcept = 0;
    virtual int32_t WINRT_CALL put_TransferProgress(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OriginalFileName(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL put_OriginalFileName(void* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatMessageAttachmentFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateChatMessageAttachment(void* mimeType, void* dataStreamReference, void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatMessageBlockingStatic>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL MarkMessageAsBlockedAsync(void* localChatMessageId, bool blocked, void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatMessageChange>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ChangeType(Windows::ApplicationModel::Chat::ChatMessageChangeType* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Message(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatMessageChangeReader>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL AcceptChanges() noexcept = 0;
    virtual int32_t WINRT_CALL AcceptChangesThrough(void* lastChangeToAcknowledge) noexcept = 0;
    virtual int32_t WINRT_CALL ReadBatchAsync(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatMessageChangeTracker>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Enable() noexcept = 0;
    virtual int32_t WINRT_CALL GetChangeReader(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL Reset() noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatMessageChangedDeferral>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Complete() noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatMessageChangedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDeferral(void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatMessageManager2Statics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL RegisterTransportAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetTransportAsync(void* transportId, void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatMessageManagerStatic>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetTransportsAsync(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL RequestStoreAsync(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL ShowComposeSmsMessageAsync(void* message, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL ShowSmsSettings() noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatMessageManagerStatics3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL RequestSyncManagerAsync(void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatMessageNotificationTriggerDetails>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ChatMessage(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatMessageNotificationTriggerDetails2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ShouldDisplayToast(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL get_ShouldUpdateDetailText(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL get_ShouldUpdateBadge(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL get_ShouldUpdateActionCenter(bool* result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatMessageReader>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ReadBatchAsync(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatMessageReader2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ReadBatchWithCountAsync(int32_t count, void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatMessageStore>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ChangeTracker(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL DeleteMessageAsync(void* localMessageId, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL DownloadMessageAsync(void* localChatMessageId, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetMessageAsync(void* localChatMessageId, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetMessageReader1(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetMessageReader2(Windows::Foundation::TimeSpan recentTimeLimit, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL MarkMessageReadAsync(void* localChatMessageId, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL RetrySendMessageAsync(void* localChatMessageId, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL SendMessageAsync(void* chatMessage, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL ValidateMessage(void* chatMessage, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL add_MessageChanged(void* value, winrt::event_token* returnValue) noexcept = 0;
    virtual int32_t WINRT_CALL remove_MessageChanged(winrt::event_token value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatMessageStore2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ForwardMessageAsync(void* localChatMessageId, void* addresses, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetConversationAsync(void* conversationId, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetConversationForTransportsAsync(void* conversationId, void* transportIds, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetConversationFromThreadingInfoAsync(void* threadingInfo, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetConversationReader(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetConversationForTransportsReader(void* transportIds, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetMessageByRemoteIdAsync(void* transportId, void* remoteId, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetUnseenCountAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetUnseenCountForTransportsReaderAsync(void* transportIds, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL MarkAsSeenAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL MarkAsSeenForTransportsAsync(void* transportIds, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetSearchReader(void* value, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL SaveMessageAsync(void* chatMessage, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TryCancelDownloadMessageAsync(void* localChatMessageId, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TryCancelSendMessageAsync(void* localChatMessageId, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL add_StoreChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_StoreChanged(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatMessageStore3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetMessageBySyncIdAsync(void* syncId, void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatMessageStoreChangedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Id(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL get_Kind(Windows::ApplicationModel::Chat::ChatStoreChangedEventKind* result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatMessageTransport>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsAppSetAsNotificationProvider(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsActive(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TransportFriendlyName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TransportId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL RequestSetAsNotificationProviderAsync(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatMessageTransport2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Configuration(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL get_TransportKind(Windows::ApplicationModel::Chat::ChatMessageTransportKind* result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatMessageTransportConfiguration>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_MaxAttachmentCount(int32_t* result) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxMessageSizeInKilobytes(int32_t* result) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxRecipientCount(int32_t* result) noexcept = 0;
    virtual int32_t WINRT_CALL get_SupportedVideoFormat(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedProperties(void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatMessageValidationResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_MaxPartCount(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PartCount(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RemainingCharacterCountInPart(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Status(Windows::ApplicationModel::Chat::ChatMessageValidationStatus* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatQueryOptions>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SearchString(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL put_SearchString(void* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatRecipientDeliveryInfo>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_TransportAddress(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL put_TransportAddress(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DeliveryTime(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL put_DeliveryTime(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ReadTime(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL put_ReadTime(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TransportErrorCodeCategory(Windows::ApplicationModel::Chat::ChatTransportErrorCodeCategory* result) noexcept = 0;
    virtual int32_t WINRT_CALL get_TransportInterpretedErrorCode(Windows::ApplicationModel::Chat::ChatTransportInterpretedErrorCode* result) noexcept = 0;
    virtual int32_t WINRT_CALL get_TransportErrorCode(int32_t* result) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsErrorPermanent(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL get_Status(Windows::ApplicationModel::Chat::ChatMessageStatus* result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatSearchReader>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ReadBatchAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL ReadBatchWithCountAsync(int32_t count, void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatSyncConfiguration>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsSyncEnabled(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsSyncEnabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RestoreHistorySpan(Windows::ApplicationModel::Chat::ChatRestoreHistorySpan* result) noexcept = 0;
    virtual int32_t WINRT_CALL put_RestoreHistorySpan(Windows::ApplicationModel::Chat::ChatRestoreHistorySpan value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IChatSyncManager>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Configuration(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL AssociateAccountAsync(void* webAccount, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL UnassociateAccountAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL IsAccountAssociated(void* webAccount, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL StartSync() noexcept = 0;
    virtual int32_t WINRT_CALL SetConfigurationAsync(void* configuration, void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IRcsEndUserMessage>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_TransportId(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL get_Title(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL get_Text(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsPinRequired(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL get_Actions(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL SendResponseAsync(void* action, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL SendResponseWithPinAsync(void* action, void* pin, void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IRcsEndUserMessageAction>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Label(void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IRcsEndUserMessageAvailableEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsMessageAvailable(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL get_Message(void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IRcsEndUserMessageAvailableTriggerDetails>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Title(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Text(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IRcsEndUserMessageManager>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_MessageAvailableChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_MessageAvailableChanged(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IRcsManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetEndUserMessageManager(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetTransportsAsync(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetTransportAsync(void* transportId, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL LeaveConversationAsync(void* conversation, void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IRcsManagerStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_TransportListChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_TransportListChanged(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IRcsServiceKindSupportedChangedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ServiceKind(Windows::ApplicationModel::Chat::RcsServiceKind* result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IRcsTransport>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ExtendedProperties(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsActive(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TransportFriendlyName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TransportId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Configuration(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL IsStoreAndForwardEnabled(Windows::ApplicationModel::Chat::RcsServiceKind serviceKind, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL IsServiceKindSupported(Windows::ApplicationModel::Chat::RcsServiceKind serviceKind, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL add_ServiceKindSupportedChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ServiceKindSupportedChanged(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IRcsTransportConfiguration>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_MaxAttachmentCount(int32_t* result) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxMessageSizeInKilobytes(int32_t* result) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxGroupMessageSizeInKilobytes(int32_t* result) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxRecipientCount(int32_t* result) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxFileSizeInKilobytes(int32_t* result) noexcept = 0;
    virtual int32_t WINRT_CALL get_WarningFileSizeInKilobytes(int32_t* result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Chat::IRemoteParticipantComposingChangedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_TransportId(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL get_ParticipantAddress(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsComposing(bool* result) noexcept = 0;
};};

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatCapabilities
{
    bool IsOnline() const;
    bool IsChatCapable() const;
    bool IsFileTransferCapable() const;
    bool IsGeoLocationPushCapable() const;
    bool IsIntegratedMessagingCapable() const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatCapabilities> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatCapabilities<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatCapabilitiesManagerStatics
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatCapabilities> GetCachedCapabilitiesAsync(param::hstring const& address) const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatCapabilities> GetCapabilitiesFromNetworkAsync(param::hstring const& address) const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatCapabilitiesManagerStatics<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatCapabilitiesManagerStatics2
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatCapabilities> GetCachedCapabilitiesAsync(param::hstring const& address, param::hstring const& transportId) const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatCapabilities> GetCapabilitiesFromNetworkAsync(param::hstring const& address, param::hstring const& transportId) const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics2> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatCapabilitiesManagerStatics2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatConversation
{
    bool HasUnreadMessages() const;
    hstring Id() const;
    hstring Subject() const;
    void Subject(param::hstring const& value) const;
    bool IsConversationMuted() const;
    void IsConversationMuted(bool value) const;
    hstring MostRecentMessageId() const;
    Windows::Foundation::Collections::IVector<hstring> Participants() const;
    Windows::ApplicationModel::Chat::ChatConversationThreadingInfo ThreadingInfo() const;
    Windows::Foundation::IAsyncAction DeleteAsync() const;
    Windows::ApplicationModel::Chat::ChatMessageReader GetMessageReader() const;
    Windows::Foundation::IAsyncAction MarkMessagesAsReadAsync() const;
    Windows::Foundation::IAsyncAction MarkMessagesAsReadAsync(Windows::Foundation::DateTime const& value) const;
    Windows::Foundation::IAsyncAction SaveAsync() const;
    void NotifyLocalParticipantComposing(param::hstring const& transportId, param::hstring const& participantAddress, bool isComposing) const;
    void NotifyRemoteParticipantComposing(param::hstring const& transportId, param::hstring const& participantAddress, bool isComposing) const;
    winrt::event_token RemoteParticipantComposingChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Chat::ChatConversation, Windows::ApplicationModel::Chat::RemoteParticipantComposingChangedEventArgs> const& handler) const;
    using RemoteParticipantComposingChanged_revoker = impl::event_revoker<Windows::ApplicationModel::Chat::IChatConversation, &impl::abi_t<Windows::ApplicationModel::Chat::IChatConversation>::remove_RemoteParticipantComposingChanged>;
    RemoteParticipantComposingChanged_revoker RemoteParticipantComposingChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Chat::ChatConversation, Windows::ApplicationModel::Chat::RemoteParticipantComposingChangedEventArgs> const& handler) const;
    void RemoteParticipantComposingChanged(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatConversation> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatConversation<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatConversation2
{
    bool CanModifyParticipants() const;
    void CanModifyParticipants(bool value) const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatConversation2> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatConversation2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatConversationReader
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::ChatConversation>> ReadBatchAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::ChatConversation>> ReadBatchAsync(int32_t count) const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatConversationReader> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatConversationReader<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatConversationThreadingInfo
{
    hstring ContactId() const;
    void ContactId(param::hstring const& value) const;
    hstring Custom() const;
    void Custom(param::hstring const& value) const;
    hstring ConversationId() const;
    void ConversationId(param::hstring const& value) const;
    Windows::Foundation::Collections::IVector<hstring> Participants() const;
    Windows::ApplicationModel::Chat::ChatConversationThreadingKind Kind() const;
    void Kind(Windows::ApplicationModel::Chat::ChatConversationThreadingKind const& value) const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatConversationThreadingInfo> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatConversationThreadingInfo<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatItem
{
    Windows::ApplicationModel::Chat::ChatItemKind ItemKind() const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatItem> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatItem<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatMessage
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Chat::ChatMessageAttachment> Attachments() const;
    hstring Body() const;
    void Body(param::hstring const& value) const;
    hstring From() const;
    hstring Id() const;
    bool IsForwardingDisabled() const;
    bool IsIncoming() const;
    bool IsRead() const;
    Windows::Foundation::DateTime LocalTimestamp() const;
    Windows::Foundation::DateTime NetworkTimestamp() const;
    Windows::Foundation::Collections::IVector<hstring> Recipients() const;
    Windows::Foundation::Collections::IMapView<hstring, Windows::ApplicationModel::Chat::ChatMessageStatus> RecipientSendStatuses() const;
    Windows::ApplicationModel::Chat::ChatMessageStatus Status() const;
    hstring Subject() const;
    hstring TransportFriendlyName() const;
    hstring TransportId() const;
    void TransportId(param::hstring const& value) const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatMessage> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatMessage<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatMessage2
{
    uint64_t EstimatedDownloadSize() const;
    void EstimatedDownloadSize(uint64_t value) const;
    void From(param::hstring const& value) const;
    bool IsAutoReply() const;
    void IsAutoReply(bool value) const;
    void IsForwardingDisabled(bool value) const;
    bool IsReplyDisabled() const;
    void IsIncoming(bool value) const;
    void IsRead(bool value) const;
    bool IsSeen() const;
    void IsSeen(bool value) const;
    bool IsSimMessage() const;
    void LocalTimestamp(Windows::Foundation::DateTime const& value) const;
    Windows::ApplicationModel::Chat::ChatMessageKind MessageKind() const;
    void MessageKind(Windows::ApplicationModel::Chat::ChatMessageKind const& value) const;
    Windows::ApplicationModel::Chat::ChatMessageOperatorKind MessageOperatorKind() const;
    void MessageOperatorKind(Windows::ApplicationModel::Chat::ChatMessageOperatorKind const& value) const;
    void NetworkTimestamp(Windows::Foundation::DateTime const& value) const;
    bool IsReceivedDuringQuietHours() const;
    void IsReceivedDuringQuietHours(bool value) const;
    void RemoteId(param::hstring const& value) const;
    void Status(Windows::ApplicationModel::Chat::ChatMessageStatus const& value) const;
    void Subject(param::hstring const& value) const;
    bool ShouldSuppressNotification() const;
    void ShouldSuppressNotification(bool value) const;
    Windows::ApplicationModel::Chat::ChatConversationThreadingInfo ThreadingInfo() const;
    void ThreadingInfo(Windows::ApplicationModel::Chat::ChatConversationThreadingInfo const& value) const;
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Chat::ChatRecipientDeliveryInfo> RecipientsDeliveryInfos() const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatMessage2> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatMessage2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatMessage3
{
    hstring RemoteId() const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatMessage3> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatMessage3<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatMessage4
{
    hstring SyncId() const;
    void SyncId(param::hstring const& value) const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatMessage4> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatMessage4<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatMessageAttachment
{
    Windows::Storage::Streams::IRandomAccessStreamReference DataStreamReference() const;
    void DataStreamReference(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const;
    uint32_t GroupId() const;
    void GroupId(uint32_t value) const;
    hstring MimeType() const;
    void MimeType(param::hstring const& value) const;
    hstring Text() const;
    void Text(param::hstring const& value) const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatMessageAttachment> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatMessageAttachment<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatMessageAttachment2
{
    Windows::Storage::Streams::IRandomAccessStreamReference Thumbnail() const;
    void Thumbnail(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const;
    double TransferProgress() const;
    void TransferProgress(double value) const;
    hstring OriginalFileName() const;
    void OriginalFileName(param::hstring const& value) const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatMessageAttachment2> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatMessageAttachment2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatMessageAttachmentFactory
{
    Windows::ApplicationModel::Chat::ChatMessageAttachment CreateChatMessageAttachment(param::hstring const& mimeType, Windows::Storage::Streams::IRandomAccessStreamReference const& dataStreamReference) const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatMessageAttachmentFactory> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatMessageAttachmentFactory<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatMessageBlockingStatic
{
    Windows::Foundation::IAsyncAction MarkMessageAsBlockedAsync(param::hstring const& localChatMessageId, bool blocked) const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatMessageBlockingStatic> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatMessageBlockingStatic<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatMessageChange
{
    Windows::ApplicationModel::Chat::ChatMessageChangeType ChangeType() const;
    Windows::ApplicationModel::Chat::ChatMessage Message() const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatMessageChange> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatMessageChange<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatMessageChangeReader
{
    void AcceptChanges() const;
    void AcceptChangesThrough(Windows::ApplicationModel::Chat::ChatMessageChange const& lastChangeToAcknowledge) const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::ChatMessageChange>> ReadBatchAsync() const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatMessageChangeReader> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatMessageChangeReader<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatMessageChangeTracker
{
    void Enable() const;
    Windows::ApplicationModel::Chat::ChatMessageChangeReader GetChangeReader() const;
    void Reset() const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatMessageChangeTracker> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatMessageChangeTracker<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatMessageChangedDeferral
{
    void Complete() const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatMessageChangedDeferral> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatMessageChangedDeferral<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatMessageChangedEventArgs
{
    Windows::ApplicationModel::Chat::ChatMessageChangedDeferral GetDeferral() const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatMessageChangedEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatMessageChangedEventArgs<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatMessageManager2Statics
{
    Windows::Foundation::IAsyncOperation<hstring> RegisterTransportAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatMessageTransport> GetTransportAsync(param::hstring const& transportId) const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatMessageManager2Statics> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatMessageManager2Statics<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatMessageManagerStatic
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::ChatMessageTransport>> GetTransportsAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatMessageStore> RequestStoreAsync() const;
    Windows::Foundation::IAsyncAction ShowComposeSmsMessageAsync(Windows::ApplicationModel::Chat::ChatMessage const& message) const;
    void ShowSmsSettings() const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatMessageManagerStatic> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatMessageManagerStatic<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatMessageManagerStatics3
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatSyncManager> RequestSyncManagerAsync() const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatMessageManagerStatics3> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatMessageManagerStatics3<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatMessageNotificationTriggerDetails
{
    Windows::ApplicationModel::Chat::ChatMessage ChatMessage() const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatMessageNotificationTriggerDetails> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatMessageNotificationTriggerDetails<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatMessageNotificationTriggerDetails2
{
    bool ShouldDisplayToast() const;
    bool ShouldUpdateDetailText() const;
    bool ShouldUpdateBadge() const;
    bool ShouldUpdateActionCenter() const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatMessageNotificationTriggerDetails2> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatMessageNotificationTriggerDetails2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatMessageReader
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::ChatMessage>> ReadBatchAsync() const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatMessageReader> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatMessageReader<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatMessageReader2
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::ChatMessage>> ReadBatchAsync(int32_t count) const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatMessageReader2> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatMessageReader2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatMessageStore
{
    Windows::ApplicationModel::Chat::ChatMessageChangeTracker ChangeTracker() const;
    Windows::Foundation::IAsyncAction DeleteMessageAsync(param::hstring const& localMessageId) const;
    Windows::Foundation::IAsyncAction DownloadMessageAsync(param::hstring const& localChatMessageId) const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatMessage> GetMessageAsync(param::hstring const& localChatMessageId) const;
    Windows::ApplicationModel::Chat::ChatMessageReader GetMessageReader() const;
    Windows::ApplicationModel::Chat::ChatMessageReader GetMessageReader(Windows::Foundation::TimeSpan const& recentTimeLimit) const;
    Windows::Foundation::IAsyncAction MarkMessageReadAsync(param::hstring const& localChatMessageId) const;
    Windows::Foundation::IAsyncAction RetrySendMessageAsync(param::hstring const& localChatMessageId) const;
    Windows::Foundation::IAsyncAction SendMessageAsync(Windows::ApplicationModel::Chat::ChatMessage const& chatMessage) const;
    Windows::ApplicationModel::Chat::ChatMessageValidationResult ValidateMessage(Windows::ApplicationModel::Chat::ChatMessage const& chatMessage) const;
    winrt::event_token MessageChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Chat::ChatMessageStore, Windows::ApplicationModel::Chat::ChatMessageChangedEventArgs> const& value) const;
    using MessageChanged_revoker = impl::event_revoker<Windows::ApplicationModel::Chat::IChatMessageStore, &impl::abi_t<Windows::ApplicationModel::Chat::IChatMessageStore>::remove_MessageChanged>;
    MessageChanged_revoker MessageChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Chat::ChatMessageStore, Windows::ApplicationModel::Chat::ChatMessageChangedEventArgs> const& value) const;
    void MessageChanged(winrt::event_token const& value) const noexcept;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatMessageStore> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatMessageStore<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatMessageStore2
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatMessage> ForwardMessageAsync(param::hstring const& localChatMessageId, param::async_iterable<hstring> const& addresses) const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatConversation> GetConversationAsync(param::hstring const& conversationId) const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatConversation> GetConversationAsync(param::hstring const& conversationId, param::async_iterable<hstring> const& transportIds) const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatConversation> GetConversationFromThreadingInfoAsync(Windows::ApplicationModel::Chat::ChatConversationThreadingInfo const& threadingInfo) const;
    Windows::ApplicationModel::Chat::ChatConversationReader GetConversationReader() const;
    Windows::ApplicationModel::Chat::ChatConversationReader GetConversationReader(param::iterable<hstring> const& transportIds) const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatMessage> GetMessageByRemoteIdAsync(param::hstring const& transportId, param::hstring const& remoteId) const;
    Windows::Foundation::IAsyncOperation<int32_t> GetUnseenCountAsync() const;
    Windows::Foundation::IAsyncOperation<int32_t> GetUnseenCountAsync(param::async_iterable<hstring> const& transportIds) const;
    Windows::Foundation::IAsyncAction MarkAsSeenAsync() const;
    Windows::Foundation::IAsyncAction MarkAsSeenAsync(param::async_iterable<hstring> const& transportIds) const;
    Windows::ApplicationModel::Chat::ChatSearchReader GetSearchReader(Windows::ApplicationModel::Chat::ChatQueryOptions const& value) const;
    Windows::Foundation::IAsyncAction SaveMessageAsync(Windows::ApplicationModel::Chat::ChatMessage const& chatMessage) const;
    Windows::Foundation::IAsyncOperation<bool> TryCancelDownloadMessageAsync(param::hstring const& localChatMessageId) const;
    Windows::Foundation::IAsyncOperation<bool> TryCancelSendMessageAsync(param::hstring const& localChatMessageId) const;
    winrt::event_token StoreChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Chat::ChatMessageStore, Windows::ApplicationModel::Chat::ChatMessageStoreChangedEventArgs> const& handler) const;
    using StoreChanged_revoker = impl::event_revoker<Windows::ApplicationModel::Chat::IChatMessageStore2, &impl::abi_t<Windows::ApplicationModel::Chat::IChatMessageStore2>::remove_StoreChanged>;
    StoreChanged_revoker StoreChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Chat::ChatMessageStore, Windows::ApplicationModel::Chat::ChatMessageStoreChangedEventArgs> const& handler) const;
    void StoreChanged(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatMessageStore2> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatMessageStore3
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatMessage> GetMessageBySyncIdAsync(param::hstring const& syncId) const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatMessageStore3> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatMessageStore3<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatMessageStoreChangedEventArgs
{
    hstring Id() const;
    Windows::ApplicationModel::Chat::ChatStoreChangedEventKind Kind() const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatMessageStoreChangedEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatMessageStoreChangedEventArgs<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatMessageTransport
{
    bool IsAppSetAsNotificationProvider() const;
    bool IsActive() const;
    hstring TransportFriendlyName() const;
    hstring TransportId() const;
    Windows::Foundation::IAsyncAction RequestSetAsNotificationProviderAsync() const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatMessageTransport> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatMessageTransport<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatMessageTransport2
{
    Windows::ApplicationModel::Chat::ChatMessageTransportConfiguration Configuration() const;
    Windows::ApplicationModel::Chat::ChatMessageTransportKind TransportKind() const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatMessageTransport2> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatMessageTransport2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatMessageTransportConfiguration
{
    int32_t MaxAttachmentCount() const;
    int32_t MaxMessageSizeInKilobytes() const;
    int32_t MaxRecipientCount() const;
    Windows::Media::MediaProperties::MediaEncodingProfile SupportedVideoFormat() const;
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> ExtendedProperties() const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatMessageTransportConfiguration> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatMessageTransportConfiguration<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatMessageValidationResult
{
    Windows::Foundation::IReference<uint32_t> MaxPartCount() const;
    Windows::Foundation::IReference<uint32_t> PartCount() const;
    Windows::Foundation::IReference<uint32_t> RemainingCharacterCountInPart() const;
    Windows::ApplicationModel::Chat::ChatMessageValidationStatus Status() const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatMessageValidationResult> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatMessageValidationResult<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatQueryOptions
{
    hstring SearchString() const;
    void SearchString(param::hstring const& value) const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatQueryOptions> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatQueryOptions<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatRecipientDeliveryInfo
{
    hstring TransportAddress() const;
    void TransportAddress(param::hstring const& value) const;
    Windows::Foundation::IReference<Windows::Foundation::DateTime> DeliveryTime() const;
    void DeliveryTime(optional<Windows::Foundation::DateTime> const& value) const;
    Windows::Foundation::IReference<Windows::Foundation::DateTime> ReadTime() const;
    void ReadTime(optional<Windows::Foundation::DateTime> const& value) const;
    Windows::ApplicationModel::Chat::ChatTransportErrorCodeCategory TransportErrorCodeCategory() const;
    Windows::ApplicationModel::Chat::ChatTransportInterpretedErrorCode TransportInterpretedErrorCode() const;
    int32_t TransportErrorCode() const;
    bool IsErrorPermanent() const;
    Windows::ApplicationModel::Chat::ChatMessageStatus Status() const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatRecipientDeliveryInfo> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatRecipientDeliveryInfo<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatSearchReader
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::IChatItem>> ReadBatchAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::IChatItem>> ReadBatchAsync(int32_t count) const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatSearchReader> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatSearchReader<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatSyncConfiguration
{
    bool IsSyncEnabled() const;
    void IsSyncEnabled(bool value) const;
    Windows::ApplicationModel::Chat::ChatRestoreHistorySpan RestoreHistorySpan() const;
    void RestoreHistorySpan(Windows::ApplicationModel::Chat::ChatRestoreHistorySpan const& value) const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatSyncConfiguration> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatSyncConfiguration<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IChatSyncManager
{
    Windows::ApplicationModel::Chat::ChatSyncConfiguration Configuration() const;
    Windows::Foundation::IAsyncAction AssociateAccountAsync(Windows::Security::Credentials::WebAccount const& webAccount) const;
    Windows::Foundation::IAsyncAction UnassociateAccountAsync() const;
    bool IsAccountAssociated(Windows::Security::Credentials::WebAccount const& webAccount) const;
    void StartSync() const;
    Windows::Foundation::IAsyncAction SetConfigurationAsync(Windows::ApplicationModel::Chat::ChatSyncConfiguration const& configuration) const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IChatSyncManager> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IChatSyncManager<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IRcsEndUserMessage
{
    hstring TransportId() const;
    hstring Title() const;
    hstring Text() const;
    bool IsPinRequired() const;
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::RcsEndUserMessageAction> Actions() const;
    Windows::Foundation::IAsyncAction SendResponseAsync(Windows::ApplicationModel::Chat::RcsEndUserMessageAction const& action) const;
    Windows::Foundation::IAsyncAction SendResponseWithPinAsync(Windows::ApplicationModel::Chat::RcsEndUserMessageAction const& action, param::hstring const& pin) const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IRcsEndUserMessage> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IRcsEndUserMessage<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IRcsEndUserMessageAction
{
    hstring Label() const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IRcsEndUserMessageAction> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IRcsEndUserMessageAction<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IRcsEndUserMessageAvailableEventArgs
{
    bool IsMessageAvailable() const;
    Windows::ApplicationModel::Chat::RcsEndUserMessage Message() const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IRcsEndUserMessageAvailableEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IRcsEndUserMessageAvailableEventArgs<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IRcsEndUserMessageAvailableTriggerDetails
{
    hstring Title() const;
    hstring Text() const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IRcsEndUserMessageAvailableTriggerDetails> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IRcsEndUserMessageAvailableTriggerDetails<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IRcsEndUserMessageManager
{
    winrt::event_token MessageAvailableChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Chat::RcsEndUserMessageManager, Windows::ApplicationModel::Chat::RcsEndUserMessageAvailableEventArgs> const& handler) const;
    using MessageAvailableChanged_revoker = impl::event_revoker<Windows::ApplicationModel::Chat::IRcsEndUserMessageManager, &impl::abi_t<Windows::ApplicationModel::Chat::IRcsEndUserMessageManager>::remove_MessageAvailableChanged>;
    MessageAvailableChanged_revoker MessageAvailableChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Chat::RcsEndUserMessageManager, Windows::ApplicationModel::Chat::RcsEndUserMessageAvailableEventArgs> const& handler) const;
    void MessageAvailableChanged(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::ApplicationModel::Chat::IRcsEndUserMessageManager> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IRcsEndUserMessageManager<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IRcsManagerStatics
{
    Windows::ApplicationModel::Chat::RcsEndUserMessageManager GetEndUserMessageManager() const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::RcsTransport>> GetTransportsAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::RcsTransport> GetTransportAsync(param::hstring const& transportId) const;
    Windows::Foundation::IAsyncAction LeaveConversationAsync(Windows::ApplicationModel::Chat::ChatConversation const& conversation) const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IRcsManagerStatics> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IRcsManagerStatics<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IRcsManagerStatics2
{
    winrt::event_token TransportListChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    using TransportListChanged_revoker = impl::event_revoker<Windows::ApplicationModel::Chat::IRcsManagerStatics2, &impl::abi_t<Windows::ApplicationModel::Chat::IRcsManagerStatics2>::remove_TransportListChanged>;
    TransportListChanged_revoker TransportListChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    void TransportListChanged(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::ApplicationModel::Chat::IRcsManagerStatics2> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IRcsManagerStatics2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IRcsServiceKindSupportedChangedEventArgs
{
    Windows::ApplicationModel::Chat::RcsServiceKind ServiceKind() const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IRcsServiceKindSupportedChangedEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IRcsServiceKindSupportedChangedEventArgs<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IRcsTransport
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> ExtendedProperties() const;
    bool IsActive() const;
    hstring TransportFriendlyName() const;
    hstring TransportId() const;
    Windows::ApplicationModel::Chat::RcsTransportConfiguration Configuration() const;
    bool IsStoreAndForwardEnabled(Windows::ApplicationModel::Chat::RcsServiceKind const& serviceKind) const;
    bool IsServiceKindSupported(Windows::ApplicationModel::Chat::RcsServiceKind const& serviceKind) const;
    winrt::event_token ServiceKindSupportedChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Chat::RcsTransport, Windows::ApplicationModel::Chat::RcsServiceKindSupportedChangedEventArgs> const& handler) const;
    using ServiceKindSupportedChanged_revoker = impl::event_revoker<Windows::ApplicationModel::Chat::IRcsTransport, &impl::abi_t<Windows::ApplicationModel::Chat::IRcsTransport>::remove_ServiceKindSupportedChanged>;
    ServiceKindSupportedChanged_revoker ServiceKindSupportedChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Chat::RcsTransport, Windows::ApplicationModel::Chat::RcsServiceKindSupportedChangedEventArgs> const& handler) const;
    void ServiceKindSupportedChanged(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::ApplicationModel::Chat::IRcsTransport> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IRcsTransport<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IRcsTransportConfiguration
{
    int32_t MaxAttachmentCount() const;
    int32_t MaxMessageSizeInKilobytes() const;
    int32_t MaxGroupMessageSizeInKilobytes() const;
    int32_t MaxRecipientCount() const;
    int32_t MaxFileSizeInKilobytes() const;
    int32_t WarningFileSizeInKilobytes() const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IRcsTransportConfiguration> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IRcsTransportConfiguration<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Chat_IRemoteParticipantComposingChangedEventArgs
{
    hstring TransportId() const;
    hstring ParticipantAddress() const;
    bool IsComposing() const;
};
template <> struct consume<Windows::ApplicationModel::Chat::IRemoteParticipantComposingChangedEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_Chat_IRemoteParticipantComposingChangedEventArgs<D>; };

}
