// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Data::Text {

struct TextSegment;

}

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct Deferral;
struct Uri;

}

WINRT_EXPORT namespace winrt::Windows::Foundation::Collections {

struct IPropertySet;
struct ValueSet;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IRandomAccessStreamReference;
struct IRandomAccessStreamWithContentType;
struct RandomAccessStreamReference;

}

WINRT_EXPORT namespace winrt::Windows::System {

struct User;

}

WINRT_EXPORT namespace winrt::Windows::UI {

struct Color;

}

WINRT_EXPORT namespace winrt::Windows::UI::Popups {

enum class Placement;

}

WINRT_EXPORT namespace winrt::Windows::UI::ViewManagement {

enum class ViewSizePreference;

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Contacts {

enum class ContactAddressKind : int32_t
{
    Home = 0,
    Work = 1,
    Other = 2,
};

enum class ContactAnnotationOperations : uint32_t
{
    None = 0x0,
    ContactProfile = 0x1,
    Message = 0x2,
    AudioCall = 0x4,
    VideoCall = 0x8,
    SocialFeeds = 0x10,
    Share = 0x20,
};

enum class ContactAnnotationStoreAccessType : int32_t
{
    AppAnnotationsReadWrite = 0,
    AllAnnotationsReadWrite = 1,
};

enum class ContactBatchStatus : int32_t
{
    Success = 0,
    ServerSearchSyncManagerError = 1,
    ServerSearchUnknownError = 2,
};

enum class ContactCardHeaderKind : int32_t
{
    Default = 0,
    Basic = 1,
    Enterprise = 2,
};

enum class ContactCardTabKind : int32_t
{
    Default = 0,
    Email = 1,
    Messaging = 2,
    Phone = 3,
    Video = 4,
    OrganizationalHierarchy = 5,
};

enum class ContactChangeType : int32_t
{
    Created = 0,
    Modified = 1,
    Deleted = 2,
    ChangeTrackingLost = 3,
};

enum class ContactDateKind : int32_t
{
    Birthday = 0,
    Anniversary = 1,
    Other = 2,
};

enum class ContactEmailKind : int32_t
{
    Personal = 0,
    Work = 1,
    Other = 2,
};

enum class ContactFieldCategory : int32_t
{
    None = 0,
    Home = 1,
    Work = 2,
    Mobile = 3,
    Other = 4,
};

enum class ContactFieldType : int32_t
{
    Email = 0,
    PhoneNumber = 1,
    Location = 2,
    InstantMessage = 3,
    Custom = 4,
    ConnectedServiceAccount = 5,
    ImportantDate = 6,
    Address = 7,
    SignificantOther = 8,
    Notes = 9,
    Website = 10,
    JobInfo = 11,
};

enum class ContactListOtherAppReadAccess : int32_t
{
    SystemOnly = 0,
    Limited = 1,
    Full = 2,
    None = 3,
};

enum class ContactListOtherAppWriteAccess : int32_t
{
    None = 0,
    SystemOnly = 1,
    Limited = 2,
};

enum class ContactListSyncStatus : int32_t
{
    Idle = 0,
    Syncing = 1,
    UpToDate = 2,
    AuthenticationError = 3,
    PolicyError = 4,
    UnknownError = 5,
    ManualAccountRemovalRequired = 6,
};

enum class ContactMatchReasonKind : int32_t
{
    Name = 0,
    EmailAddress = 1,
    PhoneNumber = 2,
    JobInfo = 3,
    YomiName = 4,
    Other = 5,
};

enum class ContactNameOrder : int32_t
{
    FirstNameLastName = 0,
    LastNameFirstName = 1,
};

enum class ContactPhoneKind : int32_t
{
    Home = 0,
    Mobile = 1,
    Work = 2,
    Other = 3,
    Pager = 4,
    BusinessFax = 5,
    HomeFax = 6,
    Company = 7,
    Assistant = 8,
    Radio = 9,
};

enum class ContactQueryDesiredFields : uint32_t
{
    None = 0x0,
    PhoneNumber = 0x1,
    EmailAddress = 0x2,
    PostalAddress = 0x4,
};

enum class ContactQuerySearchFields : uint32_t
{
    None = 0x0,
    Name = 0x1,
    Email = 0x2,
    Phone = 0x4,
    All = 0xFFFFFFFF,
};

enum class ContactQuerySearchScope : int32_t
{
    Local = 0,
    Server = 1,
};

enum class ContactRelationship : int32_t
{
    Other = 0,
    Spouse = 1,
    Partner = 2,
    Sibling = 3,
    Parent = 4,
    Child = 5,
};

enum class ContactSelectionMode : int32_t
{
    Contacts = 0,
    Fields = 1,
};

enum class ContactStoreAccessType : int32_t
{
    AppContactsReadWrite = 0,
    AllContactsReadOnly = 1,
    AllContactsReadWrite = 2,
};

enum class PinnedContactSurface : int32_t
{
    StartMenu = 0,
    Taskbar = 1,
};

struct IAggregateContactManager;
struct IAggregateContactManager2;
struct IContact;
struct IContact2;
struct IContact3;
struct IContactAddress;
struct IContactAnnotation;
struct IContactAnnotation2;
struct IContactAnnotationList;
struct IContactAnnotationStore;
struct IContactAnnotationStore2;
struct IContactBatch;
struct IContactCardDelayedDataLoader;
struct IContactCardOptions;
struct IContactCardOptions2;
struct IContactChange;
struct IContactChangeReader;
struct IContactChangeTracker;
struct IContactChangeTracker2;
struct IContactChangedDeferral;
struct IContactChangedEventArgs;
struct IContactConnectedServiceAccount;
struct IContactDate;
struct IContactEmail;
struct IContactField;
struct IContactFieldFactory;
struct IContactGroup;
struct IContactInformation;
struct IContactInstantMessageField;
struct IContactInstantMessageFieldFactory;
struct IContactJobInfo;
struct IContactLaunchActionVerbsStatics;
struct IContactList;
struct IContactList2;
struct IContactList3;
struct IContactListLimitedWriteOperations;
struct IContactListSyncConstraints;
struct IContactListSyncManager;
struct IContactListSyncManager2;
struct IContactLocationField;
struct IContactLocationFieldFactory;
struct IContactManagerForUser;
struct IContactManagerForUser2;
struct IContactManagerStatics;
struct IContactManagerStatics2;
struct IContactManagerStatics3;
struct IContactManagerStatics4;
struct IContactManagerStatics5;
struct IContactMatchReason;
struct IContactName;
struct IContactPanel;
struct IContactPanelClosingEventArgs;
struct IContactPanelLaunchFullAppRequestedEventArgs;
struct IContactPhone;
struct IContactPicker;
struct IContactPicker2;
struct IContactPicker3;
struct IContactPickerStatics;
struct IContactQueryOptions;
struct IContactQueryOptionsFactory;
struct IContactQueryTextSearch;
struct IContactReader;
struct IContactSignificantOther;
struct IContactSignificantOther2;
struct IContactStore;
struct IContactStore2;
struct IContactStore3;
struct IContactStoreNotificationTriggerDetails;
struct IContactWebsite;
struct IContactWebsite2;
struct IFullContactCardOptions;
struct IKnownContactFieldStatics;
struct IPinnedContactIdsQueryResult;
struct IPinnedContactManager;
struct IPinnedContactManagerStatics;
struct AggregateContactManager;
struct Contact;
struct ContactAddress;
struct ContactAnnotation;
struct ContactAnnotationList;
struct ContactAnnotationStore;
struct ContactBatch;
struct ContactCardDelayedDataLoader;
struct ContactCardOptions;
struct ContactChange;
struct ContactChangeReader;
struct ContactChangeTracker;
struct ContactChangedDeferral;
struct ContactChangedEventArgs;
struct ContactConnectedServiceAccount;
struct ContactDate;
struct ContactEmail;
struct ContactField;
struct ContactFieldFactory;
struct ContactGroup;
struct ContactInformation;
struct ContactInstantMessageField;
struct ContactJobInfo;
struct ContactLaunchActionVerbs;
struct ContactList;
struct ContactListLimitedWriteOperations;
struct ContactListSyncConstraints;
struct ContactListSyncManager;
struct ContactLocationField;
struct ContactManager;
struct ContactManagerForUser;
struct ContactMatchReason;
struct ContactPanel;
struct ContactPanelClosingEventArgs;
struct ContactPanelLaunchFullAppRequestedEventArgs;
struct ContactPhone;
struct ContactPicker;
struct ContactQueryOptions;
struct ContactQueryTextSearch;
struct ContactReader;
struct ContactSignificantOther;
struct ContactStore;
struct ContactStoreNotificationTriggerDetails;
struct ContactWebsite;
struct FullContactCardOptions;
struct KnownContactField;
struct PinnedContactIdsQueryResult;
struct PinnedContactManager;

}

namespace winrt::impl {

template<> struct is_enum_flag<Windows::ApplicationModel::Contacts::ContactAnnotationOperations> : std::true_type {};
template<> struct is_enum_flag<Windows::ApplicationModel::Contacts::ContactQueryDesiredFields> : std::true_type {};
template<> struct is_enum_flag<Windows::ApplicationModel::Contacts::ContactQuerySearchFields> : std::true_type {};
template <> struct category<Windows::ApplicationModel::Contacts::IAggregateContactManager>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IAggregateContactManager2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContact>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContact2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContact3>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactAddress>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactAnnotation>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactAnnotation2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactAnnotationList>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactAnnotationStore>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactAnnotationStore2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactBatch>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactCardDelayedDataLoader>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactCardOptions>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactCardOptions2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactChange>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactChangeReader>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactChangeTracker>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactChangeTracker2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactChangedDeferral>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactChangedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactConnectedServiceAccount>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactDate>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactEmail>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactField>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactFieldFactory>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactGroup>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactInformation>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactInstantMessageField>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactInstantMessageFieldFactory>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactJobInfo>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactLaunchActionVerbsStatics>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactList>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactList2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactList3>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactListLimitedWriteOperations>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactListSyncConstraints>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactListSyncManager>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactListSyncManager2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactLocationField>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactLocationFieldFactory>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactManagerForUser>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactManagerForUser2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactManagerStatics2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactManagerStatics3>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactManagerStatics4>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactManagerStatics5>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactMatchReason>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactName>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactPanel>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactPanelClosingEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactPanelLaunchFullAppRequestedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactPhone>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactPicker>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactPicker2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactPicker3>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactPickerStatics>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactQueryOptions>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactQueryOptionsFactory>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactQueryTextSearch>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactReader>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactSignificantOther>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactSignificantOther2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactStore>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactStore2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactStore3>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactStoreNotificationTriggerDetails>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactWebsite>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IContactWebsite2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IFullContactCardOptions>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IKnownContactFieldStatics>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IPinnedContactIdsQueryResult>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IPinnedContactManager>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::IPinnedContactManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::AggregateContactManager>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::Contact>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactAddress>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactAnnotation>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactAnnotationList>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactAnnotationStore>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactBatch>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactCardDelayedDataLoader>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactCardOptions>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactChange>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactChangeReader>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactChangeTracker>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactChangedDeferral>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactChangedEventArgs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactConnectedServiceAccount>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactDate>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactEmail>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactField>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactFieldFactory>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactGroup>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactInformation>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactInstantMessageField>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactJobInfo>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactLaunchActionVerbs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactList>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactListLimitedWriteOperations>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactListSyncConstraints>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactListSyncManager>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactLocationField>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactManager>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactManagerForUser>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactMatchReason>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactPanel>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactPanelClosingEventArgs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactPanelLaunchFullAppRequestedEventArgs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactPhone>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactPicker>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactQueryOptions>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactQueryTextSearch>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactReader>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactSignificantOther>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactStore>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactStoreNotificationTriggerDetails>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactWebsite>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::FullContactCardOptions>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::KnownContactField>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::PinnedContactIdsQueryResult>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::PinnedContactManager>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactAddressKind>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactAnnotationOperations>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactAnnotationStoreAccessType>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactBatchStatus>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactCardHeaderKind>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactCardTabKind>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactChangeType>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactDateKind>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactEmailKind>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactFieldCategory>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactFieldType>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactListOtherAppReadAccess>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactListOtherAppWriteAccess>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactListSyncStatus>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactMatchReasonKind>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactNameOrder>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactPhoneKind>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactQueryDesiredFields>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactQuerySearchFields>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactQuerySearchScope>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactRelationship>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactSelectionMode>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Contacts::ContactStoreAccessType>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Contacts::PinnedContactSurface>{ using type = enum_category; };
template <> struct name<Windows::ApplicationModel::Contacts::IAggregateContactManager>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IAggregateContactManager" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IAggregateContactManager2>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IAggregateContactManager2" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContact>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContact" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContact2>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContact2" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContact3>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContact3" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactAddress>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactAddress" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactAnnotation>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactAnnotation" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactAnnotation2>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactAnnotation2" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactAnnotationList>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactAnnotationList" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactAnnotationStore>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactAnnotationStore" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactAnnotationStore2>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactAnnotationStore2" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactBatch>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactBatch" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactCardDelayedDataLoader>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactCardDelayedDataLoader" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactCardOptions>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactCardOptions" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactCardOptions2>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactCardOptions2" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactChange>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactChange" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactChangeReader>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactChangeReader" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactChangeTracker>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactChangeTracker" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactChangeTracker2>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactChangeTracker2" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactChangedDeferral>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactChangedDeferral" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactChangedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactChangedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactConnectedServiceAccount>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactConnectedServiceAccount" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactDate>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactDate" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactEmail>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactEmail" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactField>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactField" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactFieldFactory>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactFieldFactory" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactGroup>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactGroup" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactInformation>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactInformation" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactInstantMessageField>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactInstantMessageField" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactInstantMessageFieldFactory>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactInstantMessageFieldFactory" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactJobInfo>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactJobInfo" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactLaunchActionVerbsStatics>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactLaunchActionVerbsStatics" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactList>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactList" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactList2>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactList2" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactList3>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactList3" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactListLimitedWriteOperations>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactListLimitedWriteOperations" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactListSyncConstraints>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactListSyncConstraints" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactListSyncManager>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactListSyncManager" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactListSyncManager2>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactListSyncManager2" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactLocationField>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactLocationField" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactLocationFieldFactory>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactLocationFieldFactory" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactManagerForUser>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactManagerForUser" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactManagerForUser2>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactManagerForUser2" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactManagerStatics>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactManagerStatics" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactManagerStatics2>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactManagerStatics2" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactManagerStatics3>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactManagerStatics3" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactManagerStatics4>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactManagerStatics4" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactManagerStatics5>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactManagerStatics5" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactMatchReason>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactMatchReason" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactName>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactName" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactPanel>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactPanel" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactPanelClosingEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactPanelClosingEventArgs" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactPanelLaunchFullAppRequestedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactPanelLaunchFullAppRequestedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactPhone>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactPhone" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactPicker>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactPicker" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactPicker2>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactPicker2" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactPicker3>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactPicker3" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactPickerStatics>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactPickerStatics" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactQueryOptions>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactQueryOptions" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactQueryOptionsFactory>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactQueryOptionsFactory" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactQueryTextSearch>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactQueryTextSearch" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactReader>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactReader" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactSignificantOther>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactSignificantOther" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactSignificantOther2>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactSignificantOther2" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactStore>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactStore" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactStore2>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactStore2" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactStore3>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactStore3" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactStoreNotificationTriggerDetails>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactStoreNotificationTriggerDetails" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactWebsite>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactWebsite" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IContactWebsite2>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IContactWebsite2" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IFullContactCardOptions>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IFullContactCardOptions" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IKnownContactFieldStatics>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IKnownContactFieldStatics" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IPinnedContactIdsQueryResult>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IPinnedContactIdsQueryResult" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IPinnedContactManager>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IPinnedContactManager" }; };
template <> struct name<Windows::ApplicationModel::Contacts::IPinnedContactManagerStatics>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.IPinnedContactManagerStatics" }; };
template <> struct name<Windows::ApplicationModel::Contacts::AggregateContactManager>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.AggregateContactManager" }; };
template <> struct name<Windows::ApplicationModel::Contacts::Contact>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.Contact" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactAddress>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactAddress" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactAnnotation>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactAnnotation" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactAnnotationList>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactAnnotationList" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactAnnotationStore>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactAnnotationStore" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactBatch>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactBatch" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactCardDelayedDataLoader>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactCardDelayedDataLoader" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactCardOptions>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactCardOptions" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactChange>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactChange" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactChangeReader>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactChangeReader" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactChangeTracker>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactChangeTracker" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactChangedDeferral>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactChangedDeferral" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactChangedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactChangedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactConnectedServiceAccount>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactConnectedServiceAccount" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactDate>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactDate" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactEmail>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactEmail" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactField>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactField" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactFieldFactory>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactFieldFactory" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactGroup>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactGroup" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactInformation>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactInformation" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactInstantMessageField>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactInstantMessageField" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactJobInfo>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactJobInfo" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactLaunchActionVerbs>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactLaunchActionVerbs" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactList>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactList" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactListLimitedWriteOperations>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactListLimitedWriteOperations" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactListSyncConstraints>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactListSyncConstraints" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactListSyncManager>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactListSyncManager" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactLocationField>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactLocationField" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactManager>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactManager" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactManagerForUser>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactManagerForUser" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactMatchReason>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactMatchReason" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactPanel>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactPanel" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactPanelClosingEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactPanelClosingEventArgs" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactPanelLaunchFullAppRequestedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactPanelLaunchFullAppRequestedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactPhone>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactPhone" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactPicker>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactPicker" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactQueryOptions>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactQueryOptions" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactQueryTextSearch>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactQueryTextSearch" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactReader>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactReader" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactSignificantOther>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactSignificantOther" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactStore>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactStore" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactStoreNotificationTriggerDetails>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactStoreNotificationTriggerDetails" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactWebsite>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactWebsite" }; };
template <> struct name<Windows::ApplicationModel::Contacts::FullContactCardOptions>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.FullContactCardOptions" }; };
template <> struct name<Windows::ApplicationModel::Contacts::KnownContactField>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.KnownContactField" }; };
template <> struct name<Windows::ApplicationModel::Contacts::PinnedContactIdsQueryResult>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.PinnedContactIdsQueryResult" }; };
template <> struct name<Windows::ApplicationModel::Contacts::PinnedContactManager>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.PinnedContactManager" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactAddressKind>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactAddressKind" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactAnnotationOperations>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactAnnotationOperations" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactAnnotationStoreAccessType>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactAnnotationStoreAccessType" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactBatchStatus>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactBatchStatus" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactCardHeaderKind>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactCardHeaderKind" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactCardTabKind>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactCardTabKind" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactChangeType>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactChangeType" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactDateKind>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactDateKind" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactEmailKind>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactEmailKind" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactFieldCategory>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactFieldCategory" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactFieldType>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactFieldType" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactListOtherAppReadAccess>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactListOtherAppReadAccess" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactListOtherAppWriteAccess>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactListOtherAppWriteAccess" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactListSyncStatus>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactListSyncStatus" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactMatchReasonKind>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactMatchReasonKind" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactNameOrder>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactNameOrder" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactPhoneKind>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactPhoneKind" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactQueryDesiredFields>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactQueryDesiredFields" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactQuerySearchFields>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactQuerySearchFields" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactQuerySearchScope>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactQuerySearchScope" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactRelationship>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactRelationship" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactSelectionMode>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactSelectionMode" }; };
template <> struct name<Windows::ApplicationModel::Contacts::ContactStoreAccessType>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.ContactStoreAccessType" }; };
template <> struct name<Windows::ApplicationModel::Contacts::PinnedContactSurface>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.PinnedContactSurface" }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IAggregateContactManager>{ static constexpr guid value{ 0x0379D5DD,0xDB5A,0x4FD3,{ 0xB5,0x4E,0x4D,0xF1,0x79,0x17,0xA2,0x12 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IAggregateContactManager2>{ static constexpr guid value{ 0x5E8CC2D8,0xA9CD,0x4430,{ 0x9C,0x4B,0x01,0x34,0x8D,0xB2,0xCA,0x50 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContact>{ static constexpr guid value{ 0xEC0072F3,0x2118,0x4049,{ 0x9E,0xBC,0x17,0xF0,0xAB,0x69,0x2B,0x64 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContact2>{ static constexpr guid value{ 0xF312F365,0xBB77,0x4C94,{ 0x80,0x2D,0x83,0x28,0xCE,0xE4,0x0C,0x08 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContact3>{ static constexpr guid value{ 0x48201E67,0xE08E,0x42A4,{ 0xB5,0x61,0x41,0xD0,0x8C,0xA9,0x57,0x5D } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactAddress>{ static constexpr guid value{ 0x9739D39A,0x42CE,0x4872,{ 0x8D,0x70,0x30,0x63,0xAA,0x58,0x4B,0x70 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactAnnotation>{ static constexpr guid value{ 0x821FC2EF,0x7D41,0x44A2,{ 0x84,0xC3,0x60,0xA2,0x81,0xDD,0x7B,0x86 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactAnnotation2>{ static constexpr guid value{ 0xB691ECF3,0x4AB7,0x4A1F,{ 0x99,0x41,0x0C,0x9C,0xF3,0x17,0x1B,0x75 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactAnnotationList>{ static constexpr guid value{ 0x92A486AA,0x5C88,0x45B9,{ 0xAA,0xD0,0x46,0x18,0x88,0xE6,0x8D,0x8A } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactAnnotationStore>{ static constexpr guid value{ 0x23ACF4AA,0x7A77,0x457D,{ 0x82,0x03,0x98,0x7F,0x4B,0x31,0xAF,0x09 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactAnnotationStore2>{ static constexpr guid value{ 0x7EDE23FD,0x61E7,0x4967,{ 0x8E,0xC5,0xBD,0xF2,0x80,0xA2,0x40,0x63 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactBatch>{ static constexpr guid value{ 0x35D1972D,0xBFCE,0x46BB,{ 0x93,0xF8,0xA5,0xB0,0x6E,0xC5,0xE2,0x01 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactCardDelayedDataLoader>{ static constexpr guid value{ 0xB60AF902,0x1546,0x434D,{ 0x86,0x9C,0x6E,0x35,0x20,0x76,0x0E,0xF3 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactCardOptions>{ static constexpr guid value{ 0x8C0A4F7E,0x6AB6,0x4F3F,{ 0xBE,0x72,0x81,0x72,0x36,0xEE,0xEA,0x5B } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactCardOptions2>{ static constexpr guid value{ 0x8F271BA0,0xD74B,0x4CC6,{ 0x9F,0x53,0x1B,0x0E,0xB5,0xD1,0x27,0x3C } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactChange>{ static constexpr guid value{ 0x951D4B10,0x6A59,0x4720,{ 0xA4,0xE1,0x36,0x3D,0x98,0xC1,0x35,0xD5 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactChangeReader>{ static constexpr guid value{ 0x217319FA,0x2D0C,0x42E0,{ 0xA9,0xDA,0x3E,0xCD,0x56,0xA7,0x8A,0x47 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactChangeTracker>{ static constexpr guid value{ 0x6E992952,0x309B,0x404D,{ 0x97,0x12,0xB3,0x7B,0xD3,0x02,0x78,0xAA } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactChangeTracker2>{ static constexpr guid value{ 0x7F8AD0FC,0x9321,0x4D18,{ 0x9C,0x09,0xD7,0x08,0xC6,0x3F,0xCD,0x31 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactChangedDeferral>{ static constexpr guid value{ 0xC5143AE8,0x1B03,0x46F8,{ 0xB6,0x94,0xA5,0x23,0xE8,0x3C,0xFC,0xB6 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactChangedEventArgs>{ static constexpr guid value{ 0x525E7FD1,0x73F3,0x4B7D,{ 0xA9,0x18,0x58,0x0B,0xE4,0x36,0x61,0x21 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactConnectedServiceAccount>{ static constexpr guid value{ 0xF6F83553,0xAA27,0x4731,{ 0x8E,0x4A,0x3D,0xEC,0x5C,0xE9,0xEE,0xC9 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactDate>{ static constexpr guid value{ 0xFE98AE66,0xB205,0x4934,{ 0x91,0x74,0x0F,0xF2,0xB0,0x56,0x57,0x07 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactEmail>{ static constexpr guid value{ 0x90A219A9,0xE3D3,0x4D63,{ 0x99,0x3B,0x05,0xB9,0xA5,0x39,0x3A,0xBF } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactField>{ static constexpr guid value{ 0xB176486A,0xD293,0x492C,{ 0xA0,0x58,0xDB,0x57,0x5B,0x3E,0x3C,0x0F } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactFieldFactory>{ static constexpr guid value{ 0x85E2913F,0x0E4A,0x4A3E,{ 0x89,0x94,0x40,0x6A,0xE7,0xED,0x64,0x6E } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactGroup>{ static constexpr guid value{ 0x59BDEB01,0x9E9A,0x475D,{ 0xBF,0xE5,0xA3,0x7B,0x80,0x6D,0x85,0x2C } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactInformation>{ static constexpr guid value{ 0x275EB6D4,0x6A2E,0x4278,{ 0xA9,0x14,0xE4,0x60,0xD5,0xF0,0x88,0xF6 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactInstantMessageField>{ static constexpr guid value{ 0xCCE33B37,0x0D85,0x41FA,{ 0xB4,0x3D,0xDA,0x59,0x9C,0x3E,0xB0,0x09 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactInstantMessageFieldFactory>{ static constexpr guid value{ 0xBA0B6794,0x91A3,0x4BB2,{ 0xB1,0xB9,0x69,0xA5,0xDF,0xF0,0xBA,0x09 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactJobInfo>{ static constexpr guid value{ 0x6D117B4C,0xCE50,0x4B43,{ 0x9E,0x69,0xB1,0x82,0x58,0xEA,0x53,0x15 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactLaunchActionVerbsStatics>{ static constexpr guid value{ 0xFB1232D6,0xEE73,0x46E7,{ 0x87,0x61,0x11,0xCD,0x01,0x57,0x72,0x8F } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactList>{ static constexpr guid value{ 0x16DDEC75,0x392C,0x4845,{ 0x9D,0xFB,0x51,0xA3,0xE7,0xEF,0x3E,0x42 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactList2>{ static constexpr guid value{ 0xCB3943B4,0x4550,0x4DCB,{ 0x92,0x29,0x40,0xFF,0x91,0xFB,0x02,0x03 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactList3>{ static constexpr guid value{ 0x1578EE57,0x26FC,0x41E8,{ 0xA8,0x50,0x5A,0xA3,0x25,0x14,0xAC,0xA9 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactListLimitedWriteOperations>{ static constexpr guid value{ 0xE19813DA,0x4A0B,0x44B8,{ 0x9A,0x1F,0xA0,0xF3,0xD2,0x18,0x17,0x5F } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactListSyncConstraints>{ static constexpr guid value{ 0xB2B0BF01,0x3062,0x4E2E,{ 0x96,0x9D,0x01,0x8D,0x19,0x87,0xF3,0x14 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactListSyncManager>{ static constexpr guid value{ 0x146E83BE,0x7925,0x4ACC,{ 0x9D,0xE5,0x21,0xDD,0xD0,0x6F,0x86,0x74 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactListSyncManager2>{ static constexpr guid value{ 0xA9591247,0xBB55,0x4E23,{ 0x81,0x28,0x37,0x01,0x34,0xA8,0x5D,0x0D } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactLocationField>{ static constexpr guid value{ 0x9EC00F82,0xAB6E,0x4B36,{ 0x89,0xE3,0xB2,0x3B,0xC0,0xA1,0xDA,0xCC } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactLocationFieldFactory>{ static constexpr guid value{ 0xF79932D7,0x2FDF,0x43FE,{ 0x8F,0x18,0x41,0x89,0x73,0x90,0xBC,0xFE } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactManagerForUser>{ static constexpr guid value{ 0xB74BBA57,0x1076,0x4BEF,{ 0xAE,0xF3,0x54,0x68,0x6D,0x18,0x38,0x7D } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactManagerForUser2>{ static constexpr guid value{ 0x4D469C2E,0x3B75,0x4A73,{ 0xBB,0x30,0x73,0x66,0x45,0x47,0x22,0x56 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactManagerStatics>{ static constexpr guid value{ 0x81F21AC0,0xF661,0x4708,{ 0xBA,0x4F,0xD3,0x86,0xBD,0x0D,0x62,0x2E } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactManagerStatics2>{ static constexpr guid value{ 0xA178E620,0x47D8,0x48CC,{ 0x96,0x3C,0x95,0x92,0xB6,0xE5,0x10,0xC6 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactManagerStatics3>{ static constexpr guid value{ 0xC4CC3D42,0x7586,0x492A,{ 0x93,0x0B,0x7B,0xC1,0x38,0xFC,0x21,0x39 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactManagerStatics4>{ static constexpr guid value{ 0x24982272,0x347B,0x46DC,{ 0x8D,0x95,0x51,0xBD,0x41,0xE1,0x5A,0xAF } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactManagerStatics5>{ static constexpr guid value{ 0xF7591A87,0xACB7,0x4FAD,{ 0x90,0xF2,0xA8,0xAB,0x64,0xCD,0xBB,0xA4 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactMatchReason>{ static constexpr guid value{ 0xBC922504,0xE7D8,0x413E,{ 0x95,0xF4,0xB7,0x5C,0x54,0xC7,0x40,0x77 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactName>{ static constexpr guid value{ 0xF404E97B,0x9034,0x453C,{ 0x8E,0xBF,0x14,0x0A,0x38,0xC8,0x6F,0x1D } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactPanel>{ static constexpr guid value{ 0x41BF1265,0xD2EE,0x4B97,{ 0xA8,0x0A,0x7D,0x8D,0x64,0xCC,0xA6,0xF5 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactPanelClosingEventArgs>{ static constexpr guid value{ 0x222174D3,0xCF4B,0x46D7,{ 0xB7,0x39,0x6E,0xDC,0x16,0x11,0x0B,0xFB } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactPanelLaunchFullAppRequestedEventArgs>{ static constexpr guid value{ 0x88D61C0E,0x23B4,0x4BE8,{ 0x8A,0xFC,0x07,0x2C,0x25,0xA4,0x19,0x0D } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactPhone>{ static constexpr guid value{ 0x467DAB65,0x2712,0x4F52,{ 0xB7,0x83,0x9E,0xA8,0x11,0x1C,0x63,0xCD } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactPicker>{ static constexpr guid value{ 0x0E09FD91,0x42F8,0x4055,{ 0x90,0xA0,0x89,0x6F,0x96,0x73,0x89,0x36 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactPicker2>{ static constexpr guid value{ 0xB35011CF,0x5CEF,0x4D24,{ 0xAA,0x0C,0x34,0x0C,0x52,0x08,0x72,0x5D } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactPicker3>{ static constexpr guid value{ 0x0E723315,0xB243,0x4BED,{ 0x85,0x16,0x22,0xB1,0xA7,0xAC,0x0A,0xCE } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactPickerStatics>{ static constexpr guid value{ 0x7488C029,0x6A53,0x4258,{ 0xA3,0xE9,0x62,0xDF,0xF6,0x78,0x4B,0x6C } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactQueryOptions>{ static constexpr guid value{ 0x4408CC9E,0x7D7C,0x42F0,{ 0x8A,0xC7,0xF5,0x07,0x33,0xEC,0xDB,0xC1 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactQueryOptionsFactory>{ static constexpr guid value{ 0x543FBA47,0x8CE7,0x46CB,{ 0x9D,0xAC,0x9A,0xA4,0x2A,0x1B,0xC8,0xE2 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactQueryTextSearch>{ static constexpr guid value{ 0xF7E3F9CB,0xA957,0x439B,{ 0xA0,0xB7,0x1C,0x02,0xA1,0x96,0x3F,0xF0 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactReader>{ static constexpr guid value{ 0xD397E42E,0x1488,0x42F2,{ 0xBF,0x64,0x25,0x3F,0x48,0x84,0xBF,0xED } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactSignificantOther>{ static constexpr guid value{ 0x8873B5AB,0xC5FB,0x46D8,{ 0x93,0xFE,0xDA,0x3F,0xF1,0x93,0x40,0x54 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactSignificantOther2>{ static constexpr guid value{ 0x8D7BD474,0x3F03,0x45F8,{ 0xBA,0x0F,0xC4,0xED,0x37,0xD6,0x42,0x19 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactStore>{ static constexpr guid value{ 0x2C220B10,0x3A6C,0x4293,{ 0xB9,0xBC,0xFE,0x98,0x7F,0x6E,0x0D,0x52 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactStore2>{ static constexpr guid value{ 0x18CE1C22,0xEBD5,0x4BFB,{ 0xB6,0x90,0x5F,0x4F,0x27,0xC4,0xF0,0xE8 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactStore3>{ static constexpr guid value{ 0xCB882C6C,0x004E,0x4050,{ 0x87,0xF0,0x84,0x04,0x07,0xEE,0x68,0x18 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactStoreNotificationTriggerDetails>{ static constexpr guid value{ 0xABB298D6,0x878A,0x4F8B,{ 0xA9,0xCE,0x46,0xBB,0x7D,0x1C,0x84,0xCE } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactWebsite>{ static constexpr guid value{ 0x9F130176,0xDC1B,0x4055,{ 0xAD,0x66,0x65,0x2F,0x39,0xD9,0x90,0xE8 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IContactWebsite2>{ static constexpr guid value{ 0xF87EE91E,0x5647,0x4068,{ 0xBB,0x5E,0x4B,0x6F,0x43,0x7C,0xE3,0x08 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IFullContactCardOptions>{ static constexpr guid value{ 0x8744436C,0x5CF9,0x4683,{ 0xBD,0xCA,0xA1,0xFD,0xEB,0xF8,0xDB,0xCE } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IKnownContactFieldStatics>{ static constexpr guid value{ 0x2E0E1B12,0xD627,0x4FCA,{ 0xBA,0xD4,0x1F,0xAF,0x16,0x8C,0x7D,0x14 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IPinnedContactIdsQueryResult>{ static constexpr guid value{ 0x7D9B2552,0x1579,0x4DDC,{ 0x87,0x1F,0xA3,0x0A,0x3A,0xEA,0x9B,0xA1 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IPinnedContactManager>{ static constexpr guid value{ 0xFCBC740C,0xE1D6,0x45C3,{ 0xB8,0xB6,0xA3,0x56,0x04,0xE1,0x67,0xA0 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::IPinnedContactManagerStatics>{ static constexpr guid value{ 0xF65CCC7E,0xFDF9,0x486A,{ 0xAC,0xE9,0xBC,0x31,0x1D,0x0A,0xE7,0xF0 } }; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::AggregateContactManager>{ using type = Windows::ApplicationModel::Contacts::IAggregateContactManager; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::Contact>{ using type = Windows::ApplicationModel::Contacts::IContact; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactAddress>{ using type = Windows::ApplicationModel::Contacts::IContactAddress; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactAnnotation>{ using type = Windows::ApplicationModel::Contacts::IContactAnnotation; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactAnnotationList>{ using type = Windows::ApplicationModel::Contacts::IContactAnnotationList; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactAnnotationStore>{ using type = Windows::ApplicationModel::Contacts::IContactAnnotationStore; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactBatch>{ using type = Windows::ApplicationModel::Contacts::IContactBatch; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactCardDelayedDataLoader>{ using type = Windows::ApplicationModel::Contacts::IContactCardDelayedDataLoader; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactCardOptions>{ using type = Windows::ApplicationModel::Contacts::IContactCardOptions; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactChange>{ using type = Windows::ApplicationModel::Contacts::IContactChange; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactChangeReader>{ using type = Windows::ApplicationModel::Contacts::IContactChangeReader; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactChangeTracker>{ using type = Windows::ApplicationModel::Contacts::IContactChangeTracker; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactChangedDeferral>{ using type = Windows::ApplicationModel::Contacts::IContactChangedDeferral; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactChangedEventArgs>{ using type = Windows::ApplicationModel::Contacts::IContactChangedEventArgs; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactConnectedServiceAccount>{ using type = Windows::ApplicationModel::Contacts::IContactConnectedServiceAccount; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactDate>{ using type = Windows::ApplicationModel::Contacts::IContactDate; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactEmail>{ using type = Windows::ApplicationModel::Contacts::IContactEmail; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactField>{ using type = Windows::ApplicationModel::Contacts::IContactField; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactFieldFactory>{ using type = Windows::ApplicationModel::Contacts::IContactFieldFactory; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactGroup>{ using type = Windows::ApplicationModel::Contacts::IContactGroup; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactInformation>{ using type = Windows::ApplicationModel::Contacts::IContactInformation; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactInstantMessageField>{ using type = Windows::ApplicationModel::Contacts::IContactInstantMessageField; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactJobInfo>{ using type = Windows::ApplicationModel::Contacts::IContactJobInfo; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactList>{ using type = Windows::ApplicationModel::Contacts::IContactList; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactListLimitedWriteOperations>{ using type = Windows::ApplicationModel::Contacts::IContactListLimitedWriteOperations; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactListSyncConstraints>{ using type = Windows::ApplicationModel::Contacts::IContactListSyncConstraints; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactListSyncManager>{ using type = Windows::ApplicationModel::Contacts::IContactListSyncManager; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactLocationField>{ using type = Windows::ApplicationModel::Contacts::IContactLocationField; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactManagerForUser>{ using type = Windows::ApplicationModel::Contacts::IContactManagerForUser; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactMatchReason>{ using type = Windows::ApplicationModel::Contacts::IContactMatchReason; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactPanel>{ using type = Windows::ApplicationModel::Contacts::IContactPanel; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactPanelClosingEventArgs>{ using type = Windows::ApplicationModel::Contacts::IContactPanelClosingEventArgs; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactPanelLaunchFullAppRequestedEventArgs>{ using type = Windows::ApplicationModel::Contacts::IContactPanelLaunchFullAppRequestedEventArgs; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactPhone>{ using type = Windows::ApplicationModel::Contacts::IContactPhone; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactPicker>{ using type = Windows::ApplicationModel::Contacts::IContactPicker; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactQueryOptions>{ using type = Windows::ApplicationModel::Contacts::IContactQueryOptions; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactQueryTextSearch>{ using type = Windows::ApplicationModel::Contacts::IContactQueryTextSearch; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactReader>{ using type = Windows::ApplicationModel::Contacts::IContactReader; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactSignificantOther>{ using type = Windows::ApplicationModel::Contacts::IContactSignificantOther; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactStore>{ using type = Windows::ApplicationModel::Contacts::IContactStore; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactStoreNotificationTriggerDetails>{ using type = Windows::ApplicationModel::Contacts::IContactStoreNotificationTriggerDetails; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::ContactWebsite>{ using type = Windows::ApplicationModel::Contacts::IContactWebsite; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::FullContactCardOptions>{ using type = Windows::ApplicationModel::Contacts::IFullContactCardOptions; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::PinnedContactIdsQueryResult>{ using type = Windows::ApplicationModel::Contacts::IPinnedContactIdsQueryResult; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::PinnedContactManager>{ using type = Windows::ApplicationModel::Contacts::IPinnedContactManager; };

template <> struct abi<Windows::ApplicationModel::Contacts::IAggregateContactManager>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL FindRawContactsAsync(void* contact, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL TryLinkContactsAsync(void* primaryContact, void* secondaryContact, void** contact) noexcept = 0;
    virtual int32_t WINRT_CALL UnlinkRawContactAsync(void* contact, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL TrySetPreferredSourceForPictureAsync(void* aggregateContact, void* rawContact, void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IAggregateContactManager2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL SetRemoteIdentificationInformationAsync(void* contactListId, void* remoteSourceId, void* accountId, void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContact>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Name(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Thumbnail(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Thumbnail(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Fields(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContact2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Id(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Id(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Notes(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Notes(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Phones(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Emails(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Addresses(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ConnectedServiceAccounts(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ImportantDates(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DataSuppliers(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_JobInfo(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SignificantOthers(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Websites(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProviderProperties(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContact3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ContactListId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DisplayPictureUserUpdateTime(Windows::Foundation::DateTime* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DisplayPictureUserUpdateTime(Windows::Foundation::DateTime value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsMe(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AggregateId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RemoteId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RemoteId(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RingToneToken(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RingToneToken(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsDisplayPictureManuallySet(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LargeDisplayPicture(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SmallDisplayPicture(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SourceDisplayPicture(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SourceDisplayPicture(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TextToneToken(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_TextToneToken(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsAggregate(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FullName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DisplayNameOverride(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DisplayNameOverride(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Nickname(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Nickname(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SortName(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactAddress>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_StreetAddress(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_StreetAddress(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Locality(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Locality(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Region(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Region(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Country(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Country(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PostalCode(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_PostalCode(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Kind(Windows::ApplicationModel::Contacts::ContactAddressKind* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Kind(Windows::ApplicationModel::Contacts::ContactAddressKind value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Description(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Description(void* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactAnnotation>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Id(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AnnotationListId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContactId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ContactId(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RemoteId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RemoteId(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SupportedOperations(Windows::ApplicationModel::Contacts::ContactAnnotationOperations* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SupportedOperations(Windows::ApplicationModel::Contacts::ContactAnnotationOperations value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsDisabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProviderProperties(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactAnnotation2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ContactListId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ContactListId(void* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactAnnotationList>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Id(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProviderPackageFamilyName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UserDataAccountId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL DeleteAsync(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL TrySaveAnnotationAsync(void* annotation, void** ppResult) noexcept = 0;
    virtual int32_t WINRT_CALL GetAnnotationAsync(void* annotationId, void** annotation) noexcept = 0;
    virtual int32_t WINRT_CALL FindAnnotationsByRemoteIdAsync(void* remoteId, void** annotations) noexcept = 0;
    virtual int32_t WINRT_CALL FindAnnotationsAsync(void** annotations) noexcept = 0;
    virtual int32_t WINRT_CALL DeleteAnnotationAsync(void* annotation, void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactAnnotationStore>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL FindContactIdsByEmailAsync(void* emailAddress, void** contactIds) noexcept = 0;
    virtual int32_t WINRT_CALL FindContactIdsByPhoneNumberAsync(void* phoneNumber, void** contactIds) noexcept = 0;
    virtual int32_t WINRT_CALL FindAnnotationsForContactAsync(void* contact, void** annotations) noexcept = 0;
    virtual int32_t WINRT_CALL DisableAnnotationAsync(void* annotation, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateAnnotationListAsync(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateAnnotationListInAccountAsync(void* userDataAccountId, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetAnnotationListAsync(void* annotationListId, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL FindAnnotationListsAsync(void** lists) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactAnnotationStore2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL FindAnnotationsForContactListAsync(void* contactListId, void** annotations) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactBatch>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Contacts(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Status(Windows::ApplicationModel::Contacts::ContactBatchStatus* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactCardDelayedDataLoader>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL SetData(void* contact) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactCardOptions>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_HeaderKind(Windows::ApplicationModel::Contacts::ContactCardHeaderKind* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_HeaderKind(Windows::ApplicationModel::Contacts::ContactCardHeaderKind value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InitialTabKind(Windows::ApplicationModel::Contacts::ContactCardTabKind* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_InitialTabKind(Windows::ApplicationModel::Contacts::ContactCardTabKind value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactCardOptions2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ServerSearchContactListIds(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactChange>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ChangeType(Windows::ApplicationModel::Contacts::ContactChangeType* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Contact(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactChangeReader>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL AcceptChanges() noexcept = 0;
    virtual int32_t WINRT_CALL AcceptChangesThrough(void* lastChangeToAccept) noexcept = 0;
    virtual int32_t WINRT_CALL ReadBatchAsync(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactChangeTracker>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Enable() noexcept = 0;
    virtual int32_t WINRT_CALL GetChangeReader(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL Reset() noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactChangeTracker2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsTracking(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactChangedDeferral>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Complete() noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactChangedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDeferral(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactConnectedServiceAccount>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Id(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Id(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ServiceName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ServiceName(void* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactDate>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Day(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Day(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Month(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Month(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Year(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Year(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Kind(Windows::ApplicationModel::Contacts::ContactDateKind* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Kind(Windows::ApplicationModel::Contacts::ContactDateKind value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Description(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Description(void* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactEmail>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Address(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Address(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Kind(Windows::ApplicationModel::Contacts::ContactEmailKind* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Kind(Windows::ApplicationModel::Contacts::ContactEmailKind value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Description(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Description(void* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactField>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Type(Windows::ApplicationModel::Contacts::ContactFieldType* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Category(Windows::ApplicationModel::Contacts::ContactFieldCategory* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Value(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactFieldFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateField_Default(void* value, Windows::ApplicationModel::Contacts::ContactFieldType type, void** field) noexcept = 0;
    virtual int32_t WINRT_CALL CreateField_Category(void* value, Windows::ApplicationModel::Contacts::ContactFieldType type, Windows::ApplicationModel::Contacts::ContactFieldCategory category, void** field) noexcept = 0;
    virtual int32_t WINRT_CALL CreateField_Custom(void* name, void* value, Windows::ApplicationModel::Contacts::ContactFieldType type, Windows::ApplicationModel::Contacts::ContactFieldCategory category, void** field) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactGroup>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactInformation>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetThumbnailAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL get_Emails(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PhoneNumbers(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Locations(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InstantMessages(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CustomFields(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL QueryCustomFields(void* customName, void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactInstantMessageField>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_UserName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Service(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DisplayText(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LaunchUri(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactInstantMessageFieldFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateInstantMessage_Default(void* userName, void** field) noexcept = 0;
    virtual int32_t WINRT_CALL CreateInstantMessage_Category(void* userName, Windows::ApplicationModel::Contacts::ContactFieldCategory category, void** field) noexcept = 0;
    virtual int32_t WINRT_CALL CreateInstantMessage_All(void* userName, Windows::ApplicationModel::Contacts::ContactFieldCategory category, void* service, void* displayText, void* verb, void** field) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactJobInfo>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CompanyName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CompanyName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CompanyYomiName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CompanyYomiName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Department(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Department(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Title(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Title(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Manager(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Manager(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Office(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Office(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CompanyAddress(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CompanyAddress(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Description(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Description(void* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactLaunchActionVerbsStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Call(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Message(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Map(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Post(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_VideoCall(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactList>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Id(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DisplayName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DisplayName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SourceDisplayName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsHidden(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsHidden(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OtherAppReadAccess(Windows::ApplicationModel::Contacts::ContactListOtherAppReadAccess* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_OtherAppReadAccess(Windows::ApplicationModel::Contacts::ContactListOtherAppReadAccess value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OtherAppWriteAccess(Windows::ApplicationModel::Contacts::ContactListOtherAppWriteAccess* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_OtherAppWriteAccess(Windows::ApplicationModel::Contacts::ContactListOtherAppWriteAccess value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ChangeTracker(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SyncManager(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SupportsServerSearch(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UserDataAccountId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL add_ContactChanged(void* value, winrt::event_token* returnValue) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ContactChanged(winrt::event_token value) noexcept = 0;
    virtual int32_t WINRT_CALL SaveAsync(void** returnValue) noexcept = 0;
    virtual int32_t WINRT_CALL DeleteAsync(void** returnValue) noexcept = 0;
    virtual int32_t WINRT_CALL GetContactFromRemoteIdAsync(void* remoteId, void** contact) noexcept = 0;
    virtual int32_t WINRT_CALL GetMeContactAsync(void** meContact) noexcept = 0;
    virtual int32_t WINRT_CALL GetContactReader(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetContactReaderWithOptions(void* options, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL SaveContactAsync(void* contact, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL DeleteContactAsync(void* contact, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetContactAsync(void* contactId, void** contacts) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactList2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL RegisterSyncManagerAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL put_SupportsServerSearch(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SyncConstraints(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactList3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_LimitedWriteOperations(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetChangeTracker(void* identity, void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactListLimitedWriteOperations>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL TryCreateOrUpdateContactAsync(void* contact, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryDeleteContactAsync(void* contactId, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactListSyncConstraints>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CanSyncDescriptions(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CanSyncDescriptions(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxHomePhoneNumbers(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxHomePhoneNumbers(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxMobilePhoneNumbers(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxMobilePhoneNumbers(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxWorkPhoneNumbers(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxWorkPhoneNumbers(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxOtherPhoneNumbers(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxOtherPhoneNumbers(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxPagerPhoneNumbers(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxPagerPhoneNumbers(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxBusinessFaxPhoneNumbers(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxBusinessFaxPhoneNumbers(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxHomeFaxPhoneNumbers(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxHomeFaxPhoneNumbers(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxCompanyPhoneNumbers(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxCompanyPhoneNumbers(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxAssistantPhoneNumbers(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxAssistantPhoneNumbers(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxRadioPhoneNumbers(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxRadioPhoneNumbers(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxPersonalEmailAddresses(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxPersonalEmailAddresses(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxWorkEmailAddresses(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxWorkEmailAddresses(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxOtherEmailAddresses(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxOtherEmailAddresses(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxHomeAddresses(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxHomeAddresses(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxWorkAddresses(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxWorkAddresses(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxOtherAddresses(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxOtherAddresses(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxBirthdayDates(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxBirthdayDates(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxAnniversaryDates(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxAnniversaryDates(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxOtherDates(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxOtherDates(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxOtherRelationships(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxOtherRelationships(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxSpouseRelationships(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxSpouseRelationships(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxPartnerRelationships(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxPartnerRelationships(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxSiblingRelationships(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxSiblingRelationships(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxParentRelationships(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxParentRelationships(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxChildRelationships(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxChildRelationships(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxJobInfo(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxJobInfo(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxWebsites(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxWebsites(void* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactListSyncManager>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::ApplicationModel::Contacts::ContactListSyncStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LastSuccessfulSyncTime(Windows::Foundation::DateTime* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LastAttemptedSyncTime(Windows::Foundation::DateTime* value) noexcept = 0;
    virtual int32_t WINRT_CALL SyncAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL add_SyncStatusChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_SyncStatusChanged(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactListSyncManager2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL put_Status(Windows::ApplicationModel::Contacts::ContactListSyncStatus value) noexcept = 0;
    virtual int32_t WINRT_CALL put_LastSuccessfulSyncTime(Windows::Foundation::DateTime value) noexcept = 0;
    virtual int32_t WINRT_CALL put_LastAttemptedSyncTime(Windows::Foundation::DateTime value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactLocationField>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_UnstructuredAddress(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Street(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_City(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Region(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Country(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PostalCode(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactLocationFieldFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateLocation_Default(void* unstructuredAddress, void** field) noexcept = 0;
    virtual int32_t WINRT_CALL CreateLocation_Category(void* unstructuredAddress, Windows::ApplicationModel::Contacts::ContactFieldCategory category, void** field) noexcept = 0;
    virtual int32_t WINRT_CALL CreateLocation_All(void* unstructuredAddress, Windows::ApplicationModel::Contacts::ContactFieldCategory category, void* street, void* city, void* region, void* country, void* postalCode, void** field) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactManagerForUser>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ConvertContactToVCardAsync(void* contact, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL ConvertContactToVCardAsyncWithMaxBytes(void* contact, uint32_t maxBytes, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL ConvertVCardToContactAsync(void* vCard, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL RequestStoreAsync(Windows::ApplicationModel::Contacts::ContactStoreAccessType accessType, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL RequestAnnotationStoreAsync(Windows::ApplicationModel::Contacts::ContactAnnotationStoreAccessType accessType, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL get_SystemDisplayNameOrder(Windows::ApplicationModel::Contacts::ContactNameOrder* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SystemDisplayNameOrder(Windows::ApplicationModel::Contacts::ContactNameOrder value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SystemSortOrder(Windows::ApplicationModel::Contacts::ContactNameOrder* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SystemSortOrder(Windows::ApplicationModel::Contacts::ContactNameOrder value) noexcept = 0;
    virtual int32_t WINRT_CALL get_User(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactManagerForUser2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ShowFullContactCard(void* contact, void* fullContactCardOptions) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ShowContactCard(void* contact, Windows::Foundation::Rect selection) noexcept = 0;
    virtual int32_t WINRT_CALL ShowContactCardWithPlacement(void* contact, Windows::Foundation::Rect selection, Windows::UI::Popups::Placement preferredPlacement) noexcept = 0;
    virtual int32_t WINRT_CALL ShowDelayLoadedContactCard(void* contact, Windows::Foundation::Rect selection, Windows::UI::Popups::Placement preferredPlacement, void** dataLoader) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactManagerStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL RequestStoreAsync(void** store) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactManagerStatics3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ConvertContactToVCardAsync(void* contact, void** vCard) noexcept = 0;
    virtual int32_t WINRT_CALL ConvertContactToVCardAsyncWithMaxBytes(void* contact, uint32_t maxBytes, void** vCard) noexcept = 0;
    virtual int32_t WINRT_CALL ConvertVCardToContactAsync(void* vCard, void** contact) noexcept = 0;
    virtual int32_t WINRT_CALL RequestStoreAsyncWithAccessType(Windows::ApplicationModel::Contacts::ContactStoreAccessType accessType, void** store) noexcept = 0;
    virtual int32_t WINRT_CALL RequestAnnotationStoreAsync(Windows::ApplicationModel::Contacts::ContactAnnotationStoreAccessType accessType, void** store) noexcept = 0;
    virtual int32_t WINRT_CALL IsShowContactCardSupported(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL ShowContactCardWithOptions(void* contact, Windows::Foundation::Rect selection, Windows::UI::Popups::Placement preferredPlacement, void* contactCardOptions) noexcept = 0;
    virtual int32_t WINRT_CALL IsShowDelayLoadedContactCardSupported(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL ShowDelayLoadedContactCardWithOptions(void* contact, Windows::Foundation::Rect selection, Windows::UI::Popups::Placement preferredPlacement, void* contactCardOptions, void** dataLoader) noexcept = 0;
    virtual int32_t WINRT_CALL ShowFullContactCard(void* contact, void* fullContactCardOptions) noexcept = 0;
    virtual int32_t WINRT_CALL get_SystemDisplayNameOrder(Windows::ApplicationModel::Contacts::ContactNameOrder* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SystemDisplayNameOrder(Windows::ApplicationModel::Contacts::ContactNameOrder value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SystemSortOrder(Windows::ApplicationModel::Contacts::ContactNameOrder* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SystemSortOrder(Windows::ApplicationModel::Contacts::ContactNameOrder value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactManagerStatics4>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetForUser(void* user, void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactManagerStatics5>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL IsShowFullContactCardSupportedAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL get_IncludeMiddleNameInSystemDisplayAndSort(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IncludeMiddleNameInSystemDisplayAndSort(bool value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactMatchReason>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Field(Windows::ApplicationModel::Contacts::ContactMatchReasonKind* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Segments(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Text(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactName>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_FirstName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_FirstName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LastName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_LastName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MiddleName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MiddleName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_YomiGivenName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_YomiGivenName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_YomiFamilyName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_YomiFamilyName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HonorificNameSuffix(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_HonorificNameSuffix(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HonorificNamePrefix(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_HonorificNamePrefix(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DisplayName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_YomiDisplayName(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactPanel>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ClosePanel() noexcept = 0;
    virtual int32_t WINRT_CALL get_HeaderColor(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_HeaderColor(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_LaunchFullAppRequested(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_LaunchFullAppRequested(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_Closing(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Closing(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactPanelClosingEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDeferral(void** deferral) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactPanelLaunchFullAppRequestedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactPhone>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Number(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Number(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Kind(Windows::ApplicationModel::Contacts::ContactPhoneKind* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Kind(Windows::ApplicationModel::Contacts::ContactPhoneKind value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Description(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Description(void* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactPicker>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CommitButtonText(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CommitButtonText(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SelectionMode(Windows::ApplicationModel::Contacts::ContactSelectionMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SelectionMode(Windows::ApplicationModel::Contacts::ContactSelectionMode value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DesiredFields(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL PickSingleContactAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL PickMultipleContactsAsync(void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactPicker2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DesiredFieldsWithContactFieldType(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL PickContactAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL PickContactsAsync(void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactPicker3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_User(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactPickerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateForUser(void* user, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL IsSupportedAsync(void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactQueryOptions>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_TextSearch(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContactListIds(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IncludeContactsFromHiddenLists(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IncludeContactsFromHiddenLists(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DesiredFields(Windows::ApplicationModel::Contacts::ContactQueryDesiredFields* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DesiredFields(Windows::ApplicationModel::Contacts::ContactQueryDesiredFields value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DesiredOperations(Windows::ApplicationModel::Contacts::ContactAnnotationOperations* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DesiredOperations(Windows::ApplicationModel::Contacts::ContactAnnotationOperations value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AnnotationListIds(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactQueryOptionsFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateWithText(void* text, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateWithTextAndFields(void* text, Windows::ApplicationModel::Contacts::ContactQuerySearchFields fields, void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactQueryTextSearch>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Fields(Windows::ApplicationModel::Contacts::ContactQuerySearchFields* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Fields(Windows::ApplicationModel::Contacts::ContactQuerySearchFields value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Text(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Text(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SearchScope(Windows::ApplicationModel::Contacts::ContactQuerySearchScope* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SearchScope(Windows::ApplicationModel::Contacts::ContactQuerySearchScope value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactReader>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ReadBatchAsync(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetMatchingPropertiesWithMatchReason(void* contact, void** ppRetVal) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactSignificantOther>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Name(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Description(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Description(void* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactSignificantOther2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Relationship(Windows::ApplicationModel::Contacts::ContactRelationship* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Relationship(Windows::ApplicationModel::Contacts::ContactRelationship value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactStore>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL FindContactsAsync(void** contacts) noexcept = 0;
    virtual int32_t WINRT_CALL FindContactsWithSearchTextAsync(void* searchText, void** contacts) noexcept = 0;
    virtual int32_t WINRT_CALL GetContactAsync(void* contactId, void** contacts) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactStore2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ChangeTracker(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL add_ContactChanged(void* value, winrt::event_token* returnValue) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ContactChanged(winrt::event_token value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AggregateContactManager(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL FindContactListsAsync(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetContactListAsync(void* contactListId, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateContactListAsync(void* displayName, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetMeContactAsync(void** meContact) noexcept = 0;
    virtual int32_t WINRT_CALL GetContactReader(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetContactReaderWithOptions(void* options, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateContactListInAccountAsync(void* displayName, void* userDataAccountId, void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactStore3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetChangeTracker(void* identity, void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactStoreNotificationTriggerDetails>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactWebsite>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Uri(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Uri(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Description(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Description(void* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IContactWebsite2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_RawValue(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RawValue(void* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IFullContactCardOptions>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DesiredRemainingView(Windows::UI::ViewManagement::ViewSizePreference* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DesiredRemainingView(Windows::UI::ViewManagement::ViewSizePreference value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IKnownContactFieldStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Email(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PhoneNumber(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Location(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InstantMessage(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL ConvertNameToType(void* name, Windows::ApplicationModel::Contacts::ContactFieldType* type) noexcept = 0;
    virtual int32_t WINRT_CALL ConvertTypeToName(Windows::ApplicationModel::Contacts::ContactFieldType type, void** name) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IPinnedContactIdsQueryResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ContactIds(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IPinnedContactManager>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_User(void** user) noexcept = 0;
    virtual int32_t WINRT_CALL IsPinSurfaceSupported(Windows::ApplicationModel::Contacts::PinnedContactSurface surface, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL IsContactPinned(void* contact, Windows::ApplicationModel::Contacts::PinnedContactSurface surface, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL RequestPinContactAsync(void* contact, Windows::ApplicationModel::Contacts::PinnedContactSurface surface, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RequestPinContactsAsync(void* contacts, Windows::ApplicationModel::Contacts::PinnedContactSurface surface, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RequestUnpinContactAsync(void* contact, Windows::ApplicationModel::Contacts::PinnedContactSurface surface, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL SignalContactActivity(void* contact) noexcept = 0;
    virtual int32_t WINRT_CALL GetPinnedContactIdsAsync(void** operation) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::IPinnedContactManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDefault(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetForUser(void* user, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL IsSupported(bool* result) noexcept = 0;
};};

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IAggregateContactManager
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::Contact>> FindRawContactsAsync(Windows::ApplicationModel::Contacts::Contact const& contact) const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact> TryLinkContactsAsync(Windows::ApplicationModel::Contacts::Contact const& primaryContact, Windows::ApplicationModel::Contacts::Contact const& secondaryContact) const;
    Windows::Foundation::IAsyncAction UnlinkRawContactAsync(Windows::ApplicationModel::Contacts::Contact const& contact) const;
    Windows::Foundation::IAsyncOperation<bool> TrySetPreferredSourceForPictureAsync(Windows::ApplicationModel::Contacts::Contact const& aggregateContact, Windows::ApplicationModel::Contacts::Contact const& rawContact) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IAggregateContactManager> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IAggregateContactManager<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IAggregateContactManager2
{
    Windows::Foundation::IAsyncAction SetRemoteIdentificationInformationAsync(param::hstring const& contactListId, param::hstring const& remoteSourceId, param::hstring const& accountId) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IAggregateContactManager2> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IAggregateContactManager2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContact
{
    hstring Name() const;
    void Name(param::hstring const& value) const;
    Windows::Storage::Streams::IRandomAccessStreamReference Thumbnail() const;
    void Thumbnail(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const;
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::IContactField> Fields() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContact> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContact<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContact2
{
    hstring Id() const;
    void Id(param::hstring const& value) const;
    hstring Notes() const;
    void Notes(param::hstring const& value) const;
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactPhone> Phones() const;
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactEmail> Emails() const;
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactAddress> Addresses() const;
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactConnectedServiceAccount> ConnectedServiceAccounts() const;
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactDate> ImportantDates() const;
    Windows::Foundation::Collections::IVector<hstring> DataSuppliers() const;
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactJobInfo> JobInfo() const;
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactSignificantOther> SignificantOthers() const;
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactWebsite> Websites() const;
    Windows::Foundation::Collections::IPropertySet ProviderProperties() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContact2> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContact2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContact3
{
    hstring ContactListId() const;
    Windows::Foundation::DateTime DisplayPictureUserUpdateTime() const;
    void DisplayPictureUserUpdateTime(Windows::Foundation::DateTime const& value) const;
    bool IsMe() const;
    hstring AggregateId() const;
    hstring RemoteId() const;
    void RemoteId(param::hstring const& value) const;
    hstring RingToneToken() const;
    void RingToneToken(param::hstring const& value) const;
    bool IsDisplayPictureManuallySet() const;
    Windows::Storage::Streams::IRandomAccessStreamReference LargeDisplayPicture() const;
    Windows::Storage::Streams::IRandomAccessStreamReference SmallDisplayPicture() const;
    Windows::Storage::Streams::IRandomAccessStreamReference SourceDisplayPicture() const;
    void SourceDisplayPicture(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const;
    hstring TextToneToken() const;
    void TextToneToken(param::hstring const& value) const;
    bool IsAggregate() const;
    hstring FullName() const;
    hstring DisplayNameOverride() const;
    void DisplayNameOverride(param::hstring const& value) const;
    hstring Nickname() const;
    void Nickname(param::hstring const& value) const;
    hstring SortName() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContact3> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContact3<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactAddress
{
    hstring StreetAddress() const;
    void StreetAddress(param::hstring const& value) const;
    hstring Locality() const;
    void Locality(param::hstring const& value) const;
    hstring Region() const;
    void Region(param::hstring const& value) const;
    hstring Country() const;
    void Country(param::hstring const& value) const;
    hstring PostalCode() const;
    void PostalCode(param::hstring const& value) const;
    Windows::ApplicationModel::Contacts::ContactAddressKind Kind() const;
    void Kind(Windows::ApplicationModel::Contacts::ContactAddressKind const& value) const;
    hstring Description() const;
    void Description(param::hstring const& value) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactAddress> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactAddress<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactAnnotation
{
    hstring Id() const;
    hstring AnnotationListId() const;
    hstring ContactId() const;
    void ContactId(param::hstring const& value) const;
    hstring RemoteId() const;
    void RemoteId(param::hstring const& value) const;
    Windows::ApplicationModel::Contacts::ContactAnnotationOperations SupportedOperations() const;
    void SupportedOperations(Windows::ApplicationModel::Contacts::ContactAnnotationOperations const& value) const;
    bool IsDisabled() const;
    Windows::Foundation::Collections::ValueSet ProviderProperties() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactAnnotation> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactAnnotation<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactAnnotation2
{
    hstring ContactListId() const;
    void ContactListId(param::hstring const& value) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactAnnotation2> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactAnnotation2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactAnnotationList
{
    hstring Id() const;
    hstring ProviderPackageFamilyName() const;
    hstring UserDataAccountId() const;
    Windows::Foundation::IAsyncAction DeleteAsync() const;
    Windows::Foundation::IAsyncOperation<bool> TrySaveAnnotationAsync(Windows::ApplicationModel::Contacts::ContactAnnotation const& annotation) const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactAnnotation> GetAnnotationAsync(param::hstring const& annotationId) const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactAnnotation>> FindAnnotationsByRemoteIdAsync(param::hstring const& remoteId) const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactAnnotation>> FindAnnotationsAsync() const;
    Windows::Foundation::IAsyncAction DeleteAnnotationAsync(Windows::ApplicationModel::Contacts::ContactAnnotation const& annotation) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactAnnotationList> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactAnnotationList<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactAnnotationStore
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>> FindContactIdsByEmailAsync(param::hstring const& emailAddress) const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>> FindContactIdsByPhoneNumberAsync(param::hstring const& phoneNumber) const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactAnnotation>> FindAnnotationsForContactAsync(Windows::ApplicationModel::Contacts::Contact const& contact) const;
    Windows::Foundation::IAsyncAction DisableAnnotationAsync(Windows::ApplicationModel::Contacts::ContactAnnotation const& annotation) const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactAnnotationList> CreateAnnotationListAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactAnnotationList> CreateAnnotationListAsync(param::hstring const& userDataAccountId) const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactAnnotationList> GetAnnotationListAsync(param::hstring const& annotationListId) const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactAnnotationList>> FindAnnotationListsAsync() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactAnnotationStore> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactAnnotationStore<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactAnnotationStore2
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactAnnotation>> FindAnnotationsForContactListAsync(param::hstring const& contactListId) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactAnnotationStore2> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactAnnotationStore2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactBatch
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::Contact> Contacts() const;
    Windows::ApplicationModel::Contacts::ContactBatchStatus Status() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactBatch> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactBatch<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactCardDelayedDataLoader
{
    void SetData(Windows::ApplicationModel::Contacts::Contact const& contact) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactCardDelayedDataLoader> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactCardDelayedDataLoader<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactCardOptions
{
    Windows::ApplicationModel::Contacts::ContactCardHeaderKind HeaderKind() const;
    void HeaderKind(Windows::ApplicationModel::Contacts::ContactCardHeaderKind const& value) const;
    Windows::ApplicationModel::Contacts::ContactCardTabKind InitialTabKind() const;
    void InitialTabKind(Windows::ApplicationModel::Contacts::ContactCardTabKind const& value) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactCardOptions> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactCardOptions<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactCardOptions2
{
    Windows::Foundation::Collections::IVector<hstring> ServerSearchContactListIds() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactCardOptions2> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactCardOptions2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactChange
{
    Windows::ApplicationModel::Contacts::ContactChangeType ChangeType() const;
    Windows::ApplicationModel::Contacts::Contact Contact() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactChange> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactChange<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactChangeReader
{
    void AcceptChanges() const;
    void AcceptChangesThrough(Windows::ApplicationModel::Contacts::ContactChange const& lastChangeToAccept) const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactChange>> ReadBatchAsync() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactChangeReader> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactChangeReader<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactChangeTracker
{
    void Enable() const;
    Windows::ApplicationModel::Contacts::ContactChangeReader GetChangeReader() const;
    void Reset() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactChangeTracker> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactChangeTracker<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactChangeTracker2
{
    bool IsTracking() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactChangeTracker2> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactChangeTracker2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactChangedDeferral
{
    void Complete() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactChangedDeferral> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactChangedDeferral<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactChangedEventArgs
{
    Windows::ApplicationModel::Contacts::ContactChangedDeferral GetDeferral() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactChangedEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactChangedEventArgs<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactConnectedServiceAccount
{
    hstring Id() const;
    void Id(param::hstring const& value) const;
    hstring ServiceName() const;
    void ServiceName(param::hstring const& value) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactConnectedServiceAccount> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactConnectedServiceAccount<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactDate
{
    Windows::Foundation::IReference<uint32_t> Day() const;
    void Day(optional<uint32_t> const& value) const;
    Windows::Foundation::IReference<uint32_t> Month() const;
    void Month(optional<uint32_t> const& value) const;
    Windows::Foundation::IReference<int32_t> Year() const;
    void Year(optional<int32_t> const& value) const;
    Windows::ApplicationModel::Contacts::ContactDateKind Kind() const;
    void Kind(Windows::ApplicationModel::Contacts::ContactDateKind const& value) const;
    hstring Description() const;
    void Description(param::hstring const& value) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactDate> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactDate<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactEmail
{
    hstring Address() const;
    void Address(param::hstring const& value) const;
    Windows::ApplicationModel::Contacts::ContactEmailKind Kind() const;
    void Kind(Windows::ApplicationModel::Contacts::ContactEmailKind const& value) const;
    hstring Description() const;
    void Description(param::hstring const& value) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactEmail> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactEmail<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactField
{
    Windows::ApplicationModel::Contacts::ContactFieldType Type() const;
    Windows::ApplicationModel::Contacts::ContactFieldCategory Category() const;
    hstring Name() const;
    hstring Value() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactField> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactField<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactFieldFactory
{
    Windows::ApplicationModel::Contacts::ContactField CreateField(param::hstring const& value, Windows::ApplicationModel::Contacts::ContactFieldType const& type) const;
    Windows::ApplicationModel::Contacts::ContactField CreateField(param::hstring const& value, Windows::ApplicationModel::Contacts::ContactFieldType const& type, Windows::ApplicationModel::Contacts::ContactFieldCategory const& category) const;
    Windows::ApplicationModel::Contacts::ContactField CreateField(param::hstring const& name, param::hstring const& value, Windows::ApplicationModel::Contacts::ContactFieldType const& type, Windows::ApplicationModel::Contacts::ContactFieldCategory const& category) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactFieldFactory> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactFieldFactory<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactGroup
{
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactGroup> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactGroup<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactInformation
{
    hstring Name() const;
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStreamWithContentType> GetThumbnailAsync() const;
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactField> Emails() const;
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactField> PhoneNumbers() const;
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactLocationField> Locations() const;
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactInstantMessageField> InstantMessages() const;
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactField> CustomFields() const;
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactField> QueryCustomFields(param::hstring const& customName) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactInformation> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactInformation<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactInstantMessageField
{
    hstring UserName() const;
    hstring Service() const;
    hstring DisplayText() const;
    Windows::Foundation::Uri LaunchUri() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactInstantMessageField> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactInstantMessageField<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactInstantMessageFieldFactory
{
    Windows::ApplicationModel::Contacts::ContactInstantMessageField CreateInstantMessage(param::hstring const& userName) const;
    Windows::ApplicationModel::Contacts::ContactInstantMessageField CreateInstantMessage(param::hstring const& userName, Windows::ApplicationModel::Contacts::ContactFieldCategory const& category) const;
    Windows::ApplicationModel::Contacts::ContactInstantMessageField CreateInstantMessage(param::hstring const& userName, Windows::ApplicationModel::Contacts::ContactFieldCategory const& category, param::hstring const& service, param::hstring const& displayText, Windows::Foundation::Uri const& verb) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactInstantMessageFieldFactory> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactInstantMessageFieldFactory<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactJobInfo
{
    hstring CompanyName() const;
    void CompanyName(param::hstring const& value) const;
    hstring CompanyYomiName() const;
    void CompanyYomiName(param::hstring const& value) const;
    hstring Department() const;
    void Department(param::hstring const& value) const;
    hstring Title() const;
    void Title(param::hstring const& value) const;
    hstring Manager() const;
    void Manager(param::hstring const& value) const;
    hstring Office() const;
    void Office(param::hstring const& value) const;
    hstring CompanyAddress() const;
    void CompanyAddress(param::hstring const& value) const;
    hstring Description() const;
    void Description(param::hstring const& value) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactJobInfo> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactJobInfo<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactLaunchActionVerbsStatics
{
    hstring Call() const;
    hstring Message() const;
    hstring Map() const;
    hstring Post() const;
    hstring VideoCall() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactLaunchActionVerbsStatics> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactLaunchActionVerbsStatics<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactList
{
    hstring Id() const;
    hstring DisplayName() const;
    void DisplayName(param::hstring const& value) const;
    hstring SourceDisplayName() const;
    bool IsHidden() const;
    void IsHidden(bool value) const;
    Windows::ApplicationModel::Contacts::ContactListOtherAppReadAccess OtherAppReadAccess() const;
    void OtherAppReadAccess(Windows::ApplicationModel::Contacts::ContactListOtherAppReadAccess const& value) const;
    Windows::ApplicationModel::Contacts::ContactListOtherAppWriteAccess OtherAppWriteAccess() const;
    void OtherAppWriteAccess(Windows::ApplicationModel::Contacts::ContactListOtherAppWriteAccess const& value) const;
    Windows::ApplicationModel::Contacts::ContactChangeTracker ChangeTracker() const;
    Windows::ApplicationModel::Contacts::ContactListSyncManager SyncManager() const;
    bool SupportsServerSearch() const;
    hstring UserDataAccountId() const;
    winrt::event_token ContactChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::ContactList, Windows::ApplicationModel::Contacts::ContactChangedEventArgs> const& value) const;
    using ContactChanged_revoker = impl::event_revoker<Windows::ApplicationModel::Contacts::IContactList, &impl::abi_t<Windows::ApplicationModel::Contacts::IContactList>::remove_ContactChanged>;
    ContactChanged_revoker ContactChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::ContactList, Windows::ApplicationModel::Contacts::ContactChangedEventArgs> const& value) const;
    void ContactChanged(winrt::event_token const& value) const noexcept;
    Windows::Foundation::IAsyncAction SaveAsync() const;
    Windows::Foundation::IAsyncAction DeleteAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact> GetContactFromRemoteIdAsync(param::hstring const& remoteId) const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact> GetMeContactAsync() const;
    Windows::ApplicationModel::Contacts::ContactReader GetContactReader() const;
    Windows::ApplicationModel::Contacts::ContactReader GetContactReader(Windows::ApplicationModel::Contacts::ContactQueryOptions const& options) const;
    Windows::Foundation::IAsyncAction SaveContactAsync(Windows::ApplicationModel::Contacts::Contact const& contact) const;
    Windows::Foundation::IAsyncAction DeleteContactAsync(Windows::ApplicationModel::Contacts::Contact const& contact) const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact> GetContactAsync(param::hstring const& contactId) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactList> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactList<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactList2
{
    Windows::Foundation::IAsyncAction RegisterSyncManagerAsync() const;
    void SupportsServerSearch(bool value) const;
    Windows::ApplicationModel::Contacts::ContactListSyncConstraints SyncConstraints() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactList2> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactList2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactList3
{
    Windows::ApplicationModel::Contacts::ContactListLimitedWriteOperations LimitedWriteOperations() const;
    Windows::ApplicationModel::Contacts::ContactChangeTracker GetChangeTracker(param::hstring const& identity) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactList3> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactList3<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactListLimitedWriteOperations
{
    Windows::Foundation::IAsyncOperation<bool> TryCreateOrUpdateContactAsync(Windows::ApplicationModel::Contacts::Contact const& contact) const;
    Windows::Foundation::IAsyncOperation<bool> TryDeleteContactAsync(param::hstring const& contactId) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactListLimitedWriteOperations> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactListLimitedWriteOperations<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints
{
    bool CanSyncDescriptions() const;
    void CanSyncDescriptions(bool value) const;
    Windows::Foundation::IReference<int32_t> MaxHomePhoneNumbers() const;
    void MaxHomePhoneNumbers(optional<int32_t> const& value) const;
    Windows::Foundation::IReference<int32_t> MaxMobilePhoneNumbers() const;
    void MaxMobilePhoneNumbers(optional<int32_t> const& value) const;
    Windows::Foundation::IReference<int32_t> MaxWorkPhoneNumbers() const;
    void MaxWorkPhoneNumbers(optional<int32_t> const& value) const;
    Windows::Foundation::IReference<int32_t> MaxOtherPhoneNumbers() const;
    void MaxOtherPhoneNumbers(optional<int32_t> const& value) const;
    Windows::Foundation::IReference<int32_t> MaxPagerPhoneNumbers() const;
    void MaxPagerPhoneNumbers(optional<int32_t> const& value) const;
    Windows::Foundation::IReference<int32_t> MaxBusinessFaxPhoneNumbers() const;
    void MaxBusinessFaxPhoneNumbers(optional<int32_t> const& value) const;
    Windows::Foundation::IReference<int32_t> MaxHomeFaxPhoneNumbers() const;
    void MaxHomeFaxPhoneNumbers(optional<int32_t> const& value) const;
    Windows::Foundation::IReference<int32_t> MaxCompanyPhoneNumbers() const;
    void MaxCompanyPhoneNumbers(optional<int32_t> const& value) const;
    Windows::Foundation::IReference<int32_t> MaxAssistantPhoneNumbers() const;
    void MaxAssistantPhoneNumbers(optional<int32_t> const& value) const;
    Windows::Foundation::IReference<int32_t> MaxRadioPhoneNumbers() const;
    void MaxRadioPhoneNumbers(optional<int32_t> const& value) const;
    Windows::Foundation::IReference<int32_t> MaxPersonalEmailAddresses() const;
    void MaxPersonalEmailAddresses(optional<int32_t> const& value) const;
    Windows::Foundation::IReference<int32_t> MaxWorkEmailAddresses() const;
    void MaxWorkEmailAddresses(optional<int32_t> const& value) const;
    Windows::Foundation::IReference<int32_t> MaxOtherEmailAddresses() const;
    void MaxOtherEmailAddresses(optional<int32_t> const& value) const;
    Windows::Foundation::IReference<int32_t> MaxHomeAddresses() const;
    void MaxHomeAddresses(optional<int32_t> const& value) const;
    Windows::Foundation::IReference<int32_t> MaxWorkAddresses() const;
    void MaxWorkAddresses(optional<int32_t> const& value) const;
    Windows::Foundation::IReference<int32_t> MaxOtherAddresses() const;
    void MaxOtherAddresses(optional<int32_t> const& value) const;
    Windows::Foundation::IReference<int32_t> MaxBirthdayDates() const;
    void MaxBirthdayDates(optional<int32_t> const& value) const;
    Windows::Foundation::IReference<int32_t> MaxAnniversaryDates() const;
    void MaxAnniversaryDates(optional<int32_t> const& value) const;
    Windows::Foundation::IReference<int32_t> MaxOtherDates() const;
    void MaxOtherDates(optional<int32_t> const& value) const;
    Windows::Foundation::IReference<int32_t> MaxOtherRelationships() const;
    void MaxOtherRelationships(optional<int32_t> const& value) const;
    Windows::Foundation::IReference<int32_t> MaxSpouseRelationships() const;
    void MaxSpouseRelationships(optional<int32_t> const& value) const;
    Windows::Foundation::IReference<int32_t> MaxPartnerRelationships() const;
    void MaxPartnerRelationships(optional<int32_t> const& value) const;
    Windows::Foundation::IReference<int32_t> MaxSiblingRelationships() const;
    void MaxSiblingRelationships(optional<int32_t> const& value) const;
    Windows::Foundation::IReference<int32_t> MaxParentRelationships() const;
    void MaxParentRelationships(optional<int32_t> const& value) const;
    Windows::Foundation::IReference<int32_t> MaxChildRelationships() const;
    void MaxChildRelationships(optional<int32_t> const& value) const;
    Windows::Foundation::IReference<int32_t> MaxJobInfo() const;
    void MaxJobInfo(optional<int32_t> const& value) const;
    Windows::Foundation::IReference<int32_t> MaxWebsites() const;
    void MaxWebsites(optional<int32_t> const& value) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactListSyncConstraints> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactListSyncManager
{
    Windows::ApplicationModel::Contacts::ContactListSyncStatus Status() const;
    Windows::Foundation::DateTime LastSuccessfulSyncTime() const;
    Windows::Foundation::DateTime LastAttemptedSyncTime() const;
    Windows::Foundation::IAsyncOperation<bool> SyncAsync() const;
    winrt::event_token SyncStatusChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::ContactListSyncManager, Windows::Foundation::IInspectable> const& handler) const;
    using SyncStatusChanged_revoker = impl::event_revoker<Windows::ApplicationModel::Contacts::IContactListSyncManager, &impl::abi_t<Windows::ApplicationModel::Contacts::IContactListSyncManager>::remove_SyncStatusChanged>;
    SyncStatusChanged_revoker SyncStatusChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::ContactListSyncManager, Windows::Foundation::IInspectable> const& handler) const;
    void SyncStatusChanged(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactListSyncManager> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactListSyncManager<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactListSyncManager2
{
    void Status(Windows::ApplicationModel::Contacts::ContactListSyncStatus const& value) const;
    void LastSuccessfulSyncTime(Windows::Foundation::DateTime const& value) const;
    void LastAttemptedSyncTime(Windows::Foundation::DateTime const& value) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactListSyncManager2> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactListSyncManager2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactLocationField
{
    hstring UnstructuredAddress() const;
    hstring Street() const;
    hstring City() const;
    hstring Region() const;
    hstring Country() const;
    hstring PostalCode() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactLocationField> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactLocationField<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactLocationFieldFactory
{
    Windows::ApplicationModel::Contacts::ContactLocationField CreateLocation(param::hstring const& unstructuredAddress) const;
    Windows::ApplicationModel::Contacts::ContactLocationField CreateLocation(param::hstring const& unstructuredAddress, Windows::ApplicationModel::Contacts::ContactFieldCategory const& category) const;
    Windows::ApplicationModel::Contacts::ContactLocationField CreateLocation(param::hstring const& unstructuredAddress, Windows::ApplicationModel::Contacts::ContactFieldCategory const& category, param::hstring const& street, param::hstring const& city, param::hstring const& region, param::hstring const& country, param::hstring const& postalCode) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactLocationFieldFactory> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactLocationFieldFactory<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactManagerForUser
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::RandomAccessStreamReference> ConvertContactToVCardAsync(Windows::ApplicationModel::Contacts::Contact const& contact) const;
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::RandomAccessStreamReference> ConvertContactToVCardAsync(Windows::ApplicationModel::Contacts::Contact const& contact, uint32_t maxBytes) const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact> ConvertVCardToContactAsync(Windows::Storage::Streams::IRandomAccessStreamReference const& vCard) const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactStore> RequestStoreAsync(Windows::ApplicationModel::Contacts::ContactStoreAccessType const& accessType) const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactAnnotationStore> RequestAnnotationStoreAsync(Windows::ApplicationModel::Contacts::ContactAnnotationStoreAccessType const& accessType) const;
    Windows::ApplicationModel::Contacts::ContactNameOrder SystemDisplayNameOrder() const;
    void SystemDisplayNameOrder(Windows::ApplicationModel::Contacts::ContactNameOrder const& value) const;
    Windows::ApplicationModel::Contacts::ContactNameOrder SystemSortOrder() const;
    void SystemSortOrder(Windows::ApplicationModel::Contacts::ContactNameOrder const& value) const;
    Windows::System::User User() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactManagerForUser> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactManagerForUser<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactManagerForUser2
{
    void ShowFullContactCard(Windows::ApplicationModel::Contacts::Contact const& contact, Windows::ApplicationModel::Contacts::FullContactCardOptions const& fullContactCardOptions) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactManagerForUser2> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactManagerForUser2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactManagerStatics
{
    void ShowContactCard(Windows::ApplicationModel::Contacts::Contact const& contact, Windows::Foundation::Rect const& selection) const;
    void ShowContactCard(Windows::ApplicationModel::Contacts::Contact const& contact, Windows::Foundation::Rect const& selection, Windows::UI::Popups::Placement const& preferredPlacement) const;
    Windows::ApplicationModel::Contacts::ContactCardDelayedDataLoader ShowDelayLoadedContactCard(Windows::ApplicationModel::Contacts::Contact const& contact, Windows::Foundation::Rect const& selection, Windows::UI::Popups::Placement const& preferredPlacement) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactManagerStatics> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactManagerStatics<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactManagerStatics2
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactStore> RequestStoreAsync() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactManagerStatics2> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactManagerStatics2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactManagerStatics3
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::RandomAccessStreamReference> ConvertContactToVCardAsync(Windows::ApplicationModel::Contacts::Contact const& contact) const;
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::RandomAccessStreamReference> ConvertContactToVCardAsync(Windows::ApplicationModel::Contacts::Contact const& contact, uint32_t maxBytes) const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact> ConvertVCardToContactAsync(Windows::Storage::Streams::IRandomAccessStreamReference const& vCard) const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactStore> RequestStoreAsync(Windows::ApplicationModel::Contacts::ContactStoreAccessType const& accessType) const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactAnnotationStore> RequestAnnotationStoreAsync(Windows::ApplicationModel::Contacts::ContactAnnotationStoreAccessType const& accessType) const;
    bool IsShowContactCardSupported() const;
    void ShowContactCard(Windows::ApplicationModel::Contacts::Contact const& contact, Windows::Foundation::Rect const& selection, Windows::UI::Popups::Placement const& preferredPlacement, Windows::ApplicationModel::Contacts::ContactCardOptions const& contactCardOptions) const;
    bool IsShowDelayLoadedContactCardSupported() const;
    Windows::ApplicationModel::Contacts::ContactCardDelayedDataLoader ShowDelayLoadedContactCard(Windows::ApplicationModel::Contacts::Contact const& contact, Windows::Foundation::Rect const& selection, Windows::UI::Popups::Placement const& preferredPlacement, Windows::ApplicationModel::Contacts::ContactCardOptions const& contactCardOptions) const;
    void ShowFullContactCard(Windows::ApplicationModel::Contacts::Contact const& contact, Windows::ApplicationModel::Contacts::FullContactCardOptions const& fullContactCardOptions) const;
    Windows::ApplicationModel::Contacts::ContactNameOrder SystemDisplayNameOrder() const;
    void SystemDisplayNameOrder(Windows::ApplicationModel::Contacts::ContactNameOrder const& value) const;
    Windows::ApplicationModel::Contacts::ContactNameOrder SystemSortOrder() const;
    void SystemSortOrder(Windows::ApplicationModel::Contacts::ContactNameOrder const& value) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactManagerStatics3> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactManagerStatics3<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactManagerStatics4
{
    Windows::ApplicationModel::Contacts::ContactManagerForUser GetForUser(Windows::System::User const& user) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactManagerStatics4> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactManagerStatics4<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactManagerStatics5
{
    Windows::Foundation::IAsyncOperation<bool> IsShowFullContactCardSupportedAsync() const;
    bool IncludeMiddleNameInSystemDisplayAndSort() const;
    void IncludeMiddleNameInSystemDisplayAndSort(bool value) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactManagerStatics5> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactManagerStatics5<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactMatchReason
{
    Windows::ApplicationModel::Contacts::ContactMatchReasonKind Field() const;
    Windows::Foundation::Collections::IVectorView<Windows::Data::Text::TextSegment> Segments() const;
    hstring Text() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactMatchReason> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactMatchReason<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactName
{
    hstring FirstName() const;
    void FirstName(param::hstring const& value) const;
    hstring LastName() const;
    void LastName(param::hstring const& value) const;
    hstring MiddleName() const;
    void MiddleName(param::hstring const& value) const;
    hstring YomiGivenName() const;
    void YomiGivenName(param::hstring const& value) const;
    hstring YomiFamilyName() const;
    void YomiFamilyName(param::hstring const& value) const;
    hstring HonorificNameSuffix() const;
    void HonorificNameSuffix(param::hstring const& value) const;
    hstring HonorificNamePrefix() const;
    void HonorificNamePrefix(param::hstring const& value) const;
    hstring DisplayName() const;
    hstring YomiDisplayName() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactName> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactName<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactPanel
{
    void ClosePanel() const;
    Windows::Foundation::IReference<Windows::UI::Color> HeaderColor() const;
    void HeaderColor(optional<Windows::UI::Color> const& value) const;
    winrt::event_token LaunchFullAppRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::ContactPanel, Windows::ApplicationModel::Contacts::ContactPanelLaunchFullAppRequestedEventArgs> const& handler) const;
    using LaunchFullAppRequested_revoker = impl::event_revoker<Windows::ApplicationModel::Contacts::IContactPanel, &impl::abi_t<Windows::ApplicationModel::Contacts::IContactPanel>::remove_LaunchFullAppRequested>;
    LaunchFullAppRequested_revoker LaunchFullAppRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::ContactPanel, Windows::ApplicationModel::Contacts::ContactPanelLaunchFullAppRequestedEventArgs> const& handler) const;
    void LaunchFullAppRequested(winrt::event_token const& token) const noexcept;
    winrt::event_token Closing(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::ContactPanel, Windows::ApplicationModel::Contacts::ContactPanelClosingEventArgs> const& handler) const;
    using Closing_revoker = impl::event_revoker<Windows::ApplicationModel::Contacts::IContactPanel, &impl::abi_t<Windows::ApplicationModel::Contacts::IContactPanel>::remove_Closing>;
    Closing_revoker Closing(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::ContactPanel, Windows::ApplicationModel::Contacts::ContactPanelClosingEventArgs> const& handler) const;
    void Closing(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactPanel> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactPanel<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactPanelClosingEventArgs
{
    Windows::Foundation::Deferral GetDeferral() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactPanelClosingEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactPanelClosingEventArgs<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactPanelLaunchFullAppRequestedEventArgs
{
    bool Handled() const;
    void Handled(bool value) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactPanelLaunchFullAppRequestedEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactPanelLaunchFullAppRequestedEventArgs<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactPhone
{
    hstring Number() const;
    void Number(param::hstring const& value) const;
    Windows::ApplicationModel::Contacts::ContactPhoneKind Kind() const;
    void Kind(Windows::ApplicationModel::Contacts::ContactPhoneKind const& value) const;
    hstring Description() const;
    void Description(param::hstring const& value) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactPhone> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactPhone<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactPicker
{
    hstring CommitButtonText() const;
    void CommitButtonText(param::hstring const& value) const;
    Windows::ApplicationModel::Contacts::ContactSelectionMode SelectionMode() const;
    void SelectionMode(Windows::ApplicationModel::Contacts::ContactSelectionMode const& value) const;
    Windows::Foundation::Collections::IVector<hstring> DesiredFields() const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactInformation> PickSingleContactAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactInformation>> PickMultipleContactsAsync() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactPicker> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactPicker<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactPicker2
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactFieldType> DesiredFieldsWithContactFieldType() const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact> PickContactAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::Contact>> PickContactsAsync() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactPicker2> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactPicker2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactPicker3
{
    Windows::System::User User() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactPicker3> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactPicker3<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactPickerStatics
{
    Windows::ApplicationModel::Contacts::ContactPicker CreateForUser(Windows::System::User const& user) const;
    Windows::Foundation::IAsyncOperation<bool> IsSupportedAsync() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactPickerStatics> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactPickerStatics<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactQueryOptions
{
    Windows::ApplicationModel::Contacts::ContactQueryTextSearch TextSearch() const;
    Windows::Foundation::Collections::IVector<hstring> ContactListIds() const;
    bool IncludeContactsFromHiddenLists() const;
    void IncludeContactsFromHiddenLists(bool value) const;
    Windows::ApplicationModel::Contacts::ContactQueryDesiredFields DesiredFields() const;
    void DesiredFields(Windows::ApplicationModel::Contacts::ContactQueryDesiredFields const& value) const;
    Windows::ApplicationModel::Contacts::ContactAnnotationOperations DesiredOperations() const;
    void DesiredOperations(Windows::ApplicationModel::Contacts::ContactAnnotationOperations const& value) const;
    Windows::Foundation::Collections::IVector<hstring> AnnotationListIds() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactQueryOptions> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactQueryOptions<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactQueryOptionsFactory
{
    Windows::ApplicationModel::Contacts::ContactQueryOptions CreateWithText(param::hstring const& text) const;
    Windows::ApplicationModel::Contacts::ContactQueryOptions CreateWithTextAndFields(param::hstring const& text, Windows::ApplicationModel::Contacts::ContactQuerySearchFields const& fields) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactQueryOptionsFactory> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactQueryOptionsFactory<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactQueryTextSearch
{
    Windows::ApplicationModel::Contacts::ContactQuerySearchFields Fields() const;
    void Fields(Windows::ApplicationModel::Contacts::ContactQuerySearchFields const& value) const;
    hstring Text() const;
    void Text(param::hstring const& value) const;
    Windows::ApplicationModel::Contacts::ContactQuerySearchScope SearchScope() const;
    void SearchScope(Windows::ApplicationModel::Contacts::ContactQuerySearchScope const& value) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactQueryTextSearch> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactQueryTextSearch<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactReader
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactBatch> ReadBatchAsync() const;
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactMatchReason> GetMatchingPropertiesWithMatchReason(Windows::ApplicationModel::Contacts::Contact const& contact) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactReader> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactReader<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactSignificantOther
{
    hstring Name() const;
    void Name(param::hstring const& value) const;
    hstring Description() const;
    void Description(param::hstring const& value) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactSignificantOther> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactSignificantOther<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactSignificantOther2
{
    Windows::ApplicationModel::Contacts::ContactRelationship Relationship() const;
    void Relationship(Windows::ApplicationModel::Contacts::ContactRelationship const& value) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactSignificantOther2> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactSignificantOther2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactStore
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::Contact>> FindContactsAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::Contact>> FindContactsAsync(param::hstring const& searchText) const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact> GetContactAsync(param::hstring const& contactId) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactStore> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactStore<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactStore2
{
    Windows::ApplicationModel::Contacts::ContactChangeTracker ChangeTracker() const;
    winrt::event_token ContactChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::ContactStore, Windows::ApplicationModel::Contacts::ContactChangedEventArgs> const& value) const;
    using ContactChanged_revoker = impl::event_revoker<Windows::ApplicationModel::Contacts::IContactStore2, &impl::abi_t<Windows::ApplicationModel::Contacts::IContactStore2>::remove_ContactChanged>;
    ContactChanged_revoker ContactChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::ContactStore, Windows::ApplicationModel::Contacts::ContactChangedEventArgs> const& value) const;
    void ContactChanged(winrt::event_token const& value) const noexcept;
    Windows::ApplicationModel::Contacts::AggregateContactManager AggregateContactManager() const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactList>> FindContactListsAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactList> GetContactListAsync(param::hstring const& contactListId) const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactList> CreateContactListAsync(param::hstring const& displayName) const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact> GetMeContactAsync() const;
    Windows::ApplicationModel::Contacts::ContactReader GetContactReader() const;
    Windows::ApplicationModel::Contacts::ContactReader GetContactReader(Windows::ApplicationModel::Contacts::ContactQueryOptions const& options) const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactList> CreateContactListAsync(param::hstring const& displayName, param::hstring const& userDataAccountId) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactStore2> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactStore2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactStore3
{
    Windows::ApplicationModel::Contacts::ContactChangeTracker GetChangeTracker(param::hstring const& identity) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactStore3> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactStore3<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactStoreNotificationTriggerDetails
{
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactStoreNotificationTriggerDetails> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactStoreNotificationTriggerDetails<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactWebsite
{
    Windows::Foundation::Uri Uri() const;
    void Uri(Windows::Foundation::Uri const& value) const;
    hstring Description() const;
    void Description(param::hstring const& value) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactWebsite> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactWebsite<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IContactWebsite2
{
    hstring RawValue() const;
    void RawValue(param::hstring const& value) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IContactWebsite2> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IContactWebsite2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IFullContactCardOptions
{
    Windows::UI::ViewManagement::ViewSizePreference DesiredRemainingView() const;
    void DesiredRemainingView(Windows::UI::ViewManagement::ViewSizePreference const& value) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IFullContactCardOptions> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IFullContactCardOptions<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IKnownContactFieldStatics
{
    hstring Email() const;
    hstring PhoneNumber() const;
    hstring Location() const;
    hstring InstantMessage() const;
    Windows::ApplicationModel::Contacts::ContactFieldType ConvertNameToType(param::hstring const& name) const;
    hstring ConvertTypeToName(Windows::ApplicationModel::Contacts::ContactFieldType const& type) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IKnownContactFieldStatics> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IKnownContactFieldStatics<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IPinnedContactIdsQueryResult
{
    Windows::Foundation::Collections::IVector<hstring> ContactIds() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IPinnedContactIdsQueryResult> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IPinnedContactIdsQueryResult<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IPinnedContactManager
{
    Windows::System::User User() const;
    bool IsPinSurfaceSupported(Windows::ApplicationModel::Contacts::PinnedContactSurface const& surface) const;
    bool IsContactPinned(Windows::ApplicationModel::Contacts::Contact const& contact, Windows::ApplicationModel::Contacts::PinnedContactSurface const& surface) const;
    Windows::Foundation::IAsyncOperation<bool> RequestPinContactAsync(Windows::ApplicationModel::Contacts::Contact const& contact, Windows::ApplicationModel::Contacts::PinnedContactSurface const& surface) const;
    Windows::Foundation::IAsyncOperation<bool> RequestPinContactsAsync(param::async_iterable<Windows::ApplicationModel::Contacts::Contact> const& contacts, Windows::ApplicationModel::Contacts::PinnedContactSurface const& surface) const;
    Windows::Foundation::IAsyncOperation<bool> RequestUnpinContactAsync(Windows::ApplicationModel::Contacts::Contact const& contact, Windows::ApplicationModel::Contacts::PinnedContactSurface const& surface) const;
    void SignalContactActivity(Windows::ApplicationModel::Contacts::Contact const& contact) const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::PinnedContactIdsQueryResult> GetPinnedContactIdsAsync() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IPinnedContactManager> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IPinnedContactManager<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_IPinnedContactManagerStatics
{
    Windows::ApplicationModel::Contacts::PinnedContactManager GetDefault() const;
    Windows::ApplicationModel::Contacts::PinnedContactManager GetForUser(Windows::System::User const& user) const;
    bool IsSupported() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::IPinnedContactManagerStatics> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_IPinnedContactManagerStatics<D>; };

}
