// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Data.Text.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.UI.Popups.2.h"
#include "winrt/impl/Windows.UI.ViewManagement.2.h"
#include "winrt/impl/Windows.ApplicationModel.Contacts.2.h"
#include "winrt/Windows.ApplicationModel.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::Contact>> consume_Windows_ApplicationModel_Contacts_IAggregateContactManager<D>::FindRawContactsAsync(Windows::ApplicationModel::Contacts::Contact const& contact) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::Contact>> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IAggregateContactManager)->FindRawContactsAsync(get_abi(contact), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact> consume_Windows_ApplicationModel_Contacts_IAggregateContactManager<D>::TryLinkContactsAsync(Windows::ApplicationModel::Contacts::Contact const& primaryContact, Windows::ApplicationModel::Contacts::Contact const& secondaryContact) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact> contact{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IAggregateContactManager)->TryLinkContactsAsync(get_abi(primaryContact), get_abi(secondaryContact), put_abi(contact)));
    return contact;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Contacts_IAggregateContactManager<D>::UnlinkRawContactAsync(Windows::ApplicationModel::Contacts::Contact const& contact) const
{
    Windows::Foundation::IAsyncAction value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IAggregateContactManager)->UnlinkRawContactAsync(get_abi(contact), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Contacts_IAggregateContactManager<D>::TrySetPreferredSourceForPictureAsync(Windows::ApplicationModel::Contacts::Contact const& aggregateContact, Windows::ApplicationModel::Contacts::Contact const& rawContact) const
{
    Windows::Foundation::IAsyncOperation<bool> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IAggregateContactManager)->TrySetPreferredSourceForPictureAsync(get_abi(aggregateContact), get_abi(rawContact), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Contacts_IAggregateContactManager2<D>::SetRemoteIdentificationInformationAsync(param::hstring const& contactListId, param::hstring const& remoteSourceId, param::hstring const& accountId) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IAggregateContactManager2)->SetRemoteIdentificationInformationAsync(get_abi(contactListId), get_abi(remoteSourceId), get_abi(accountId), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContact<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact)->get_Name(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContact<D>::Name(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact)->put_Name(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_ApplicationModel_Contacts_IContact<D>::Thumbnail() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact)->get_Thumbnail(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContact<D>::Thumbnail(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact)->put_Thumbnail(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::IContactField> consume_Windows_ApplicationModel_Contacts_IContact<D>::Fields() const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::IContactField> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact)->get_Fields(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContact2<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact2)->get_Id(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContact2<D>::Id(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact2)->put_Id(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContact2<D>::Notes() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact2)->get_Notes(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContact2<D>::Notes(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact2)->put_Notes(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactPhone> consume_Windows_ApplicationModel_Contacts_IContact2<D>::Phones() const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactPhone> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact2)->get_Phones(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactEmail> consume_Windows_ApplicationModel_Contacts_IContact2<D>::Emails() const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactEmail> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact2)->get_Emails(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactAddress> consume_Windows_ApplicationModel_Contacts_IContact2<D>::Addresses() const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactAddress> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact2)->get_Addresses(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactConnectedServiceAccount> consume_Windows_ApplicationModel_Contacts_IContact2<D>::ConnectedServiceAccounts() const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactConnectedServiceAccount> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact2)->get_ConnectedServiceAccounts(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactDate> consume_Windows_ApplicationModel_Contacts_IContact2<D>::ImportantDates() const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactDate> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact2)->get_ImportantDates(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_ApplicationModel_Contacts_IContact2<D>::DataSuppliers() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact2)->get_DataSuppliers(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactJobInfo> consume_Windows_ApplicationModel_Contacts_IContact2<D>::JobInfo() const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactJobInfo> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact2)->get_JobInfo(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactSignificantOther> consume_Windows_ApplicationModel_Contacts_IContact2<D>::SignificantOthers() const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactSignificantOther> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact2)->get_SignificantOthers(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactWebsite> consume_Windows_ApplicationModel_Contacts_IContact2<D>::Websites() const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactWebsite> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact2)->get_Websites(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IPropertySet consume_Windows_ApplicationModel_Contacts_IContact2<D>::ProviderProperties() const
{
    Windows::Foundation::Collections::IPropertySet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact2)->get_ProviderProperties(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContact3<D>::ContactListId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact3)->get_ContactListId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_ApplicationModel_Contacts_IContact3<D>::DisplayPictureUserUpdateTime() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact3)->get_DisplayPictureUserUpdateTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContact3<D>::DisplayPictureUserUpdateTime(Windows::Foundation::DateTime const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact3)->put_DisplayPictureUserUpdateTime(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_Contacts_IContact3<D>::IsMe() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact3)->get_IsMe(&value));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContact3<D>::AggregateId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact3)->get_AggregateId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContact3<D>::RemoteId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact3)->get_RemoteId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContact3<D>::RemoteId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact3)->put_RemoteId(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContact3<D>::RingToneToken() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact3)->get_RingToneToken(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContact3<D>::RingToneToken(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact3)->put_RingToneToken(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_Contacts_IContact3<D>::IsDisplayPictureManuallySet() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact3)->get_IsDisplayPictureManuallySet(&value));
    return value;
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_ApplicationModel_Contacts_IContact3<D>::LargeDisplayPicture() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact3)->get_LargeDisplayPicture(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_ApplicationModel_Contacts_IContact3<D>::SmallDisplayPicture() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact3)->get_SmallDisplayPicture(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_ApplicationModel_Contacts_IContact3<D>::SourceDisplayPicture() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact3)->get_SourceDisplayPicture(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContact3<D>::SourceDisplayPicture(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact3)->put_SourceDisplayPicture(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContact3<D>::TextToneToken() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact3)->get_TextToneToken(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContact3<D>::TextToneToken(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact3)->put_TextToneToken(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_Contacts_IContact3<D>::IsAggregate() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact3)->get_IsAggregate(&value));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContact3<D>::FullName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact3)->get_FullName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContact3<D>::DisplayNameOverride() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact3)->get_DisplayNameOverride(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContact3<D>::DisplayNameOverride(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact3)->put_DisplayNameOverride(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContact3<D>::Nickname() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact3)->get_Nickname(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContact3<D>::Nickname(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact3)->put_Nickname(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContact3<D>::SortName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContact3)->get_SortName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactAddress<D>::StreetAddress() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAddress)->get_StreetAddress(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactAddress<D>::StreetAddress(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAddress)->put_StreetAddress(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactAddress<D>::Locality() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAddress)->get_Locality(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactAddress<D>::Locality(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAddress)->put_Locality(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactAddress<D>::Region() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAddress)->get_Region(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactAddress<D>::Region(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAddress)->put_Region(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactAddress<D>::Country() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAddress)->get_Country(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactAddress<D>::Country(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAddress)->put_Country(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactAddress<D>::PostalCode() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAddress)->get_PostalCode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactAddress<D>::PostalCode(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAddress)->put_PostalCode(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Contacts::ContactAddressKind consume_Windows_ApplicationModel_Contacts_IContactAddress<D>::Kind() const
{
    Windows::ApplicationModel::Contacts::ContactAddressKind value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAddress)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactAddress<D>::Kind(Windows::ApplicationModel::Contacts::ContactAddressKind const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAddress)->put_Kind(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactAddress<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAddress)->get_Description(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactAddress<D>::Description(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAddress)->put_Description(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactAnnotation<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAnnotation)->get_Id(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactAnnotation<D>::AnnotationListId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAnnotation)->get_AnnotationListId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactAnnotation<D>::ContactId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAnnotation)->get_ContactId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactAnnotation<D>::ContactId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAnnotation)->put_ContactId(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactAnnotation<D>::RemoteId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAnnotation)->get_RemoteId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactAnnotation<D>::RemoteId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAnnotation)->put_RemoteId(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Contacts::ContactAnnotationOperations consume_Windows_ApplicationModel_Contacts_IContactAnnotation<D>::SupportedOperations() const
{
    Windows::ApplicationModel::Contacts::ContactAnnotationOperations value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAnnotation)->get_SupportedOperations(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactAnnotation<D>::SupportedOperations(Windows::ApplicationModel::Contacts::ContactAnnotationOperations const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAnnotation)->put_SupportedOperations(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_Contacts_IContactAnnotation<D>::IsDisabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAnnotation)->get_IsDisabled(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::ValueSet consume_Windows_ApplicationModel_Contacts_IContactAnnotation<D>::ProviderProperties() const
{
    Windows::Foundation::Collections::ValueSet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAnnotation)->get_ProviderProperties(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactAnnotation2<D>::ContactListId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAnnotation2)->get_ContactListId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactAnnotation2<D>::ContactListId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAnnotation2)->put_ContactListId(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactAnnotationList<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAnnotationList)->get_Id(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactAnnotationList<D>::ProviderPackageFamilyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAnnotationList)->get_ProviderPackageFamilyName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactAnnotationList<D>::UserDataAccountId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAnnotationList)->get_UserDataAccountId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Contacts_IContactAnnotationList<D>::DeleteAsync() const
{
    Windows::Foundation::IAsyncAction value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAnnotationList)->DeleteAsync(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Contacts_IContactAnnotationList<D>::TrySaveAnnotationAsync(Windows::ApplicationModel::Contacts::ContactAnnotation const& annotation) const
{
    Windows::Foundation::IAsyncOperation<bool> ppResult{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAnnotationList)->TrySaveAnnotationAsync(get_abi(annotation), put_abi(ppResult)));
    return ppResult;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactAnnotation> consume_Windows_ApplicationModel_Contacts_IContactAnnotationList<D>::GetAnnotationAsync(param::hstring const& annotationId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactAnnotation> annotation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAnnotationList)->GetAnnotationAsync(get_abi(annotationId), put_abi(annotation)));
    return annotation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactAnnotation>> consume_Windows_ApplicationModel_Contacts_IContactAnnotationList<D>::FindAnnotationsByRemoteIdAsync(param::hstring const& remoteId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactAnnotation>> annotations{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAnnotationList)->FindAnnotationsByRemoteIdAsync(get_abi(remoteId), put_abi(annotations)));
    return annotations;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactAnnotation>> consume_Windows_ApplicationModel_Contacts_IContactAnnotationList<D>::FindAnnotationsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactAnnotation>> annotations{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAnnotationList)->FindAnnotationsAsync(put_abi(annotations)));
    return annotations;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Contacts_IContactAnnotationList<D>::DeleteAnnotationAsync(Windows::ApplicationModel::Contacts::ContactAnnotation const& annotation) const
{
    Windows::Foundation::IAsyncAction value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAnnotationList)->DeleteAnnotationAsync(get_abi(annotation), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>> consume_Windows_ApplicationModel_Contacts_IContactAnnotationStore<D>::FindContactIdsByEmailAsync(param::hstring const& emailAddress) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>> contactIds{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAnnotationStore)->FindContactIdsByEmailAsync(get_abi(emailAddress), put_abi(contactIds)));
    return contactIds;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>> consume_Windows_ApplicationModel_Contacts_IContactAnnotationStore<D>::FindContactIdsByPhoneNumberAsync(param::hstring const& phoneNumber) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>> contactIds{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAnnotationStore)->FindContactIdsByPhoneNumberAsync(get_abi(phoneNumber), put_abi(contactIds)));
    return contactIds;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactAnnotation>> consume_Windows_ApplicationModel_Contacts_IContactAnnotationStore<D>::FindAnnotationsForContactAsync(Windows::ApplicationModel::Contacts::Contact const& contact) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactAnnotation>> annotations{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAnnotationStore)->FindAnnotationsForContactAsync(get_abi(contact), put_abi(annotations)));
    return annotations;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Contacts_IContactAnnotationStore<D>::DisableAnnotationAsync(Windows::ApplicationModel::Contacts::ContactAnnotation const& annotation) const
{
    Windows::Foundation::IAsyncAction value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAnnotationStore)->DisableAnnotationAsync(get_abi(annotation), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactAnnotationList> consume_Windows_ApplicationModel_Contacts_IContactAnnotationStore<D>::CreateAnnotationListAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactAnnotationList> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAnnotationStore)->CreateAnnotationListAsync(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactAnnotationList> consume_Windows_ApplicationModel_Contacts_IContactAnnotationStore<D>::CreateAnnotationListAsync(param::hstring const& userDataAccountId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactAnnotationList> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAnnotationStore)->CreateAnnotationListInAccountAsync(get_abi(userDataAccountId), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactAnnotationList> consume_Windows_ApplicationModel_Contacts_IContactAnnotationStore<D>::GetAnnotationListAsync(param::hstring const& annotationListId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactAnnotationList> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAnnotationStore)->GetAnnotationListAsync(get_abi(annotationListId), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactAnnotationList>> consume_Windows_ApplicationModel_Contacts_IContactAnnotationStore<D>::FindAnnotationListsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactAnnotationList>> lists{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAnnotationStore)->FindAnnotationListsAsync(put_abi(lists)));
    return lists;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactAnnotation>> consume_Windows_ApplicationModel_Contacts_IContactAnnotationStore2<D>::FindAnnotationsForContactListAsync(param::hstring const& contactListId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactAnnotation>> annotations{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactAnnotationStore2)->FindAnnotationsForContactListAsync(get_abi(contactListId), put_abi(annotations)));
    return annotations;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::Contact> consume_Windows_ApplicationModel_Contacts_IContactBatch<D>::Contacts() const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::Contact> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactBatch)->get_Contacts(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Contacts::ContactBatchStatus consume_Windows_ApplicationModel_Contacts_IContactBatch<D>::Status() const
{
    Windows::ApplicationModel::Contacts::ContactBatchStatus value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactBatch)->get_Status(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactCardDelayedDataLoader<D>::SetData(Windows::ApplicationModel::Contacts::Contact const& contact) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactCardDelayedDataLoader)->SetData(get_abi(contact)));
}

template <typename D> Windows::ApplicationModel::Contacts::ContactCardHeaderKind consume_Windows_ApplicationModel_Contacts_IContactCardOptions<D>::HeaderKind() const
{
    Windows::ApplicationModel::Contacts::ContactCardHeaderKind value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactCardOptions)->get_HeaderKind(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactCardOptions<D>::HeaderKind(Windows::ApplicationModel::Contacts::ContactCardHeaderKind const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactCardOptions)->put_HeaderKind(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Contacts::ContactCardTabKind consume_Windows_ApplicationModel_Contacts_IContactCardOptions<D>::InitialTabKind() const
{
    Windows::ApplicationModel::Contacts::ContactCardTabKind value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactCardOptions)->get_InitialTabKind(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactCardOptions<D>::InitialTabKind(Windows::ApplicationModel::Contacts::ContactCardTabKind const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactCardOptions)->put_InitialTabKind(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_ApplicationModel_Contacts_IContactCardOptions2<D>::ServerSearchContactListIds() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactCardOptions2)->get_ServerSearchContactListIds(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Contacts::ContactChangeType consume_Windows_ApplicationModel_Contacts_IContactChange<D>::ChangeType() const
{
    Windows::ApplicationModel::Contacts::ContactChangeType value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactChange)->get_ChangeType(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Contacts::Contact consume_Windows_ApplicationModel_Contacts_IContactChange<D>::Contact() const
{
    Windows::ApplicationModel::Contacts::Contact value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactChange)->get_Contact(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactChangeReader<D>::AcceptChanges() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactChangeReader)->AcceptChanges());
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactChangeReader<D>::AcceptChangesThrough(Windows::ApplicationModel::Contacts::ContactChange const& lastChangeToAccept) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactChangeReader)->AcceptChangesThrough(get_abi(lastChangeToAccept)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactChange>> consume_Windows_ApplicationModel_Contacts_IContactChangeReader<D>::ReadBatchAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactChange>> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactChangeReader)->ReadBatchAsync(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactChangeTracker<D>::Enable() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactChangeTracker)->Enable());
}

template <typename D> Windows::ApplicationModel::Contacts::ContactChangeReader consume_Windows_ApplicationModel_Contacts_IContactChangeTracker<D>::GetChangeReader() const
{
    Windows::ApplicationModel::Contacts::ContactChangeReader value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactChangeTracker)->GetChangeReader(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactChangeTracker<D>::Reset() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactChangeTracker)->Reset());
}

template <typename D> bool consume_Windows_ApplicationModel_Contacts_IContactChangeTracker2<D>::IsTracking() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactChangeTracker2)->get_IsTracking(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactChangedDeferral<D>::Complete() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactChangedDeferral)->Complete());
}

template <typename D> Windows::ApplicationModel::Contacts::ContactChangedDeferral consume_Windows_ApplicationModel_Contacts_IContactChangedEventArgs<D>::GetDeferral() const
{
    Windows::ApplicationModel::Contacts::ContactChangedDeferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactChangedEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactConnectedServiceAccount<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactConnectedServiceAccount)->get_Id(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactConnectedServiceAccount<D>::Id(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactConnectedServiceAccount)->put_Id(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactConnectedServiceAccount<D>::ServiceName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactConnectedServiceAccount)->get_ServiceName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactConnectedServiceAccount<D>::ServiceName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactConnectedServiceAccount)->put_ServiceName(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_ApplicationModel_Contacts_IContactDate<D>::Day() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactDate)->get_Day(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactDate<D>::Day(optional<uint32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactDate)->put_Day(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_ApplicationModel_Contacts_IContactDate<D>::Month() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactDate)->get_Month(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactDate<D>::Month(optional<uint32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactDate)->put_Month(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_ApplicationModel_Contacts_IContactDate<D>::Year() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactDate)->get_Year(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactDate<D>::Year(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactDate)->put_Year(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Contacts::ContactDateKind consume_Windows_ApplicationModel_Contacts_IContactDate<D>::Kind() const
{
    Windows::ApplicationModel::Contacts::ContactDateKind value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactDate)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactDate<D>::Kind(Windows::ApplicationModel::Contacts::ContactDateKind const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactDate)->put_Kind(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactDate<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactDate)->get_Description(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactDate<D>::Description(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactDate)->put_Description(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactEmail<D>::Address() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactEmail)->get_Address(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactEmail<D>::Address(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactEmail)->put_Address(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Contacts::ContactEmailKind consume_Windows_ApplicationModel_Contacts_IContactEmail<D>::Kind() const
{
    Windows::ApplicationModel::Contacts::ContactEmailKind value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactEmail)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactEmail<D>::Kind(Windows::ApplicationModel::Contacts::ContactEmailKind const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactEmail)->put_Kind(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactEmail<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactEmail)->get_Description(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactEmail<D>::Description(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactEmail)->put_Description(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Contacts::ContactFieldType consume_Windows_ApplicationModel_Contacts_IContactField<D>::Type() const
{
    Windows::ApplicationModel::Contacts::ContactFieldType value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactField)->get_Type(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Contacts::ContactFieldCategory consume_Windows_ApplicationModel_Contacts_IContactField<D>::Category() const
{
    Windows::ApplicationModel::Contacts::ContactFieldCategory value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactField)->get_Category(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactField<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactField)->get_Name(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactField<D>::Value() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactField)->get_Value(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Contacts::ContactField consume_Windows_ApplicationModel_Contacts_IContactFieldFactory<D>::CreateField(param::hstring const& value, Windows::ApplicationModel::Contacts::ContactFieldType const& type) const
{
    Windows::ApplicationModel::Contacts::ContactField field{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactFieldFactory)->CreateField_Default(get_abi(value), get_abi(type), put_abi(field)));
    return field;
}

template <typename D> Windows::ApplicationModel::Contacts::ContactField consume_Windows_ApplicationModel_Contacts_IContactFieldFactory<D>::CreateField(param::hstring const& value, Windows::ApplicationModel::Contacts::ContactFieldType const& type, Windows::ApplicationModel::Contacts::ContactFieldCategory const& category) const
{
    Windows::ApplicationModel::Contacts::ContactField field{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactFieldFactory)->CreateField_Category(get_abi(value), get_abi(type), get_abi(category), put_abi(field)));
    return field;
}

template <typename D> Windows::ApplicationModel::Contacts::ContactField consume_Windows_ApplicationModel_Contacts_IContactFieldFactory<D>::CreateField(param::hstring const& name, param::hstring const& value, Windows::ApplicationModel::Contacts::ContactFieldType const& type, Windows::ApplicationModel::Contacts::ContactFieldCategory const& category) const
{
    Windows::ApplicationModel::Contacts::ContactField field{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactFieldFactory)->CreateField_Custom(get_abi(name), get_abi(value), get_abi(type), get_abi(category), put_abi(field)));
    return field;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactInformation<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactInformation)->get_Name(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStreamWithContentType> consume_Windows_ApplicationModel_Contacts_IContactInformation<D>::GetThumbnailAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStreamWithContentType> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactInformation)->GetThumbnailAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactField> consume_Windows_ApplicationModel_Contacts_IContactInformation<D>::Emails() const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactField> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactInformation)->get_Emails(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactField> consume_Windows_ApplicationModel_Contacts_IContactInformation<D>::PhoneNumbers() const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactField> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactInformation)->get_PhoneNumbers(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactLocationField> consume_Windows_ApplicationModel_Contacts_IContactInformation<D>::Locations() const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactLocationField> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactInformation)->get_Locations(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactInstantMessageField> consume_Windows_ApplicationModel_Contacts_IContactInformation<D>::InstantMessages() const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactInstantMessageField> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactInformation)->get_InstantMessages(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactField> consume_Windows_ApplicationModel_Contacts_IContactInformation<D>::CustomFields() const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactField> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactInformation)->get_CustomFields(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactField> consume_Windows_ApplicationModel_Contacts_IContactInformation<D>::QueryCustomFields(param::hstring const& customName) const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactField> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactInformation)->QueryCustomFields(get_abi(customName), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactInstantMessageField<D>::UserName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactInstantMessageField)->get_UserName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactInstantMessageField<D>::Service() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactInstantMessageField)->get_Service(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactInstantMessageField<D>::DisplayText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactInstantMessageField)->get_DisplayText(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_ApplicationModel_Contacts_IContactInstantMessageField<D>::LaunchUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactInstantMessageField)->get_LaunchUri(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Contacts::ContactInstantMessageField consume_Windows_ApplicationModel_Contacts_IContactInstantMessageFieldFactory<D>::CreateInstantMessage(param::hstring const& userName) const
{
    Windows::ApplicationModel::Contacts::ContactInstantMessageField field{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactInstantMessageFieldFactory)->CreateInstantMessage_Default(get_abi(userName), put_abi(field)));
    return field;
}

template <typename D> Windows::ApplicationModel::Contacts::ContactInstantMessageField consume_Windows_ApplicationModel_Contacts_IContactInstantMessageFieldFactory<D>::CreateInstantMessage(param::hstring const& userName, Windows::ApplicationModel::Contacts::ContactFieldCategory const& category) const
{
    Windows::ApplicationModel::Contacts::ContactInstantMessageField field{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactInstantMessageFieldFactory)->CreateInstantMessage_Category(get_abi(userName), get_abi(category), put_abi(field)));
    return field;
}

template <typename D> Windows::ApplicationModel::Contacts::ContactInstantMessageField consume_Windows_ApplicationModel_Contacts_IContactInstantMessageFieldFactory<D>::CreateInstantMessage(param::hstring const& userName, Windows::ApplicationModel::Contacts::ContactFieldCategory const& category, param::hstring const& service, param::hstring const& displayText, Windows::Foundation::Uri const& verb) const
{
    Windows::ApplicationModel::Contacts::ContactInstantMessageField field{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactInstantMessageFieldFactory)->CreateInstantMessage_All(get_abi(userName), get_abi(category), get_abi(service), get_abi(displayText), get_abi(verb), put_abi(field)));
    return field;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactJobInfo<D>::CompanyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactJobInfo)->get_CompanyName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactJobInfo<D>::CompanyName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactJobInfo)->put_CompanyName(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactJobInfo<D>::CompanyYomiName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactJobInfo)->get_CompanyYomiName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactJobInfo<D>::CompanyYomiName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactJobInfo)->put_CompanyYomiName(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactJobInfo<D>::Department() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactJobInfo)->get_Department(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactJobInfo<D>::Department(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactJobInfo)->put_Department(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactJobInfo<D>::Title() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactJobInfo)->get_Title(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactJobInfo<D>::Title(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactJobInfo)->put_Title(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactJobInfo<D>::Manager() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactJobInfo)->get_Manager(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactJobInfo<D>::Manager(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactJobInfo)->put_Manager(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactJobInfo<D>::Office() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactJobInfo)->get_Office(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactJobInfo<D>::Office(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactJobInfo)->put_Office(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactJobInfo<D>::CompanyAddress() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactJobInfo)->get_CompanyAddress(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactJobInfo<D>::CompanyAddress(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactJobInfo)->put_CompanyAddress(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactJobInfo<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactJobInfo)->get_Description(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactJobInfo<D>::Description(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactJobInfo)->put_Description(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactLaunchActionVerbsStatics<D>::Call() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactLaunchActionVerbsStatics)->get_Call(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactLaunchActionVerbsStatics<D>::Message() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactLaunchActionVerbsStatics)->get_Message(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactLaunchActionVerbsStatics<D>::Map() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactLaunchActionVerbsStatics)->get_Map(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactLaunchActionVerbsStatics<D>::Post() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactLaunchActionVerbsStatics)->get_Post(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactLaunchActionVerbsStatics<D>::VideoCall() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactLaunchActionVerbsStatics)->get_VideoCall(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactList<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactList)->get_Id(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactList<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactList)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactList<D>::DisplayName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactList)->put_DisplayName(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactList<D>::SourceDisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactList)->get_SourceDisplayName(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Contacts_IContactList<D>::IsHidden() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactList)->get_IsHidden(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactList<D>::IsHidden(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactList)->put_IsHidden(value));
}

template <typename D> Windows::ApplicationModel::Contacts::ContactListOtherAppReadAccess consume_Windows_ApplicationModel_Contacts_IContactList<D>::OtherAppReadAccess() const
{
    Windows::ApplicationModel::Contacts::ContactListOtherAppReadAccess value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactList)->get_OtherAppReadAccess(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactList<D>::OtherAppReadAccess(Windows::ApplicationModel::Contacts::ContactListOtherAppReadAccess const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactList)->put_OtherAppReadAccess(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Contacts::ContactListOtherAppWriteAccess consume_Windows_ApplicationModel_Contacts_IContactList<D>::OtherAppWriteAccess() const
{
    Windows::ApplicationModel::Contacts::ContactListOtherAppWriteAccess value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactList)->get_OtherAppWriteAccess(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactList<D>::OtherAppWriteAccess(Windows::ApplicationModel::Contacts::ContactListOtherAppWriteAccess const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactList)->put_OtherAppWriteAccess(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Contacts::ContactChangeTracker consume_Windows_ApplicationModel_Contacts_IContactList<D>::ChangeTracker() const
{
    Windows::ApplicationModel::Contacts::ContactChangeTracker value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactList)->get_ChangeTracker(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Contacts::ContactListSyncManager consume_Windows_ApplicationModel_Contacts_IContactList<D>::SyncManager() const
{
    Windows::ApplicationModel::Contacts::ContactListSyncManager value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactList)->get_SyncManager(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Contacts_IContactList<D>::SupportsServerSearch() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactList)->get_SupportsServerSearch(&value));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactList<D>::UserDataAccountId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactList)->get_UserDataAccountId(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Contacts_IContactList<D>::ContactChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::ContactList, Windows::ApplicationModel::Contacts::ContactChangedEventArgs> const& value) const
{
    winrt::event_token returnValue{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactList)->add_ContactChanged(get_abi(value), put_abi(returnValue)));
    return returnValue;
}

template <typename D> typename consume_Windows_ApplicationModel_Contacts_IContactList<D>::ContactChanged_revoker consume_Windows_ApplicationModel_Contacts_IContactList<D>::ContactChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::ContactList, Windows::ApplicationModel::Contacts::ContactChangedEventArgs> const& value) const
{
    return impl::make_event_revoker<D, ContactChanged_revoker>(this, ContactChanged(value));
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactList<D>::ContactChanged(winrt::event_token const& value) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactList)->remove_ContactChanged(get_abi(value)));
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Contacts_IContactList<D>::SaveAsync() const
{
    Windows::Foundation::IAsyncAction returnValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactList)->SaveAsync(put_abi(returnValue)));
    return returnValue;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Contacts_IContactList<D>::DeleteAsync() const
{
    Windows::Foundation::IAsyncAction returnValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactList)->DeleteAsync(put_abi(returnValue)));
    return returnValue;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact> consume_Windows_ApplicationModel_Contacts_IContactList<D>::GetContactFromRemoteIdAsync(param::hstring const& remoteId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact> contact{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactList)->GetContactFromRemoteIdAsync(get_abi(remoteId), put_abi(contact)));
    return contact;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact> consume_Windows_ApplicationModel_Contacts_IContactList<D>::GetMeContactAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact> meContact{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactList)->GetMeContactAsync(put_abi(meContact)));
    return meContact;
}

template <typename D> Windows::ApplicationModel::Contacts::ContactReader consume_Windows_ApplicationModel_Contacts_IContactList<D>::GetContactReader() const
{
    Windows::ApplicationModel::Contacts::ContactReader value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactList)->GetContactReader(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Contacts::ContactReader consume_Windows_ApplicationModel_Contacts_IContactList<D>::GetContactReader(Windows::ApplicationModel::Contacts::ContactQueryOptions const& options) const
{
    Windows::ApplicationModel::Contacts::ContactReader value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactList)->GetContactReaderWithOptions(get_abi(options), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Contacts_IContactList<D>::SaveContactAsync(Windows::ApplicationModel::Contacts::Contact const& contact) const
{
    Windows::Foundation::IAsyncAction value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactList)->SaveContactAsync(get_abi(contact), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Contacts_IContactList<D>::DeleteContactAsync(Windows::ApplicationModel::Contacts::Contact const& contact) const
{
    Windows::Foundation::IAsyncAction value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactList)->DeleteContactAsync(get_abi(contact), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact> consume_Windows_ApplicationModel_Contacts_IContactList<D>::GetContactAsync(param::hstring const& contactId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact> contacts{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactList)->GetContactAsync(get_abi(contactId), put_abi(contacts)));
    return contacts;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Contacts_IContactList2<D>::RegisterSyncManagerAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactList2)->RegisterSyncManagerAsync(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactList2<D>::SupportsServerSearch(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactList2)->put_SupportsServerSearch(value));
}

template <typename D> Windows::ApplicationModel::Contacts::ContactListSyncConstraints consume_Windows_ApplicationModel_Contacts_IContactList2<D>::SyncConstraints() const
{
    Windows::ApplicationModel::Contacts::ContactListSyncConstraints value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactList2)->get_SyncConstraints(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Contacts::ContactListLimitedWriteOperations consume_Windows_ApplicationModel_Contacts_IContactList3<D>::LimitedWriteOperations() const
{
    Windows::ApplicationModel::Contacts::ContactListLimitedWriteOperations value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactList3)->get_LimitedWriteOperations(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Contacts::ContactChangeTracker consume_Windows_ApplicationModel_Contacts_IContactList3<D>::GetChangeTracker(param::hstring const& identity) const
{
    Windows::ApplicationModel::Contacts::ContactChangeTracker result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactList3)->GetChangeTracker(get_abi(identity), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Contacts_IContactListLimitedWriteOperations<D>::TryCreateOrUpdateContactAsync(Windows::ApplicationModel::Contacts::Contact const& contact) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListLimitedWriteOperations)->TryCreateOrUpdateContactAsync(get_abi(contact), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Contacts_IContactListLimitedWriteOperations<D>::TryDeleteContactAsync(param::hstring const& contactId) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListLimitedWriteOperations)->TryDeleteContactAsync(get_abi(contactId), put_abi(operation)));
    return operation;
}

template <typename D> bool consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::CanSyncDescriptions() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_CanSyncDescriptions(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::CanSyncDescriptions(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_CanSyncDescriptions(value));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxHomePhoneNumbers() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxHomePhoneNumbers(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxHomePhoneNumbers(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxHomePhoneNumbers(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxMobilePhoneNumbers() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxMobilePhoneNumbers(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxMobilePhoneNumbers(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxMobilePhoneNumbers(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxWorkPhoneNumbers() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxWorkPhoneNumbers(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxWorkPhoneNumbers(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxWorkPhoneNumbers(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxOtherPhoneNumbers() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxOtherPhoneNumbers(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxOtherPhoneNumbers(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxOtherPhoneNumbers(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxPagerPhoneNumbers() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxPagerPhoneNumbers(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxPagerPhoneNumbers(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxPagerPhoneNumbers(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxBusinessFaxPhoneNumbers() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxBusinessFaxPhoneNumbers(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxBusinessFaxPhoneNumbers(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxBusinessFaxPhoneNumbers(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxHomeFaxPhoneNumbers() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxHomeFaxPhoneNumbers(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxHomeFaxPhoneNumbers(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxHomeFaxPhoneNumbers(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxCompanyPhoneNumbers() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxCompanyPhoneNumbers(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxCompanyPhoneNumbers(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxCompanyPhoneNumbers(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxAssistantPhoneNumbers() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxAssistantPhoneNumbers(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxAssistantPhoneNumbers(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxAssistantPhoneNumbers(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxRadioPhoneNumbers() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxRadioPhoneNumbers(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxRadioPhoneNumbers(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxRadioPhoneNumbers(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxPersonalEmailAddresses() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxPersonalEmailAddresses(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxPersonalEmailAddresses(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxPersonalEmailAddresses(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxWorkEmailAddresses() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxWorkEmailAddresses(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxWorkEmailAddresses(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxWorkEmailAddresses(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxOtherEmailAddresses() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxOtherEmailAddresses(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxOtherEmailAddresses(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxOtherEmailAddresses(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxHomeAddresses() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxHomeAddresses(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxHomeAddresses(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxHomeAddresses(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxWorkAddresses() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxWorkAddresses(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxWorkAddresses(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxWorkAddresses(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxOtherAddresses() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxOtherAddresses(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxOtherAddresses(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxOtherAddresses(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxBirthdayDates() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxBirthdayDates(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxBirthdayDates(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxBirthdayDates(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxAnniversaryDates() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxAnniversaryDates(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxAnniversaryDates(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxAnniversaryDates(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxOtherDates() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxOtherDates(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxOtherDates(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxOtherDates(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxOtherRelationships() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxOtherRelationships(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxOtherRelationships(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxOtherRelationships(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxSpouseRelationships() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxSpouseRelationships(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxSpouseRelationships(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxSpouseRelationships(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxPartnerRelationships() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxPartnerRelationships(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxPartnerRelationships(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxPartnerRelationships(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxSiblingRelationships() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxSiblingRelationships(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxSiblingRelationships(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxSiblingRelationships(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxParentRelationships() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxParentRelationships(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxParentRelationships(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxParentRelationships(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxChildRelationships() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxChildRelationships(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxChildRelationships(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxChildRelationships(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxJobInfo() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxJobInfo(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxJobInfo(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxJobInfo(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxWebsites() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxWebsites(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxWebsites(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxWebsites(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Contacts::ContactListSyncStatus consume_Windows_ApplicationModel_Contacts_IContactListSyncManager<D>::Status() const
{
    Windows::ApplicationModel::Contacts::ContactListSyncStatus value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncManager)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_ApplicationModel_Contacts_IContactListSyncManager<D>::LastSuccessfulSyncTime() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncManager)->get_LastSuccessfulSyncTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_ApplicationModel_Contacts_IContactListSyncManager<D>::LastAttemptedSyncTime() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncManager)->get_LastAttemptedSyncTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Contacts_IContactListSyncManager<D>::SyncAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncManager)->SyncAsync(put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Contacts_IContactListSyncManager<D>::SyncStatusChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::ContactListSyncManager, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncManager)->add_SyncStatusChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Contacts_IContactListSyncManager<D>::SyncStatusChanged_revoker consume_Windows_ApplicationModel_Contacts_IContactListSyncManager<D>::SyncStatusChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::ContactListSyncManager, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, SyncStatusChanged_revoker>(this, SyncStatusChanged(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactListSyncManager<D>::SyncStatusChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncManager)->remove_SyncStatusChanged(get_abi(token)));
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactListSyncManager2<D>::Status(Windows::ApplicationModel::Contacts::ContactListSyncStatus const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncManager2)->put_Status(get_abi(value)));
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactListSyncManager2<D>::LastSuccessfulSyncTime(Windows::Foundation::DateTime const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncManager2)->put_LastSuccessfulSyncTime(get_abi(value)));
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactListSyncManager2<D>::LastAttemptedSyncTime(Windows::Foundation::DateTime const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactListSyncManager2)->put_LastAttemptedSyncTime(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactLocationField<D>::UnstructuredAddress() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactLocationField)->get_UnstructuredAddress(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactLocationField<D>::Street() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactLocationField)->get_Street(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactLocationField<D>::City() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactLocationField)->get_City(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactLocationField<D>::Region() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactLocationField)->get_Region(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactLocationField<D>::Country() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactLocationField)->get_Country(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactLocationField<D>::PostalCode() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactLocationField)->get_PostalCode(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Contacts::ContactLocationField consume_Windows_ApplicationModel_Contacts_IContactLocationFieldFactory<D>::CreateLocation(param::hstring const& unstructuredAddress) const
{
    Windows::ApplicationModel::Contacts::ContactLocationField field{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactLocationFieldFactory)->CreateLocation_Default(get_abi(unstructuredAddress), put_abi(field)));
    return field;
}

template <typename D> Windows::ApplicationModel::Contacts::ContactLocationField consume_Windows_ApplicationModel_Contacts_IContactLocationFieldFactory<D>::CreateLocation(param::hstring const& unstructuredAddress, Windows::ApplicationModel::Contacts::ContactFieldCategory const& category) const
{
    Windows::ApplicationModel::Contacts::ContactLocationField field{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactLocationFieldFactory)->CreateLocation_Category(get_abi(unstructuredAddress), get_abi(category), put_abi(field)));
    return field;
}

template <typename D> Windows::ApplicationModel::Contacts::ContactLocationField consume_Windows_ApplicationModel_Contacts_IContactLocationFieldFactory<D>::CreateLocation(param::hstring const& unstructuredAddress, Windows::ApplicationModel::Contacts::ContactFieldCategory const& category, param::hstring const& street, param::hstring const& city, param::hstring const& region, param::hstring const& country, param::hstring const& postalCode) const
{
    Windows::ApplicationModel::Contacts::ContactLocationField field{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactLocationFieldFactory)->CreateLocation_All(get_abi(unstructuredAddress), get_abi(category), get_abi(street), get_abi(city), get_abi(region), get_abi(country), get_abi(postalCode), put_abi(field)));
    return field;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::RandomAccessStreamReference> consume_Windows_ApplicationModel_Contacts_IContactManagerForUser<D>::ConvertContactToVCardAsync(Windows::ApplicationModel::Contacts::Contact const& contact) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::RandomAccessStreamReference> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactManagerForUser)->ConvertContactToVCardAsync(get_abi(contact), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::RandomAccessStreamReference> consume_Windows_ApplicationModel_Contacts_IContactManagerForUser<D>::ConvertContactToVCardAsync(Windows::ApplicationModel::Contacts::Contact const& contact, uint32_t maxBytes) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::RandomAccessStreamReference> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactManagerForUser)->ConvertContactToVCardAsyncWithMaxBytes(get_abi(contact), maxBytes, put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact> consume_Windows_ApplicationModel_Contacts_IContactManagerForUser<D>::ConvertVCardToContactAsync(Windows::Storage::Streams::IRandomAccessStreamReference const& vCard) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactManagerForUser)->ConvertVCardToContactAsync(get_abi(vCard), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactStore> consume_Windows_ApplicationModel_Contacts_IContactManagerForUser<D>::RequestStoreAsync(Windows::ApplicationModel::Contacts::ContactStoreAccessType const& accessType) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactStore> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactManagerForUser)->RequestStoreAsync(get_abi(accessType), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactAnnotationStore> consume_Windows_ApplicationModel_Contacts_IContactManagerForUser<D>::RequestAnnotationStoreAsync(Windows::ApplicationModel::Contacts::ContactAnnotationStoreAccessType const& accessType) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactAnnotationStore> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactManagerForUser)->RequestAnnotationStoreAsync(get_abi(accessType), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Contacts::ContactNameOrder consume_Windows_ApplicationModel_Contacts_IContactManagerForUser<D>::SystemDisplayNameOrder() const
{
    Windows::ApplicationModel::Contacts::ContactNameOrder value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactManagerForUser)->get_SystemDisplayNameOrder(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactManagerForUser<D>::SystemDisplayNameOrder(Windows::ApplicationModel::Contacts::ContactNameOrder const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactManagerForUser)->put_SystemDisplayNameOrder(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Contacts::ContactNameOrder consume_Windows_ApplicationModel_Contacts_IContactManagerForUser<D>::SystemSortOrder() const
{
    Windows::ApplicationModel::Contacts::ContactNameOrder value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactManagerForUser)->get_SystemSortOrder(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactManagerForUser<D>::SystemSortOrder(Windows::ApplicationModel::Contacts::ContactNameOrder const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactManagerForUser)->put_SystemSortOrder(get_abi(value)));
}

template <typename D> Windows::System::User consume_Windows_ApplicationModel_Contacts_IContactManagerForUser<D>::User() const
{
    Windows::System::User value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactManagerForUser)->get_User(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactManagerForUser2<D>::ShowFullContactCard(Windows::ApplicationModel::Contacts::Contact const& contact, Windows::ApplicationModel::Contacts::FullContactCardOptions const& fullContactCardOptions) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactManagerForUser2)->ShowFullContactCard(get_abi(contact), get_abi(fullContactCardOptions)));
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactManagerStatics<D>::ShowContactCard(Windows::ApplicationModel::Contacts::Contact const& contact, Windows::Foundation::Rect const& selection) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactManagerStatics)->ShowContactCard(get_abi(contact), get_abi(selection)));
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactManagerStatics<D>::ShowContactCard(Windows::ApplicationModel::Contacts::Contact const& contact, Windows::Foundation::Rect const& selection, Windows::UI::Popups::Placement const& preferredPlacement) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactManagerStatics)->ShowContactCardWithPlacement(get_abi(contact), get_abi(selection), get_abi(preferredPlacement)));
}

template <typename D> Windows::ApplicationModel::Contacts::ContactCardDelayedDataLoader consume_Windows_ApplicationModel_Contacts_IContactManagerStatics<D>::ShowDelayLoadedContactCard(Windows::ApplicationModel::Contacts::Contact const& contact, Windows::Foundation::Rect const& selection, Windows::UI::Popups::Placement const& preferredPlacement) const
{
    Windows::ApplicationModel::Contacts::ContactCardDelayedDataLoader dataLoader{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactManagerStatics)->ShowDelayLoadedContactCard(get_abi(contact), get_abi(selection), get_abi(preferredPlacement), put_abi(dataLoader)));
    return dataLoader;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactStore> consume_Windows_ApplicationModel_Contacts_IContactManagerStatics2<D>::RequestStoreAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactStore> store{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactManagerStatics2)->RequestStoreAsync(put_abi(store)));
    return store;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::RandomAccessStreamReference> consume_Windows_ApplicationModel_Contacts_IContactManagerStatics3<D>::ConvertContactToVCardAsync(Windows::ApplicationModel::Contacts::Contact const& contact) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::RandomAccessStreamReference> vCard{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactManagerStatics3)->ConvertContactToVCardAsync(get_abi(contact), put_abi(vCard)));
    return vCard;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::RandomAccessStreamReference> consume_Windows_ApplicationModel_Contacts_IContactManagerStatics3<D>::ConvertContactToVCardAsync(Windows::ApplicationModel::Contacts::Contact const& contact, uint32_t maxBytes) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::RandomAccessStreamReference> vCard{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactManagerStatics3)->ConvertContactToVCardAsyncWithMaxBytes(get_abi(contact), maxBytes, put_abi(vCard)));
    return vCard;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact> consume_Windows_ApplicationModel_Contacts_IContactManagerStatics3<D>::ConvertVCardToContactAsync(Windows::Storage::Streams::IRandomAccessStreamReference const& vCard) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact> contact{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactManagerStatics3)->ConvertVCardToContactAsync(get_abi(vCard), put_abi(contact)));
    return contact;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactStore> consume_Windows_ApplicationModel_Contacts_IContactManagerStatics3<D>::RequestStoreAsync(Windows::ApplicationModel::Contacts::ContactStoreAccessType const& accessType) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactStore> store{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactManagerStatics3)->RequestStoreAsyncWithAccessType(get_abi(accessType), put_abi(store)));
    return store;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactAnnotationStore> consume_Windows_ApplicationModel_Contacts_IContactManagerStatics3<D>::RequestAnnotationStoreAsync(Windows::ApplicationModel::Contacts::ContactAnnotationStoreAccessType const& accessType) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactAnnotationStore> store{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactManagerStatics3)->RequestAnnotationStoreAsync(get_abi(accessType), put_abi(store)));
    return store;
}

template <typename D> bool consume_Windows_ApplicationModel_Contacts_IContactManagerStatics3<D>::IsShowContactCardSupported() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactManagerStatics3)->IsShowContactCardSupported(&result));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactManagerStatics3<D>::ShowContactCard(Windows::ApplicationModel::Contacts::Contact const& contact, Windows::Foundation::Rect const& selection, Windows::UI::Popups::Placement const& preferredPlacement, Windows::ApplicationModel::Contacts::ContactCardOptions const& contactCardOptions) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactManagerStatics3)->ShowContactCardWithOptions(get_abi(contact), get_abi(selection), get_abi(preferredPlacement), get_abi(contactCardOptions)));
}

template <typename D> bool consume_Windows_ApplicationModel_Contacts_IContactManagerStatics3<D>::IsShowDelayLoadedContactCardSupported() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactManagerStatics3)->IsShowDelayLoadedContactCardSupported(&result));
    return result;
}

template <typename D> Windows::ApplicationModel::Contacts::ContactCardDelayedDataLoader consume_Windows_ApplicationModel_Contacts_IContactManagerStatics3<D>::ShowDelayLoadedContactCard(Windows::ApplicationModel::Contacts::Contact const& contact, Windows::Foundation::Rect const& selection, Windows::UI::Popups::Placement const& preferredPlacement, Windows::ApplicationModel::Contacts::ContactCardOptions const& contactCardOptions) const
{
    Windows::ApplicationModel::Contacts::ContactCardDelayedDataLoader dataLoader{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactManagerStatics3)->ShowDelayLoadedContactCardWithOptions(get_abi(contact), get_abi(selection), get_abi(preferredPlacement), get_abi(contactCardOptions), put_abi(dataLoader)));
    return dataLoader;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactManagerStatics3<D>::ShowFullContactCard(Windows::ApplicationModel::Contacts::Contact const& contact, Windows::ApplicationModel::Contacts::FullContactCardOptions const& fullContactCardOptions) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactManagerStatics3)->ShowFullContactCard(get_abi(contact), get_abi(fullContactCardOptions)));
}

template <typename D> Windows::ApplicationModel::Contacts::ContactNameOrder consume_Windows_ApplicationModel_Contacts_IContactManagerStatics3<D>::SystemDisplayNameOrder() const
{
    Windows::ApplicationModel::Contacts::ContactNameOrder value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactManagerStatics3)->get_SystemDisplayNameOrder(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactManagerStatics3<D>::SystemDisplayNameOrder(Windows::ApplicationModel::Contacts::ContactNameOrder const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactManagerStatics3)->put_SystemDisplayNameOrder(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Contacts::ContactNameOrder consume_Windows_ApplicationModel_Contacts_IContactManagerStatics3<D>::SystemSortOrder() const
{
    Windows::ApplicationModel::Contacts::ContactNameOrder value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactManagerStatics3)->get_SystemSortOrder(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactManagerStatics3<D>::SystemSortOrder(Windows::ApplicationModel::Contacts::ContactNameOrder const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactManagerStatics3)->put_SystemSortOrder(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Contacts::ContactManagerForUser consume_Windows_ApplicationModel_Contacts_IContactManagerStatics4<D>::GetForUser(Windows::System::User const& user) const
{
    Windows::ApplicationModel::Contacts::ContactManagerForUser result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactManagerStatics4)->GetForUser(get_abi(user), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Contacts_IContactManagerStatics5<D>::IsShowFullContactCardSupportedAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactManagerStatics5)->IsShowFullContactCardSupportedAsync(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_Contacts_IContactManagerStatics5<D>::IncludeMiddleNameInSystemDisplayAndSort() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactManagerStatics5)->get_IncludeMiddleNameInSystemDisplayAndSort(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactManagerStatics5<D>::IncludeMiddleNameInSystemDisplayAndSort(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactManagerStatics5)->put_IncludeMiddleNameInSystemDisplayAndSort(value));
}

template <typename D> Windows::ApplicationModel::Contacts::ContactMatchReasonKind consume_Windows_ApplicationModel_Contacts_IContactMatchReason<D>::Field() const
{
    Windows::ApplicationModel::Contacts::ContactMatchReasonKind value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactMatchReason)->get_Field(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Data::Text::TextSegment> consume_Windows_ApplicationModel_Contacts_IContactMatchReason<D>::Segments() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Data::Text::TextSegment> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactMatchReason)->get_Segments(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactMatchReason<D>::Text() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactMatchReason)->get_Text(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactName<D>::FirstName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactName)->get_FirstName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactName<D>::FirstName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactName)->put_FirstName(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactName<D>::LastName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactName)->get_LastName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactName<D>::LastName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactName)->put_LastName(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactName<D>::MiddleName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactName)->get_MiddleName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactName<D>::MiddleName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactName)->put_MiddleName(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactName<D>::YomiGivenName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactName)->get_YomiGivenName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactName<D>::YomiGivenName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactName)->put_YomiGivenName(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactName<D>::YomiFamilyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactName)->get_YomiFamilyName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactName<D>::YomiFamilyName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactName)->put_YomiFamilyName(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactName<D>::HonorificNameSuffix() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactName)->get_HonorificNameSuffix(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactName<D>::HonorificNameSuffix(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactName)->put_HonorificNameSuffix(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactName<D>::HonorificNamePrefix() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactName)->get_HonorificNamePrefix(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactName<D>::HonorificNamePrefix(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactName)->put_HonorificNamePrefix(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactName<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactName)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactName<D>::YomiDisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactName)->get_YomiDisplayName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactPanel<D>::ClosePanel() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactPanel)->ClosePanel());
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_ApplicationModel_Contacts_IContactPanel<D>::HeaderColor() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactPanel)->get_HeaderColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactPanel<D>::HeaderColor(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactPanel)->put_HeaderColor(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Contacts_IContactPanel<D>::LaunchFullAppRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::ContactPanel, Windows::ApplicationModel::Contacts::ContactPanelLaunchFullAppRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactPanel)->add_LaunchFullAppRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Contacts_IContactPanel<D>::LaunchFullAppRequested_revoker consume_Windows_ApplicationModel_Contacts_IContactPanel<D>::LaunchFullAppRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::ContactPanel, Windows::ApplicationModel::Contacts::ContactPanelLaunchFullAppRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, LaunchFullAppRequested_revoker>(this, LaunchFullAppRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactPanel<D>::LaunchFullAppRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactPanel)->remove_LaunchFullAppRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Contacts_IContactPanel<D>::Closing(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::ContactPanel, Windows::ApplicationModel::Contacts::ContactPanelClosingEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactPanel)->add_Closing(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Contacts_IContactPanel<D>::Closing_revoker consume_Windows_ApplicationModel_Contacts_IContactPanel<D>::Closing(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::ContactPanel, Windows::ApplicationModel::Contacts::ContactPanelClosingEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Closing_revoker>(this, Closing(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactPanel<D>::Closing(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactPanel)->remove_Closing(get_abi(token)));
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_Contacts_IContactPanelClosingEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral deferral{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactPanelClosingEventArgs)->GetDeferral(put_abi(deferral)));
    return deferral;
}

template <typename D> bool consume_Windows_ApplicationModel_Contacts_IContactPanelLaunchFullAppRequestedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactPanelLaunchFullAppRequestedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactPanelLaunchFullAppRequestedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactPanelLaunchFullAppRequestedEventArgs)->put_Handled(value));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactPhone<D>::Number() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactPhone)->get_Number(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactPhone<D>::Number(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactPhone)->put_Number(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Contacts::ContactPhoneKind consume_Windows_ApplicationModel_Contacts_IContactPhone<D>::Kind() const
{
    Windows::ApplicationModel::Contacts::ContactPhoneKind value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactPhone)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactPhone<D>::Kind(Windows::ApplicationModel::Contacts::ContactPhoneKind const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactPhone)->put_Kind(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactPhone<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactPhone)->get_Description(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactPhone<D>::Description(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactPhone)->put_Description(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactPicker<D>::CommitButtonText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactPicker)->get_CommitButtonText(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactPicker<D>::CommitButtonText(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactPicker)->put_CommitButtonText(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Contacts::ContactSelectionMode consume_Windows_ApplicationModel_Contacts_IContactPicker<D>::SelectionMode() const
{
    Windows::ApplicationModel::Contacts::ContactSelectionMode value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactPicker)->get_SelectionMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactPicker<D>::SelectionMode(Windows::ApplicationModel::Contacts::ContactSelectionMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactPicker)->put_SelectionMode(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_ApplicationModel_Contacts_IContactPicker<D>::DesiredFields() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactPicker)->get_DesiredFields(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactInformation> consume_Windows_ApplicationModel_Contacts_IContactPicker<D>::PickSingleContactAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactInformation> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactPicker)->PickSingleContactAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactInformation>> consume_Windows_ApplicationModel_Contacts_IContactPicker<D>::PickMultipleContactsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactInformation>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactPicker)->PickMultipleContactsAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactFieldType> consume_Windows_ApplicationModel_Contacts_IContactPicker2<D>::DesiredFieldsWithContactFieldType() const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactFieldType> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactPicker2)->get_DesiredFieldsWithContactFieldType(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact> consume_Windows_ApplicationModel_Contacts_IContactPicker2<D>::PickContactAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactPicker2)->PickContactAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::Contact>> consume_Windows_ApplicationModel_Contacts_IContactPicker2<D>::PickContactsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::Contact>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactPicker2)->PickContactsAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::System::User consume_Windows_ApplicationModel_Contacts_IContactPicker3<D>::User() const
{
    Windows::System::User value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactPicker3)->get_User(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Contacts::ContactPicker consume_Windows_ApplicationModel_Contacts_IContactPickerStatics<D>::CreateForUser(Windows::System::User const& user) const
{
    Windows::ApplicationModel::Contacts::ContactPicker result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactPickerStatics)->CreateForUser(get_abi(user), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Contacts_IContactPickerStatics<D>::IsSupportedAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactPickerStatics)->IsSupportedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Contacts::ContactQueryTextSearch consume_Windows_ApplicationModel_Contacts_IContactQueryOptions<D>::TextSearch() const
{
    Windows::ApplicationModel::Contacts::ContactQueryTextSearch value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactQueryOptions)->get_TextSearch(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_ApplicationModel_Contacts_IContactQueryOptions<D>::ContactListIds() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactQueryOptions)->get_ContactListIds(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Contacts_IContactQueryOptions<D>::IncludeContactsFromHiddenLists() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactQueryOptions)->get_IncludeContactsFromHiddenLists(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactQueryOptions<D>::IncludeContactsFromHiddenLists(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactQueryOptions)->put_IncludeContactsFromHiddenLists(value));
}

template <typename D> Windows::ApplicationModel::Contacts::ContactQueryDesiredFields consume_Windows_ApplicationModel_Contacts_IContactQueryOptions<D>::DesiredFields() const
{
    Windows::ApplicationModel::Contacts::ContactQueryDesiredFields value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactQueryOptions)->get_DesiredFields(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactQueryOptions<D>::DesiredFields(Windows::ApplicationModel::Contacts::ContactQueryDesiredFields const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactQueryOptions)->put_DesiredFields(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Contacts::ContactAnnotationOperations consume_Windows_ApplicationModel_Contacts_IContactQueryOptions<D>::DesiredOperations() const
{
    Windows::ApplicationModel::Contacts::ContactAnnotationOperations value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactQueryOptions)->get_DesiredOperations(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactQueryOptions<D>::DesiredOperations(Windows::ApplicationModel::Contacts::ContactAnnotationOperations const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactQueryOptions)->put_DesiredOperations(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_ApplicationModel_Contacts_IContactQueryOptions<D>::AnnotationListIds() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactQueryOptions)->get_AnnotationListIds(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Contacts::ContactQueryOptions consume_Windows_ApplicationModel_Contacts_IContactQueryOptionsFactory<D>::CreateWithText(param::hstring const& text) const
{
    Windows::ApplicationModel::Contacts::ContactQueryOptions result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactQueryOptionsFactory)->CreateWithText(get_abi(text), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Contacts::ContactQueryOptions consume_Windows_ApplicationModel_Contacts_IContactQueryOptionsFactory<D>::CreateWithTextAndFields(param::hstring const& text, Windows::ApplicationModel::Contacts::ContactQuerySearchFields const& fields) const
{
    Windows::ApplicationModel::Contacts::ContactQueryOptions result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactQueryOptionsFactory)->CreateWithTextAndFields(get_abi(text), get_abi(fields), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Contacts::ContactQuerySearchFields consume_Windows_ApplicationModel_Contacts_IContactQueryTextSearch<D>::Fields() const
{
    Windows::ApplicationModel::Contacts::ContactQuerySearchFields value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactQueryTextSearch)->get_Fields(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactQueryTextSearch<D>::Fields(Windows::ApplicationModel::Contacts::ContactQuerySearchFields const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactQueryTextSearch)->put_Fields(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactQueryTextSearch<D>::Text() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactQueryTextSearch)->get_Text(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactQueryTextSearch<D>::Text(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactQueryTextSearch)->put_Text(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Contacts::ContactQuerySearchScope consume_Windows_ApplicationModel_Contacts_IContactQueryTextSearch<D>::SearchScope() const
{
    Windows::ApplicationModel::Contacts::ContactQuerySearchScope value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactQueryTextSearch)->get_SearchScope(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactQueryTextSearch<D>::SearchScope(Windows::ApplicationModel::Contacts::ContactQuerySearchScope const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactQueryTextSearch)->put_SearchScope(get_abi(value)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactBatch> consume_Windows_ApplicationModel_Contacts_IContactReader<D>::ReadBatchAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactBatch> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactReader)->ReadBatchAsync(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactMatchReason> consume_Windows_ApplicationModel_Contacts_IContactReader<D>::GetMatchingPropertiesWithMatchReason(Windows::ApplicationModel::Contacts::Contact const& contact) const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactMatchReason> ppRetVal{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactReader)->GetMatchingPropertiesWithMatchReason(get_abi(contact), put_abi(ppRetVal)));
    return ppRetVal;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactSignificantOther<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactSignificantOther)->get_Name(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactSignificantOther<D>::Name(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactSignificantOther)->put_Name(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactSignificantOther<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactSignificantOther)->get_Description(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactSignificantOther<D>::Description(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactSignificantOther)->put_Description(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Contacts::ContactRelationship consume_Windows_ApplicationModel_Contacts_IContactSignificantOther2<D>::Relationship() const
{
    Windows::ApplicationModel::Contacts::ContactRelationship value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactSignificantOther2)->get_Relationship(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactSignificantOther2<D>::Relationship(Windows::ApplicationModel::Contacts::ContactRelationship const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactSignificantOther2)->put_Relationship(get_abi(value)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::Contact>> consume_Windows_ApplicationModel_Contacts_IContactStore<D>::FindContactsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::Contact>> contacts{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactStore)->FindContactsAsync(put_abi(contacts)));
    return contacts;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::Contact>> consume_Windows_ApplicationModel_Contacts_IContactStore<D>::FindContactsAsync(param::hstring const& searchText) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::Contact>> contacts{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactStore)->FindContactsWithSearchTextAsync(get_abi(searchText), put_abi(contacts)));
    return contacts;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact> consume_Windows_ApplicationModel_Contacts_IContactStore<D>::GetContactAsync(param::hstring const& contactId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact> contacts{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactStore)->GetContactAsync(get_abi(contactId), put_abi(contacts)));
    return contacts;
}

template <typename D> Windows::ApplicationModel::Contacts::ContactChangeTracker consume_Windows_ApplicationModel_Contacts_IContactStore2<D>::ChangeTracker() const
{
    Windows::ApplicationModel::Contacts::ContactChangeTracker value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactStore2)->get_ChangeTracker(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Contacts_IContactStore2<D>::ContactChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::ContactStore, Windows::ApplicationModel::Contacts::ContactChangedEventArgs> const& value) const
{
    winrt::event_token returnValue{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactStore2)->add_ContactChanged(get_abi(value), put_abi(returnValue)));
    return returnValue;
}

template <typename D> typename consume_Windows_ApplicationModel_Contacts_IContactStore2<D>::ContactChanged_revoker consume_Windows_ApplicationModel_Contacts_IContactStore2<D>::ContactChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::ContactStore, Windows::ApplicationModel::Contacts::ContactChangedEventArgs> const& value) const
{
    return impl::make_event_revoker<D, ContactChanged_revoker>(this, ContactChanged(value));
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactStore2<D>::ContactChanged(winrt::event_token const& value) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactStore2)->remove_ContactChanged(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Contacts::AggregateContactManager consume_Windows_ApplicationModel_Contacts_IContactStore2<D>::AggregateContactManager() const
{
    Windows::ApplicationModel::Contacts::AggregateContactManager value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactStore2)->get_AggregateContactManager(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactList>> consume_Windows_ApplicationModel_Contacts_IContactStore2<D>::FindContactListsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactList>> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactStore2)->FindContactListsAsync(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactList> consume_Windows_ApplicationModel_Contacts_IContactStore2<D>::GetContactListAsync(param::hstring const& contactListId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactList> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactStore2)->GetContactListAsync(get_abi(contactListId), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactList> consume_Windows_ApplicationModel_Contacts_IContactStore2<D>::CreateContactListAsync(param::hstring const& displayName) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactList> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactStore2)->CreateContactListAsync(get_abi(displayName), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact> consume_Windows_ApplicationModel_Contacts_IContactStore2<D>::GetMeContactAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact> meContact{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactStore2)->GetMeContactAsync(put_abi(meContact)));
    return meContact;
}

template <typename D> Windows::ApplicationModel::Contacts::ContactReader consume_Windows_ApplicationModel_Contacts_IContactStore2<D>::GetContactReader() const
{
    Windows::ApplicationModel::Contacts::ContactReader value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactStore2)->GetContactReader(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Contacts::ContactReader consume_Windows_ApplicationModel_Contacts_IContactStore2<D>::GetContactReader(Windows::ApplicationModel::Contacts::ContactQueryOptions const& options) const
{
    Windows::ApplicationModel::Contacts::ContactReader value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactStore2)->GetContactReaderWithOptions(get_abi(options), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactList> consume_Windows_ApplicationModel_Contacts_IContactStore2<D>::CreateContactListAsync(param::hstring const& displayName, param::hstring const& userDataAccountId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactList> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactStore2)->CreateContactListInAccountAsync(get_abi(displayName), get_abi(userDataAccountId), put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Contacts::ContactChangeTracker consume_Windows_ApplicationModel_Contacts_IContactStore3<D>::GetChangeTracker(param::hstring const& identity) const
{
    Windows::ApplicationModel::Contacts::ContactChangeTracker result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactStore3)->GetChangeTracker(get_abi(identity), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Uri consume_Windows_ApplicationModel_Contacts_IContactWebsite<D>::Uri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactWebsite)->get_Uri(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactWebsite<D>::Uri(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactWebsite)->put_Uri(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactWebsite<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactWebsite)->get_Description(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactWebsite<D>::Description(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactWebsite)->put_Description(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IContactWebsite2<D>::RawValue() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactWebsite2)->get_RawValue(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IContactWebsite2<D>::RawValue(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IContactWebsite2)->put_RawValue(get_abi(value)));
}

template <typename D> Windows::UI::ViewManagement::ViewSizePreference consume_Windows_ApplicationModel_Contacts_IFullContactCardOptions<D>::DesiredRemainingView() const
{
    Windows::UI::ViewManagement::ViewSizePreference value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IFullContactCardOptions)->get_DesiredRemainingView(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IFullContactCardOptions<D>::DesiredRemainingView(Windows::UI::ViewManagement::ViewSizePreference const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IFullContactCardOptions)->put_DesiredRemainingView(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IKnownContactFieldStatics<D>::Email() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IKnownContactFieldStatics)->get_Email(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IKnownContactFieldStatics<D>::PhoneNumber() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IKnownContactFieldStatics)->get_PhoneNumber(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IKnownContactFieldStatics<D>::Location() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IKnownContactFieldStatics)->get_Location(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IKnownContactFieldStatics<D>::InstantMessage() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IKnownContactFieldStatics)->get_InstantMessage(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Contacts::ContactFieldType consume_Windows_ApplicationModel_Contacts_IKnownContactFieldStatics<D>::ConvertNameToType(param::hstring const& name) const
{
    Windows::ApplicationModel::Contacts::ContactFieldType type{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IKnownContactFieldStatics)->ConvertNameToType(get_abi(name), put_abi(type)));
    return type;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_IKnownContactFieldStatics<D>::ConvertTypeToName(Windows::ApplicationModel::Contacts::ContactFieldType const& type) const
{
    hstring name{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IKnownContactFieldStatics)->ConvertTypeToName(get_abi(type), put_abi(name)));
    return name;
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_ApplicationModel_Contacts_IPinnedContactIdsQueryResult<D>::ContactIds() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IPinnedContactIdsQueryResult)->get_ContactIds(put_abi(value)));
    return value;
}

template <typename D> Windows::System::User consume_Windows_ApplicationModel_Contacts_IPinnedContactManager<D>::User() const
{
    Windows::System::User user{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IPinnedContactManager)->get_User(put_abi(user)));
    return user;
}

template <typename D> bool consume_Windows_ApplicationModel_Contacts_IPinnedContactManager<D>::IsPinSurfaceSupported(Windows::ApplicationModel::Contacts::PinnedContactSurface const& surface) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IPinnedContactManager)->IsPinSurfaceSupported(get_abi(surface), &result));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_Contacts_IPinnedContactManager<D>::IsContactPinned(Windows::ApplicationModel::Contacts::Contact const& contact, Windows::ApplicationModel::Contacts::PinnedContactSurface const& surface) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IPinnedContactManager)->IsContactPinned(get_abi(contact), get_abi(surface), &result));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Contacts_IPinnedContactManager<D>::RequestPinContactAsync(Windows::ApplicationModel::Contacts::Contact const& contact, Windows::ApplicationModel::Contacts::PinnedContactSurface const& surface) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IPinnedContactManager)->RequestPinContactAsync(get_abi(contact), get_abi(surface), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Contacts_IPinnedContactManager<D>::RequestPinContactsAsync(param::async_iterable<Windows::ApplicationModel::Contacts::Contact> const& contacts, Windows::ApplicationModel::Contacts::PinnedContactSurface const& surface) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IPinnedContactManager)->RequestPinContactsAsync(get_abi(contacts), get_abi(surface), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Contacts_IPinnedContactManager<D>::RequestUnpinContactAsync(Windows::ApplicationModel::Contacts::Contact const& contact, Windows::ApplicationModel::Contacts::PinnedContactSurface const& surface) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IPinnedContactManager)->RequestUnpinContactAsync(get_abi(contact), get_abi(surface), put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_IPinnedContactManager<D>::SignalContactActivity(Windows::ApplicationModel::Contacts::Contact const& contact) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IPinnedContactManager)->SignalContactActivity(get_abi(contact)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::PinnedContactIdsQueryResult> consume_Windows_ApplicationModel_Contacts_IPinnedContactManager<D>::GetPinnedContactIdsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::PinnedContactIdsQueryResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IPinnedContactManager)->GetPinnedContactIdsAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::ApplicationModel::Contacts::PinnedContactManager consume_Windows_ApplicationModel_Contacts_IPinnedContactManagerStatics<D>::GetDefault() const
{
    Windows::ApplicationModel::Contacts::PinnedContactManager result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IPinnedContactManagerStatics)->GetDefault(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Contacts::PinnedContactManager consume_Windows_ApplicationModel_Contacts_IPinnedContactManagerStatics<D>::GetForUser(Windows::System::User const& user) const
{
    Windows::ApplicationModel::Contacts::PinnedContactManager result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IPinnedContactManagerStatics)->GetForUser(get_abi(user), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_Contacts_IPinnedContactManagerStatics<D>::IsSupported() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::IPinnedContactManagerStatics)->IsSupported(&result));
    return result;
}

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IAggregateContactManager> : produce_base<D, Windows::ApplicationModel::Contacts::IAggregateContactManager>
{
    int32_t WINRT_CALL FindRawContactsAsync(void* contact, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindRawContactsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::Contact>>), Windows::ApplicationModel::Contacts::Contact const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::Contact>>>(this->shim().FindRawContactsAsync(*reinterpret_cast<Windows::ApplicationModel::Contacts::Contact const*>(&contact)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryLinkContactsAsync(void* primaryContact, void* secondaryContact, void** contact) noexcept final
    {
        try
        {
            *contact = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryLinkContactsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact>), Windows::ApplicationModel::Contacts::Contact const, Windows::ApplicationModel::Contacts::Contact const);
            *contact = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact>>(this->shim().TryLinkContactsAsync(*reinterpret_cast<Windows::ApplicationModel::Contacts::Contact const*>(&primaryContact), *reinterpret_cast<Windows::ApplicationModel::Contacts::Contact const*>(&secondaryContact)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UnlinkRawContactAsync(void* contact, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnlinkRawContactAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Contacts::Contact const);
            *value = detach_from<Windows::Foundation::IAsyncAction>(this->shim().UnlinkRawContactAsync(*reinterpret_cast<Windows::ApplicationModel::Contacts::Contact const*>(&contact)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySetPreferredSourceForPictureAsync(void* aggregateContact, void* rawContact, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySetPreferredSourceForPictureAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::ApplicationModel::Contacts::Contact const, Windows::ApplicationModel::Contacts::Contact const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TrySetPreferredSourceForPictureAsync(*reinterpret_cast<Windows::ApplicationModel::Contacts::Contact const*>(&aggregateContact), *reinterpret_cast<Windows::ApplicationModel::Contacts::Contact const*>(&rawContact)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IAggregateContactManager2> : produce_base<D, Windows::ApplicationModel::Contacts::IAggregateContactManager2>
{
    int32_t WINRT_CALL SetRemoteIdentificationInformationAsync(void* contactListId, void* remoteSourceId, void* accountId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetRemoteIdentificationInformationAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const, hstring const, hstring const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetRemoteIdentificationInformationAsync(*reinterpret_cast<hstring const*>(&contactListId), *reinterpret_cast<hstring const*>(&remoteSourceId), *reinterpret_cast<hstring const*>(&accountId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContact> : produce_base<D, Windows::ApplicationModel::Contacts::IContact>
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

    int32_t WINRT_CALL put_Name(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(void), hstring const&);
            this->shim().Name(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Thumbnail(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Thumbnail, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().Thumbnail());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Thumbnail(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Thumbnail, WINRT_WRAP(void), Windows::Storage::Streams::IRandomAccessStreamReference const&);
            this->shim().Thumbnail(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Fields(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Fields, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::IContactField>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::IContactField>>(this->shim().Fields());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContact2> : produce_base<D, Windows::ApplicationModel::Contacts::IContact2>
{
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

    int32_t WINRT_CALL put_Id(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(void), hstring const&);
            this->shim().Id(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Notes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Notes, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Notes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Notes(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Notes, WINRT_WRAP(void), hstring const&);
            this->shim().Notes(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Phones(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Phones, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactPhone>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactPhone>>(this->shim().Phones());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Emails(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Emails, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactEmail>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactEmail>>(this->shim().Emails());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Addresses(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Addresses, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactAddress>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactAddress>>(this->shim().Addresses());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ConnectedServiceAccounts(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectedServiceAccounts, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactConnectedServiceAccount>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactConnectedServiceAccount>>(this->shim().ConnectedServiceAccounts());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ImportantDates(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImportantDates, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactDate>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactDate>>(this->shim().ImportantDates());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DataSuppliers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataSuppliers, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().DataSuppliers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_JobInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(JobInfo, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactJobInfo>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactJobInfo>>(this->shim().JobInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SignificantOthers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SignificantOthers, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactSignificantOther>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactSignificantOther>>(this->shim().SignificantOthers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Websites(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Websites, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactWebsite>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactWebsite>>(this->shim().Websites());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProviderProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProviderProperties, WINRT_WRAP(Windows::Foundation::Collections::IPropertySet));
            *value = detach_from<Windows::Foundation::Collections::IPropertySet>(this->shim().ProviderProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContact3> : produce_base<D, Windows::ApplicationModel::Contacts::IContact3>
{
    int32_t WINRT_CALL get_ContactListId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContactListId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ContactListId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayPictureUserUpdateTime(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayPictureUserUpdateTime, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().DisplayPictureUserUpdateTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DisplayPictureUserUpdateTime(Windows::Foundation::DateTime value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayPictureUserUpdateTime, WINRT_WRAP(void), Windows::Foundation::DateTime const&);
            this->shim().DisplayPictureUserUpdateTime(*reinterpret_cast<Windows::Foundation::DateTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsMe(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsMe, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsMe());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AggregateId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AggregateId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AggregateId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RemoteId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoteId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RemoteId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RemoteId(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoteId, WINRT_WRAP(void), hstring const&);
            this->shim().RemoteId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RingToneToken(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RingToneToken, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RingToneToken());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RingToneToken(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RingToneToken, WINRT_WRAP(void), hstring const&);
            this->shim().RingToneToken(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDisplayPictureManuallySet(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDisplayPictureManuallySet, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDisplayPictureManuallySet());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LargeDisplayPicture(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LargeDisplayPicture, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().LargeDisplayPicture());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SmallDisplayPicture(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SmallDisplayPicture, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().SmallDisplayPicture());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SourceDisplayPicture(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceDisplayPicture, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().SourceDisplayPicture());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SourceDisplayPicture(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceDisplayPicture, WINRT_WRAP(void), Windows::Storage::Streams::IRandomAccessStreamReference const&);
            this->shim().SourceDisplayPicture(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TextToneToken(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TextToneToken, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TextToneToken());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TextToneToken(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TextToneToken, WINRT_WRAP(void), hstring const&);
            this->shim().TextToneToken(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsAggregate(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAggregate, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsAggregate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FullName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FullName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FullName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayNameOverride(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayNameOverride, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayNameOverride());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DisplayNameOverride(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayNameOverride, WINRT_WRAP(void), hstring const&);
            this->shim().DisplayNameOverride(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Nickname(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Nickname, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Nickname());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Nickname(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Nickname, WINRT_WRAP(void), hstring const&);
            this->shim().Nickname(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SortName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SortName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SortName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactAddress> : produce_base<D, Windows::ApplicationModel::Contacts::IContactAddress>
{
    int32_t WINRT_CALL get_StreetAddress(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StreetAddress, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().StreetAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StreetAddress(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StreetAddress, WINRT_WRAP(void), hstring const&);
            this->shim().StreetAddress(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Locality(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Locality, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Locality());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Locality(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Locality, WINRT_WRAP(void), hstring const&);
            this->shim().Locality(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Region(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Region, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Region());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Region(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Region, WINRT_WRAP(void), hstring const&);
            this->shim().Region(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Country(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Country, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Country());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Country(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Country, WINRT_WRAP(void), hstring const&);
            this->shim().Country(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PostalCode(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PostalCode, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PostalCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PostalCode(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PostalCode, WINRT_WRAP(void), hstring const&);
            this->shim().PostalCode(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Kind(Windows::ApplicationModel::Contacts::ContactAddressKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactAddressKind));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactAddressKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Kind(Windows::ApplicationModel::Contacts::ContactAddressKind value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(void), Windows::ApplicationModel::Contacts::ContactAddressKind const&);
            this->shim().Kind(*reinterpret_cast<Windows::ApplicationModel::Contacts::ContactAddressKind const*>(&value));
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

    int32_t WINRT_CALL put_Description(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(void), hstring const&);
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactAnnotation> : produce_base<D, Windows::ApplicationModel::Contacts::IContactAnnotation>
{
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

    int32_t WINRT_CALL get_AnnotationListId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AnnotationListId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AnnotationListId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContactId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContactId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ContactId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContactId(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContactId, WINRT_WRAP(void), hstring const&);
            this->shim().ContactId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RemoteId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoteId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RemoteId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RemoteId(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoteId, WINRT_WRAP(void), hstring const&);
            this->shim().RemoteId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedOperations(Windows::ApplicationModel::Contacts::ContactAnnotationOperations* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedOperations, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactAnnotationOperations));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactAnnotationOperations>(this->shim().SupportedOperations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SupportedOperations(Windows::ApplicationModel::Contacts::ContactAnnotationOperations value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedOperations, WINRT_WRAP(void), Windows::ApplicationModel::Contacts::ContactAnnotationOperations const&);
            this->shim().SupportedOperations(*reinterpret_cast<Windows::ApplicationModel::Contacts::ContactAnnotationOperations const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDisabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDisabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDisabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProviderProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProviderProperties, WINRT_WRAP(Windows::Foundation::Collections::ValueSet));
            *value = detach_from<Windows::Foundation::Collections::ValueSet>(this->shim().ProviderProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactAnnotation2> : produce_base<D, Windows::ApplicationModel::Contacts::IContactAnnotation2>
{
    int32_t WINRT_CALL get_ContactListId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContactListId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ContactListId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContactListId(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContactListId, WINRT_WRAP(void), hstring const&);
            this->shim().ContactListId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactAnnotationList> : produce_base<D, Windows::ApplicationModel::Contacts::IContactAnnotationList>
{
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

    int32_t WINRT_CALL get_ProviderPackageFamilyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProviderPackageFamilyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ProviderPackageFamilyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UserDataAccountId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserDataAccountId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UserDataAccountId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *value = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DeleteAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySaveAnnotationAsync(void* annotation, void** ppResult) noexcept final
    {
        try
        {
            *ppResult = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySaveAnnotationAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::ApplicationModel::Contacts::ContactAnnotation const);
            *ppResult = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TrySaveAnnotationAsync(*reinterpret_cast<Windows::ApplicationModel::Contacts::ContactAnnotation const*>(&annotation)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAnnotationAsync(void* annotationId, void** annotation) noexcept final
    {
        try
        {
            *annotation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAnnotationAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactAnnotation>), hstring const);
            *annotation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactAnnotation>>(this->shim().GetAnnotationAsync(*reinterpret_cast<hstring const*>(&annotationId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAnnotationsByRemoteIdAsync(void* remoteId, void** annotations) noexcept final
    {
        try
        {
            *annotations = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAnnotationsByRemoteIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactAnnotation>>), hstring const);
            *annotations = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactAnnotation>>>(this->shim().FindAnnotationsByRemoteIdAsync(*reinterpret_cast<hstring const*>(&remoteId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAnnotationsAsync(void** annotations) noexcept final
    {
        try
        {
            *annotations = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAnnotationsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactAnnotation>>));
            *annotations = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactAnnotation>>>(this->shim().FindAnnotationsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteAnnotationAsync(void* annotation, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteAnnotationAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Contacts::ContactAnnotation const);
            *value = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DeleteAnnotationAsync(*reinterpret_cast<Windows::ApplicationModel::Contacts::ContactAnnotation const*>(&annotation)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactAnnotationStore> : produce_base<D, Windows::ApplicationModel::Contacts::IContactAnnotationStore>
{
    int32_t WINRT_CALL FindContactIdsByEmailAsync(void* emailAddress, void** contactIds) noexcept final
    {
        try
        {
            *contactIds = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindContactIdsByEmailAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>>), hstring const);
            *contactIds = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>>>(this->shim().FindContactIdsByEmailAsync(*reinterpret_cast<hstring const*>(&emailAddress)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindContactIdsByPhoneNumberAsync(void* phoneNumber, void** contactIds) noexcept final
    {
        try
        {
            *contactIds = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindContactIdsByPhoneNumberAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>>), hstring const);
            *contactIds = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>>>(this->shim().FindContactIdsByPhoneNumberAsync(*reinterpret_cast<hstring const*>(&phoneNumber)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAnnotationsForContactAsync(void* contact, void** annotations) noexcept final
    {
        try
        {
            *annotations = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAnnotationsForContactAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactAnnotation>>), Windows::ApplicationModel::Contacts::Contact const);
            *annotations = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactAnnotation>>>(this->shim().FindAnnotationsForContactAsync(*reinterpret_cast<Windows::ApplicationModel::Contacts::Contact const*>(&contact)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DisableAnnotationAsync(void* annotation, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisableAnnotationAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Contacts::ContactAnnotation const);
            *value = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DisableAnnotationAsync(*reinterpret_cast<Windows::ApplicationModel::Contacts::ContactAnnotation const*>(&annotation)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateAnnotationListAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAnnotationListAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactAnnotationList>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactAnnotationList>>(this->shim().CreateAnnotationListAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateAnnotationListInAccountAsync(void* userDataAccountId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAnnotationListAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactAnnotationList>), hstring const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactAnnotationList>>(this->shim().CreateAnnotationListAsync(*reinterpret_cast<hstring const*>(&userDataAccountId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAnnotationListAsync(void* annotationListId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAnnotationListAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactAnnotationList>), hstring const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactAnnotationList>>(this->shim().GetAnnotationListAsync(*reinterpret_cast<hstring const*>(&annotationListId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAnnotationListsAsync(void** lists) noexcept final
    {
        try
        {
            *lists = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAnnotationListsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactAnnotationList>>));
            *lists = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactAnnotationList>>>(this->shim().FindAnnotationListsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactAnnotationStore2> : produce_base<D, Windows::ApplicationModel::Contacts::IContactAnnotationStore2>
{
    int32_t WINRT_CALL FindAnnotationsForContactListAsync(void* contactListId, void** annotations) noexcept final
    {
        try
        {
            *annotations = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAnnotationsForContactListAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactAnnotation>>), hstring const);
            *annotations = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactAnnotation>>>(this->shim().FindAnnotationsForContactListAsync(*reinterpret_cast<hstring const*>(&contactListId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactBatch> : produce_base<D, Windows::ApplicationModel::Contacts::IContactBatch>
{
    int32_t WINRT_CALL get_Contacts(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Contacts, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::Contact>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::Contact>>(this->shim().Contacts());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(Windows::ApplicationModel::Contacts::ContactBatchStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactBatchStatus));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactBatchStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactCardDelayedDataLoader> : produce_base<D, Windows::ApplicationModel::Contacts::IContactCardDelayedDataLoader>
{
    int32_t WINRT_CALL SetData(void* contact) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetData, WINRT_WRAP(void), Windows::ApplicationModel::Contacts::Contact const&);
            this->shim().SetData(*reinterpret_cast<Windows::ApplicationModel::Contacts::Contact const*>(&contact));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactCardOptions> : produce_base<D, Windows::ApplicationModel::Contacts::IContactCardOptions>
{
    int32_t WINRT_CALL get_HeaderKind(Windows::ApplicationModel::Contacts::ContactCardHeaderKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeaderKind, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactCardHeaderKind));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactCardHeaderKind>(this->shim().HeaderKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_HeaderKind(Windows::ApplicationModel::Contacts::ContactCardHeaderKind value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeaderKind, WINRT_WRAP(void), Windows::ApplicationModel::Contacts::ContactCardHeaderKind const&);
            this->shim().HeaderKind(*reinterpret_cast<Windows::ApplicationModel::Contacts::ContactCardHeaderKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InitialTabKind(Windows::ApplicationModel::Contacts::ContactCardTabKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InitialTabKind, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactCardTabKind));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactCardTabKind>(this->shim().InitialTabKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InitialTabKind(Windows::ApplicationModel::Contacts::ContactCardTabKind value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InitialTabKind, WINRT_WRAP(void), Windows::ApplicationModel::Contacts::ContactCardTabKind const&);
            this->shim().InitialTabKind(*reinterpret_cast<Windows::ApplicationModel::Contacts::ContactCardTabKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactCardOptions2> : produce_base<D, Windows::ApplicationModel::Contacts::IContactCardOptions2>
{
    int32_t WINRT_CALL get_ServerSearchContactListIds(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServerSearchContactListIds, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().ServerSearchContactListIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactChange> : produce_base<D, Windows::ApplicationModel::Contacts::IContactChange>
{
    int32_t WINRT_CALL get_ChangeType(Windows::ApplicationModel::Contacts::ContactChangeType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChangeType, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactChangeType));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactChangeType>(this->shim().ChangeType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Contact(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Contact, WINRT_WRAP(Windows::ApplicationModel::Contacts::Contact));
            *value = detach_from<Windows::ApplicationModel::Contacts::Contact>(this->shim().Contact());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactChangeReader> : produce_base<D, Windows::ApplicationModel::Contacts::IContactChangeReader>
{
    int32_t WINRT_CALL AcceptChanges() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AcceptChanges, WINRT_WRAP(void));
            this->shim().AcceptChanges();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AcceptChangesThrough(void* lastChangeToAccept) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AcceptChangesThrough, WINRT_WRAP(void), Windows::ApplicationModel::Contacts::ContactChange const&);
            this->shim().AcceptChangesThrough(*reinterpret_cast<Windows::ApplicationModel::Contacts::ContactChange const*>(&lastChangeToAccept));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadBatchAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadBatchAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactChange>>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactChange>>>(this->shim().ReadBatchAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactChangeTracker> : produce_base<D, Windows::ApplicationModel::Contacts::IContactChangeTracker>
{
    int32_t WINRT_CALL Enable() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Enable, WINRT_WRAP(void));
            this->shim().Enable();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetChangeReader(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetChangeReader, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactChangeReader));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactChangeReader>(this->shim().GetChangeReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Reset() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reset, WINRT_WRAP(void));
            this->shim().Reset();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactChangeTracker2> : produce_base<D, Windows::ApplicationModel::Contacts::IContactChangeTracker2>
{
    int32_t WINRT_CALL get_IsTracking(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTracking, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsTracking());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactChangedDeferral> : produce_base<D, Windows::ApplicationModel::Contacts::IContactChangedDeferral>
{
    int32_t WINRT_CALL Complete() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Complete, WINRT_WRAP(void));
            this->shim().Complete();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactChangedEventArgs> : produce_base<D, Windows::ApplicationModel::Contacts::IContactChangedEventArgs>
{
    int32_t WINRT_CALL GetDeferral(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactChangedDeferral));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactChangedDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactConnectedServiceAccount> : produce_base<D, Windows::ApplicationModel::Contacts::IContactConnectedServiceAccount>
{
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

    int32_t WINRT_CALL put_Id(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(void), hstring const&);
            this->shim().Id(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServiceName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ServiceName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ServiceName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceName, WINRT_WRAP(void), hstring const&);
            this->shim().ServiceName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactDate> : produce_base<D, Windows::ApplicationModel::Contacts::IContactDate>
{
    int32_t WINRT_CALL get_Day(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Day, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().Day());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Day(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Day, WINRT_WRAP(void), Windows::Foundation::IReference<uint32_t> const&);
            this->shim().Day(*reinterpret_cast<Windows::Foundation::IReference<uint32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Month(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Month, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().Month());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Month(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Month, WINRT_WRAP(void), Windows::Foundation::IReference<uint32_t> const&);
            this->shim().Month(*reinterpret_cast<Windows::Foundation::IReference<uint32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Year(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Year, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().Year());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Year(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Year, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().Year(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Kind(Windows::ApplicationModel::Contacts::ContactDateKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactDateKind));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactDateKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Kind(Windows::ApplicationModel::Contacts::ContactDateKind value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(void), Windows::ApplicationModel::Contacts::ContactDateKind const&);
            this->shim().Kind(*reinterpret_cast<Windows::ApplicationModel::Contacts::ContactDateKind const*>(&value));
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

    int32_t WINRT_CALL put_Description(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(void), hstring const&);
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactEmail> : produce_base<D, Windows::ApplicationModel::Contacts::IContactEmail>
{
    int32_t WINRT_CALL get_Address(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Address, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Address());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Address(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Address, WINRT_WRAP(void), hstring const&);
            this->shim().Address(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Kind(Windows::ApplicationModel::Contacts::ContactEmailKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactEmailKind));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactEmailKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Kind(Windows::ApplicationModel::Contacts::ContactEmailKind value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(void), Windows::ApplicationModel::Contacts::ContactEmailKind const&);
            this->shim().Kind(*reinterpret_cast<Windows::ApplicationModel::Contacts::ContactEmailKind const*>(&value));
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

    int32_t WINRT_CALL put_Description(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(void), hstring const&);
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactField> : produce_base<D, Windows::ApplicationModel::Contacts::IContactField>
{
    int32_t WINRT_CALL get_Type(Windows::ApplicationModel::Contacts::ContactFieldType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactFieldType));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactFieldType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Category(Windows::ApplicationModel::Contacts::ContactFieldCategory* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Category, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactFieldCategory));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactFieldCategory>(this->shim().Category());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL get_Value(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactFieldFactory> : produce_base<D, Windows::ApplicationModel::Contacts::IContactFieldFactory>
{
    int32_t WINRT_CALL CreateField_Default(void* value, Windows::ApplicationModel::Contacts::ContactFieldType type, void** field) noexcept final
    {
        try
        {
            *field = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateField, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactField), hstring const&, Windows::ApplicationModel::Contacts::ContactFieldType const&);
            *field = detach_from<Windows::ApplicationModel::Contacts::ContactField>(this->shim().CreateField(*reinterpret_cast<hstring const*>(&value), *reinterpret_cast<Windows::ApplicationModel::Contacts::ContactFieldType const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateField_Category(void* value, Windows::ApplicationModel::Contacts::ContactFieldType type, Windows::ApplicationModel::Contacts::ContactFieldCategory category, void** field) noexcept final
    {
        try
        {
            *field = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateField, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactField), hstring const&, Windows::ApplicationModel::Contacts::ContactFieldType const&, Windows::ApplicationModel::Contacts::ContactFieldCategory const&);
            *field = detach_from<Windows::ApplicationModel::Contacts::ContactField>(this->shim().CreateField(*reinterpret_cast<hstring const*>(&value), *reinterpret_cast<Windows::ApplicationModel::Contacts::ContactFieldType const*>(&type), *reinterpret_cast<Windows::ApplicationModel::Contacts::ContactFieldCategory const*>(&category)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateField_Custom(void* name, void* value, Windows::ApplicationModel::Contacts::ContactFieldType type, Windows::ApplicationModel::Contacts::ContactFieldCategory category, void** field) noexcept final
    {
        try
        {
            *field = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateField, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactField), hstring const&, hstring const&, Windows::ApplicationModel::Contacts::ContactFieldType const&, Windows::ApplicationModel::Contacts::ContactFieldCategory const&);
            *field = detach_from<Windows::ApplicationModel::Contacts::ContactField>(this->shim().CreateField(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&value), *reinterpret_cast<Windows::ApplicationModel::Contacts::ContactFieldType const*>(&type), *reinterpret_cast<Windows::ApplicationModel::Contacts::ContactFieldCategory const*>(&category)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactGroup> : produce_base<D, Windows::ApplicationModel::Contacts::IContactGroup>
{};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactInformation> : produce_base<D, Windows::ApplicationModel::Contacts::IContactInformation>
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

    int32_t WINRT_CALL GetThumbnailAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetThumbnailAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStreamWithContentType>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStreamWithContentType>>(this->shim().GetThumbnailAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Emails(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Emails, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactField>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactField>>(this->shim().Emails());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PhoneNumbers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhoneNumbers, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactField>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactField>>(this->shim().PhoneNumbers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Locations(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Locations, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactLocationField>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactLocationField>>(this->shim().Locations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InstantMessages(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InstantMessages, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactInstantMessageField>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactInstantMessageField>>(this->shim().InstantMessages());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CustomFields(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CustomFields, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactField>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactField>>(this->shim().CustomFields());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL QueryCustomFields(void* customName, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QueryCustomFields, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactField>), hstring const&);
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactField>>(this->shim().QueryCustomFields(*reinterpret_cast<hstring const*>(&customName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactInstantMessageField> : produce_base<D, Windows::ApplicationModel::Contacts::IContactInstantMessageField>
{
    int32_t WINRT_CALL get_UserName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UserName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Service(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Service, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Service());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LaunchUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().LaunchUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactInstantMessageFieldFactory> : produce_base<D, Windows::ApplicationModel::Contacts::IContactInstantMessageFieldFactory>
{
    int32_t WINRT_CALL CreateInstantMessage_Default(void* userName, void** field) noexcept final
    {
        try
        {
            *field = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstantMessage, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactInstantMessageField), hstring const&);
            *field = detach_from<Windows::ApplicationModel::Contacts::ContactInstantMessageField>(this->shim().CreateInstantMessage(*reinterpret_cast<hstring const*>(&userName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateInstantMessage_Category(void* userName, Windows::ApplicationModel::Contacts::ContactFieldCategory category, void** field) noexcept final
    {
        try
        {
            *field = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstantMessage, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactInstantMessageField), hstring const&, Windows::ApplicationModel::Contacts::ContactFieldCategory const&);
            *field = detach_from<Windows::ApplicationModel::Contacts::ContactInstantMessageField>(this->shim().CreateInstantMessage(*reinterpret_cast<hstring const*>(&userName), *reinterpret_cast<Windows::ApplicationModel::Contacts::ContactFieldCategory const*>(&category)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateInstantMessage_All(void* userName, Windows::ApplicationModel::Contacts::ContactFieldCategory category, void* service, void* displayText, void* verb, void** field) noexcept final
    {
        try
        {
            *field = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstantMessage, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactInstantMessageField), hstring const&, Windows::ApplicationModel::Contacts::ContactFieldCategory const&, hstring const&, hstring const&, Windows::Foundation::Uri const&);
            *field = detach_from<Windows::ApplicationModel::Contacts::ContactInstantMessageField>(this->shim().CreateInstantMessage(*reinterpret_cast<hstring const*>(&userName), *reinterpret_cast<Windows::ApplicationModel::Contacts::ContactFieldCategory const*>(&category), *reinterpret_cast<hstring const*>(&service), *reinterpret_cast<hstring const*>(&displayText), *reinterpret_cast<Windows::Foundation::Uri const*>(&verb)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactJobInfo> : produce_base<D, Windows::ApplicationModel::Contacts::IContactJobInfo>
{
    int32_t WINRT_CALL get_CompanyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompanyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CompanyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CompanyName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompanyName, WINRT_WRAP(void), hstring const&);
            this->shim().CompanyName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CompanyYomiName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompanyYomiName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CompanyYomiName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CompanyYomiName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompanyYomiName, WINRT_WRAP(void), hstring const&);
            this->shim().CompanyYomiName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Department(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Department, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Department());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Department(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Department, WINRT_WRAP(void), hstring const&);
            this->shim().Department(*reinterpret_cast<hstring const*>(&value));
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

    int32_t WINRT_CALL put_Title(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(void), hstring const&);
            this->shim().Title(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Manager(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Manager, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Manager());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Manager(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Manager, WINRT_WRAP(void), hstring const&);
            this->shim().Manager(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Office(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Office, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Office());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Office(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Office, WINRT_WRAP(void), hstring const&);
            this->shim().Office(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CompanyAddress(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompanyAddress, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CompanyAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CompanyAddress(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompanyAddress, WINRT_WRAP(void), hstring const&);
            this->shim().CompanyAddress(*reinterpret_cast<hstring const*>(&value));
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

    int32_t WINRT_CALL put_Description(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(void), hstring const&);
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactLaunchActionVerbsStatics> : produce_base<D, Windows::ApplicationModel::Contacts::IContactLaunchActionVerbsStatics>
{
    int32_t WINRT_CALL get_Call(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Call, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Call());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Message(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Message, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Map(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Map, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Map());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Post(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Post, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Post());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoCall(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoCall, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoCall());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactList> : produce_base<D, Windows::ApplicationModel::Contacts::IContactList>
{
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

    int32_t WINRT_CALL get_DisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DisplayName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayName, WINRT_WRAP(void), hstring const&);
            this->shim().DisplayName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SourceDisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceDisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SourceDisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsHidden(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsHidden, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsHidden());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsHidden(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsHidden, WINRT_WRAP(void), bool);
            this->shim().IsHidden(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OtherAppReadAccess(Windows::ApplicationModel::Contacts::ContactListOtherAppReadAccess* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OtherAppReadAccess, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactListOtherAppReadAccess));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactListOtherAppReadAccess>(this->shim().OtherAppReadAccess());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OtherAppReadAccess(Windows::ApplicationModel::Contacts::ContactListOtherAppReadAccess value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OtherAppReadAccess, WINRT_WRAP(void), Windows::ApplicationModel::Contacts::ContactListOtherAppReadAccess const&);
            this->shim().OtherAppReadAccess(*reinterpret_cast<Windows::ApplicationModel::Contacts::ContactListOtherAppReadAccess const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OtherAppWriteAccess(Windows::ApplicationModel::Contacts::ContactListOtherAppWriteAccess* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OtherAppWriteAccess, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactListOtherAppWriteAccess));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactListOtherAppWriteAccess>(this->shim().OtherAppWriteAccess());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OtherAppWriteAccess(Windows::ApplicationModel::Contacts::ContactListOtherAppWriteAccess value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OtherAppWriteAccess, WINRT_WRAP(void), Windows::ApplicationModel::Contacts::ContactListOtherAppWriteAccess const&);
            this->shim().OtherAppWriteAccess(*reinterpret_cast<Windows::ApplicationModel::Contacts::ContactListOtherAppWriteAccess const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ChangeTracker(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChangeTracker, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactChangeTracker));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactChangeTracker>(this->shim().ChangeTracker());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SyncManager(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SyncManager, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactListSyncManager));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactListSyncManager>(this->shim().SyncManager());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportsServerSearch(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportsServerSearch, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().SupportsServerSearch());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UserDataAccountId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserDataAccountId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UserDataAccountId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ContactChanged(void* value, winrt::event_token* returnValue) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContactChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::ContactList, Windows::ApplicationModel::Contacts::ContactChangedEventArgs> const&);
            *returnValue = detach_from<winrt::event_token>(this->shim().ContactChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::ContactList, Windows::ApplicationModel::Contacts::ContactChangedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ContactChanged(winrt::event_token value) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ContactChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ContactChanged(*reinterpret_cast<winrt::event_token const*>(&value));
        return 0;
    }

    int32_t WINRT_CALL SaveAsync(void** returnValue) noexcept final
    {
        try
        {
            *returnValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *returnValue = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SaveAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteAsync(void** returnValue) noexcept final
    {
        try
        {
            *returnValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *returnValue = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DeleteAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetContactFromRemoteIdAsync(void* remoteId, void** contact) noexcept final
    {
        try
        {
            *contact = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetContactFromRemoteIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact>), hstring const);
            *contact = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact>>(this->shim().GetContactFromRemoteIdAsync(*reinterpret_cast<hstring const*>(&remoteId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetMeContactAsync(void** meContact) noexcept final
    {
        try
        {
            *meContact = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetMeContactAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact>));
            *meContact = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact>>(this->shim().GetMeContactAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetContactReader(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetContactReader, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactReader));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactReader>(this->shim().GetContactReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetContactReaderWithOptions(void* options, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetContactReader, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactReader), Windows::ApplicationModel::Contacts::ContactQueryOptions const&);
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactReader>(this->shim().GetContactReader(*reinterpret_cast<Windows::ApplicationModel::Contacts::ContactQueryOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SaveContactAsync(void* contact, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveContactAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Contacts::Contact const);
            *value = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SaveContactAsync(*reinterpret_cast<Windows::ApplicationModel::Contacts::Contact const*>(&contact)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteContactAsync(void* contact, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteContactAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Contacts::Contact const);
            *value = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DeleteContactAsync(*reinterpret_cast<Windows::ApplicationModel::Contacts::Contact const*>(&contact)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetContactAsync(void* contactId, void** contacts) noexcept final
    {
        try
        {
            *contacts = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetContactAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact>), hstring const);
            *contacts = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact>>(this->shim().GetContactAsync(*reinterpret_cast<hstring const*>(&contactId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactList2> : produce_base<D, Windows::ApplicationModel::Contacts::IContactList2>
{
    int32_t WINRT_CALL RegisterSyncManagerAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterSyncManagerAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().RegisterSyncManagerAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SupportsServerSearch(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportsServerSearch, WINRT_WRAP(void), bool);
            this->shim().SupportsServerSearch(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SyncConstraints(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SyncConstraints, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactListSyncConstraints));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactListSyncConstraints>(this->shim().SyncConstraints());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactList3> : produce_base<D, Windows::ApplicationModel::Contacts::IContactList3>
{
    int32_t WINRT_CALL get_LimitedWriteOperations(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LimitedWriteOperations, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactListLimitedWriteOperations));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactListLimitedWriteOperations>(this->shim().LimitedWriteOperations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetChangeTracker(void* identity, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetChangeTracker, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactChangeTracker), hstring const&);
            *result = detach_from<Windows::ApplicationModel::Contacts::ContactChangeTracker>(this->shim().GetChangeTracker(*reinterpret_cast<hstring const*>(&identity)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactListLimitedWriteOperations> : produce_base<D, Windows::ApplicationModel::Contacts::IContactListLimitedWriteOperations>
{
    int32_t WINRT_CALL TryCreateOrUpdateContactAsync(void* contact, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryCreateOrUpdateContactAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::ApplicationModel::Contacts::Contact const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryCreateOrUpdateContactAsync(*reinterpret_cast<Windows::ApplicationModel::Contacts::Contact const*>(&contact)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryDeleteContactAsync(void* contactId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryDeleteContactAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryDeleteContactAsync(*reinterpret_cast<hstring const*>(&contactId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactListSyncConstraints> : produce_base<D, Windows::ApplicationModel::Contacts::IContactListSyncConstraints>
{
    int32_t WINRT_CALL get_CanSyncDescriptions(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanSyncDescriptions, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanSyncDescriptions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CanSyncDescriptions(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanSyncDescriptions, WINRT_WRAP(void), bool);
            this->shim().CanSyncDescriptions(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxHomePhoneNumbers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxHomePhoneNumbers, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().MaxHomePhoneNumbers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxHomePhoneNumbers(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxHomePhoneNumbers, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().MaxHomePhoneNumbers(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxMobilePhoneNumbers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxMobilePhoneNumbers, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().MaxMobilePhoneNumbers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxMobilePhoneNumbers(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxMobilePhoneNumbers, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().MaxMobilePhoneNumbers(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxWorkPhoneNumbers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxWorkPhoneNumbers, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().MaxWorkPhoneNumbers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxWorkPhoneNumbers(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxWorkPhoneNumbers, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().MaxWorkPhoneNumbers(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxOtherPhoneNumbers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxOtherPhoneNumbers, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().MaxOtherPhoneNumbers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxOtherPhoneNumbers(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxOtherPhoneNumbers, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().MaxOtherPhoneNumbers(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxPagerPhoneNumbers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxPagerPhoneNumbers, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().MaxPagerPhoneNumbers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxPagerPhoneNumbers(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxPagerPhoneNumbers, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().MaxPagerPhoneNumbers(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxBusinessFaxPhoneNumbers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxBusinessFaxPhoneNumbers, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().MaxBusinessFaxPhoneNumbers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxBusinessFaxPhoneNumbers(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxBusinessFaxPhoneNumbers, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().MaxBusinessFaxPhoneNumbers(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxHomeFaxPhoneNumbers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxHomeFaxPhoneNumbers, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().MaxHomeFaxPhoneNumbers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxHomeFaxPhoneNumbers(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxHomeFaxPhoneNumbers, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().MaxHomeFaxPhoneNumbers(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxCompanyPhoneNumbers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxCompanyPhoneNumbers, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().MaxCompanyPhoneNumbers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxCompanyPhoneNumbers(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxCompanyPhoneNumbers, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().MaxCompanyPhoneNumbers(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxAssistantPhoneNumbers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxAssistantPhoneNumbers, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().MaxAssistantPhoneNumbers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxAssistantPhoneNumbers(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxAssistantPhoneNumbers, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().MaxAssistantPhoneNumbers(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxRadioPhoneNumbers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxRadioPhoneNumbers, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().MaxRadioPhoneNumbers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxRadioPhoneNumbers(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxRadioPhoneNumbers, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().MaxRadioPhoneNumbers(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxPersonalEmailAddresses(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxPersonalEmailAddresses, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().MaxPersonalEmailAddresses());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxPersonalEmailAddresses(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxPersonalEmailAddresses, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().MaxPersonalEmailAddresses(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxWorkEmailAddresses(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxWorkEmailAddresses, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().MaxWorkEmailAddresses());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxWorkEmailAddresses(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxWorkEmailAddresses, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().MaxWorkEmailAddresses(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxOtherEmailAddresses(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxOtherEmailAddresses, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().MaxOtherEmailAddresses());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxOtherEmailAddresses(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxOtherEmailAddresses, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().MaxOtherEmailAddresses(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxHomeAddresses(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxHomeAddresses, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().MaxHomeAddresses());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxHomeAddresses(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxHomeAddresses, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().MaxHomeAddresses(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxWorkAddresses(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxWorkAddresses, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().MaxWorkAddresses());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxWorkAddresses(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxWorkAddresses, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().MaxWorkAddresses(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxOtherAddresses(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxOtherAddresses, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().MaxOtherAddresses());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxOtherAddresses(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxOtherAddresses, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().MaxOtherAddresses(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxBirthdayDates(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxBirthdayDates, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().MaxBirthdayDates());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxBirthdayDates(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxBirthdayDates, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().MaxBirthdayDates(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxAnniversaryDates(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxAnniversaryDates, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().MaxAnniversaryDates());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxAnniversaryDates(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxAnniversaryDates, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().MaxAnniversaryDates(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxOtherDates(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxOtherDates, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().MaxOtherDates());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxOtherDates(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxOtherDates, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().MaxOtherDates(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxOtherRelationships(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxOtherRelationships, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().MaxOtherRelationships());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxOtherRelationships(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxOtherRelationships, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().MaxOtherRelationships(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxSpouseRelationships(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxSpouseRelationships, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().MaxSpouseRelationships());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxSpouseRelationships(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxSpouseRelationships, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().MaxSpouseRelationships(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxPartnerRelationships(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxPartnerRelationships, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().MaxPartnerRelationships());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxPartnerRelationships(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxPartnerRelationships, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().MaxPartnerRelationships(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxSiblingRelationships(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxSiblingRelationships, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().MaxSiblingRelationships());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxSiblingRelationships(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxSiblingRelationships, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().MaxSiblingRelationships(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxParentRelationships(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxParentRelationships, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().MaxParentRelationships());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxParentRelationships(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxParentRelationships, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().MaxParentRelationships(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxChildRelationships(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxChildRelationships, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().MaxChildRelationships());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxChildRelationships(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxChildRelationships, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().MaxChildRelationships(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxJobInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxJobInfo, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().MaxJobInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxJobInfo(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxJobInfo, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().MaxJobInfo(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxWebsites(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxWebsites, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().MaxWebsites());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxWebsites(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxWebsites, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().MaxWebsites(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactListSyncManager> : produce_base<D, Windows::ApplicationModel::Contacts::IContactListSyncManager>
{
    int32_t WINRT_CALL get_Status(Windows::ApplicationModel::Contacts::ContactListSyncStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactListSyncStatus));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactListSyncStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LastSuccessfulSyncTime(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastSuccessfulSyncTime, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().LastSuccessfulSyncTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LastAttemptedSyncTime(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastAttemptedSyncTime, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().LastAttemptedSyncTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SyncAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SyncAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().SyncAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_SyncStatusChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SyncStatusChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::ContactListSyncManager, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().SyncStatusChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::ContactListSyncManager, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SyncStatusChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SyncStatusChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SyncStatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactListSyncManager2> : produce_base<D, Windows::ApplicationModel::Contacts::IContactListSyncManager2>
{
    int32_t WINRT_CALL put_Status(Windows::ApplicationModel::Contacts::ContactListSyncStatus value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(void), Windows::ApplicationModel::Contacts::ContactListSyncStatus const&);
            this->shim().Status(*reinterpret_cast<Windows::ApplicationModel::Contacts::ContactListSyncStatus const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LastSuccessfulSyncTime(Windows::Foundation::DateTime value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastSuccessfulSyncTime, WINRT_WRAP(void), Windows::Foundation::DateTime const&);
            this->shim().LastSuccessfulSyncTime(*reinterpret_cast<Windows::Foundation::DateTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LastAttemptedSyncTime(Windows::Foundation::DateTime value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastAttemptedSyncTime, WINRT_WRAP(void), Windows::Foundation::DateTime const&);
            this->shim().LastAttemptedSyncTime(*reinterpret_cast<Windows::Foundation::DateTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactLocationField> : produce_base<D, Windows::ApplicationModel::Contacts::IContactLocationField>
{
    int32_t WINRT_CALL get_UnstructuredAddress(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnstructuredAddress, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UnstructuredAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Street(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Street, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Street());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_City(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(City, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().City());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Region(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Region, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Region());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Country(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Country, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Country());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PostalCode(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PostalCode, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PostalCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactLocationFieldFactory> : produce_base<D, Windows::ApplicationModel::Contacts::IContactLocationFieldFactory>
{
    int32_t WINRT_CALL CreateLocation_Default(void* unstructuredAddress, void** field) noexcept final
    {
        try
        {
            *field = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateLocation, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactLocationField), hstring const&);
            *field = detach_from<Windows::ApplicationModel::Contacts::ContactLocationField>(this->shim().CreateLocation(*reinterpret_cast<hstring const*>(&unstructuredAddress)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateLocation_Category(void* unstructuredAddress, Windows::ApplicationModel::Contacts::ContactFieldCategory category, void** field) noexcept final
    {
        try
        {
            *field = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateLocation, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactLocationField), hstring const&, Windows::ApplicationModel::Contacts::ContactFieldCategory const&);
            *field = detach_from<Windows::ApplicationModel::Contacts::ContactLocationField>(this->shim().CreateLocation(*reinterpret_cast<hstring const*>(&unstructuredAddress), *reinterpret_cast<Windows::ApplicationModel::Contacts::ContactFieldCategory const*>(&category)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateLocation_All(void* unstructuredAddress, Windows::ApplicationModel::Contacts::ContactFieldCategory category, void* street, void* city, void* region, void* country, void* postalCode, void** field) noexcept final
    {
        try
        {
            *field = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateLocation, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactLocationField), hstring const&, Windows::ApplicationModel::Contacts::ContactFieldCategory const&, hstring const&, hstring const&, hstring const&, hstring const&, hstring const&);
            *field = detach_from<Windows::ApplicationModel::Contacts::ContactLocationField>(this->shim().CreateLocation(*reinterpret_cast<hstring const*>(&unstructuredAddress), *reinterpret_cast<Windows::ApplicationModel::Contacts::ContactFieldCategory const*>(&category), *reinterpret_cast<hstring const*>(&street), *reinterpret_cast<hstring const*>(&city), *reinterpret_cast<hstring const*>(&region), *reinterpret_cast<hstring const*>(&country), *reinterpret_cast<hstring const*>(&postalCode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactManagerForUser> : produce_base<D, Windows::ApplicationModel::Contacts::IContactManagerForUser>
{
    int32_t WINRT_CALL ConvertContactToVCardAsync(void* contact, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConvertContactToVCardAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::RandomAccessStreamReference>), Windows::ApplicationModel::Contacts::Contact const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::RandomAccessStreamReference>>(this->shim().ConvertContactToVCardAsync(*reinterpret_cast<Windows::ApplicationModel::Contacts::Contact const*>(&contact)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConvertContactToVCardAsyncWithMaxBytes(void* contact, uint32_t maxBytes, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConvertContactToVCardAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::RandomAccessStreamReference>), Windows::ApplicationModel::Contacts::Contact const, uint32_t);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::RandomAccessStreamReference>>(this->shim().ConvertContactToVCardAsync(*reinterpret_cast<Windows::ApplicationModel::Contacts::Contact const*>(&contact), maxBytes));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConvertVCardToContactAsync(void* vCard, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConvertVCardToContactAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact>), Windows::Storage::Streams::IRandomAccessStreamReference const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact>>(this->shim().ConvertVCardToContactAsync(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&vCard)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestStoreAsync(Windows::ApplicationModel::Contacts::ContactStoreAccessType accessType, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestStoreAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactStore>), Windows::ApplicationModel::Contacts::ContactStoreAccessType const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactStore>>(this->shim().RequestStoreAsync(*reinterpret_cast<Windows::ApplicationModel::Contacts::ContactStoreAccessType const*>(&accessType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestAnnotationStoreAsync(Windows::ApplicationModel::Contacts::ContactAnnotationStoreAccessType accessType, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAnnotationStoreAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactAnnotationStore>), Windows::ApplicationModel::Contacts::ContactAnnotationStoreAccessType const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactAnnotationStore>>(this->shim().RequestAnnotationStoreAsync(*reinterpret_cast<Windows::ApplicationModel::Contacts::ContactAnnotationStoreAccessType const*>(&accessType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SystemDisplayNameOrder(Windows::ApplicationModel::Contacts::ContactNameOrder* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemDisplayNameOrder, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactNameOrder));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactNameOrder>(this->shim().SystemDisplayNameOrder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SystemDisplayNameOrder(Windows::ApplicationModel::Contacts::ContactNameOrder value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemDisplayNameOrder, WINRT_WRAP(void), Windows::ApplicationModel::Contacts::ContactNameOrder const&);
            this->shim().SystemDisplayNameOrder(*reinterpret_cast<Windows::ApplicationModel::Contacts::ContactNameOrder const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SystemSortOrder(Windows::ApplicationModel::Contacts::ContactNameOrder* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemSortOrder, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactNameOrder));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactNameOrder>(this->shim().SystemSortOrder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SystemSortOrder(Windows::ApplicationModel::Contacts::ContactNameOrder value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemSortOrder, WINRT_WRAP(void), Windows::ApplicationModel::Contacts::ContactNameOrder const&);
            this->shim().SystemSortOrder(*reinterpret_cast<Windows::ApplicationModel::Contacts::ContactNameOrder const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_User(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(User, WINRT_WRAP(Windows::System::User));
            *value = detach_from<Windows::System::User>(this->shim().User());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactManagerForUser2> : produce_base<D, Windows::ApplicationModel::Contacts::IContactManagerForUser2>
{
    int32_t WINRT_CALL ShowFullContactCard(void* contact, void* fullContactCardOptions) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowFullContactCard, WINRT_WRAP(void), Windows::ApplicationModel::Contacts::Contact const&, Windows::ApplicationModel::Contacts::FullContactCardOptions const&);
            this->shim().ShowFullContactCard(*reinterpret_cast<Windows::ApplicationModel::Contacts::Contact const*>(&contact), *reinterpret_cast<Windows::ApplicationModel::Contacts::FullContactCardOptions const*>(&fullContactCardOptions));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactManagerStatics> : produce_base<D, Windows::ApplicationModel::Contacts::IContactManagerStatics>
{
    int32_t WINRT_CALL ShowContactCard(void* contact, Windows::Foundation::Rect selection) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowContactCard, WINRT_WRAP(void), Windows::ApplicationModel::Contacts::Contact const&, Windows::Foundation::Rect const&);
            this->shim().ShowContactCard(*reinterpret_cast<Windows::ApplicationModel::Contacts::Contact const*>(&contact), *reinterpret_cast<Windows::Foundation::Rect const*>(&selection));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowContactCardWithPlacement(void* contact, Windows::Foundation::Rect selection, Windows::UI::Popups::Placement preferredPlacement) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowContactCard, WINRT_WRAP(void), Windows::ApplicationModel::Contacts::Contact const&, Windows::Foundation::Rect const&, Windows::UI::Popups::Placement const&);
            this->shim().ShowContactCard(*reinterpret_cast<Windows::ApplicationModel::Contacts::Contact const*>(&contact), *reinterpret_cast<Windows::Foundation::Rect const*>(&selection), *reinterpret_cast<Windows::UI::Popups::Placement const*>(&preferredPlacement));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowDelayLoadedContactCard(void* contact, Windows::Foundation::Rect selection, Windows::UI::Popups::Placement preferredPlacement, void** dataLoader) noexcept final
    {
        try
        {
            *dataLoader = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowDelayLoadedContactCard, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactCardDelayedDataLoader), Windows::ApplicationModel::Contacts::Contact const&, Windows::Foundation::Rect const&, Windows::UI::Popups::Placement const&);
            *dataLoader = detach_from<Windows::ApplicationModel::Contacts::ContactCardDelayedDataLoader>(this->shim().ShowDelayLoadedContactCard(*reinterpret_cast<Windows::ApplicationModel::Contacts::Contact const*>(&contact), *reinterpret_cast<Windows::Foundation::Rect const*>(&selection), *reinterpret_cast<Windows::UI::Popups::Placement const*>(&preferredPlacement)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactManagerStatics2> : produce_base<D, Windows::ApplicationModel::Contacts::IContactManagerStatics2>
{
    int32_t WINRT_CALL RequestStoreAsync(void** store) noexcept final
    {
        try
        {
            *store = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestStoreAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactStore>));
            *store = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactStore>>(this->shim().RequestStoreAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactManagerStatics3> : produce_base<D, Windows::ApplicationModel::Contacts::IContactManagerStatics3>
{
    int32_t WINRT_CALL ConvertContactToVCardAsync(void* contact, void** vCard) noexcept final
    {
        try
        {
            *vCard = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConvertContactToVCardAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::RandomAccessStreamReference>), Windows::ApplicationModel::Contacts::Contact const);
            *vCard = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::RandomAccessStreamReference>>(this->shim().ConvertContactToVCardAsync(*reinterpret_cast<Windows::ApplicationModel::Contacts::Contact const*>(&contact)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConvertContactToVCardAsyncWithMaxBytes(void* contact, uint32_t maxBytes, void** vCard) noexcept final
    {
        try
        {
            *vCard = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConvertContactToVCardAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::RandomAccessStreamReference>), Windows::ApplicationModel::Contacts::Contact const, uint32_t);
            *vCard = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::RandomAccessStreamReference>>(this->shim().ConvertContactToVCardAsync(*reinterpret_cast<Windows::ApplicationModel::Contacts::Contact const*>(&contact), maxBytes));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConvertVCardToContactAsync(void* vCard, void** contact) noexcept final
    {
        try
        {
            *contact = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConvertVCardToContactAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact>), Windows::Storage::Streams::IRandomAccessStreamReference const);
            *contact = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact>>(this->shim().ConvertVCardToContactAsync(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&vCard)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestStoreAsyncWithAccessType(Windows::ApplicationModel::Contacts::ContactStoreAccessType accessType, void** store) noexcept final
    {
        try
        {
            *store = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestStoreAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactStore>), Windows::ApplicationModel::Contacts::ContactStoreAccessType const);
            *store = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactStore>>(this->shim().RequestStoreAsync(*reinterpret_cast<Windows::ApplicationModel::Contacts::ContactStoreAccessType const*>(&accessType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestAnnotationStoreAsync(Windows::ApplicationModel::Contacts::ContactAnnotationStoreAccessType accessType, void** store) noexcept final
    {
        try
        {
            *store = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAnnotationStoreAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactAnnotationStore>), Windows::ApplicationModel::Contacts::ContactAnnotationStoreAccessType const);
            *store = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactAnnotationStore>>(this->shim().RequestAnnotationStoreAsync(*reinterpret_cast<Windows::ApplicationModel::Contacts::ContactAnnotationStoreAccessType const*>(&accessType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsShowContactCardSupported(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsShowContactCardSupported, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsShowContactCardSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowContactCardWithOptions(void* contact, Windows::Foundation::Rect selection, Windows::UI::Popups::Placement preferredPlacement, void* contactCardOptions) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowContactCard, WINRT_WRAP(void), Windows::ApplicationModel::Contacts::Contact const&, Windows::Foundation::Rect const&, Windows::UI::Popups::Placement const&, Windows::ApplicationModel::Contacts::ContactCardOptions const&);
            this->shim().ShowContactCard(*reinterpret_cast<Windows::ApplicationModel::Contacts::Contact const*>(&contact), *reinterpret_cast<Windows::Foundation::Rect const*>(&selection), *reinterpret_cast<Windows::UI::Popups::Placement const*>(&preferredPlacement), *reinterpret_cast<Windows::ApplicationModel::Contacts::ContactCardOptions const*>(&contactCardOptions));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsShowDelayLoadedContactCardSupported(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsShowDelayLoadedContactCardSupported, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsShowDelayLoadedContactCardSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowDelayLoadedContactCardWithOptions(void* contact, Windows::Foundation::Rect selection, Windows::UI::Popups::Placement preferredPlacement, void* contactCardOptions, void** dataLoader) noexcept final
    {
        try
        {
            *dataLoader = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowDelayLoadedContactCard, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactCardDelayedDataLoader), Windows::ApplicationModel::Contacts::Contact const&, Windows::Foundation::Rect const&, Windows::UI::Popups::Placement const&, Windows::ApplicationModel::Contacts::ContactCardOptions const&);
            *dataLoader = detach_from<Windows::ApplicationModel::Contacts::ContactCardDelayedDataLoader>(this->shim().ShowDelayLoadedContactCard(*reinterpret_cast<Windows::ApplicationModel::Contacts::Contact const*>(&contact), *reinterpret_cast<Windows::Foundation::Rect const*>(&selection), *reinterpret_cast<Windows::UI::Popups::Placement const*>(&preferredPlacement), *reinterpret_cast<Windows::ApplicationModel::Contacts::ContactCardOptions const*>(&contactCardOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowFullContactCard(void* contact, void* fullContactCardOptions) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowFullContactCard, WINRT_WRAP(void), Windows::ApplicationModel::Contacts::Contact const&, Windows::ApplicationModel::Contacts::FullContactCardOptions const&);
            this->shim().ShowFullContactCard(*reinterpret_cast<Windows::ApplicationModel::Contacts::Contact const*>(&contact), *reinterpret_cast<Windows::ApplicationModel::Contacts::FullContactCardOptions const*>(&fullContactCardOptions));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SystemDisplayNameOrder(Windows::ApplicationModel::Contacts::ContactNameOrder* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemDisplayNameOrder, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactNameOrder));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactNameOrder>(this->shim().SystemDisplayNameOrder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SystemDisplayNameOrder(Windows::ApplicationModel::Contacts::ContactNameOrder value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemDisplayNameOrder, WINRT_WRAP(void), Windows::ApplicationModel::Contacts::ContactNameOrder const&);
            this->shim().SystemDisplayNameOrder(*reinterpret_cast<Windows::ApplicationModel::Contacts::ContactNameOrder const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SystemSortOrder(Windows::ApplicationModel::Contacts::ContactNameOrder* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemSortOrder, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactNameOrder));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactNameOrder>(this->shim().SystemSortOrder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SystemSortOrder(Windows::ApplicationModel::Contacts::ContactNameOrder value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemSortOrder, WINRT_WRAP(void), Windows::ApplicationModel::Contacts::ContactNameOrder const&);
            this->shim().SystemSortOrder(*reinterpret_cast<Windows::ApplicationModel::Contacts::ContactNameOrder const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactManagerStatics4> : produce_base<D, Windows::ApplicationModel::Contacts::IContactManagerStatics4>
{
    int32_t WINRT_CALL GetForUser(void* user, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForUser, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactManagerForUser), Windows::System::User const&);
            *result = detach_from<Windows::ApplicationModel::Contacts::ContactManagerForUser>(this->shim().GetForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactManagerStatics5> : produce_base<D, Windows::ApplicationModel::Contacts::IContactManagerStatics5>
{
    int32_t WINRT_CALL IsShowFullContactCardSupportedAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsShowFullContactCardSupportedAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().IsShowFullContactCardSupportedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IncludeMiddleNameInSystemDisplayAndSort(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IncludeMiddleNameInSystemDisplayAndSort, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IncludeMiddleNameInSystemDisplayAndSort());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IncludeMiddleNameInSystemDisplayAndSort(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IncludeMiddleNameInSystemDisplayAndSort, WINRT_WRAP(void), bool);
            this->shim().IncludeMiddleNameInSystemDisplayAndSort(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactMatchReason> : produce_base<D, Windows::ApplicationModel::Contacts::IContactMatchReason>
{
    int32_t WINRT_CALL get_Field(Windows::ApplicationModel::Contacts::ContactMatchReasonKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Field, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactMatchReasonKind));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactMatchReasonKind>(this->shim().Field());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Segments(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Segments, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Data::Text::TextSegment>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Data::Text::TextSegment>>(this->shim().Segments());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactName> : produce_base<D, Windows::ApplicationModel::Contacts::IContactName>
{
    int32_t WINRT_CALL get_FirstName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FirstName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FirstName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FirstName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FirstName, WINRT_WRAP(void), hstring const&);
            this->shim().FirstName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LastName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().LastName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LastName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastName, WINRT_WRAP(void), hstring const&);
            this->shim().LastName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MiddleName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MiddleName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MiddleName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MiddleName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MiddleName, WINRT_WRAP(void), hstring const&);
            this->shim().MiddleName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_YomiGivenName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(YomiGivenName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().YomiGivenName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_YomiGivenName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(YomiGivenName, WINRT_WRAP(void), hstring const&);
            this->shim().YomiGivenName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_YomiFamilyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(YomiFamilyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().YomiFamilyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_YomiFamilyName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(YomiFamilyName, WINRT_WRAP(void), hstring const&);
            this->shim().YomiFamilyName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HonorificNameSuffix(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HonorificNameSuffix, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().HonorificNameSuffix());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_HonorificNameSuffix(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HonorificNameSuffix, WINRT_WRAP(void), hstring const&);
            this->shim().HonorificNameSuffix(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HonorificNamePrefix(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HonorificNamePrefix, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().HonorificNamePrefix());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_HonorificNamePrefix(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HonorificNamePrefix, WINRT_WRAP(void), hstring const&);
            this->shim().HonorificNamePrefix(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_YomiDisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(YomiDisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().YomiDisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactPanel> : produce_base<D, Windows::ApplicationModel::Contacts::IContactPanel>
{
    int32_t WINRT_CALL ClosePanel() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClosePanel, WINRT_WRAP(void));
            this->shim().ClosePanel();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HeaderColor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeaderColor, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().HeaderColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_HeaderColor(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeaderColor, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().HeaderColor(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_LaunchFullAppRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchFullAppRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::ContactPanel, Windows::ApplicationModel::Contacts::ContactPanelLaunchFullAppRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().LaunchFullAppRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::ContactPanel, Windows::ApplicationModel::Contacts::ContactPanelLaunchFullAppRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_LaunchFullAppRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(LaunchFullAppRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().LaunchFullAppRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Closing(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Closing, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::ContactPanel, Windows::ApplicationModel::Contacts::ContactPanelClosingEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Closing(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::ContactPanel, Windows::ApplicationModel::Contacts::ContactPanelClosingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Closing(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Closing, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Closing(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactPanelClosingEventArgs> : produce_base<D, Windows::ApplicationModel::Contacts::IContactPanelClosingEventArgs>
{
    int32_t WINRT_CALL GetDeferral(void** deferral) noexcept final
    {
        try
        {
            *deferral = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Foundation::Deferral));
            *deferral = detach_from<Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactPanelLaunchFullAppRequestedEventArgs> : produce_base<D, Windows::ApplicationModel::Contacts::IContactPanelLaunchFullAppRequestedEventArgs>
{
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
struct produce<D, Windows::ApplicationModel::Contacts::IContactPhone> : produce_base<D, Windows::ApplicationModel::Contacts::IContactPhone>
{
    int32_t WINRT_CALL get_Number(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Number, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Number());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Number(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Number, WINRT_WRAP(void), hstring const&);
            this->shim().Number(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Kind(Windows::ApplicationModel::Contacts::ContactPhoneKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactPhoneKind));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactPhoneKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Kind(Windows::ApplicationModel::Contacts::ContactPhoneKind value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(void), Windows::ApplicationModel::Contacts::ContactPhoneKind const&);
            this->shim().Kind(*reinterpret_cast<Windows::ApplicationModel::Contacts::ContactPhoneKind const*>(&value));
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

    int32_t WINRT_CALL put_Description(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(void), hstring const&);
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactPicker> : produce_base<D, Windows::ApplicationModel::Contacts::IContactPicker>
{
    int32_t WINRT_CALL get_CommitButtonText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CommitButtonText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CommitButtonText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CommitButtonText(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CommitButtonText, WINRT_WRAP(void), hstring const&);
            this->shim().CommitButtonText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectionMode(Windows::ApplicationModel::Contacts::ContactSelectionMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectionMode, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactSelectionMode));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactSelectionMode>(this->shim().SelectionMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SelectionMode(Windows::ApplicationModel::Contacts::ContactSelectionMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectionMode, WINRT_WRAP(void), Windows::ApplicationModel::Contacts::ContactSelectionMode const&);
            this->shim().SelectionMode(*reinterpret_cast<Windows::ApplicationModel::Contacts::ContactSelectionMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DesiredFields(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredFields, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().DesiredFields());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PickSingleContactAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PickSingleContactAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactInformation>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactInformation>>(this->shim().PickSingleContactAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PickMultipleContactsAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PickMultipleContactsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactInformation>>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactInformation>>>(this->shim().PickMultipleContactsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactPicker2> : produce_base<D, Windows::ApplicationModel::Contacts::IContactPicker2>
{
    int32_t WINRT_CALL get_DesiredFieldsWithContactFieldType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredFieldsWithContactFieldType, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactFieldType>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactFieldType>>(this->shim().DesiredFieldsWithContactFieldType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PickContactAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PickContactAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact>>(this->shim().PickContactAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PickContactsAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PickContactsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::Contact>>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::Contact>>>(this->shim().PickContactsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactPicker3> : produce_base<D, Windows::ApplicationModel::Contacts::IContactPicker3>
{
    int32_t WINRT_CALL get_User(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(User, WINRT_WRAP(Windows::System::User));
            *value = detach_from<Windows::System::User>(this->shim().User());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactPickerStatics> : produce_base<D, Windows::ApplicationModel::Contacts::IContactPickerStatics>
{
    int32_t WINRT_CALL CreateForUser(void* user, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateForUser, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactPicker), Windows::System::User const&);
            *result = detach_from<Windows::ApplicationModel::Contacts::ContactPicker>(this->shim().CreateForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsSupportedAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSupportedAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().IsSupportedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactQueryOptions> : produce_base<D, Windows::ApplicationModel::Contacts::IContactQueryOptions>
{
    int32_t WINRT_CALL get_TextSearch(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TextSearch, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactQueryTextSearch));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactQueryTextSearch>(this->shim().TextSearch());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContactListIds(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContactListIds, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().ContactListIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IncludeContactsFromHiddenLists(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IncludeContactsFromHiddenLists, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IncludeContactsFromHiddenLists());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IncludeContactsFromHiddenLists(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IncludeContactsFromHiddenLists, WINRT_WRAP(void), bool);
            this->shim().IncludeContactsFromHiddenLists(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DesiredFields(Windows::ApplicationModel::Contacts::ContactQueryDesiredFields* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredFields, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactQueryDesiredFields));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactQueryDesiredFields>(this->shim().DesiredFields());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DesiredFields(Windows::ApplicationModel::Contacts::ContactQueryDesiredFields value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredFields, WINRT_WRAP(void), Windows::ApplicationModel::Contacts::ContactQueryDesiredFields const&);
            this->shim().DesiredFields(*reinterpret_cast<Windows::ApplicationModel::Contacts::ContactQueryDesiredFields const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DesiredOperations(Windows::ApplicationModel::Contacts::ContactAnnotationOperations* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredOperations, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactAnnotationOperations));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactAnnotationOperations>(this->shim().DesiredOperations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DesiredOperations(Windows::ApplicationModel::Contacts::ContactAnnotationOperations value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredOperations, WINRT_WRAP(void), Windows::ApplicationModel::Contacts::ContactAnnotationOperations const&);
            this->shim().DesiredOperations(*reinterpret_cast<Windows::ApplicationModel::Contacts::ContactAnnotationOperations const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AnnotationListIds(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AnnotationListIds, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().AnnotationListIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactQueryOptionsFactory> : produce_base<D, Windows::ApplicationModel::Contacts::IContactQueryOptionsFactory>
{
    int32_t WINRT_CALL CreateWithText(void* text, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithText, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactQueryOptions), hstring const&);
            *result = detach_from<Windows::ApplicationModel::Contacts::ContactQueryOptions>(this->shim().CreateWithText(*reinterpret_cast<hstring const*>(&text)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithTextAndFields(void* text, Windows::ApplicationModel::Contacts::ContactQuerySearchFields fields, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithTextAndFields, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactQueryOptions), hstring const&, Windows::ApplicationModel::Contacts::ContactQuerySearchFields const&);
            *result = detach_from<Windows::ApplicationModel::Contacts::ContactQueryOptions>(this->shim().CreateWithTextAndFields(*reinterpret_cast<hstring const*>(&text), *reinterpret_cast<Windows::ApplicationModel::Contacts::ContactQuerySearchFields const*>(&fields)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactQueryTextSearch> : produce_base<D, Windows::ApplicationModel::Contacts::IContactQueryTextSearch>
{
    int32_t WINRT_CALL get_Fields(Windows::ApplicationModel::Contacts::ContactQuerySearchFields* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Fields, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactQuerySearchFields));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactQuerySearchFields>(this->shim().Fields());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Fields(Windows::ApplicationModel::Contacts::ContactQuerySearchFields value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Fields, WINRT_WRAP(void), Windows::ApplicationModel::Contacts::ContactQuerySearchFields const&);
            this->shim().Fields(*reinterpret_cast<Windows::ApplicationModel::Contacts::ContactQuerySearchFields const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL get_SearchScope(Windows::ApplicationModel::Contacts::ContactQuerySearchScope* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SearchScope, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactQuerySearchScope));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactQuerySearchScope>(this->shim().SearchScope());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SearchScope(Windows::ApplicationModel::Contacts::ContactQuerySearchScope value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SearchScope, WINRT_WRAP(void), Windows::ApplicationModel::Contacts::ContactQuerySearchScope const&);
            this->shim().SearchScope(*reinterpret_cast<Windows::ApplicationModel::Contacts::ContactQuerySearchScope const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactReader> : produce_base<D, Windows::ApplicationModel::Contacts::IContactReader>
{
    int32_t WINRT_CALL ReadBatchAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadBatchAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactBatch>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactBatch>>(this->shim().ReadBatchAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetMatchingPropertiesWithMatchReason(void* contact, void** ppRetVal) noexcept final
    {
        try
        {
            *ppRetVal = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetMatchingPropertiesWithMatchReason, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactMatchReason>), Windows::ApplicationModel::Contacts::Contact const&);
            *ppRetVal = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactMatchReason>>(this->shim().GetMatchingPropertiesWithMatchReason(*reinterpret_cast<Windows::ApplicationModel::Contacts::Contact const*>(&contact)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactSignificantOther> : produce_base<D, Windows::ApplicationModel::Contacts::IContactSignificantOther>
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

    int32_t WINRT_CALL put_Name(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(void), hstring const&);
            this->shim().Name(*reinterpret_cast<hstring const*>(&value));
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

    int32_t WINRT_CALL put_Description(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(void), hstring const&);
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactSignificantOther2> : produce_base<D, Windows::ApplicationModel::Contacts::IContactSignificantOther2>
{
    int32_t WINRT_CALL get_Relationship(Windows::ApplicationModel::Contacts::ContactRelationship* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Relationship, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactRelationship));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactRelationship>(this->shim().Relationship());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Relationship(Windows::ApplicationModel::Contacts::ContactRelationship value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Relationship, WINRT_WRAP(void), Windows::ApplicationModel::Contacts::ContactRelationship const&);
            this->shim().Relationship(*reinterpret_cast<Windows::ApplicationModel::Contacts::ContactRelationship const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactStore> : produce_base<D, Windows::ApplicationModel::Contacts::IContactStore>
{
    int32_t WINRT_CALL FindContactsAsync(void** contacts) noexcept final
    {
        try
        {
            *contacts = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindContactsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::Contact>>));
            *contacts = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::Contact>>>(this->shim().FindContactsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindContactsWithSearchTextAsync(void* searchText, void** contacts) noexcept final
    {
        try
        {
            *contacts = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindContactsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::Contact>>), hstring const);
            *contacts = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::Contact>>>(this->shim().FindContactsAsync(*reinterpret_cast<hstring const*>(&searchText)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetContactAsync(void* contactId, void** contacts) noexcept final
    {
        try
        {
            *contacts = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetContactAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact>), hstring const);
            *contacts = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact>>(this->shim().GetContactAsync(*reinterpret_cast<hstring const*>(&contactId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactStore2> : produce_base<D, Windows::ApplicationModel::Contacts::IContactStore2>
{
    int32_t WINRT_CALL get_ChangeTracker(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChangeTracker, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactChangeTracker));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactChangeTracker>(this->shim().ChangeTracker());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ContactChanged(void* value, winrt::event_token* returnValue) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContactChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::ContactStore, Windows::ApplicationModel::Contacts::ContactChangedEventArgs> const&);
            *returnValue = detach_from<winrt::event_token>(this->shim().ContactChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::ContactStore, Windows::ApplicationModel::Contacts::ContactChangedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ContactChanged(winrt::event_token value) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ContactChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ContactChanged(*reinterpret_cast<winrt::event_token const*>(&value));
        return 0;
    }

    int32_t WINRT_CALL get_AggregateContactManager(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AggregateContactManager, WINRT_WRAP(Windows::ApplicationModel::Contacts::AggregateContactManager));
            *value = detach_from<Windows::ApplicationModel::Contacts::AggregateContactManager>(this->shim().AggregateContactManager());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindContactListsAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindContactListsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactList>>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactList>>>(this->shim().FindContactListsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetContactListAsync(void* contactListId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetContactListAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactList>), hstring const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactList>>(this->shim().GetContactListAsync(*reinterpret_cast<hstring const*>(&contactListId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateContactListAsync(void* displayName, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateContactListAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactList>), hstring const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactList>>(this->shim().CreateContactListAsync(*reinterpret_cast<hstring const*>(&displayName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetMeContactAsync(void** meContact) noexcept final
    {
        try
        {
            *meContact = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetMeContactAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact>));
            *meContact = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact>>(this->shim().GetMeContactAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetContactReader(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetContactReader, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactReader));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactReader>(this->shim().GetContactReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetContactReaderWithOptions(void* options, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetContactReader, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactReader), Windows::ApplicationModel::Contacts::ContactQueryOptions const&);
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactReader>(this->shim().GetContactReader(*reinterpret_cast<Windows::ApplicationModel::Contacts::ContactQueryOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateContactListInAccountAsync(void* displayName, void* userDataAccountId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateContactListAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactList>), hstring const, hstring const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactList>>(this->shim().CreateContactListAsync(*reinterpret_cast<hstring const*>(&displayName), *reinterpret_cast<hstring const*>(&userDataAccountId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactStore3> : produce_base<D, Windows::ApplicationModel::Contacts::IContactStore3>
{
    int32_t WINRT_CALL GetChangeTracker(void* identity, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetChangeTracker, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactChangeTracker), hstring const&);
            *result = detach_from<Windows::ApplicationModel::Contacts::ContactChangeTracker>(this->shim().GetChangeTracker(*reinterpret_cast<hstring const*>(&identity)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactStoreNotificationTriggerDetails> : produce_base<D, Windows::ApplicationModel::Contacts::IContactStoreNotificationTriggerDetails>
{};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactWebsite> : produce_base<D, Windows::ApplicationModel::Contacts::IContactWebsite>
{
    int32_t WINRT_CALL get_Uri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Uri(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uri, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().Uri(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
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

    int32_t WINRT_CALL put_Description(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(void), hstring const&);
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IContactWebsite2> : produce_base<D, Windows::ApplicationModel::Contacts::IContactWebsite2>
{
    int32_t WINRT_CALL get_RawValue(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RawValue, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RawValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RawValue(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RawValue, WINRT_WRAP(void), hstring const&);
            this->shim().RawValue(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IFullContactCardOptions> : produce_base<D, Windows::ApplicationModel::Contacts::IFullContactCardOptions>
{
    int32_t WINRT_CALL get_DesiredRemainingView(Windows::UI::ViewManagement::ViewSizePreference* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredRemainingView, WINRT_WRAP(Windows::UI::ViewManagement::ViewSizePreference));
            *value = detach_from<Windows::UI::ViewManagement::ViewSizePreference>(this->shim().DesiredRemainingView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DesiredRemainingView(Windows::UI::ViewManagement::ViewSizePreference value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredRemainingView, WINRT_WRAP(void), Windows::UI::ViewManagement::ViewSizePreference const&);
            this->shim().DesiredRemainingView(*reinterpret_cast<Windows::UI::ViewManagement::ViewSizePreference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IKnownContactFieldStatics> : produce_base<D, Windows::ApplicationModel::Contacts::IKnownContactFieldStatics>
{
    int32_t WINRT_CALL get_Email(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Email, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Email());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PhoneNumber(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhoneNumber, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PhoneNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Location(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Location, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Location());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InstantMessage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InstantMessage, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().InstantMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConvertNameToType(void* name, Windows::ApplicationModel::Contacts::ContactFieldType* type) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConvertNameToType, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactFieldType), hstring const&);
            *type = detach_from<Windows::ApplicationModel::Contacts::ContactFieldType>(this->shim().ConvertNameToType(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConvertTypeToName(Windows::ApplicationModel::Contacts::ContactFieldType type, void** name) noexcept final
    {
        try
        {
            *name = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConvertTypeToName, WINRT_WRAP(hstring), Windows::ApplicationModel::Contacts::ContactFieldType const&);
            *name = detach_from<hstring>(this->shim().ConvertTypeToName(*reinterpret_cast<Windows::ApplicationModel::Contacts::ContactFieldType const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IPinnedContactIdsQueryResult> : produce_base<D, Windows::ApplicationModel::Contacts::IPinnedContactIdsQueryResult>
{
    int32_t WINRT_CALL get_ContactIds(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContactIds, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().ContactIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IPinnedContactManager> : produce_base<D, Windows::ApplicationModel::Contacts::IPinnedContactManager>
{
    int32_t WINRT_CALL get_User(void** user) noexcept final
    {
        try
        {
            *user = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(User, WINRT_WRAP(Windows::System::User));
            *user = detach_from<Windows::System::User>(this->shim().User());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsPinSurfaceSupported(Windows::ApplicationModel::Contacts::PinnedContactSurface surface, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPinSurfaceSupported, WINRT_WRAP(bool), Windows::ApplicationModel::Contacts::PinnedContactSurface const&);
            *result = detach_from<bool>(this->shim().IsPinSurfaceSupported(*reinterpret_cast<Windows::ApplicationModel::Contacts::PinnedContactSurface const*>(&surface)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsContactPinned(void* contact, Windows::ApplicationModel::Contacts::PinnedContactSurface surface, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsContactPinned, WINRT_WRAP(bool), Windows::ApplicationModel::Contacts::Contact const&, Windows::ApplicationModel::Contacts::PinnedContactSurface const&);
            *result = detach_from<bool>(this->shim().IsContactPinned(*reinterpret_cast<Windows::ApplicationModel::Contacts::Contact const*>(&contact), *reinterpret_cast<Windows::ApplicationModel::Contacts::PinnedContactSurface const*>(&surface)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestPinContactAsync(void* contact, Windows::ApplicationModel::Contacts::PinnedContactSurface surface, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestPinContactAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::ApplicationModel::Contacts::Contact const, Windows::ApplicationModel::Contacts::PinnedContactSurface const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestPinContactAsync(*reinterpret_cast<Windows::ApplicationModel::Contacts::Contact const*>(&contact), *reinterpret_cast<Windows::ApplicationModel::Contacts::PinnedContactSurface const*>(&surface)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestPinContactsAsync(void* contacts, Windows::ApplicationModel::Contacts::PinnedContactSurface surface, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestPinContactsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Contacts::Contact> const, Windows::ApplicationModel::Contacts::PinnedContactSurface const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestPinContactsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Contacts::Contact> const*>(&contacts), *reinterpret_cast<Windows::ApplicationModel::Contacts::PinnedContactSurface const*>(&surface)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestUnpinContactAsync(void* contact, Windows::ApplicationModel::Contacts::PinnedContactSurface surface, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestUnpinContactAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::ApplicationModel::Contacts::Contact const, Windows::ApplicationModel::Contacts::PinnedContactSurface const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestUnpinContactAsync(*reinterpret_cast<Windows::ApplicationModel::Contacts::Contact const*>(&contact), *reinterpret_cast<Windows::ApplicationModel::Contacts::PinnedContactSurface const*>(&surface)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SignalContactActivity(void* contact) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SignalContactActivity, WINRT_WRAP(void), Windows::ApplicationModel::Contacts::Contact const&);
            this->shim().SignalContactActivity(*reinterpret_cast<Windows::ApplicationModel::Contacts::Contact const*>(&contact));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPinnedContactIdsAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPinnedContactIdsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::PinnedContactIdsQueryResult>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::PinnedContactIdsQueryResult>>(this->shim().GetPinnedContactIdsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::IPinnedContactManagerStatics> : produce_base<D, Windows::ApplicationModel::Contacts::IPinnedContactManagerStatics>
{
    int32_t WINRT_CALL GetDefault(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::ApplicationModel::Contacts::PinnedContactManager));
            *result = detach_from<Windows::ApplicationModel::Contacts::PinnedContactManager>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetForUser(void* user, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForUser, WINRT_WRAP(Windows::ApplicationModel::Contacts::PinnedContactManager), Windows::System::User const&);
            *result = detach_from<Windows::ApplicationModel::Contacts::PinnedContactManager>(this->shim().GetForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Contacts {

inline Contact::Contact() :
    Contact(impl::call_factory<Contact>([](auto&& f) { return f.template ActivateInstance<Contact>(); }))
{}

inline ContactAddress::ContactAddress() :
    ContactAddress(impl::call_factory<ContactAddress>([](auto&& f) { return f.template ActivateInstance<ContactAddress>(); }))
{}

inline ContactAnnotation::ContactAnnotation() :
    ContactAnnotation(impl::call_factory<ContactAnnotation>([](auto&& f) { return f.template ActivateInstance<ContactAnnotation>(); }))
{}

inline ContactCardOptions::ContactCardOptions() :
    ContactCardOptions(impl::call_factory<ContactCardOptions>([](auto&& f) { return f.template ActivateInstance<ContactCardOptions>(); }))
{}

inline ContactConnectedServiceAccount::ContactConnectedServiceAccount() :
    ContactConnectedServiceAccount(impl::call_factory<ContactConnectedServiceAccount>([](auto&& f) { return f.template ActivateInstance<ContactConnectedServiceAccount>(); }))
{}

inline ContactDate::ContactDate() :
    ContactDate(impl::call_factory<ContactDate>([](auto&& f) { return f.template ActivateInstance<ContactDate>(); }))
{}

inline ContactEmail::ContactEmail() :
    ContactEmail(impl::call_factory<ContactEmail>([](auto&& f) { return f.template ActivateInstance<ContactEmail>(); }))
{}

inline ContactField::ContactField(param::hstring const& value, Windows::ApplicationModel::Contacts::ContactFieldType const& type) :
    ContactField(impl::call_factory<ContactField, Windows::ApplicationModel::Contacts::IContactFieldFactory>([&](auto&& f) { return f.CreateField(value, type); }))
{}

inline ContactField::ContactField(param::hstring const& value, Windows::ApplicationModel::Contacts::ContactFieldType const& type, Windows::ApplicationModel::Contacts::ContactFieldCategory const& category) :
    ContactField(impl::call_factory<ContactField, Windows::ApplicationModel::Contacts::IContactFieldFactory>([&](auto&& f) { return f.CreateField(value, type, category); }))
{}

inline ContactField::ContactField(param::hstring const& name, param::hstring const& value, Windows::ApplicationModel::Contacts::ContactFieldType const& type, Windows::ApplicationModel::Contacts::ContactFieldCategory const& category) :
    ContactField(impl::call_factory<ContactField, Windows::ApplicationModel::Contacts::IContactFieldFactory>([&](auto&& f) { return f.CreateField(name, value, type, category); }))
{}

inline ContactFieldFactory::ContactFieldFactory() :
    ContactFieldFactory(impl::call_factory<ContactFieldFactory>([](auto&& f) { return f.template ActivateInstance<ContactFieldFactory>(); }))
{}

inline ContactInstantMessageField::ContactInstantMessageField(param::hstring const& userName) :
    ContactInstantMessageField(impl::call_factory<ContactInstantMessageField, Windows::ApplicationModel::Contacts::IContactInstantMessageFieldFactory>([&](auto&& f) { return f.CreateInstantMessage(userName); }))
{}

inline ContactInstantMessageField::ContactInstantMessageField(param::hstring const& userName, Windows::ApplicationModel::Contacts::ContactFieldCategory const& category) :
    ContactInstantMessageField(impl::call_factory<ContactInstantMessageField, Windows::ApplicationModel::Contacts::IContactInstantMessageFieldFactory>([&](auto&& f) { return f.CreateInstantMessage(userName, category); }))
{}

inline ContactInstantMessageField::ContactInstantMessageField(param::hstring const& userName, Windows::ApplicationModel::Contacts::ContactFieldCategory const& category, param::hstring const& service, param::hstring const& displayText, Windows::Foundation::Uri const& verb) :
    ContactInstantMessageField(impl::call_factory<ContactInstantMessageField, Windows::ApplicationModel::Contacts::IContactInstantMessageFieldFactory>([&](auto&& f) { return f.CreateInstantMessage(userName, category, service, displayText, verb); }))
{}

inline ContactJobInfo::ContactJobInfo() :
    ContactJobInfo(impl::call_factory<ContactJobInfo>([](auto&& f) { return f.template ActivateInstance<ContactJobInfo>(); }))
{}

inline hstring ContactLaunchActionVerbs::Call()
{
    return impl::call_factory<ContactLaunchActionVerbs, Windows::ApplicationModel::Contacts::IContactLaunchActionVerbsStatics>([&](auto&& f) { return f.Call(); });
}

inline hstring ContactLaunchActionVerbs::Message()
{
    return impl::call_factory<ContactLaunchActionVerbs, Windows::ApplicationModel::Contacts::IContactLaunchActionVerbsStatics>([&](auto&& f) { return f.Message(); });
}

inline hstring ContactLaunchActionVerbs::Map()
{
    return impl::call_factory<ContactLaunchActionVerbs, Windows::ApplicationModel::Contacts::IContactLaunchActionVerbsStatics>([&](auto&& f) { return f.Map(); });
}

inline hstring ContactLaunchActionVerbs::Post()
{
    return impl::call_factory<ContactLaunchActionVerbs, Windows::ApplicationModel::Contacts::IContactLaunchActionVerbsStatics>([&](auto&& f) { return f.Post(); });
}

inline hstring ContactLaunchActionVerbs::VideoCall()
{
    return impl::call_factory<ContactLaunchActionVerbs, Windows::ApplicationModel::Contacts::IContactLaunchActionVerbsStatics>([&](auto&& f) { return f.VideoCall(); });
}

inline ContactLocationField::ContactLocationField(param::hstring const& unstructuredAddress) :
    ContactLocationField(impl::call_factory<ContactLocationField, Windows::ApplicationModel::Contacts::IContactLocationFieldFactory>([&](auto&& f) { return f.CreateLocation(unstructuredAddress); }))
{}

inline ContactLocationField::ContactLocationField(param::hstring const& unstructuredAddress, Windows::ApplicationModel::Contacts::ContactFieldCategory const& category) :
    ContactLocationField(impl::call_factory<ContactLocationField, Windows::ApplicationModel::Contacts::IContactLocationFieldFactory>([&](auto&& f) { return f.CreateLocation(unstructuredAddress, category); }))
{}

inline ContactLocationField::ContactLocationField(param::hstring const& unstructuredAddress, Windows::ApplicationModel::Contacts::ContactFieldCategory const& category, param::hstring const& street, param::hstring const& city, param::hstring const& region, param::hstring const& country, param::hstring const& postalCode) :
    ContactLocationField(impl::call_factory<ContactLocationField, Windows::ApplicationModel::Contacts::IContactLocationFieldFactory>([&](auto&& f) { return f.CreateLocation(unstructuredAddress, category, street, city, region, country, postalCode); }))
{}

inline void ContactManager::ShowContactCard(Windows::ApplicationModel::Contacts::Contact const& contact, Windows::Foundation::Rect const& selection)
{
    impl::call_factory<ContactManager, Windows::ApplicationModel::Contacts::IContactManagerStatics>([&](auto&& f) { return f.ShowContactCard(contact, selection); });
}

inline void ContactManager::ShowContactCard(Windows::ApplicationModel::Contacts::Contact const& contact, Windows::Foundation::Rect const& selection, Windows::UI::Popups::Placement const& preferredPlacement)
{
    impl::call_factory<ContactManager, Windows::ApplicationModel::Contacts::IContactManagerStatics>([&](auto&& f) { return f.ShowContactCard(contact, selection, preferredPlacement); });
}

inline Windows::ApplicationModel::Contacts::ContactCardDelayedDataLoader ContactManager::ShowDelayLoadedContactCard(Windows::ApplicationModel::Contacts::Contact const& contact, Windows::Foundation::Rect const& selection, Windows::UI::Popups::Placement const& preferredPlacement)
{
    return impl::call_factory<ContactManager, Windows::ApplicationModel::Contacts::IContactManagerStatics>([&](auto&& f) { return f.ShowDelayLoadedContactCard(contact, selection, preferredPlacement); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactStore> ContactManager::RequestStoreAsync()
{
    return impl::call_factory<ContactManager, Windows::ApplicationModel::Contacts::IContactManagerStatics2>([&](auto&& f) { return f.RequestStoreAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::RandomAccessStreamReference> ContactManager::ConvertContactToVCardAsync(Windows::ApplicationModel::Contacts::Contact const& contact)
{
    return impl::call_factory<ContactManager, Windows::ApplicationModel::Contacts::IContactManagerStatics3>([&](auto&& f) { return f.ConvertContactToVCardAsync(contact); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::RandomAccessStreamReference> ContactManager::ConvertContactToVCardAsync(Windows::ApplicationModel::Contacts::Contact const& contact, uint32_t maxBytes)
{
    return impl::call_factory<ContactManager, Windows::ApplicationModel::Contacts::IContactManagerStatics3>([&](auto&& f) { return f.ConvertContactToVCardAsync(contact, maxBytes); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::Contact> ContactManager::ConvertVCardToContactAsync(Windows::Storage::Streams::IRandomAccessStreamReference const& vCard)
{
    return impl::call_factory<ContactManager, Windows::ApplicationModel::Contacts::IContactManagerStatics3>([&](auto&& f) { return f.ConvertVCardToContactAsync(vCard); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactStore> ContactManager::RequestStoreAsync(Windows::ApplicationModel::Contacts::ContactStoreAccessType const& accessType)
{
    return impl::call_factory<ContactManager, Windows::ApplicationModel::Contacts::IContactManagerStatics3>([&](auto&& f) { return f.RequestStoreAsync(accessType); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Contacts::ContactAnnotationStore> ContactManager::RequestAnnotationStoreAsync(Windows::ApplicationModel::Contacts::ContactAnnotationStoreAccessType const& accessType)
{
    return impl::call_factory<ContactManager, Windows::ApplicationModel::Contacts::IContactManagerStatics3>([&](auto&& f) { return f.RequestAnnotationStoreAsync(accessType); });
}

inline bool ContactManager::IsShowContactCardSupported()
{
    return impl::call_factory<ContactManager, Windows::ApplicationModel::Contacts::IContactManagerStatics3>([&](auto&& f) { return f.IsShowContactCardSupported(); });
}

inline void ContactManager::ShowContactCard(Windows::ApplicationModel::Contacts::Contact const& contact, Windows::Foundation::Rect const& selection, Windows::UI::Popups::Placement const& preferredPlacement, Windows::ApplicationModel::Contacts::ContactCardOptions const& contactCardOptions)
{
    impl::call_factory<ContactManager, Windows::ApplicationModel::Contacts::IContactManagerStatics3>([&](auto&& f) { return f.ShowContactCard(contact, selection, preferredPlacement, contactCardOptions); });
}

inline bool ContactManager::IsShowDelayLoadedContactCardSupported()
{
    return impl::call_factory<ContactManager, Windows::ApplicationModel::Contacts::IContactManagerStatics3>([&](auto&& f) { return f.IsShowDelayLoadedContactCardSupported(); });
}

inline Windows::ApplicationModel::Contacts::ContactCardDelayedDataLoader ContactManager::ShowDelayLoadedContactCard(Windows::ApplicationModel::Contacts::Contact const& contact, Windows::Foundation::Rect const& selection, Windows::UI::Popups::Placement const& preferredPlacement, Windows::ApplicationModel::Contacts::ContactCardOptions const& contactCardOptions)
{
    return impl::call_factory<ContactManager, Windows::ApplicationModel::Contacts::IContactManagerStatics3>([&](auto&& f) { return f.ShowDelayLoadedContactCard(contact, selection, preferredPlacement, contactCardOptions); });
}

inline void ContactManager::ShowFullContactCard(Windows::ApplicationModel::Contacts::Contact const& contact, Windows::ApplicationModel::Contacts::FullContactCardOptions const& fullContactCardOptions)
{
    impl::call_factory<ContactManager, Windows::ApplicationModel::Contacts::IContactManagerStatics3>([&](auto&& f) { return f.ShowFullContactCard(contact, fullContactCardOptions); });
}

inline Windows::ApplicationModel::Contacts::ContactNameOrder ContactManager::SystemDisplayNameOrder()
{
    return impl::call_factory<ContactManager, Windows::ApplicationModel::Contacts::IContactManagerStatics3>([&](auto&& f) { return f.SystemDisplayNameOrder(); });
}

inline void ContactManager::SystemDisplayNameOrder(Windows::ApplicationModel::Contacts::ContactNameOrder const& value)
{
    impl::call_factory<ContactManager, Windows::ApplicationModel::Contacts::IContactManagerStatics3>([&](auto&& f) { return f.SystemDisplayNameOrder(value); });
}

inline Windows::ApplicationModel::Contacts::ContactNameOrder ContactManager::SystemSortOrder()
{
    return impl::call_factory<ContactManager, Windows::ApplicationModel::Contacts::IContactManagerStatics3>([&](auto&& f) { return f.SystemSortOrder(); });
}

inline void ContactManager::SystemSortOrder(Windows::ApplicationModel::Contacts::ContactNameOrder const& value)
{
    impl::call_factory<ContactManager, Windows::ApplicationModel::Contacts::IContactManagerStatics3>([&](auto&& f) { return f.SystemSortOrder(value); });
}

inline Windows::ApplicationModel::Contacts::ContactManagerForUser ContactManager::GetForUser(Windows::System::User const& user)
{
    return impl::call_factory<ContactManager, Windows::ApplicationModel::Contacts::IContactManagerStatics4>([&](auto&& f) { return f.GetForUser(user); });
}

inline Windows::Foundation::IAsyncOperation<bool> ContactManager::IsShowFullContactCardSupportedAsync()
{
    return impl::call_factory<ContactManager, Windows::ApplicationModel::Contacts::IContactManagerStatics5>([&](auto&& f) { return f.IsShowFullContactCardSupportedAsync(); });
}

inline bool ContactManager::IncludeMiddleNameInSystemDisplayAndSort()
{
    return impl::call_factory<ContactManager, Windows::ApplicationModel::Contacts::IContactManagerStatics5>([&](auto&& f) { return f.IncludeMiddleNameInSystemDisplayAndSort(); });
}

inline void ContactManager::IncludeMiddleNameInSystemDisplayAndSort(bool value)
{
    impl::call_factory<ContactManager, Windows::ApplicationModel::Contacts::IContactManagerStatics5>([&](auto&& f) { return f.IncludeMiddleNameInSystemDisplayAndSort(value); });
}

inline ContactPhone::ContactPhone() :
    ContactPhone(impl::call_factory<ContactPhone>([](auto&& f) { return f.template ActivateInstance<ContactPhone>(); }))
{}

inline ContactPicker::ContactPicker() :
    ContactPicker(impl::call_factory<ContactPicker>([](auto&& f) { return f.template ActivateInstance<ContactPicker>(); }))
{}

inline Windows::ApplicationModel::Contacts::ContactPicker ContactPicker::CreateForUser(Windows::System::User const& user)
{
    return impl::call_factory<ContactPicker, Windows::ApplicationModel::Contacts::IContactPickerStatics>([&](auto&& f) { return f.CreateForUser(user); });
}

inline Windows::Foundation::IAsyncOperation<bool> ContactPicker::IsSupportedAsync()
{
    return impl::call_factory<ContactPicker, Windows::ApplicationModel::Contacts::IContactPickerStatics>([&](auto&& f) { return f.IsSupportedAsync(); });
}

inline ContactQueryOptions::ContactQueryOptions() :
    ContactQueryOptions(impl::call_factory<ContactQueryOptions>([](auto&& f) { return f.template ActivateInstance<ContactQueryOptions>(); }))
{}

inline ContactQueryOptions::ContactQueryOptions(param::hstring const& text) :
    ContactQueryOptions(impl::call_factory<ContactQueryOptions, Windows::ApplicationModel::Contacts::IContactQueryOptionsFactory>([&](auto&& f) { return f.CreateWithText(text); }))
{}

inline ContactQueryOptions::ContactQueryOptions(param::hstring const& text, Windows::ApplicationModel::Contacts::ContactQuerySearchFields const& fields) :
    ContactQueryOptions(impl::call_factory<ContactQueryOptions, Windows::ApplicationModel::Contacts::IContactQueryOptionsFactory>([&](auto&& f) { return f.CreateWithTextAndFields(text, fields); }))
{}

inline ContactSignificantOther::ContactSignificantOther() :
    ContactSignificantOther(impl::call_factory<ContactSignificantOther>([](auto&& f) { return f.template ActivateInstance<ContactSignificantOther>(); }))
{}

inline ContactWebsite::ContactWebsite() :
    ContactWebsite(impl::call_factory<ContactWebsite>([](auto&& f) { return f.template ActivateInstance<ContactWebsite>(); }))
{}

inline FullContactCardOptions::FullContactCardOptions() :
    FullContactCardOptions(impl::call_factory<FullContactCardOptions>([](auto&& f) { return f.template ActivateInstance<FullContactCardOptions>(); }))
{}

inline hstring KnownContactField::Email()
{
    return impl::call_factory<KnownContactField, Windows::ApplicationModel::Contacts::IKnownContactFieldStatics>([&](auto&& f) { return f.Email(); });
}

inline hstring KnownContactField::PhoneNumber()
{
    return impl::call_factory<KnownContactField, Windows::ApplicationModel::Contacts::IKnownContactFieldStatics>([&](auto&& f) { return f.PhoneNumber(); });
}

inline hstring KnownContactField::Location()
{
    return impl::call_factory<KnownContactField, Windows::ApplicationModel::Contacts::IKnownContactFieldStatics>([&](auto&& f) { return f.Location(); });
}

inline hstring KnownContactField::InstantMessage()
{
    return impl::call_factory<KnownContactField, Windows::ApplicationModel::Contacts::IKnownContactFieldStatics>([&](auto&& f) { return f.InstantMessage(); });
}

inline Windows::ApplicationModel::Contacts::ContactFieldType KnownContactField::ConvertNameToType(param::hstring const& name)
{
    return impl::call_factory<KnownContactField, Windows::ApplicationModel::Contacts::IKnownContactFieldStatics>([&](auto&& f) { return f.ConvertNameToType(name); });
}

inline hstring KnownContactField::ConvertTypeToName(Windows::ApplicationModel::Contacts::ContactFieldType const& type)
{
    return impl::call_factory<KnownContactField, Windows::ApplicationModel::Contacts::IKnownContactFieldStatics>([&](auto&& f) { return f.ConvertTypeToName(type); });
}

inline Windows::ApplicationModel::Contacts::PinnedContactManager PinnedContactManager::GetDefault()
{
    return impl::call_factory<PinnedContactManager, Windows::ApplicationModel::Contacts::IPinnedContactManagerStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline Windows::ApplicationModel::Contacts::PinnedContactManager PinnedContactManager::GetForUser(Windows::System::User const& user)
{
    return impl::call_factory<PinnedContactManager, Windows::ApplicationModel::Contacts::IPinnedContactManagerStatics>([&](auto&& f) { return f.GetForUser(user); });
}

inline bool PinnedContactManager::IsSupported()
{
    return impl::call_factory<PinnedContactManager, Windows::ApplicationModel::Contacts::IPinnedContactManagerStatics>([&](auto&& f) { return f.IsSupported(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IAggregateContactManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IAggregateContactManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IAggregateContactManager2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IAggregateContactManager2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContact> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContact> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContact2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContact2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContact3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContact3> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactAddress> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactAddress> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactAnnotation> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactAnnotation> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactAnnotation2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactAnnotation2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactAnnotationList> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactAnnotationList> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactAnnotationStore> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactAnnotationStore> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactAnnotationStore2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactAnnotationStore2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactBatch> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactBatch> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactCardDelayedDataLoader> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactCardDelayedDataLoader> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactCardOptions> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactCardOptions> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactCardOptions2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactCardOptions2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactChange> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactChange> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactChangeReader> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactChangeReader> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactChangeTracker> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactChangeTracker> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactChangeTracker2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactChangeTracker2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactChangedDeferral> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactChangedDeferral> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactChangedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactConnectedServiceAccount> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactConnectedServiceAccount> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactDate> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactDate> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactEmail> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactEmail> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactField> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactField> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactFieldFactory> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactFieldFactory> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactGroup> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactGroup> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactInformation> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactInformation> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactInstantMessageField> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactInstantMessageField> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactInstantMessageFieldFactory> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactInstantMessageFieldFactory> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactJobInfo> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactJobInfo> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactLaunchActionVerbsStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactLaunchActionVerbsStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactList> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactList> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactList2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactList2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactList3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactList3> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactListLimitedWriteOperations> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactListLimitedWriteOperations> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactListSyncManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactListSyncManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactListSyncManager2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactListSyncManager2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactLocationField> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactLocationField> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactLocationFieldFactory> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactLocationFieldFactory> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactManagerForUser> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactManagerForUser> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactManagerForUser2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactManagerForUser2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics3> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics4> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics4> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics5> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics5> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactMatchReason> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactMatchReason> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactName> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactName> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactPanel> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactPanel> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactPanelClosingEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactPanelClosingEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactPanelLaunchFullAppRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactPanelLaunchFullAppRequestedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactPhone> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactPhone> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactPicker> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactPicker> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactPicker2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactPicker2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactPicker3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactPicker3> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactPickerStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactPickerStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactQueryOptions> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactQueryOptions> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactQueryOptionsFactory> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactQueryOptionsFactory> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactQueryTextSearch> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactQueryTextSearch> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactReader> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactReader> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactSignificantOther> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactSignificantOther> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactSignificantOther2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactSignificantOther2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactStore> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactStore> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactStore2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactStore2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactStore3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactStore3> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactStoreNotificationTriggerDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactStoreNotificationTriggerDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactWebsite> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactWebsite> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactWebsite2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IContactWebsite2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IFullContactCardOptions> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IFullContactCardOptions> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IKnownContactFieldStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IKnownContactFieldStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IPinnedContactIdsQueryResult> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IPinnedContactIdsQueryResult> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IPinnedContactManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IPinnedContactManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IPinnedContactManagerStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::IPinnedContactManagerStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::AggregateContactManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::AggregateContactManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::Contact> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::Contact> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactAddress> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactAddress> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactAnnotation> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactAnnotation> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactAnnotationList> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactAnnotationList> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactAnnotationStore> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactAnnotationStore> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactBatch> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactBatch> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactCardDelayedDataLoader> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactCardDelayedDataLoader> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactCardOptions> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactCardOptions> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactChange> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactChange> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactChangeReader> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactChangeReader> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactChangeTracker> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactChangeTracker> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactChangedDeferral> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactChangedDeferral> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactChangedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactConnectedServiceAccount> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactConnectedServiceAccount> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactDate> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactDate> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactEmail> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactEmail> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactField> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactField> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactFieldFactory> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactFieldFactory> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactGroup> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactGroup> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactInformation> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactInformation> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactInstantMessageField> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactInstantMessageField> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactJobInfo> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactJobInfo> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactLaunchActionVerbs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactLaunchActionVerbs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactList> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactList> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactListLimitedWriteOperations> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactListLimitedWriteOperations> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactListSyncConstraints> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactListSyncConstraints> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactListSyncManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactListSyncManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactLocationField> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactLocationField> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactManagerForUser> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactManagerForUser> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactMatchReason> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactMatchReason> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactPanel> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactPanel> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactPanelClosingEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactPanelClosingEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactPanelLaunchFullAppRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactPanelLaunchFullAppRequestedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactPhone> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactPhone> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactPicker> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactPicker> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactQueryOptions> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactQueryOptions> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactQueryTextSearch> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactQueryTextSearch> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactReader> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactReader> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactSignificantOther> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactSignificantOther> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactStore> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactStore> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactStoreNotificationTriggerDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactStoreNotificationTriggerDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactWebsite> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::ContactWebsite> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::FullContactCardOptions> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::FullContactCardOptions> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::KnownContactField> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::KnownContactField> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::PinnedContactIdsQueryResult> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::PinnedContactIdsQueryResult> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::PinnedContactManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::PinnedContactManager> {};

}
