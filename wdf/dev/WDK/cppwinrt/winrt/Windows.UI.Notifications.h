// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.2.h"
#include "winrt/impl/Windows.Data.Xml.Dom.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.UI.Notifications.2.h"
#include "winrt/Windows.UI.h"

namespace winrt::impl {

template <typename D> Windows::UI::Notifications::AdaptiveNotificationContentKind consume_Windows_UI_Notifications_IAdaptiveNotificationContent<D>::Kind() const
{
    Windows::UI::Notifications::AdaptiveNotificationContentKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IAdaptiveNotificationContent)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMap<hstring, hstring> consume_Windows_UI_Notifications_IAdaptiveNotificationContent<D>::Hints() const
{
    Windows::Foundation::Collections::IMap<hstring, hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IAdaptiveNotificationContent)->get_Hints(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Notifications_IAdaptiveNotificationText<D>::Text() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IAdaptiveNotificationText)->get_Text(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_IAdaptiveNotificationText<D>::Text(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IAdaptiveNotificationText)->put_Text(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Notifications_IAdaptiveNotificationText<D>::Language() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IAdaptiveNotificationText)->get_Language(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_IAdaptiveNotificationText<D>::Language(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IAdaptiveNotificationText)->put_Language(get_abi(value)));
}

template <typename D> Windows::Data::Xml::Dom::XmlDocument consume_Windows_UI_Notifications_IBadgeNotification<D>::Content() const
{
    Windows::Data::Xml::Dom::XmlDocument value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IBadgeNotification)->get_Content(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_IBadgeNotification<D>::ExpirationTime(optional<Windows::Foundation::DateTime> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IBadgeNotification)->put_ExpirationTime(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_UI_Notifications_IBadgeNotification<D>::ExpirationTime() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IBadgeNotification)->get_ExpirationTime(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Notifications::BadgeNotification consume_Windows_UI_Notifications_IBadgeNotificationFactory<D>::CreateBadgeNotification(Windows::Data::Xml::Dom::XmlDocument const& content) const
{
    Windows::UI::Notifications::BadgeNotification value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IBadgeNotificationFactory)->CreateBadgeNotification(get_abi(content), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Notifications::BadgeUpdater consume_Windows_UI_Notifications_IBadgeUpdateManagerForUser<D>::CreateBadgeUpdaterForApplication() const
{
    Windows::UI::Notifications::BadgeUpdater result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IBadgeUpdateManagerForUser)->CreateBadgeUpdaterForApplication(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Notifications::BadgeUpdater consume_Windows_UI_Notifications_IBadgeUpdateManagerForUser<D>::CreateBadgeUpdaterForApplication(param::hstring const& applicationId) const
{
    Windows::UI::Notifications::BadgeUpdater result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IBadgeUpdateManagerForUser)->CreateBadgeUpdaterForApplicationWithId(get_abi(applicationId), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Notifications::BadgeUpdater consume_Windows_UI_Notifications_IBadgeUpdateManagerForUser<D>::CreateBadgeUpdaterForSecondaryTile(param::hstring const& tileId) const
{
    Windows::UI::Notifications::BadgeUpdater result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IBadgeUpdateManagerForUser)->CreateBadgeUpdaterForSecondaryTile(get_abi(tileId), put_abi(result)));
    return result;
}

template <typename D> Windows::System::User consume_Windows_UI_Notifications_IBadgeUpdateManagerForUser<D>::User() const
{
    Windows::System::User value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IBadgeUpdateManagerForUser)->get_User(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Notifications::BadgeUpdater consume_Windows_UI_Notifications_IBadgeUpdateManagerStatics<D>::CreateBadgeUpdaterForApplication() const
{
    Windows::UI::Notifications::BadgeUpdater result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IBadgeUpdateManagerStatics)->CreateBadgeUpdaterForApplication(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Notifications::BadgeUpdater consume_Windows_UI_Notifications_IBadgeUpdateManagerStatics<D>::CreateBadgeUpdaterForApplication(param::hstring const& applicationId) const
{
    Windows::UI::Notifications::BadgeUpdater result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IBadgeUpdateManagerStatics)->CreateBadgeUpdaterForApplicationWithId(get_abi(applicationId), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Notifications::BadgeUpdater consume_Windows_UI_Notifications_IBadgeUpdateManagerStatics<D>::CreateBadgeUpdaterForSecondaryTile(param::hstring const& tileId) const
{
    Windows::UI::Notifications::BadgeUpdater result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IBadgeUpdateManagerStatics)->CreateBadgeUpdaterForSecondaryTile(get_abi(tileId), put_abi(result)));
    return result;
}

template <typename D> Windows::Data::Xml::Dom::XmlDocument consume_Windows_UI_Notifications_IBadgeUpdateManagerStatics<D>::GetTemplateContent(Windows::UI::Notifications::BadgeTemplateType const& type) const
{
    Windows::Data::Xml::Dom::XmlDocument result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IBadgeUpdateManagerStatics)->GetTemplateContent(get_abi(type), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Notifications::BadgeUpdateManagerForUser consume_Windows_UI_Notifications_IBadgeUpdateManagerStatics2<D>::GetForUser(Windows::System::User const& user) const
{
    Windows::UI::Notifications::BadgeUpdateManagerForUser result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IBadgeUpdateManagerStatics2)->GetForUser(get_abi(user), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Notifications_IBadgeUpdater<D>::Update(Windows::UI::Notifications::BadgeNotification const& notification) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IBadgeUpdater)->Update(get_abi(notification)));
}

template <typename D> void consume_Windows_UI_Notifications_IBadgeUpdater<D>::Clear() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IBadgeUpdater)->Clear());
}

template <typename D> void consume_Windows_UI_Notifications_IBadgeUpdater<D>::StartPeriodicUpdate(Windows::Foundation::Uri const& badgeContent, Windows::UI::Notifications::PeriodicUpdateRecurrence const& requestedInterval) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IBadgeUpdater)->StartPeriodicUpdate(get_abi(badgeContent), get_abi(requestedInterval)));
}

template <typename D> void consume_Windows_UI_Notifications_IBadgeUpdater<D>::StartPeriodicUpdate(Windows::Foundation::Uri const& badgeContent, Windows::Foundation::DateTime const& startTime, Windows::UI::Notifications::PeriodicUpdateRecurrence const& requestedInterval) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IBadgeUpdater)->StartPeriodicUpdateAtTime(get_abi(badgeContent), get_abi(startTime), get_abi(requestedInterval)));
}

template <typename D> void consume_Windows_UI_Notifications_IBadgeUpdater<D>::StopPeriodicUpdate() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IBadgeUpdater)->StopPeriodicUpdate());
}

template <typename D> hstring consume_Windows_UI_Notifications_IKnownAdaptiveNotificationHintsStatics<D>::Style() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IKnownAdaptiveNotificationHintsStatics)->get_Style(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Notifications_IKnownAdaptiveNotificationHintsStatics<D>::Wrap() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IKnownAdaptiveNotificationHintsStatics)->get_Wrap(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Notifications_IKnownAdaptiveNotificationHintsStatics<D>::MaxLines() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IKnownAdaptiveNotificationHintsStatics)->get_MaxLines(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Notifications_IKnownAdaptiveNotificationHintsStatics<D>::MinLines() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IKnownAdaptiveNotificationHintsStatics)->get_MinLines(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Notifications_IKnownAdaptiveNotificationHintsStatics<D>::TextStacking() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IKnownAdaptiveNotificationHintsStatics)->get_TextStacking(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Notifications_IKnownAdaptiveNotificationHintsStatics<D>::Align() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IKnownAdaptiveNotificationHintsStatics)->get_Align(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::Caption() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_Caption(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::Body() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_Body(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::Base() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_Base(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::Subtitle() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_Subtitle(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::Title() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_Title(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::Subheader() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_Subheader(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::Header() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_Header(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::TitleNumeral() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_TitleNumeral(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::SubheaderNumeral() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_SubheaderNumeral(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::HeaderNumeral() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_HeaderNumeral(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::CaptionSubtle() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_CaptionSubtle(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::BodySubtle() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_BodySubtle(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::BaseSubtle() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_BaseSubtle(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::SubtitleSubtle() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_SubtitleSubtle(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::TitleSubtle() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_TitleSubtle(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::SubheaderSubtle() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_SubheaderSubtle(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::SubheaderNumeralSubtle() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_SubheaderNumeralSubtle(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::HeaderSubtle() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_HeaderSubtle(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Notifications_IKnownAdaptiveNotificationTextStylesStatics<D>::HeaderNumeralSubtle() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics)->get_HeaderNumeralSubtle(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Notifications_IKnownNotificationBindingsStatics<D>::ToastGeneric() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IKnownNotificationBindingsStatics)->get_ToastGeneric(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_UI_Notifications_INotification<D>::ExpirationTime() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::INotification)->get_ExpirationTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_INotification<D>::ExpirationTime(optional<Windows::Foundation::DateTime> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::INotification)->put_ExpirationTime(get_abi(value)));
}

template <typename D> Windows::UI::Notifications::NotificationVisual consume_Windows_UI_Notifications_INotification<D>::Visual() const
{
    Windows::UI::Notifications::NotificationVisual value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::INotification)->get_Visual(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_INotification<D>::Visual(Windows::UI::Notifications::NotificationVisual const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::INotification)->put_Visual(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Notifications_INotificationBinding<D>::Template() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::INotificationBinding)->get_Template(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_INotificationBinding<D>::Template(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::INotificationBinding)->put_Template(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Notifications_INotificationBinding<D>::Language() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::INotificationBinding)->get_Language(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_INotificationBinding<D>::Language(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::INotificationBinding)->put_Language(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IMap<hstring, hstring> consume_Windows_UI_Notifications_INotificationBinding<D>::Hints() const
{
    Windows::Foundation::Collections::IMap<hstring, hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::INotificationBinding)->get_Hints(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::Notifications::AdaptiveNotificationText> consume_Windows_UI_Notifications_INotificationBinding<D>::GetTextElements() const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::Notifications::AdaptiveNotificationText> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::INotificationBinding)->GetTextElements(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IMap<hstring, hstring> consume_Windows_UI_Notifications_INotificationData<D>::Values() const
{
    Windows::Foundation::Collections::IMap<hstring, hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::INotificationData)->get_Values(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_UI_Notifications_INotificationData<D>::SequenceNumber() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::INotificationData)->get_SequenceNumber(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_INotificationData<D>::SequenceNumber(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::INotificationData)->put_SequenceNumber(value));
}

template <typename D> Windows::UI::Notifications::NotificationData consume_Windows_UI_Notifications_INotificationDataFactory<D>::CreateNotificationData(param::iterable<Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const& initialValues, uint32_t sequenceNumber) const
{
    Windows::UI::Notifications::NotificationData value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::INotificationDataFactory)->CreateNotificationDataWithValuesAndSequenceNumber(get_abi(initialValues), sequenceNumber, put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Notifications::NotificationData consume_Windows_UI_Notifications_INotificationDataFactory<D>::CreateNotificationData(param::iterable<Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const& initialValues) const
{
    Windows::UI::Notifications::NotificationData value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::INotificationDataFactory)->CreateNotificationDataWithValues(get_abi(initialValues), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Notifications_INotificationVisual<D>::Language() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::INotificationVisual)->get_Language(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_INotificationVisual<D>::Language(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::INotificationVisual)->put_Language(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Notifications::NotificationBinding> consume_Windows_UI_Notifications_INotificationVisual<D>::Bindings() const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Notifications::NotificationBinding> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::INotificationVisual)->get_Bindings(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Notifications::NotificationBinding consume_Windows_UI_Notifications_INotificationVisual<D>::GetBinding(param::hstring const& templateName) const
{
    Windows::UI::Notifications::NotificationBinding result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::INotificationVisual)->GetBinding(get_abi(templateName), put_abi(result)));
    return result;
}

template <typename D> Windows::Data::Xml::Dom::XmlDocument consume_Windows_UI_Notifications_IScheduledTileNotification<D>::Content() const
{
    Windows::Data::Xml::Dom::XmlDocument value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IScheduledTileNotification)->get_Content(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_UI_Notifications_IScheduledTileNotification<D>::DeliveryTime() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IScheduledTileNotification)->get_DeliveryTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_IScheduledTileNotification<D>::ExpirationTime(optional<Windows::Foundation::DateTime> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IScheduledTileNotification)->put_ExpirationTime(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_UI_Notifications_IScheduledTileNotification<D>::ExpirationTime() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IScheduledTileNotification)->get_ExpirationTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_IScheduledTileNotification<D>::Tag(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IScheduledTileNotification)->put_Tag(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Notifications_IScheduledTileNotification<D>::Tag() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IScheduledTileNotification)->get_Tag(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_IScheduledTileNotification<D>::Id(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IScheduledTileNotification)->put_Id(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Notifications_IScheduledTileNotification<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IScheduledTileNotification)->get_Id(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Notifications::ScheduledTileNotification consume_Windows_UI_Notifications_IScheduledTileNotificationFactory<D>::CreateScheduledTileNotification(Windows::Data::Xml::Dom::XmlDocument const& content, Windows::Foundation::DateTime const& deliveryTime) const
{
    Windows::UI::Notifications::ScheduledTileNotification value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IScheduledTileNotificationFactory)->CreateScheduledTileNotification(get_abi(content), get_abi(deliveryTime), put_abi(value)));
    return value;
}

template <typename D> Windows::Data::Xml::Dom::XmlDocument consume_Windows_UI_Notifications_IScheduledToastNotification<D>::Content() const
{
    Windows::Data::Xml::Dom::XmlDocument value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IScheduledToastNotification)->get_Content(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_UI_Notifications_IScheduledToastNotification<D>::DeliveryTime() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IScheduledToastNotification)->get_DeliveryTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_UI_Notifications_IScheduledToastNotification<D>::SnoozeInterval() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IScheduledToastNotification)->get_SnoozeInterval(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_UI_Notifications_IScheduledToastNotification<D>::MaximumSnoozeCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IScheduledToastNotification)->get_MaximumSnoozeCount(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_IScheduledToastNotification<D>::Id(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IScheduledToastNotification)->put_Id(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Notifications_IScheduledToastNotification<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IScheduledToastNotification)->get_Id(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_IScheduledToastNotification2<D>::Tag(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IScheduledToastNotification2)->put_Tag(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Notifications_IScheduledToastNotification2<D>::Tag() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IScheduledToastNotification2)->get_Tag(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_IScheduledToastNotification2<D>::Group(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IScheduledToastNotification2)->put_Group(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Notifications_IScheduledToastNotification2<D>::Group() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IScheduledToastNotification2)->get_Group(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_IScheduledToastNotification2<D>::SuppressPopup(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IScheduledToastNotification2)->put_SuppressPopup(value));
}

template <typename D> bool consume_Windows_UI_Notifications_IScheduledToastNotification2<D>::SuppressPopup() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IScheduledToastNotification2)->get_SuppressPopup(&value));
    return value;
}

template <typename D> Windows::UI::Notifications::NotificationMirroring consume_Windows_UI_Notifications_IScheduledToastNotification3<D>::NotificationMirroring() const
{
    Windows::UI::Notifications::NotificationMirroring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IScheduledToastNotification3)->get_NotificationMirroring(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_IScheduledToastNotification3<D>::NotificationMirroring(Windows::UI::Notifications::NotificationMirroring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IScheduledToastNotification3)->put_NotificationMirroring(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Notifications_IScheduledToastNotification3<D>::RemoteId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IScheduledToastNotification3)->get_RemoteId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_IScheduledToastNotification3<D>::RemoteId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IScheduledToastNotification3)->put_RemoteId(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_UI_Notifications_IScheduledToastNotification4<D>::ExpirationTime() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IScheduledToastNotification4)->get_ExpirationTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_IScheduledToastNotification4<D>::ExpirationTime(optional<Windows::Foundation::DateTime> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IScheduledToastNotification4)->put_ExpirationTime(get_abi(value)));
}

template <typename D> Windows::UI::Notifications::ScheduledToastNotification consume_Windows_UI_Notifications_IScheduledToastNotificationFactory<D>::CreateScheduledToastNotification(Windows::Data::Xml::Dom::XmlDocument const& content, Windows::Foundation::DateTime const& deliveryTime) const
{
    Windows::UI::Notifications::ScheduledToastNotification value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IScheduledToastNotificationFactory)->CreateScheduledToastNotification(get_abi(content), get_abi(deliveryTime), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Notifications::ScheduledToastNotification consume_Windows_UI_Notifications_IScheduledToastNotificationFactory<D>::CreateScheduledToastNotificationRecurring(Windows::Data::Xml::Dom::XmlDocument const& content, Windows::Foundation::DateTime const& deliveryTime, Windows::Foundation::TimeSpan const& snoozeInterval, uint32_t maximumSnoozeCount) const
{
    Windows::UI::Notifications::ScheduledToastNotification value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IScheduledToastNotificationFactory)->CreateScheduledToastNotificationRecurring(get_abi(content), get_abi(deliveryTime), get_abi(snoozeInterval), maximumSnoozeCount, put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Notifications_IScheduledToastNotificationShowingEventArgs<D>::Cancel() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IScheduledToastNotificationShowingEventArgs)->get_Cancel(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_IScheduledToastNotificationShowingEventArgs<D>::Cancel(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IScheduledToastNotificationShowingEventArgs)->put_Cancel(value));
}

template <typename D> Windows::UI::Notifications::ScheduledToastNotification consume_Windows_UI_Notifications_IScheduledToastNotificationShowingEventArgs<D>::ScheduledToastNotification() const
{
    Windows::UI::Notifications::ScheduledToastNotification value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IScheduledToastNotificationShowingEventArgs)->get_ScheduledToastNotification(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_UI_Notifications_IScheduledToastNotificationShowingEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IScheduledToastNotificationShowingEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_UI_Notifications_IShownTileNotification<D>::Arguments() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IShownTileNotification)->get_Arguments(put_abi(value)));
    return value;
}

template <typename D> Windows::Data::Xml::Dom::XmlDocument consume_Windows_UI_Notifications_ITileFlyoutNotification<D>::Content() const
{
    Windows::Data::Xml::Dom::XmlDocument value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileFlyoutNotification)->get_Content(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_ITileFlyoutNotification<D>::ExpirationTime(optional<Windows::Foundation::DateTime> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileFlyoutNotification)->put_ExpirationTime(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_UI_Notifications_ITileFlyoutNotification<D>::ExpirationTime() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileFlyoutNotification)->get_ExpirationTime(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Notifications::TileFlyoutNotification consume_Windows_UI_Notifications_ITileFlyoutNotificationFactory<D>::CreateTileFlyoutNotification(Windows::Data::Xml::Dom::XmlDocument const& content) const
{
    Windows::UI::Notifications::TileFlyoutNotification value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileFlyoutNotificationFactory)->CreateTileFlyoutNotification(get_abi(content), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Notifications::TileFlyoutUpdater consume_Windows_UI_Notifications_ITileFlyoutUpdateManagerStatics<D>::CreateTileFlyoutUpdaterForApplication() const
{
    Windows::UI::Notifications::TileFlyoutUpdater result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileFlyoutUpdateManagerStatics)->CreateTileFlyoutUpdaterForApplication(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Notifications::TileFlyoutUpdater consume_Windows_UI_Notifications_ITileFlyoutUpdateManagerStatics<D>::CreateTileFlyoutUpdaterForApplication(param::hstring const& applicationId) const
{
    Windows::UI::Notifications::TileFlyoutUpdater result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileFlyoutUpdateManagerStatics)->CreateTileFlyoutUpdaterForApplicationWithId(get_abi(applicationId), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Notifications::TileFlyoutUpdater consume_Windows_UI_Notifications_ITileFlyoutUpdateManagerStatics<D>::CreateTileFlyoutUpdaterForSecondaryTile(param::hstring const& tileId) const
{
    Windows::UI::Notifications::TileFlyoutUpdater result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileFlyoutUpdateManagerStatics)->CreateTileFlyoutUpdaterForSecondaryTile(get_abi(tileId), put_abi(result)));
    return result;
}

template <typename D> Windows::Data::Xml::Dom::XmlDocument consume_Windows_UI_Notifications_ITileFlyoutUpdateManagerStatics<D>::GetTemplateContent(Windows::UI::Notifications::TileFlyoutTemplateType const& type) const
{
    Windows::Data::Xml::Dom::XmlDocument result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileFlyoutUpdateManagerStatics)->GetTemplateContent(get_abi(type), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Notifications_ITileFlyoutUpdater<D>::Update(Windows::UI::Notifications::TileFlyoutNotification const& notification) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileFlyoutUpdater)->Update(get_abi(notification)));
}

template <typename D> void consume_Windows_UI_Notifications_ITileFlyoutUpdater<D>::Clear() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileFlyoutUpdater)->Clear());
}

template <typename D> void consume_Windows_UI_Notifications_ITileFlyoutUpdater<D>::StartPeriodicUpdate(Windows::Foundation::Uri const& tileFlyoutContent, Windows::UI::Notifications::PeriodicUpdateRecurrence const& requestedInterval) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileFlyoutUpdater)->StartPeriodicUpdate(get_abi(tileFlyoutContent), get_abi(requestedInterval)));
}

template <typename D> void consume_Windows_UI_Notifications_ITileFlyoutUpdater<D>::StartPeriodicUpdate(Windows::Foundation::Uri const& tileFlyoutContent, Windows::Foundation::DateTime const& startTime, Windows::UI::Notifications::PeriodicUpdateRecurrence const& requestedInterval) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileFlyoutUpdater)->StartPeriodicUpdateAtTime(get_abi(tileFlyoutContent), get_abi(startTime), get_abi(requestedInterval)));
}

template <typename D> void consume_Windows_UI_Notifications_ITileFlyoutUpdater<D>::StopPeriodicUpdate() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileFlyoutUpdater)->StopPeriodicUpdate());
}

template <typename D> Windows::UI::Notifications::NotificationSetting consume_Windows_UI_Notifications_ITileFlyoutUpdater<D>::Setting() const
{
    Windows::UI::Notifications::NotificationSetting value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileFlyoutUpdater)->get_Setting(put_abi(value)));
    return value;
}

template <typename D> Windows::Data::Xml::Dom::XmlDocument consume_Windows_UI_Notifications_ITileNotification<D>::Content() const
{
    Windows::Data::Xml::Dom::XmlDocument value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileNotification)->get_Content(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_ITileNotification<D>::ExpirationTime(optional<Windows::Foundation::DateTime> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileNotification)->put_ExpirationTime(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_UI_Notifications_ITileNotification<D>::ExpirationTime() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileNotification)->get_ExpirationTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_ITileNotification<D>::Tag(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileNotification)->put_Tag(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Notifications_ITileNotification<D>::Tag() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileNotification)->get_Tag(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Notifications::TileNotification consume_Windows_UI_Notifications_ITileNotificationFactory<D>::CreateTileNotification(Windows::Data::Xml::Dom::XmlDocument const& content) const
{
    Windows::UI::Notifications::TileNotification value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileNotificationFactory)->CreateTileNotification(get_abi(content), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Notifications::TileUpdater consume_Windows_UI_Notifications_ITileUpdateManagerForUser<D>::CreateTileUpdaterForApplicationForUser() const
{
    Windows::UI::Notifications::TileUpdater result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileUpdateManagerForUser)->CreateTileUpdaterForApplication(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Notifications::TileUpdater consume_Windows_UI_Notifications_ITileUpdateManagerForUser<D>::CreateTileUpdaterForApplication(param::hstring const& applicationId) const
{
    Windows::UI::Notifications::TileUpdater result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileUpdateManagerForUser)->CreateTileUpdaterForApplicationWithId(get_abi(applicationId), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Notifications::TileUpdater consume_Windows_UI_Notifications_ITileUpdateManagerForUser<D>::CreateTileUpdaterForSecondaryTile(param::hstring const& tileId) const
{
    Windows::UI::Notifications::TileUpdater result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileUpdateManagerForUser)->CreateTileUpdaterForSecondaryTile(get_abi(tileId), put_abi(result)));
    return result;
}

template <typename D> Windows::System::User consume_Windows_UI_Notifications_ITileUpdateManagerForUser<D>::User() const
{
    Windows::System::User value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileUpdateManagerForUser)->get_User(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Notifications::TileUpdater consume_Windows_UI_Notifications_ITileUpdateManagerStatics<D>::CreateTileUpdaterForApplication() const
{
    Windows::UI::Notifications::TileUpdater result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileUpdateManagerStatics)->CreateTileUpdaterForApplication(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Notifications::TileUpdater consume_Windows_UI_Notifications_ITileUpdateManagerStatics<D>::CreateTileUpdaterForApplication(param::hstring const& applicationId) const
{
    Windows::UI::Notifications::TileUpdater result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileUpdateManagerStatics)->CreateTileUpdaterForApplicationWithId(get_abi(applicationId), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Notifications::TileUpdater consume_Windows_UI_Notifications_ITileUpdateManagerStatics<D>::CreateTileUpdaterForSecondaryTile(param::hstring const& tileId) const
{
    Windows::UI::Notifications::TileUpdater result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileUpdateManagerStatics)->CreateTileUpdaterForSecondaryTile(get_abi(tileId), put_abi(result)));
    return result;
}

template <typename D> Windows::Data::Xml::Dom::XmlDocument consume_Windows_UI_Notifications_ITileUpdateManagerStatics<D>::GetTemplateContent(Windows::UI::Notifications::TileTemplateType const& type) const
{
    Windows::Data::Xml::Dom::XmlDocument result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileUpdateManagerStatics)->GetTemplateContent(get_abi(type), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Notifications::TileUpdateManagerForUser consume_Windows_UI_Notifications_ITileUpdateManagerStatics2<D>::GetForUser(Windows::System::User const& user) const
{
    Windows::UI::Notifications::TileUpdateManagerForUser result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileUpdateManagerStatics2)->GetForUser(get_abi(user), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Notifications_ITileUpdater<D>::Update(Windows::UI::Notifications::TileNotification const& notification) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileUpdater)->Update(get_abi(notification)));
}

template <typename D> void consume_Windows_UI_Notifications_ITileUpdater<D>::Clear() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileUpdater)->Clear());
}

template <typename D> void consume_Windows_UI_Notifications_ITileUpdater<D>::EnableNotificationQueue(bool enable) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileUpdater)->EnableNotificationQueue(enable));
}

template <typename D> Windows::UI::Notifications::NotificationSetting consume_Windows_UI_Notifications_ITileUpdater<D>::Setting() const
{
    Windows::UI::Notifications::NotificationSetting value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileUpdater)->get_Setting(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_ITileUpdater<D>::AddToSchedule(Windows::UI::Notifications::ScheduledTileNotification const& scheduledTile) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileUpdater)->AddToSchedule(get_abi(scheduledTile)));
}

template <typename D> void consume_Windows_UI_Notifications_ITileUpdater<D>::RemoveFromSchedule(Windows::UI::Notifications::ScheduledTileNotification const& scheduledTile) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileUpdater)->RemoveFromSchedule(get_abi(scheduledTile)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::Notifications::ScheduledTileNotification> consume_Windows_UI_Notifications_ITileUpdater<D>::GetScheduledTileNotifications() const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::Notifications::ScheduledTileNotification> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileUpdater)->GetScheduledTileNotifications(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Notifications_ITileUpdater<D>::StartPeriodicUpdate(Windows::Foundation::Uri const& tileContent, Windows::UI::Notifications::PeriodicUpdateRecurrence const& requestedInterval) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileUpdater)->StartPeriodicUpdate(get_abi(tileContent), get_abi(requestedInterval)));
}

template <typename D> void consume_Windows_UI_Notifications_ITileUpdater<D>::StartPeriodicUpdate(Windows::Foundation::Uri const& tileContent, Windows::Foundation::DateTime const& startTime, Windows::UI::Notifications::PeriodicUpdateRecurrence const& requestedInterval) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileUpdater)->StartPeriodicUpdateAtTime(get_abi(tileContent), get_abi(startTime), get_abi(requestedInterval)));
}

template <typename D> void consume_Windows_UI_Notifications_ITileUpdater<D>::StopPeriodicUpdate() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileUpdater)->StopPeriodicUpdate());
}

template <typename D> void consume_Windows_UI_Notifications_ITileUpdater<D>::StartPeriodicUpdateBatch(param::iterable<Windows::Foundation::Uri> const& tileContents, Windows::UI::Notifications::PeriodicUpdateRecurrence const& requestedInterval) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileUpdater)->StartPeriodicUpdateBatch(get_abi(tileContents), get_abi(requestedInterval)));
}

template <typename D> void consume_Windows_UI_Notifications_ITileUpdater<D>::StartPeriodicUpdateBatch(param::iterable<Windows::Foundation::Uri> const& tileContents, Windows::Foundation::DateTime const& startTime, Windows::UI::Notifications::PeriodicUpdateRecurrence const& requestedInterval) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileUpdater)->StartPeriodicUpdateBatchAtTime(get_abi(tileContents), get_abi(startTime), get_abi(requestedInterval)));
}

template <typename D> void consume_Windows_UI_Notifications_ITileUpdater2<D>::EnableNotificationQueueForSquare150x150(bool enable) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileUpdater2)->EnableNotificationQueueForSquare150x150(enable));
}

template <typename D> void consume_Windows_UI_Notifications_ITileUpdater2<D>::EnableNotificationQueueForWide310x150(bool enable) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileUpdater2)->EnableNotificationQueueForWide310x150(enable));
}

template <typename D> void consume_Windows_UI_Notifications_ITileUpdater2<D>::EnableNotificationQueueForSquare310x310(bool enable) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::ITileUpdater2)->EnableNotificationQueueForSquare310x310(enable));
}

template <typename D> hstring consume_Windows_UI_Notifications_IToastActivatedEventArgs<D>::Arguments() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastActivatedEventArgs)->get_Arguments(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::ValueSet consume_Windows_UI_Notifications_IToastActivatedEventArgs2<D>::UserInput() const
{
    Windows::Foundation::Collections::ValueSet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastActivatedEventArgs2)->get_UserInput(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Notifications_IToastCollection<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastCollection)->get_Id(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Notifications_IToastCollection<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastCollection)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_IToastCollection<D>::DisplayName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastCollection)->put_DisplayName(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Notifications_IToastCollection<D>::LaunchArgs() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastCollection)->get_LaunchArgs(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_IToastCollection<D>::LaunchArgs(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastCollection)->put_LaunchArgs(get_abi(value)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_UI_Notifications_IToastCollection<D>::Icon() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastCollection)->get_Icon(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_IToastCollection<D>::Icon(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastCollection)->put_Icon(get_abi(value)));
}

template <typename D> Windows::UI::Notifications::ToastCollection consume_Windows_UI_Notifications_IToastCollectionFactory<D>::CreateInstance(param::hstring const& collectionId, param::hstring const& displayName, param::hstring const& launchArgs, Windows::Foundation::Uri const& iconUri) const
{
    Windows::UI::Notifications::ToastCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastCollectionFactory)->CreateInstance(get_abi(collectionId), get_abi(displayName), get_abi(launchArgs), get_abi(iconUri), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_UI_Notifications_IToastCollectionManager<D>::SaveToastCollectionAsync(Windows::UI::Notifications::ToastCollection const& collection) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastCollectionManager)->SaveToastCollectionAsync(get_abi(collection), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::UI::Notifications::ToastCollection>> consume_Windows_UI_Notifications_IToastCollectionManager<D>::FindAllToastCollectionsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::UI::Notifications::ToastCollection>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastCollectionManager)->FindAllToastCollectionsAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::UI::Notifications::ToastCollection> consume_Windows_UI_Notifications_IToastCollectionManager<D>::GetToastCollectionAsync(param::hstring const& collectionId) const
{
    Windows::Foundation::IAsyncOperation<Windows::UI::Notifications::ToastCollection> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastCollectionManager)->GetToastCollectionAsync(get_abi(collectionId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_UI_Notifications_IToastCollectionManager<D>::RemoveToastCollectionAsync(param::hstring const& collectionId) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastCollectionManager)->RemoveToastCollectionAsync(get_abi(collectionId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_UI_Notifications_IToastCollectionManager<D>::RemoveAllToastCollectionsAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastCollectionManager)->RemoveAllToastCollectionsAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::System::User consume_Windows_UI_Notifications_IToastCollectionManager<D>::User() const
{
    Windows::System::User value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastCollectionManager)->get_User(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Notifications_IToastCollectionManager<D>::AppId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastCollectionManager)->get_AppId(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Notifications::ToastDismissalReason consume_Windows_UI_Notifications_IToastDismissedEventArgs<D>::Reason() const
{
    Windows::UI::Notifications::ToastDismissalReason value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastDismissedEventArgs)->get_Reason(put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_UI_Notifications_IToastFailedEventArgs<D>::ErrorCode() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastFailedEventArgs)->get_ErrorCode(put_abi(value)));
    return value;
}

template <typename D> Windows::Data::Xml::Dom::XmlDocument consume_Windows_UI_Notifications_IToastNotification<D>::Content() const
{
    Windows::Data::Xml::Dom::XmlDocument value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotification)->get_Content(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_IToastNotification<D>::ExpirationTime(optional<Windows::Foundation::DateTime> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotification)->put_ExpirationTime(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_UI_Notifications_IToastNotification<D>::ExpirationTime() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotification)->get_ExpirationTime(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_Notifications_IToastNotification<D>::Dismissed(Windows::Foundation::TypedEventHandler<Windows::UI::Notifications::ToastNotification, Windows::UI::Notifications::ToastDismissedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotification)->add_Dismissed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Notifications_IToastNotification<D>::Dismissed_revoker consume_Windows_UI_Notifications_IToastNotification<D>::Dismissed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Notifications::ToastNotification, Windows::UI::Notifications::ToastDismissedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Dismissed_revoker>(this, Dismissed(handler));
}

template <typename D> void consume_Windows_UI_Notifications_IToastNotification<D>::Dismissed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Notifications::IToastNotification)->remove_Dismissed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Notifications_IToastNotification<D>::Activated(Windows::Foundation::TypedEventHandler<Windows::UI::Notifications::ToastNotification, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotification)->add_Activated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Notifications_IToastNotification<D>::Activated_revoker consume_Windows_UI_Notifications_IToastNotification<D>::Activated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Notifications::ToastNotification, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Activated_revoker>(this, Activated(handler));
}

template <typename D> void consume_Windows_UI_Notifications_IToastNotification<D>::Activated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Notifications::IToastNotification)->remove_Activated(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Notifications_IToastNotification<D>::Failed(Windows::Foundation::TypedEventHandler<Windows::UI::Notifications::ToastNotification, Windows::UI::Notifications::ToastFailedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotification)->add_Failed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Notifications_IToastNotification<D>::Failed_revoker consume_Windows_UI_Notifications_IToastNotification<D>::Failed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Notifications::ToastNotification, Windows::UI::Notifications::ToastFailedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Failed_revoker>(this, Failed(handler));
}

template <typename D> void consume_Windows_UI_Notifications_IToastNotification<D>::Failed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Notifications::IToastNotification)->remove_Failed(get_abi(token)));
}

template <typename D> void consume_Windows_UI_Notifications_IToastNotification2<D>::Tag(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotification2)->put_Tag(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Notifications_IToastNotification2<D>::Tag() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotification2)->get_Tag(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_IToastNotification2<D>::Group(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotification2)->put_Group(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Notifications_IToastNotification2<D>::Group() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotification2)->get_Group(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_IToastNotification2<D>::SuppressPopup(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotification2)->put_SuppressPopup(value));
}

template <typename D> bool consume_Windows_UI_Notifications_IToastNotification2<D>::SuppressPopup() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotification2)->get_SuppressPopup(&value));
    return value;
}

template <typename D> Windows::UI::Notifications::NotificationMirroring consume_Windows_UI_Notifications_IToastNotification3<D>::NotificationMirroring() const
{
    Windows::UI::Notifications::NotificationMirroring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotification3)->get_NotificationMirroring(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_IToastNotification3<D>::NotificationMirroring(Windows::UI::Notifications::NotificationMirroring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotification3)->put_NotificationMirroring(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Notifications_IToastNotification3<D>::RemoteId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotification3)->get_RemoteId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_IToastNotification3<D>::RemoteId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotification3)->put_RemoteId(get_abi(value)));
}

template <typename D> Windows::UI::Notifications::NotificationData consume_Windows_UI_Notifications_IToastNotification4<D>::Data() const
{
    Windows::UI::Notifications::NotificationData value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotification4)->get_Data(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_IToastNotification4<D>::Data(Windows::UI::Notifications::NotificationData const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotification4)->put_Data(get_abi(value)));
}

template <typename D> Windows::UI::Notifications::ToastNotificationPriority consume_Windows_UI_Notifications_IToastNotification4<D>::Priority() const
{
    Windows::UI::Notifications::ToastNotificationPriority value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotification4)->get_Priority(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_IToastNotification4<D>::Priority(Windows::UI::Notifications::ToastNotificationPriority const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotification4)->put_Priority(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Notifications_IToastNotification6<D>::ExpiresOnReboot() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotification6)->get_ExpiresOnReboot(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_IToastNotification6<D>::ExpiresOnReboot(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotification6)->put_ExpiresOnReboot(value));
}

template <typename D> hstring consume_Windows_UI_Notifications_IToastNotificationActionTriggerDetail<D>::Argument() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotificationActionTriggerDetail)->get_Argument(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::ValueSet consume_Windows_UI_Notifications_IToastNotificationActionTriggerDetail<D>::UserInput() const
{
    Windows::Foundation::Collections::ValueSet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotificationActionTriggerDetail)->get_UserInput(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Notifications::ToastNotification consume_Windows_UI_Notifications_IToastNotificationFactory<D>::CreateToastNotification(Windows::Data::Xml::Dom::XmlDocument const& content) const
{
    Windows::UI::Notifications::ToastNotification value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotificationFactory)->CreateToastNotification(get_abi(content), put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_IToastNotificationHistory<D>::RemoveGroup(param::hstring const& group) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotificationHistory)->RemoveGroup(get_abi(group)));
}

template <typename D> void consume_Windows_UI_Notifications_IToastNotificationHistory<D>::RemoveGroup(param::hstring const& group, param::hstring const& applicationId) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotificationHistory)->RemoveGroupWithId(get_abi(group), get_abi(applicationId)));
}

template <typename D> void consume_Windows_UI_Notifications_IToastNotificationHistory<D>::Remove(param::hstring const& tag, param::hstring const& group, param::hstring const& applicationId) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotificationHistory)->RemoveGroupedTagWithId(get_abi(tag), get_abi(group), get_abi(applicationId)));
}

template <typename D> void consume_Windows_UI_Notifications_IToastNotificationHistory<D>::Remove(param::hstring const& tag, param::hstring const& group) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotificationHistory)->RemoveGroupedTag(get_abi(tag), get_abi(group)));
}

template <typename D> void consume_Windows_UI_Notifications_IToastNotificationHistory<D>::Remove(param::hstring const& tag) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotificationHistory)->Remove(get_abi(tag)));
}

template <typename D> void consume_Windows_UI_Notifications_IToastNotificationHistory<D>::Clear() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotificationHistory)->Clear());
}

template <typename D> void consume_Windows_UI_Notifications_IToastNotificationHistory<D>::Clear(param::hstring const& applicationId) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotificationHistory)->ClearWithId(get_abi(applicationId)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::Notifications::ToastNotification> consume_Windows_UI_Notifications_IToastNotificationHistory2<D>::GetHistory() const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::Notifications::ToastNotification> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotificationHistory2)->GetHistory(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::Notifications::ToastNotification> consume_Windows_UI_Notifications_IToastNotificationHistory2<D>::GetHistory(param::hstring const& applicationId) const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::Notifications::ToastNotification> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotificationHistory2)->GetHistoryWithId(get_abi(applicationId), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Notifications::ToastHistoryChangedType consume_Windows_UI_Notifications_IToastNotificationHistoryChangedTriggerDetail<D>::ChangeType() const
{
    Windows::UI::Notifications::ToastHistoryChangedType value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotificationHistoryChangedTriggerDetail)->get_ChangeType(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Notifications_IToastNotificationHistoryChangedTriggerDetail2<D>::CollectionId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotificationHistoryChangedTriggerDetail2)->get_CollectionId(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Notifications::ToastNotifier consume_Windows_UI_Notifications_IToastNotificationManagerForUser<D>::CreateToastNotifier() const
{
    Windows::UI::Notifications::ToastNotifier result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotificationManagerForUser)->CreateToastNotifier(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Notifications::ToastNotifier consume_Windows_UI_Notifications_IToastNotificationManagerForUser<D>::CreateToastNotifier(param::hstring const& applicationId) const
{
    Windows::UI::Notifications::ToastNotifier result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotificationManagerForUser)->CreateToastNotifierWithId(get_abi(applicationId), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Notifications::ToastNotificationHistory consume_Windows_UI_Notifications_IToastNotificationManagerForUser<D>::History() const
{
    Windows::UI::Notifications::ToastNotificationHistory value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotificationManagerForUser)->get_History(put_abi(value)));
    return value;
}

template <typename D> Windows::System::User consume_Windows_UI_Notifications_IToastNotificationManagerForUser<D>::User() const
{
    Windows::System::User value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotificationManagerForUser)->get_User(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::UI::Notifications::ToastNotifier> consume_Windows_UI_Notifications_IToastNotificationManagerForUser2<D>::GetToastNotifierForToastCollectionIdAsync(param::hstring const& collectionId) const
{
    Windows::Foundation::IAsyncOperation<Windows::UI::Notifications::ToastNotifier> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotificationManagerForUser2)->GetToastNotifierForToastCollectionIdAsync(get_abi(collectionId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::UI::Notifications::ToastNotificationHistory> consume_Windows_UI_Notifications_IToastNotificationManagerForUser2<D>::GetHistoryForToastCollectionIdAsync(param::hstring const& collectionId) const
{
    Windows::Foundation::IAsyncOperation<Windows::UI::Notifications::ToastNotificationHistory> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotificationManagerForUser2)->GetHistoryForToastCollectionIdAsync(get_abi(collectionId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::UI::Notifications::ToastCollectionManager consume_Windows_UI_Notifications_IToastNotificationManagerForUser2<D>::GetToastCollectionManager() const
{
    Windows::UI::Notifications::ToastCollectionManager result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotificationManagerForUser2)->GetToastCollectionManager(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Notifications::ToastCollectionManager consume_Windows_UI_Notifications_IToastNotificationManagerForUser2<D>::GetToastCollectionManager(param::hstring const& appId) const
{
    Windows::UI::Notifications::ToastCollectionManager result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotificationManagerForUser2)->GetToastCollectionManagerWithAppId(get_abi(appId), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Notifications::ToastNotifier consume_Windows_UI_Notifications_IToastNotificationManagerStatics<D>::CreateToastNotifier() const
{
    Windows::UI::Notifications::ToastNotifier result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotificationManagerStatics)->CreateToastNotifier(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Notifications::ToastNotifier consume_Windows_UI_Notifications_IToastNotificationManagerStatics<D>::CreateToastNotifier(param::hstring const& applicationId) const
{
    Windows::UI::Notifications::ToastNotifier result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotificationManagerStatics)->CreateToastNotifierWithId(get_abi(applicationId), put_abi(result)));
    return result;
}

template <typename D> Windows::Data::Xml::Dom::XmlDocument consume_Windows_UI_Notifications_IToastNotificationManagerStatics<D>::GetTemplateContent(Windows::UI::Notifications::ToastTemplateType const& type) const
{
    Windows::Data::Xml::Dom::XmlDocument result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotificationManagerStatics)->GetTemplateContent(get_abi(type), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Notifications::ToastNotificationHistory consume_Windows_UI_Notifications_IToastNotificationManagerStatics2<D>::History() const
{
    Windows::UI::Notifications::ToastNotificationHistory value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotificationManagerStatics2)->get_History(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Notifications::ToastNotificationManagerForUser consume_Windows_UI_Notifications_IToastNotificationManagerStatics4<D>::GetForUser(Windows::System::User const& user) const
{
    Windows::UI::Notifications::ToastNotificationManagerForUser result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotificationManagerStatics4)->GetForUser(get_abi(user), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Notifications_IToastNotificationManagerStatics4<D>::ConfigureNotificationMirroring(Windows::UI::Notifications::NotificationMirroring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotificationManagerStatics4)->ConfigureNotificationMirroring(get_abi(value)));
}

template <typename D> Windows::UI::Notifications::ToastNotificationManagerForUser consume_Windows_UI_Notifications_IToastNotificationManagerStatics5<D>::GetDefault() const
{
    Windows::UI::Notifications::ToastNotificationManagerForUser result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotificationManagerStatics5)->GetDefault(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Notifications_IToastNotifier<D>::Show(Windows::UI::Notifications::ToastNotification const& notification) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotifier)->Show(get_abi(notification)));
}

template <typename D> void consume_Windows_UI_Notifications_IToastNotifier<D>::Hide(Windows::UI::Notifications::ToastNotification const& notification) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotifier)->Hide(get_abi(notification)));
}

template <typename D> Windows::UI::Notifications::NotificationSetting consume_Windows_UI_Notifications_IToastNotifier<D>::Setting() const
{
    Windows::UI::Notifications::NotificationSetting value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotifier)->get_Setting(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Notifications_IToastNotifier<D>::AddToSchedule(Windows::UI::Notifications::ScheduledToastNotification const& scheduledToast) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotifier)->AddToSchedule(get_abi(scheduledToast)));
}

template <typename D> void consume_Windows_UI_Notifications_IToastNotifier<D>::RemoveFromSchedule(Windows::UI::Notifications::ScheduledToastNotification const& scheduledToast) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotifier)->RemoveFromSchedule(get_abi(scheduledToast)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::Notifications::ScheduledToastNotification> consume_Windows_UI_Notifications_IToastNotifier<D>::GetScheduledToastNotifications() const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::Notifications::ScheduledToastNotification> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotifier)->GetScheduledToastNotifications(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Notifications::NotificationUpdateResult consume_Windows_UI_Notifications_IToastNotifier2<D>::Update(Windows::UI::Notifications::NotificationData const& data, param::hstring const& tag, param::hstring const& group) const
{
    Windows::UI::Notifications::NotificationUpdateResult result{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotifier2)->UpdateWithTagAndGroup(get_abi(data), get_abi(tag), get_abi(group), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Notifications::NotificationUpdateResult consume_Windows_UI_Notifications_IToastNotifier2<D>::Update(Windows::UI::Notifications::NotificationData const& data, param::hstring const& tag) const
{
    Windows::UI::Notifications::NotificationUpdateResult result{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotifier2)->UpdateWithTag(get_abi(data), get_abi(tag), put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_UI_Notifications_IToastNotifier3<D>::ScheduledToastNotificationShowing(Windows::Foundation::TypedEventHandler<Windows::UI::Notifications::ToastNotifier, Windows::UI::Notifications::ScheduledToastNotificationShowingEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IToastNotifier3)->add_ScheduledToastNotificationShowing(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Notifications_IToastNotifier3<D>::ScheduledToastNotificationShowing_revoker consume_Windows_UI_Notifications_IToastNotifier3<D>::ScheduledToastNotificationShowing(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Notifications::ToastNotifier, Windows::UI::Notifications::ScheduledToastNotificationShowingEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ScheduledToastNotificationShowing_revoker>(this, ScheduledToastNotificationShowing(handler));
}

template <typename D> void consume_Windows_UI_Notifications_IToastNotifier3<D>::ScheduledToastNotificationShowing(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Notifications::IToastNotifier3)->remove_ScheduledToastNotificationShowing(get_abi(token)));
}

template <typename D> Windows::UI::Notifications::Notification consume_Windows_UI_Notifications_IUserNotification<D>::Notification() const
{
    Windows::UI::Notifications::Notification value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IUserNotification)->get_Notification(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::AppInfo consume_Windows_UI_Notifications_IUserNotification<D>::AppInfo() const
{
    Windows::ApplicationModel::AppInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IUserNotification)->get_AppInfo(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_UI_Notifications_IUserNotification<D>::Id() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IUserNotification)->get_Id(&value));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_UI_Notifications_IUserNotification<D>::CreationTime() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IUserNotification)->get_CreationTime(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Notifications::UserNotificationChangedKind consume_Windows_UI_Notifications_IUserNotificationChangedEventArgs<D>::ChangeKind() const
{
    Windows::UI::Notifications::UserNotificationChangedKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IUserNotificationChangedEventArgs)->get_ChangeKind(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_UI_Notifications_IUserNotificationChangedEventArgs<D>::UserNotificationId() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::IUserNotificationChangedEventArgs)->get_UserNotificationId(&value));
    return value;
}

template <typename D>
struct produce<D, Windows::UI::Notifications::IAdaptiveNotificationContent> : produce_base<D, Windows::UI::Notifications::IAdaptiveNotificationContent>
{
    int32_t WINRT_CALL get_Kind(Windows::UI::Notifications::AdaptiveNotificationContentKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::UI::Notifications::AdaptiveNotificationContentKind));
            *value = detach_from<Windows::UI::Notifications::AdaptiveNotificationContentKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Hints(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Hints, WINRT_WRAP(Windows::Foundation::Collections::IMap<hstring, hstring>));
            *value = detach_from<Windows::Foundation::Collections::IMap<hstring, hstring>>(this->shim().Hints());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IAdaptiveNotificationText> : produce_base<D, Windows::UI::Notifications::IAdaptiveNotificationText>
{
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

    int32_t WINRT_CALL get_Language(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Language, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Language());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Language(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Language, WINRT_WRAP(void), hstring const&);
            this->shim().Language(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IBadgeNotification> : produce_base<D, Windows::UI::Notifications::IBadgeNotification>
{
    int32_t WINRT_CALL get_Content(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Content, WINRT_WRAP(Windows::Data::Xml::Dom::XmlDocument));
            *value = detach_from<Windows::Data::Xml::Dom::XmlDocument>(this->shim().Content());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ExpirationTime(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpirationTime, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::DateTime> const&);
            this->shim().ExpirationTime(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExpirationTime(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpirationTime, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().ExpirationTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IBadgeNotificationFactory> : produce_base<D, Windows::UI::Notifications::IBadgeNotificationFactory>
{
    int32_t WINRT_CALL CreateBadgeNotification(void* content, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateBadgeNotification, WINRT_WRAP(Windows::UI::Notifications::BadgeNotification), Windows::Data::Xml::Dom::XmlDocument const&);
            *value = detach_from<Windows::UI::Notifications::BadgeNotification>(this->shim().CreateBadgeNotification(*reinterpret_cast<Windows::Data::Xml::Dom::XmlDocument const*>(&content)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IBadgeUpdateManagerForUser> : produce_base<D, Windows::UI::Notifications::IBadgeUpdateManagerForUser>
{
    int32_t WINRT_CALL CreateBadgeUpdaterForApplication(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateBadgeUpdaterForApplication, WINRT_WRAP(Windows::UI::Notifications::BadgeUpdater));
            *result = detach_from<Windows::UI::Notifications::BadgeUpdater>(this->shim().CreateBadgeUpdaterForApplication());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateBadgeUpdaterForApplicationWithId(void* applicationId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateBadgeUpdaterForApplication, WINRT_WRAP(Windows::UI::Notifications::BadgeUpdater), hstring const&);
            *result = detach_from<Windows::UI::Notifications::BadgeUpdater>(this->shim().CreateBadgeUpdaterForApplication(*reinterpret_cast<hstring const*>(&applicationId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateBadgeUpdaterForSecondaryTile(void* tileId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateBadgeUpdaterForSecondaryTile, WINRT_WRAP(Windows::UI::Notifications::BadgeUpdater), hstring const&);
            *result = detach_from<Windows::UI::Notifications::BadgeUpdater>(this->shim().CreateBadgeUpdaterForSecondaryTile(*reinterpret_cast<hstring const*>(&tileId)));
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
struct produce<D, Windows::UI::Notifications::IBadgeUpdateManagerStatics> : produce_base<D, Windows::UI::Notifications::IBadgeUpdateManagerStatics>
{
    int32_t WINRT_CALL CreateBadgeUpdaterForApplication(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateBadgeUpdaterForApplication, WINRT_WRAP(Windows::UI::Notifications::BadgeUpdater));
            *result = detach_from<Windows::UI::Notifications::BadgeUpdater>(this->shim().CreateBadgeUpdaterForApplication());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateBadgeUpdaterForApplicationWithId(void* applicationId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateBadgeUpdaterForApplication, WINRT_WRAP(Windows::UI::Notifications::BadgeUpdater), hstring const&);
            *result = detach_from<Windows::UI::Notifications::BadgeUpdater>(this->shim().CreateBadgeUpdaterForApplication(*reinterpret_cast<hstring const*>(&applicationId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateBadgeUpdaterForSecondaryTile(void* tileId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateBadgeUpdaterForSecondaryTile, WINRT_WRAP(Windows::UI::Notifications::BadgeUpdater), hstring const&);
            *result = detach_from<Windows::UI::Notifications::BadgeUpdater>(this->shim().CreateBadgeUpdaterForSecondaryTile(*reinterpret_cast<hstring const*>(&tileId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetTemplateContent(Windows::UI::Notifications::BadgeTemplateType type, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTemplateContent, WINRT_WRAP(Windows::Data::Xml::Dom::XmlDocument), Windows::UI::Notifications::BadgeTemplateType const&);
            *result = detach_from<Windows::Data::Xml::Dom::XmlDocument>(this->shim().GetTemplateContent(*reinterpret_cast<Windows::UI::Notifications::BadgeTemplateType const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IBadgeUpdateManagerStatics2> : produce_base<D, Windows::UI::Notifications::IBadgeUpdateManagerStatics2>
{
    int32_t WINRT_CALL GetForUser(void* user, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForUser, WINRT_WRAP(Windows::UI::Notifications::BadgeUpdateManagerForUser), Windows::System::User const&);
            *result = detach_from<Windows::UI::Notifications::BadgeUpdateManagerForUser>(this->shim().GetForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IBadgeUpdater> : produce_base<D, Windows::UI::Notifications::IBadgeUpdater>
{
    int32_t WINRT_CALL Update(void* notification) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Update, WINRT_WRAP(void), Windows::UI::Notifications::BadgeNotification const&);
            this->shim().Update(*reinterpret_cast<Windows::UI::Notifications::BadgeNotification const*>(&notification));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Clear() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Clear, WINRT_WRAP(void));
            this->shim().Clear();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartPeriodicUpdate(void* badgeContent, Windows::UI::Notifications::PeriodicUpdateRecurrence requestedInterval) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartPeriodicUpdate, WINRT_WRAP(void), Windows::Foundation::Uri const&, Windows::UI::Notifications::PeriodicUpdateRecurrence const&);
            this->shim().StartPeriodicUpdate(*reinterpret_cast<Windows::Foundation::Uri const*>(&badgeContent), *reinterpret_cast<Windows::UI::Notifications::PeriodicUpdateRecurrence const*>(&requestedInterval));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartPeriodicUpdateAtTime(void* badgeContent, Windows::Foundation::DateTime startTime, Windows::UI::Notifications::PeriodicUpdateRecurrence requestedInterval) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartPeriodicUpdate, WINRT_WRAP(void), Windows::Foundation::Uri const&, Windows::Foundation::DateTime const&, Windows::UI::Notifications::PeriodicUpdateRecurrence const&);
            this->shim().StartPeriodicUpdate(*reinterpret_cast<Windows::Foundation::Uri const*>(&badgeContent), *reinterpret_cast<Windows::Foundation::DateTime const*>(&startTime), *reinterpret_cast<Windows::UI::Notifications::PeriodicUpdateRecurrence const*>(&requestedInterval));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopPeriodicUpdate() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopPeriodicUpdate, WINRT_WRAP(void));
            this->shim().StopPeriodicUpdate();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IKnownAdaptiveNotificationHintsStatics> : produce_base<D, Windows::UI::Notifications::IKnownAdaptiveNotificationHintsStatics>
{
    int32_t WINRT_CALL get_Style(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Style, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Style());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Wrap(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Wrap, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Wrap());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxLines(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxLines, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MaxLines());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinLines(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinLines, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MinLines());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TextStacking(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TextStacking, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TextStacking());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Align(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Align, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Align());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics> : produce_base<D, Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics>
{
    int32_t WINRT_CALL get_Caption(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Caption, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Caption());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Body(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Body, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Body());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Base(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Base, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Base());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Subtitle(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Subtitle, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Subtitle());
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

    int32_t WINRT_CALL get_Subheader(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Subheader, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Subheader());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Header(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Header, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Header());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TitleNumeral(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TitleNumeral, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TitleNumeral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SubheaderNumeral(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SubheaderNumeral, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SubheaderNumeral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HeaderNumeral(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeaderNumeral, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().HeaderNumeral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CaptionSubtle(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CaptionSubtle, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CaptionSubtle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BodySubtle(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BodySubtle, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BodySubtle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BaseSubtle(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BaseSubtle, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BaseSubtle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SubtitleSubtle(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SubtitleSubtle, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SubtitleSubtle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TitleSubtle(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TitleSubtle, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TitleSubtle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SubheaderSubtle(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SubheaderSubtle, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SubheaderSubtle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SubheaderNumeralSubtle(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SubheaderNumeralSubtle, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SubheaderNumeralSubtle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HeaderSubtle(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeaderSubtle, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().HeaderSubtle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HeaderNumeralSubtle(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeaderNumeralSubtle, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().HeaderNumeralSubtle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IKnownNotificationBindingsStatics> : produce_base<D, Windows::UI::Notifications::IKnownNotificationBindingsStatics>
{
    int32_t WINRT_CALL get_ToastGeneric(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToastGeneric, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ToastGeneric());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::INotification> : produce_base<D, Windows::UI::Notifications::INotification>
{
    int32_t WINRT_CALL get_ExpirationTime(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpirationTime, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().ExpirationTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ExpirationTime(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpirationTime, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::DateTime> const&);
            this->shim().ExpirationTime(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Visual(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Visual, WINRT_WRAP(Windows::UI::Notifications::NotificationVisual));
            *value = detach_from<Windows::UI::Notifications::NotificationVisual>(this->shim().Visual());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Visual(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Visual, WINRT_WRAP(void), Windows::UI::Notifications::NotificationVisual const&);
            this->shim().Visual(*reinterpret_cast<Windows::UI::Notifications::NotificationVisual const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::INotificationBinding> : produce_base<D, Windows::UI::Notifications::INotificationBinding>
{
    int32_t WINRT_CALL get_Template(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Template, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Template());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Template(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Template, WINRT_WRAP(void), hstring const&);
            this->shim().Template(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Language(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Language, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Language());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Language(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Language, WINRT_WRAP(void), hstring const&);
            this->shim().Language(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Hints(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Hints, WINRT_WRAP(Windows::Foundation::Collections::IMap<hstring, hstring>));
            *value = detach_from<Windows::Foundation::Collections::IMap<hstring, hstring>>(this->shim().Hints());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetTextElements(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTextElements, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::Notifications::AdaptiveNotificationText>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::Notifications::AdaptiveNotificationText>>(this->shim().GetTextElements());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::INotificationData> : produce_base<D, Windows::UI::Notifications::INotificationData>
{
    int32_t WINRT_CALL get_Values(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Values, WINRT_WRAP(Windows::Foundation::Collections::IMap<hstring, hstring>));
            *value = detach_from<Windows::Foundation::Collections::IMap<hstring, hstring>>(this->shim().Values());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SequenceNumber(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SequenceNumber, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().SequenceNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SequenceNumber(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SequenceNumber, WINRT_WRAP(void), uint32_t);
            this->shim().SequenceNumber(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::INotificationDataFactory> : produce_base<D, Windows::UI::Notifications::INotificationDataFactory>
{
    int32_t WINRT_CALL CreateNotificationDataWithValuesAndSequenceNumber(void* initialValues, uint32_t sequenceNumber, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateNotificationData, WINRT_WRAP(Windows::UI::Notifications::NotificationData), Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const&, uint32_t);
            *value = detach_from<Windows::UI::Notifications::NotificationData>(this->shim().CreateNotificationData(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const*>(&initialValues), sequenceNumber));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateNotificationDataWithValues(void* initialValues, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateNotificationData, WINRT_WRAP(Windows::UI::Notifications::NotificationData), Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const&);
            *value = detach_from<Windows::UI::Notifications::NotificationData>(this->shim().CreateNotificationData(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const*>(&initialValues)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::INotificationVisual> : produce_base<D, Windows::UI::Notifications::INotificationVisual>
{
    int32_t WINRT_CALL get_Language(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Language, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Language());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Language(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Language, WINRT_WRAP(void), hstring const&);
            this->shim().Language(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Bindings(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bindings, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Notifications::NotificationBinding>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Notifications::NotificationBinding>>(this->shim().Bindings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetBinding(void* templateName, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetBinding, WINRT_WRAP(Windows::UI::Notifications::NotificationBinding), hstring const&);
            *result = detach_from<Windows::UI::Notifications::NotificationBinding>(this->shim().GetBinding(*reinterpret_cast<hstring const*>(&templateName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IScheduledTileNotification> : produce_base<D, Windows::UI::Notifications::IScheduledTileNotification>
{
    int32_t WINRT_CALL get_Content(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Content, WINRT_WRAP(Windows::Data::Xml::Dom::XmlDocument));
            *value = detach_from<Windows::Data::Xml::Dom::XmlDocument>(this->shim().Content());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeliveryTime(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeliveryTime, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().DeliveryTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ExpirationTime(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpirationTime, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::DateTime> const&);
            this->shim().ExpirationTime(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExpirationTime(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpirationTime, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().ExpirationTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Tag(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tag, WINRT_WRAP(void), hstring const&);
            this->shim().Tag(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Tag(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tag, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Tag());
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
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IScheduledTileNotificationFactory> : produce_base<D, Windows::UI::Notifications::IScheduledTileNotificationFactory>
{
    int32_t WINRT_CALL CreateScheduledTileNotification(void* content, Windows::Foundation::DateTime deliveryTime, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateScheduledTileNotification, WINRT_WRAP(Windows::UI::Notifications::ScheduledTileNotification), Windows::Data::Xml::Dom::XmlDocument const&, Windows::Foundation::DateTime const&);
            *value = detach_from<Windows::UI::Notifications::ScheduledTileNotification>(this->shim().CreateScheduledTileNotification(*reinterpret_cast<Windows::Data::Xml::Dom::XmlDocument const*>(&content), *reinterpret_cast<Windows::Foundation::DateTime const*>(&deliveryTime)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IScheduledToastNotification> : produce_base<D, Windows::UI::Notifications::IScheduledToastNotification>
{
    int32_t WINRT_CALL get_Content(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Content, WINRT_WRAP(Windows::Data::Xml::Dom::XmlDocument));
            *value = detach_from<Windows::Data::Xml::Dom::XmlDocument>(this->shim().Content());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeliveryTime(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeliveryTime, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().DeliveryTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SnoozeInterval(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SnoozeInterval, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().SnoozeInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaximumSnoozeCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaximumSnoozeCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaximumSnoozeCount());
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
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IScheduledToastNotification2> : produce_base<D, Windows::UI::Notifications::IScheduledToastNotification2>
{
    int32_t WINRT_CALL put_Tag(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tag, WINRT_WRAP(void), hstring const&);
            this->shim().Tag(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Tag(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tag, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Tag());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Group(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Group, WINRT_WRAP(void), hstring const&);
            this->shim().Group(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Group(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Group, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Group());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SuppressPopup(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SuppressPopup, WINRT_WRAP(void), bool);
            this->shim().SuppressPopup(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SuppressPopup(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SuppressPopup, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().SuppressPopup());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IScheduledToastNotification3> : produce_base<D, Windows::UI::Notifications::IScheduledToastNotification3>
{
    int32_t WINRT_CALL get_NotificationMirroring(Windows::UI::Notifications::NotificationMirroring* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotificationMirroring, WINRT_WRAP(Windows::UI::Notifications::NotificationMirroring));
            *value = detach_from<Windows::UI::Notifications::NotificationMirroring>(this->shim().NotificationMirroring());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_NotificationMirroring(Windows::UI::Notifications::NotificationMirroring value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotificationMirroring, WINRT_WRAP(void), Windows::UI::Notifications::NotificationMirroring const&);
            this->shim().NotificationMirroring(*reinterpret_cast<Windows::UI::Notifications::NotificationMirroring const*>(&value));
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
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IScheduledToastNotification4> : produce_base<D, Windows::UI::Notifications::IScheduledToastNotification4>
{
    int32_t WINRT_CALL get_ExpirationTime(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpirationTime, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().ExpirationTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ExpirationTime(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpirationTime, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::DateTime> const&);
            this->shim().ExpirationTime(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IScheduledToastNotificationFactory> : produce_base<D, Windows::UI::Notifications::IScheduledToastNotificationFactory>
{
    int32_t WINRT_CALL CreateScheduledToastNotification(void* content, Windows::Foundation::DateTime deliveryTime, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateScheduledToastNotification, WINRT_WRAP(Windows::UI::Notifications::ScheduledToastNotification), Windows::Data::Xml::Dom::XmlDocument const&, Windows::Foundation::DateTime const&);
            *value = detach_from<Windows::UI::Notifications::ScheduledToastNotification>(this->shim().CreateScheduledToastNotification(*reinterpret_cast<Windows::Data::Xml::Dom::XmlDocument const*>(&content), *reinterpret_cast<Windows::Foundation::DateTime const*>(&deliveryTime)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateScheduledToastNotificationRecurring(void* content, Windows::Foundation::DateTime deliveryTime, Windows::Foundation::TimeSpan snoozeInterval, uint32_t maximumSnoozeCount, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateScheduledToastNotificationRecurring, WINRT_WRAP(Windows::UI::Notifications::ScheduledToastNotification), Windows::Data::Xml::Dom::XmlDocument const&, Windows::Foundation::DateTime const&, Windows::Foundation::TimeSpan const&, uint32_t);
            *value = detach_from<Windows::UI::Notifications::ScheduledToastNotification>(this->shim().CreateScheduledToastNotificationRecurring(*reinterpret_cast<Windows::Data::Xml::Dom::XmlDocument const*>(&content), *reinterpret_cast<Windows::Foundation::DateTime const*>(&deliveryTime), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&snoozeInterval), maximumSnoozeCount));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IScheduledToastNotificationShowingEventArgs> : produce_base<D, Windows::UI::Notifications::IScheduledToastNotificationShowingEventArgs>
{
    int32_t WINRT_CALL get_Cancel(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cancel, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Cancel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Cancel(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cancel, WINRT_WRAP(void), bool);
            this->shim().Cancel(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScheduledToastNotification(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScheduledToastNotification, WINRT_WRAP(Windows::UI::Notifications::ScheduledToastNotification));
            *value = detach_from<Windows::UI::Notifications::ScheduledToastNotification>(this->shim().ScheduledToastNotification());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeferral(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Foundation::Deferral));
            *result = detach_from<Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IShownTileNotification> : produce_base<D, Windows::UI::Notifications::IShownTileNotification>
{
    int32_t WINRT_CALL get_Arguments(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Arguments, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Arguments());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::ITileFlyoutNotification> : produce_base<D, Windows::UI::Notifications::ITileFlyoutNotification>
{
    int32_t WINRT_CALL get_Content(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Content, WINRT_WRAP(Windows::Data::Xml::Dom::XmlDocument));
            *value = detach_from<Windows::Data::Xml::Dom::XmlDocument>(this->shim().Content());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ExpirationTime(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpirationTime, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::DateTime> const&);
            this->shim().ExpirationTime(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExpirationTime(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpirationTime, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().ExpirationTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::ITileFlyoutNotificationFactory> : produce_base<D, Windows::UI::Notifications::ITileFlyoutNotificationFactory>
{
    int32_t WINRT_CALL CreateTileFlyoutNotification(void* content, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateTileFlyoutNotification, WINRT_WRAP(Windows::UI::Notifications::TileFlyoutNotification), Windows::Data::Xml::Dom::XmlDocument const&);
            *value = detach_from<Windows::UI::Notifications::TileFlyoutNotification>(this->shim().CreateTileFlyoutNotification(*reinterpret_cast<Windows::Data::Xml::Dom::XmlDocument const*>(&content)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::ITileFlyoutUpdateManagerStatics> : produce_base<D, Windows::UI::Notifications::ITileFlyoutUpdateManagerStatics>
{
    int32_t WINRT_CALL CreateTileFlyoutUpdaterForApplication(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateTileFlyoutUpdaterForApplication, WINRT_WRAP(Windows::UI::Notifications::TileFlyoutUpdater));
            *result = detach_from<Windows::UI::Notifications::TileFlyoutUpdater>(this->shim().CreateTileFlyoutUpdaterForApplication());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateTileFlyoutUpdaterForApplicationWithId(void* applicationId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateTileFlyoutUpdaterForApplication, WINRT_WRAP(Windows::UI::Notifications::TileFlyoutUpdater), hstring const&);
            *result = detach_from<Windows::UI::Notifications::TileFlyoutUpdater>(this->shim().CreateTileFlyoutUpdaterForApplication(*reinterpret_cast<hstring const*>(&applicationId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateTileFlyoutUpdaterForSecondaryTile(void* tileId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateTileFlyoutUpdaterForSecondaryTile, WINRT_WRAP(Windows::UI::Notifications::TileFlyoutUpdater), hstring const&);
            *result = detach_from<Windows::UI::Notifications::TileFlyoutUpdater>(this->shim().CreateTileFlyoutUpdaterForSecondaryTile(*reinterpret_cast<hstring const*>(&tileId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetTemplateContent(Windows::UI::Notifications::TileFlyoutTemplateType type, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTemplateContent, WINRT_WRAP(Windows::Data::Xml::Dom::XmlDocument), Windows::UI::Notifications::TileFlyoutTemplateType const&);
            *result = detach_from<Windows::Data::Xml::Dom::XmlDocument>(this->shim().GetTemplateContent(*reinterpret_cast<Windows::UI::Notifications::TileFlyoutTemplateType const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::ITileFlyoutUpdater> : produce_base<D, Windows::UI::Notifications::ITileFlyoutUpdater>
{
    int32_t WINRT_CALL Update(void* notification) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Update, WINRT_WRAP(void), Windows::UI::Notifications::TileFlyoutNotification const&);
            this->shim().Update(*reinterpret_cast<Windows::UI::Notifications::TileFlyoutNotification const*>(&notification));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Clear() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Clear, WINRT_WRAP(void));
            this->shim().Clear();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartPeriodicUpdate(void* tileFlyoutContent, Windows::UI::Notifications::PeriodicUpdateRecurrence requestedInterval) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartPeriodicUpdate, WINRT_WRAP(void), Windows::Foundation::Uri const&, Windows::UI::Notifications::PeriodicUpdateRecurrence const&);
            this->shim().StartPeriodicUpdate(*reinterpret_cast<Windows::Foundation::Uri const*>(&tileFlyoutContent), *reinterpret_cast<Windows::UI::Notifications::PeriodicUpdateRecurrence const*>(&requestedInterval));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartPeriodicUpdateAtTime(void* tileFlyoutContent, Windows::Foundation::DateTime startTime, Windows::UI::Notifications::PeriodicUpdateRecurrence requestedInterval) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartPeriodicUpdate, WINRT_WRAP(void), Windows::Foundation::Uri const&, Windows::Foundation::DateTime const&, Windows::UI::Notifications::PeriodicUpdateRecurrence const&);
            this->shim().StartPeriodicUpdate(*reinterpret_cast<Windows::Foundation::Uri const*>(&tileFlyoutContent), *reinterpret_cast<Windows::Foundation::DateTime const*>(&startTime), *reinterpret_cast<Windows::UI::Notifications::PeriodicUpdateRecurrence const*>(&requestedInterval));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopPeriodicUpdate() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopPeriodicUpdate, WINRT_WRAP(void));
            this->shim().StopPeriodicUpdate();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Setting(Windows::UI::Notifications::NotificationSetting* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Setting, WINRT_WRAP(Windows::UI::Notifications::NotificationSetting));
            *value = detach_from<Windows::UI::Notifications::NotificationSetting>(this->shim().Setting());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::ITileNotification> : produce_base<D, Windows::UI::Notifications::ITileNotification>
{
    int32_t WINRT_CALL get_Content(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Content, WINRT_WRAP(Windows::Data::Xml::Dom::XmlDocument));
            *value = detach_from<Windows::Data::Xml::Dom::XmlDocument>(this->shim().Content());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ExpirationTime(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpirationTime, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::DateTime> const&);
            this->shim().ExpirationTime(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExpirationTime(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpirationTime, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().ExpirationTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Tag(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tag, WINRT_WRAP(void), hstring const&);
            this->shim().Tag(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Tag(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tag, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Tag());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::ITileNotificationFactory> : produce_base<D, Windows::UI::Notifications::ITileNotificationFactory>
{
    int32_t WINRT_CALL CreateTileNotification(void* content, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateTileNotification, WINRT_WRAP(Windows::UI::Notifications::TileNotification), Windows::Data::Xml::Dom::XmlDocument const&);
            *value = detach_from<Windows::UI::Notifications::TileNotification>(this->shim().CreateTileNotification(*reinterpret_cast<Windows::Data::Xml::Dom::XmlDocument const*>(&content)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::ITileUpdateManagerForUser> : produce_base<D, Windows::UI::Notifications::ITileUpdateManagerForUser>
{
    int32_t WINRT_CALL CreateTileUpdaterForApplication(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateTileUpdaterForApplicationForUser, WINRT_WRAP(Windows::UI::Notifications::TileUpdater));
            *result = detach_from<Windows::UI::Notifications::TileUpdater>(this->shim().CreateTileUpdaterForApplicationForUser());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateTileUpdaterForApplicationWithId(void* applicationId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateTileUpdaterForApplication, WINRT_WRAP(Windows::UI::Notifications::TileUpdater), hstring const&);
            *result = detach_from<Windows::UI::Notifications::TileUpdater>(this->shim().CreateTileUpdaterForApplication(*reinterpret_cast<hstring const*>(&applicationId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateTileUpdaterForSecondaryTile(void* tileId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateTileUpdaterForSecondaryTile, WINRT_WRAP(Windows::UI::Notifications::TileUpdater), hstring const&);
            *result = detach_from<Windows::UI::Notifications::TileUpdater>(this->shim().CreateTileUpdaterForSecondaryTile(*reinterpret_cast<hstring const*>(&tileId)));
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
struct produce<D, Windows::UI::Notifications::ITileUpdateManagerStatics> : produce_base<D, Windows::UI::Notifications::ITileUpdateManagerStatics>
{
    int32_t WINRT_CALL CreateTileUpdaterForApplication(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateTileUpdaterForApplication, WINRT_WRAP(Windows::UI::Notifications::TileUpdater));
            *result = detach_from<Windows::UI::Notifications::TileUpdater>(this->shim().CreateTileUpdaterForApplication());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateTileUpdaterForApplicationWithId(void* applicationId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateTileUpdaterForApplication, WINRT_WRAP(Windows::UI::Notifications::TileUpdater), hstring const&);
            *result = detach_from<Windows::UI::Notifications::TileUpdater>(this->shim().CreateTileUpdaterForApplication(*reinterpret_cast<hstring const*>(&applicationId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateTileUpdaterForSecondaryTile(void* tileId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateTileUpdaterForSecondaryTile, WINRT_WRAP(Windows::UI::Notifications::TileUpdater), hstring const&);
            *result = detach_from<Windows::UI::Notifications::TileUpdater>(this->shim().CreateTileUpdaterForSecondaryTile(*reinterpret_cast<hstring const*>(&tileId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetTemplateContent(Windows::UI::Notifications::TileTemplateType type, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTemplateContent, WINRT_WRAP(Windows::Data::Xml::Dom::XmlDocument), Windows::UI::Notifications::TileTemplateType const&);
            *result = detach_from<Windows::Data::Xml::Dom::XmlDocument>(this->shim().GetTemplateContent(*reinterpret_cast<Windows::UI::Notifications::TileTemplateType const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::ITileUpdateManagerStatics2> : produce_base<D, Windows::UI::Notifications::ITileUpdateManagerStatics2>
{
    int32_t WINRT_CALL GetForUser(void* user, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForUser, WINRT_WRAP(Windows::UI::Notifications::TileUpdateManagerForUser), Windows::System::User const&);
            *result = detach_from<Windows::UI::Notifications::TileUpdateManagerForUser>(this->shim().GetForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::ITileUpdater> : produce_base<D, Windows::UI::Notifications::ITileUpdater>
{
    int32_t WINRT_CALL Update(void* notification) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Update, WINRT_WRAP(void), Windows::UI::Notifications::TileNotification const&);
            this->shim().Update(*reinterpret_cast<Windows::UI::Notifications::TileNotification const*>(&notification));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Clear() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Clear, WINRT_WRAP(void));
            this->shim().Clear();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EnableNotificationQueue(bool enable) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableNotificationQueue, WINRT_WRAP(void), bool);
            this->shim().EnableNotificationQueue(enable);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Setting(Windows::UI::Notifications::NotificationSetting* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Setting, WINRT_WRAP(Windows::UI::Notifications::NotificationSetting));
            *value = detach_from<Windows::UI::Notifications::NotificationSetting>(this->shim().Setting());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddToSchedule(void* scheduledTile) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddToSchedule, WINRT_WRAP(void), Windows::UI::Notifications::ScheduledTileNotification const&);
            this->shim().AddToSchedule(*reinterpret_cast<Windows::UI::Notifications::ScheduledTileNotification const*>(&scheduledTile));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveFromSchedule(void* scheduledTile) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveFromSchedule, WINRT_WRAP(void), Windows::UI::Notifications::ScheduledTileNotification const&);
            this->shim().RemoveFromSchedule(*reinterpret_cast<Windows::UI::Notifications::ScheduledTileNotification const*>(&scheduledTile));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetScheduledTileNotifications(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetScheduledTileNotifications, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::Notifications::ScheduledTileNotification>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::Notifications::ScheduledTileNotification>>(this->shim().GetScheduledTileNotifications());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartPeriodicUpdate(void* tileContent, Windows::UI::Notifications::PeriodicUpdateRecurrence requestedInterval) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartPeriodicUpdate, WINRT_WRAP(void), Windows::Foundation::Uri const&, Windows::UI::Notifications::PeriodicUpdateRecurrence const&);
            this->shim().StartPeriodicUpdate(*reinterpret_cast<Windows::Foundation::Uri const*>(&tileContent), *reinterpret_cast<Windows::UI::Notifications::PeriodicUpdateRecurrence const*>(&requestedInterval));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartPeriodicUpdateAtTime(void* tileContent, Windows::Foundation::DateTime startTime, Windows::UI::Notifications::PeriodicUpdateRecurrence requestedInterval) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartPeriodicUpdate, WINRT_WRAP(void), Windows::Foundation::Uri const&, Windows::Foundation::DateTime const&, Windows::UI::Notifications::PeriodicUpdateRecurrence const&);
            this->shim().StartPeriodicUpdate(*reinterpret_cast<Windows::Foundation::Uri const*>(&tileContent), *reinterpret_cast<Windows::Foundation::DateTime const*>(&startTime), *reinterpret_cast<Windows::UI::Notifications::PeriodicUpdateRecurrence const*>(&requestedInterval));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopPeriodicUpdate() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopPeriodicUpdate, WINRT_WRAP(void));
            this->shim().StopPeriodicUpdate();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartPeriodicUpdateBatch(void* tileContents, Windows::UI::Notifications::PeriodicUpdateRecurrence requestedInterval) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartPeriodicUpdateBatch, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const&, Windows::UI::Notifications::PeriodicUpdateRecurrence const&);
            this->shim().StartPeriodicUpdateBatch(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const*>(&tileContents), *reinterpret_cast<Windows::UI::Notifications::PeriodicUpdateRecurrence const*>(&requestedInterval));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartPeriodicUpdateBatchAtTime(void* tileContents, Windows::Foundation::DateTime startTime, Windows::UI::Notifications::PeriodicUpdateRecurrence requestedInterval) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartPeriodicUpdateBatch, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const&, Windows::Foundation::DateTime const&, Windows::UI::Notifications::PeriodicUpdateRecurrence const&);
            this->shim().StartPeriodicUpdateBatch(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const*>(&tileContents), *reinterpret_cast<Windows::Foundation::DateTime const*>(&startTime), *reinterpret_cast<Windows::UI::Notifications::PeriodicUpdateRecurrence const*>(&requestedInterval));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::ITileUpdater2> : produce_base<D, Windows::UI::Notifications::ITileUpdater2>
{
    int32_t WINRT_CALL EnableNotificationQueueForSquare150x150(bool enable) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableNotificationQueueForSquare150x150, WINRT_WRAP(void), bool);
            this->shim().EnableNotificationQueueForSquare150x150(enable);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EnableNotificationQueueForWide310x150(bool enable) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableNotificationQueueForWide310x150, WINRT_WRAP(void), bool);
            this->shim().EnableNotificationQueueForWide310x150(enable);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EnableNotificationQueueForSquare310x310(bool enable) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableNotificationQueueForSquare310x310, WINRT_WRAP(void), bool);
            this->shim().EnableNotificationQueueForSquare310x310(enable);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IToastActivatedEventArgs> : produce_base<D, Windows::UI::Notifications::IToastActivatedEventArgs>
{
    int32_t WINRT_CALL get_Arguments(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Arguments, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Arguments());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IToastActivatedEventArgs2> : produce_base<D, Windows::UI::Notifications::IToastActivatedEventArgs2>
{
    int32_t WINRT_CALL get_UserInput(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserInput, WINRT_WRAP(Windows::Foundation::Collections::ValueSet));
            *value = detach_from<Windows::Foundation::Collections::ValueSet>(this->shim().UserInput());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IToastCollection> : produce_base<D, Windows::UI::Notifications::IToastCollection>
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

    int32_t WINRT_CALL get_LaunchArgs(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchArgs, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().LaunchArgs());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LaunchArgs(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchArgs, WINRT_WRAP(void), hstring const&);
            this->shim().LaunchArgs(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Icon(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Icon, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Icon());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Icon(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Icon, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().Icon(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IToastCollectionFactory> : produce_base<D, Windows::UI::Notifications::IToastCollectionFactory>
{
    int32_t WINRT_CALL CreateInstance(void* collectionId, void* displayName, void* launchArgs, void* iconUri, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Notifications::ToastCollection), hstring const&, hstring const&, hstring const&, Windows::Foundation::Uri const&);
            *value = detach_from<Windows::UI::Notifications::ToastCollection>(this->shim().CreateInstance(*reinterpret_cast<hstring const*>(&collectionId), *reinterpret_cast<hstring const*>(&displayName), *reinterpret_cast<hstring const*>(&launchArgs), *reinterpret_cast<Windows::Foundation::Uri const*>(&iconUri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IToastCollectionManager> : produce_base<D, Windows::UI::Notifications::IToastCollectionManager>
{
    int32_t WINRT_CALL SaveToastCollectionAsync(void* collection, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveToastCollectionAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::UI::Notifications::ToastCollection const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SaveToastCollectionAsync(*reinterpret_cast<Windows::UI::Notifications::ToastCollection const*>(&collection)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAllToastCollectionsAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAllToastCollectionsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::UI::Notifications::ToastCollection>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::UI::Notifications::ToastCollection>>>(this->shim().FindAllToastCollectionsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetToastCollectionAsync(void* collectionId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetToastCollectionAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::UI::Notifications::ToastCollection>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::UI::Notifications::ToastCollection>>(this->shim().GetToastCollectionAsync(*reinterpret_cast<hstring const*>(&collectionId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveToastCollectionAsync(void* collectionId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveToastCollectionAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().RemoveToastCollectionAsync(*reinterpret_cast<hstring const*>(&collectionId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveAllToastCollectionsAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveAllToastCollectionsAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().RemoveAllToastCollectionsAsync());
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

    int32_t WINRT_CALL get_AppId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AppId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IToastDismissedEventArgs> : produce_base<D, Windows::UI::Notifications::IToastDismissedEventArgs>
{
    int32_t WINRT_CALL get_Reason(Windows::UI::Notifications::ToastDismissalReason* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reason, WINRT_WRAP(Windows::UI::Notifications::ToastDismissalReason));
            *value = detach_from<Windows::UI::Notifications::ToastDismissalReason>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IToastFailedEventArgs> : produce_base<D, Windows::UI::Notifications::IToastFailedEventArgs>
{
    int32_t WINRT_CALL get_ErrorCode(winrt::hresult* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ErrorCode, WINRT_WRAP(winrt::hresult));
            *value = detach_from<winrt::hresult>(this->shim().ErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IToastNotification> : produce_base<D, Windows::UI::Notifications::IToastNotification>
{
    int32_t WINRT_CALL get_Content(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Content, WINRT_WRAP(Windows::Data::Xml::Dom::XmlDocument));
            *value = detach_from<Windows::Data::Xml::Dom::XmlDocument>(this->shim().Content());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ExpirationTime(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpirationTime, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::DateTime> const&);
            this->shim().ExpirationTime(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExpirationTime(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpirationTime, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().ExpirationTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Dismissed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Dismissed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Notifications::ToastNotification, Windows::UI::Notifications::ToastDismissedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Dismissed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Notifications::ToastNotification, Windows::UI::Notifications::ToastDismissedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Dismissed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Dismissed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Dismissed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Activated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Activated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Notifications::ToastNotification, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Activated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Notifications::ToastNotification, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Activated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Activated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Activated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Failed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Failed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Notifications::ToastNotification, Windows::UI::Notifications::ToastFailedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Failed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Notifications::ToastNotification, Windows::UI::Notifications::ToastFailedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Failed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Failed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Failed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IToastNotification2> : produce_base<D, Windows::UI::Notifications::IToastNotification2>
{
    int32_t WINRT_CALL put_Tag(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tag, WINRT_WRAP(void), hstring const&);
            this->shim().Tag(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Tag(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tag, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Tag());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Group(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Group, WINRT_WRAP(void), hstring const&);
            this->shim().Group(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Group(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Group, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Group());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SuppressPopup(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SuppressPopup, WINRT_WRAP(void), bool);
            this->shim().SuppressPopup(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SuppressPopup(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SuppressPopup, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().SuppressPopup());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IToastNotification3> : produce_base<D, Windows::UI::Notifications::IToastNotification3>
{
    int32_t WINRT_CALL get_NotificationMirroring(Windows::UI::Notifications::NotificationMirroring* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotificationMirroring, WINRT_WRAP(Windows::UI::Notifications::NotificationMirroring));
            *value = detach_from<Windows::UI::Notifications::NotificationMirroring>(this->shim().NotificationMirroring());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_NotificationMirroring(Windows::UI::Notifications::NotificationMirroring value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotificationMirroring, WINRT_WRAP(void), Windows::UI::Notifications::NotificationMirroring const&);
            this->shim().NotificationMirroring(*reinterpret_cast<Windows::UI::Notifications::NotificationMirroring const*>(&value));
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
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IToastNotification4> : produce_base<D, Windows::UI::Notifications::IToastNotification4>
{
    int32_t WINRT_CALL get_Data(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Data, WINRT_WRAP(Windows::UI::Notifications::NotificationData));
            *value = detach_from<Windows::UI::Notifications::NotificationData>(this->shim().Data());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Data(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Data, WINRT_WRAP(void), Windows::UI::Notifications::NotificationData const&);
            this->shim().Data(*reinterpret_cast<Windows::UI::Notifications::NotificationData const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Priority(Windows::UI::Notifications::ToastNotificationPriority* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Priority, WINRT_WRAP(Windows::UI::Notifications::ToastNotificationPriority));
            *value = detach_from<Windows::UI::Notifications::ToastNotificationPriority>(this->shim().Priority());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Priority(Windows::UI::Notifications::ToastNotificationPriority value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Priority, WINRT_WRAP(void), Windows::UI::Notifications::ToastNotificationPriority const&);
            this->shim().Priority(*reinterpret_cast<Windows::UI::Notifications::ToastNotificationPriority const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IToastNotification6> : produce_base<D, Windows::UI::Notifications::IToastNotification6>
{
    int32_t WINRT_CALL get_ExpiresOnReboot(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpiresOnReboot, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ExpiresOnReboot());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ExpiresOnReboot(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpiresOnReboot, WINRT_WRAP(void), bool);
            this->shim().ExpiresOnReboot(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IToastNotificationActionTriggerDetail> : produce_base<D, Windows::UI::Notifications::IToastNotificationActionTriggerDetail>
{
    int32_t WINRT_CALL get_Argument(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Argument, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Argument());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UserInput(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserInput, WINRT_WRAP(Windows::Foundation::Collections::ValueSet));
            *value = detach_from<Windows::Foundation::Collections::ValueSet>(this->shim().UserInput());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IToastNotificationFactory> : produce_base<D, Windows::UI::Notifications::IToastNotificationFactory>
{
    int32_t WINRT_CALL CreateToastNotification(void* content, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateToastNotification, WINRT_WRAP(Windows::UI::Notifications::ToastNotification), Windows::Data::Xml::Dom::XmlDocument const&);
            *value = detach_from<Windows::UI::Notifications::ToastNotification>(this->shim().CreateToastNotification(*reinterpret_cast<Windows::Data::Xml::Dom::XmlDocument const*>(&content)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IToastNotificationHistory> : produce_base<D, Windows::UI::Notifications::IToastNotificationHistory>
{
    int32_t WINRT_CALL RemoveGroup(void* group) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveGroup, WINRT_WRAP(void), hstring const&);
            this->shim().RemoveGroup(*reinterpret_cast<hstring const*>(&group));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveGroupWithId(void* group, void* applicationId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveGroup, WINRT_WRAP(void), hstring const&, hstring const&);
            this->shim().RemoveGroup(*reinterpret_cast<hstring const*>(&group), *reinterpret_cast<hstring const*>(&applicationId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveGroupedTagWithId(void* tag, void* group, void* applicationId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Remove, WINRT_WRAP(void), hstring const&, hstring const&, hstring const&);
            this->shim().Remove(*reinterpret_cast<hstring const*>(&tag), *reinterpret_cast<hstring const*>(&group), *reinterpret_cast<hstring const*>(&applicationId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveGroupedTag(void* tag, void* group) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Remove, WINRT_WRAP(void), hstring const&, hstring const&);
            this->shim().Remove(*reinterpret_cast<hstring const*>(&tag), *reinterpret_cast<hstring const*>(&group));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Remove(void* tag) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Remove, WINRT_WRAP(void), hstring const&);
            this->shim().Remove(*reinterpret_cast<hstring const*>(&tag));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Clear() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Clear, WINRT_WRAP(void));
            this->shim().Clear();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClearWithId(void* applicationId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Clear, WINRT_WRAP(void), hstring const&);
            this->shim().Clear(*reinterpret_cast<hstring const*>(&applicationId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IToastNotificationHistory2> : produce_base<D, Windows::UI::Notifications::IToastNotificationHistory2>
{
    int32_t WINRT_CALL GetHistory(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetHistory, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::Notifications::ToastNotification>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::Notifications::ToastNotification>>(this->shim().GetHistory());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetHistoryWithId(void* applicationId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetHistory, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::Notifications::ToastNotification>), hstring const&);
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::Notifications::ToastNotification>>(this->shim().GetHistory(*reinterpret_cast<hstring const*>(&applicationId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IToastNotificationHistoryChangedTriggerDetail> : produce_base<D, Windows::UI::Notifications::IToastNotificationHistoryChangedTriggerDetail>
{
    int32_t WINRT_CALL get_ChangeType(Windows::UI::Notifications::ToastHistoryChangedType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChangeType, WINRT_WRAP(Windows::UI::Notifications::ToastHistoryChangedType));
            *value = detach_from<Windows::UI::Notifications::ToastHistoryChangedType>(this->shim().ChangeType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IToastNotificationHistoryChangedTriggerDetail2> : produce_base<D, Windows::UI::Notifications::IToastNotificationHistoryChangedTriggerDetail2>
{
    int32_t WINRT_CALL get_CollectionId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CollectionId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CollectionId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IToastNotificationManagerForUser> : produce_base<D, Windows::UI::Notifications::IToastNotificationManagerForUser>
{
    int32_t WINRT_CALL CreateToastNotifier(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateToastNotifier, WINRT_WRAP(Windows::UI::Notifications::ToastNotifier));
            *result = detach_from<Windows::UI::Notifications::ToastNotifier>(this->shim().CreateToastNotifier());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateToastNotifierWithId(void* applicationId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateToastNotifier, WINRT_WRAP(Windows::UI::Notifications::ToastNotifier), hstring const&);
            *result = detach_from<Windows::UI::Notifications::ToastNotifier>(this->shim().CreateToastNotifier(*reinterpret_cast<hstring const*>(&applicationId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_History(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(History, WINRT_WRAP(Windows::UI::Notifications::ToastNotificationHistory));
            *value = detach_from<Windows::UI::Notifications::ToastNotificationHistory>(this->shim().History());
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
struct produce<D, Windows::UI::Notifications::IToastNotificationManagerForUser2> : produce_base<D, Windows::UI::Notifications::IToastNotificationManagerForUser2>
{
    int32_t WINRT_CALL GetToastNotifierForToastCollectionIdAsync(void* collectionId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetToastNotifierForToastCollectionIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::UI::Notifications::ToastNotifier>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::UI::Notifications::ToastNotifier>>(this->shim().GetToastNotifierForToastCollectionIdAsync(*reinterpret_cast<hstring const*>(&collectionId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetHistoryForToastCollectionIdAsync(void* collectionId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetHistoryForToastCollectionIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::UI::Notifications::ToastNotificationHistory>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::UI::Notifications::ToastNotificationHistory>>(this->shim().GetHistoryForToastCollectionIdAsync(*reinterpret_cast<hstring const*>(&collectionId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetToastCollectionManager(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetToastCollectionManager, WINRT_WRAP(Windows::UI::Notifications::ToastCollectionManager));
            *result = detach_from<Windows::UI::Notifications::ToastCollectionManager>(this->shim().GetToastCollectionManager());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetToastCollectionManagerWithAppId(void* appId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetToastCollectionManager, WINRT_WRAP(Windows::UI::Notifications::ToastCollectionManager), hstring const&);
            *result = detach_from<Windows::UI::Notifications::ToastCollectionManager>(this->shim().GetToastCollectionManager(*reinterpret_cast<hstring const*>(&appId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IToastNotificationManagerStatics> : produce_base<D, Windows::UI::Notifications::IToastNotificationManagerStatics>
{
    int32_t WINRT_CALL CreateToastNotifier(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateToastNotifier, WINRT_WRAP(Windows::UI::Notifications::ToastNotifier));
            *result = detach_from<Windows::UI::Notifications::ToastNotifier>(this->shim().CreateToastNotifier());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateToastNotifierWithId(void* applicationId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateToastNotifier, WINRT_WRAP(Windows::UI::Notifications::ToastNotifier), hstring const&);
            *result = detach_from<Windows::UI::Notifications::ToastNotifier>(this->shim().CreateToastNotifier(*reinterpret_cast<hstring const*>(&applicationId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetTemplateContent(Windows::UI::Notifications::ToastTemplateType type, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTemplateContent, WINRT_WRAP(Windows::Data::Xml::Dom::XmlDocument), Windows::UI::Notifications::ToastTemplateType const&);
            *result = detach_from<Windows::Data::Xml::Dom::XmlDocument>(this->shim().GetTemplateContent(*reinterpret_cast<Windows::UI::Notifications::ToastTemplateType const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IToastNotificationManagerStatics2> : produce_base<D, Windows::UI::Notifications::IToastNotificationManagerStatics2>
{
    int32_t WINRT_CALL get_History(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(History, WINRT_WRAP(Windows::UI::Notifications::ToastNotificationHistory));
            *value = detach_from<Windows::UI::Notifications::ToastNotificationHistory>(this->shim().History());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IToastNotificationManagerStatics4> : produce_base<D, Windows::UI::Notifications::IToastNotificationManagerStatics4>
{
    int32_t WINRT_CALL GetForUser(void* user, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForUser, WINRT_WRAP(Windows::UI::Notifications::ToastNotificationManagerForUser), Windows::System::User const&);
            *result = detach_from<Windows::UI::Notifications::ToastNotificationManagerForUser>(this->shim().GetForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConfigureNotificationMirroring(Windows::UI::Notifications::NotificationMirroring value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConfigureNotificationMirroring, WINRT_WRAP(void), Windows::UI::Notifications::NotificationMirroring const&);
            this->shim().ConfigureNotificationMirroring(*reinterpret_cast<Windows::UI::Notifications::NotificationMirroring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IToastNotificationManagerStatics5> : produce_base<D, Windows::UI::Notifications::IToastNotificationManagerStatics5>
{
    int32_t WINRT_CALL GetDefault(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::UI::Notifications::ToastNotificationManagerForUser));
            *result = detach_from<Windows::UI::Notifications::ToastNotificationManagerForUser>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IToastNotifier> : produce_base<D, Windows::UI::Notifications::IToastNotifier>
{
    int32_t WINRT_CALL Show(void* notification) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Show, WINRT_WRAP(void), Windows::UI::Notifications::ToastNotification const&);
            this->shim().Show(*reinterpret_cast<Windows::UI::Notifications::ToastNotification const*>(&notification));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Hide(void* notification) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Hide, WINRT_WRAP(void), Windows::UI::Notifications::ToastNotification const&);
            this->shim().Hide(*reinterpret_cast<Windows::UI::Notifications::ToastNotification const*>(&notification));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Setting(Windows::UI::Notifications::NotificationSetting* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Setting, WINRT_WRAP(Windows::UI::Notifications::NotificationSetting));
            *value = detach_from<Windows::UI::Notifications::NotificationSetting>(this->shim().Setting());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddToSchedule(void* scheduledToast) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddToSchedule, WINRT_WRAP(void), Windows::UI::Notifications::ScheduledToastNotification const&);
            this->shim().AddToSchedule(*reinterpret_cast<Windows::UI::Notifications::ScheduledToastNotification const*>(&scheduledToast));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveFromSchedule(void* scheduledToast) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveFromSchedule, WINRT_WRAP(void), Windows::UI::Notifications::ScheduledToastNotification const&);
            this->shim().RemoveFromSchedule(*reinterpret_cast<Windows::UI::Notifications::ScheduledToastNotification const*>(&scheduledToast));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetScheduledToastNotifications(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetScheduledToastNotifications, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::Notifications::ScheduledToastNotification>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::Notifications::ScheduledToastNotification>>(this->shim().GetScheduledToastNotifications());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IToastNotifier2> : produce_base<D, Windows::UI::Notifications::IToastNotifier2>
{
    int32_t WINRT_CALL UpdateWithTagAndGroup(void* data, void* tag, void* group, Windows::UI::Notifications::NotificationUpdateResult* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Update, WINRT_WRAP(Windows::UI::Notifications::NotificationUpdateResult), Windows::UI::Notifications::NotificationData const&, hstring const&, hstring const&);
            *result = detach_from<Windows::UI::Notifications::NotificationUpdateResult>(this->shim().Update(*reinterpret_cast<Windows::UI::Notifications::NotificationData const*>(&data), *reinterpret_cast<hstring const*>(&tag), *reinterpret_cast<hstring const*>(&group)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateWithTag(void* data, void* tag, Windows::UI::Notifications::NotificationUpdateResult* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Update, WINRT_WRAP(Windows::UI::Notifications::NotificationUpdateResult), Windows::UI::Notifications::NotificationData const&, hstring const&);
            *result = detach_from<Windows::UI::Notifications::NotificationUpdateResult>(this->shim().Update(*reinterpret_cast<Windows::UI::Notifications::NotificationData const*>(&data), *reinterpret_cast<hstring const*>(&tag)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IToastNotifier3> : produce_base<D, Windows::UI::Notifications::IToastNotifier3>
{
    int32_t WINRT_CALL add_ScheduledToastNotificationShowing(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScheduledToastNotificationShowing, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Notifications::ToastNotifier, Windows::UI::Notifications::ScheduledToastNotificationShowingEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ScheduledToastNotificationShowing(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Notifications::ToastNotifier, Windows::UI::Notifications::ScheduledToastNotificationShowingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ScheduledToastNotificationShowing(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ScheduledToastNotificationShowing, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ScheduledToastNotificationShowing(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IUserNotification> : produce_base<D, Windows::UI::Notifications::IUserNotification>
{
    int32_t WINRT_CALL get_Notification(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Notification, WINRT_WRAP(Windows::UI::Notifications::Notification));
            *value = detach_from<Windows::UI::Notifications::Notification>(this->shim().Notification());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppInfo, WINRT_WRAP(Windows::ApplicationModel::AppInfo));
            *value = detach_from<Windows::ApplicationModel::AppInfo>(this->shim().AppInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Id(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CreationTime(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreationTime, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().CreationTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::IUserNotificationChangedEventArgs> : produce_base<D, Windows::UI::Notifications::IUserNotificationChangedEventArgs>
{
    int32_t WINRT_CALL get_ChangeKind(Windows::UI::Notifications::UserNotificationChangedKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChangeKind, WINRT_WRAP(Windows::UI::Notifications::UserNotificationChangedKind));
            *value = detach_from<Windows::UI::Notifications::UserNotificationChangedKind>(this->shim().ChangeKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UserNotificationId(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserNotificationId, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().UserNotificationId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::Notifications {

inline AdaptiveNotificationText::AdaptiveNotificationText() :
    AdaptiveNotificationText(impl::call_factory<AdaptiveNotificationText>([](auto&& f) { return f.template ActivateInstance<AdaptiveNotificationText>(); }))
{}

inline BadgeNotification::BadgeNotification(Windows::Data::Xml::Dom::XmlDocument const& content) :
    BadgeNotification(impl::call_factory<BadgeNotification, Windows::UI::Notifications::IBadgeNotificationFactory>([&](auto&& f) { return f.CreateBadgeNotification(content); }))
{}

inline Windows::UI::Notifications::BadgeUpdater BadgeUpdateManager::CreateBadgeUpdaterForApplication()
{
    return impl::call_factory<BadgeUpdateManager, Windows::UI::Notifications::IBadgeUpdateManagerStatics>([&](auto&& f) { return f.CreateBadgeUpdaterForApplication(); });
}

inline Windows::UI::Notifications::BadgeUpdater BadgeUpdateManager::CreateBadgeUpdaterForApplication(param::hstring const& applicationId)
{
    return impl::call_factory<BadgeUpdateManager, Windows::UI::Notifications::IBadgeUpdateManagerStatics>([&](auto&& f) { return f.CreateBadgeUpdaterForApplication(applicationId); });
}

inline Windows::UI::Notifications::BadgeUpdater BadgeUpdateManager::CreateBadgeUpdaterForSecondaryTile(param::hstring const& tileId)
{
    return impl::call_factory<BadgeUpdateManager, Windows::UI::Notifications::IBadgeUpdateManagerStatics>([&](auto&& f) { return f.CreateBadgeUpdaterForSecondaryTile(tileId); });
}

inline Windows::Data::Xml::Dom::XmlDocument BadgeUpdateManager::GetTemplateContent(Windows::UI::Notifications::BadgeTemplateType const& type)
{
    return impl::call_factory<BadgeUpdateManager, Windows::UI::Notifications::IBadgeUpdateManagerStatics>([&](auto&& f) { return f.GetTemplateContent(type); });
}

inline Windows::UI::Notifications::BadgeUpdateManagerForUser BadgeUpdateManager::GetForUser(Windows::System::User const& user)
{
    return impl::call_factory<BadgeUpdateManager, Windows::UI::Notifications::IBadgeUpdateManagerStatics2>([&](auto&& f) { return f.GetForUser(user); });
}

inline hstring KnownAdaptiveNotificationHints::Style()
{
    return impl::call_factory<KnownAdaptiveNotificationHints, Windows::UI::Notifications::IKnownAdaptiveNotificationHintsStatics>([&](auto&& f) { return f.Style(); });
}

inline hstring KnownAdaptiveNotificationHints::Wrap()
{
    return impl::call_factory<KnownAdaptiveNotificationHints, Windows::UI::Notifications::IKnownAdaptiveNotificationHintsStatics>([&](auto&& f) { return f.Wrap(); });
}

inline hstring KnownAdaptiveNotificationHints::MaxLines()
{
    return impl::call_factory<KnownAdaptiveNotificationHints, Windows::UI::Notifications::IKnownAdaptiveNotificationHintsStatics>([&](auto&& f) { return f.MaxLines(); });
}

inline hstring KnownAdaptiveNotificationHints::MinLines()
{
    return impl::call_factory<KnownAdaptiveNotificationHints, Windows::UI::Notifications::IKnownAdaptiveNotificationHintsStatics>([&](auto&& f) { return f.MinLines(); });
}

inline hstring KnownAdaptiveNotificationHints::TextStacking()
{
    return impl::call_factory<KnownAdaptiveNotificationHints, Windows::UI::Notifications::IKnownAdaptiveNotificationHintsStatics>([&](auto&& f) { return f.TextStacking(); });
}

inline hstring KnownAdaptiveNotificationHints::Align()
{
    return impl::call_factory<KnownAdaptiveNotificationHints, Windows::UI::Notifications::IKnownAdaptiveNotificationHintsStatics>([&](auto&& f) { return f.Align(); });
}

inline hstring KnownAdaptiveNotificationTextStyles::Caption()
{
    return impl::call_factory<KnownAdaptiveNotificationTextStyles, Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics>([&](auto&& f) { return f.Caption(); });
}

inline hstring KnownAdaptiveNotificationTextStyles::Body()
{
    return impl::call_factory<KnownAdaptiveNotificationTextStyles, Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics>([&](auto&& f) { return f.Body(); });
}

inline hstring KnownAdaptiveNotificationTextStyles::Base()
{
    return impl::call_factory<KnownAdaptiveNotificationTextStyles, Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics>([&](auto&& f) { return f.Base(); });
}

inline hstring KnownAdaptiveNotificationTextStyles::Subtitle()
{
    return impl::call_factory<KnownAdaptiveNotificationTextStyles, Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics>([&](auto&& f) { return f.Subtitle(); });
}

inline hstring KnownAdaptiveNotificationTextStyles::Title()
{
    return impl::call_factory<KnownAdaptiveNotificationTextStyles, Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics>([&](auto&& f) { return f.Title(); });
}

inline hstring KnownAdaptiveNotificationTextStyles::Subheader()
{
    return impl::call_factory<KnownAdaptiveNotificationTextStyles, Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics>([&](auto&& f) { return f.Subheader(); });
}

inline hstring KnownAdaptiveNotificationTextStyles::Header()
{
    return impl::call_factory<KnownAdaptiveNotificationTextStyles, Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics>([&](auto&& f) { return f.Header(); });
}

inline hstring KnownAdaptiveNotificationTextStyles::TitleNumeral()
{
    return impl::call_factory<KnownAdaptiveNotificationTextStyles, Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics>([&](auto&& f) { return f.TitleNumeral(); });
}

inline hstring KnownAdaptiveNotificationTextStyles::SubheaderNumeral()
{
    return impl::call_factory<KnownAdaptiveNotificationTextStyles, Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics>([&](auto&& f) { return f.SubheaderNumeral(); });
}

inline hstring KnownAdaptiveNotificationTextStyles::HeaderNumeral()
{
    return impl::call_factory<KnownAdaptiveNotificationTextStyles, Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics>([&](auto&& f) { return f.HeaderNumeral(); });
}

inline hstring KnownAdaptiveNotificationTextStyles::CaptionSubtle()
{
    return impl::call_factory<KnownAdaptiveNotificationTextStyles, Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics>([&](auto&& f) { return f.CaptionSubtle(); });
}

inline hstring KnownAdaptiveNotificationTextStyles::BodySubtle()
{
    return impl::call_factory<KnownAdaptiveNotificationTextStyles, Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics>([&](auto&& f) { return f.BodySubtle(); });
}

inline hstring KnownAdaptiveNotificationTextStyles::BaseSubtle()
{
    return impl::call_factory<KnownAdaptiveNotificationTextStyles, Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics>([&](auto&& f) { return f.BaseSubtle(); });
}

inline hstring KnownAdaptiveNotificationTextStyles::SubtitleSubtle()
{
    return impl::call_factory<KnownAdaptiveNotificationTextStyles, Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics>([&](auto&& f) { return f.SubtitleSubtle(); });
}

inline hstring KnownAdaptiveNotificationTextStyles::TitleSubtle()
{
    return impl::call_factory<KnownAdaptiveNotificationTextStyles, Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics>([&](auto&& f) { return f.TitleSubtle(); });
}

inline hstring KnownAdaptiveNotificationTextStyles::SubheaderSubtle()
{
    return impl::call_factory<KnownAdaptiveNotificationTextStyles, Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics>([&](auto&& f) { return f.SubheaderSubtle(); });
}

inline hstring KnownAdaptiveNotificationTextStyles::SubheaderNumeralSubtle()
{
    return impl::call_factory<KnownAdaptiveNotificationTextStyles, Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics>([&](auto&& f) { return f.SubheaderNumeralSubtle(); });
}

inline hstring KnownAdaptiveNotificationTextStyles::HeaderSubtle()
{
    return impl::call_factory<KnownAdaptiveNotificationTextStyles, Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics>([&](auto&& f) { return f.HeaderSubtle(); });
}

inline hstring KnownAdaptiveNotificationTextStyles::HeaderNumeralSubtle()
{
    return impl::call_factory<KnownAdaptiveNotificationTextStyles, Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics>([&](auto&& f) { return f.HeaderNumeralSubtle(); });
}

inline hstring KnownNotificationBindings::ToastGeneric()
{
    return impl::call_factory<KnownNotificationBindings, Windows::UI::Notifications::IKnownNotificationBindingsStatics>([&](auto&& f) { return f.ToastGeneric(); });
}

inline Notification::Notification() :
    Notification(impl::call_factory<Notification>([](auto&& f) { return f.template ActivateInstance<Notification>(); }))
{}

inline NotificationData::NotificationData() :
    NotificationData(impl::call_factory<NotificationData>([](auto&& f) { return f.template ActivateInstance<NotificationData>(); }))
{}

inline NotificationData::NotificationData(param::iterable<Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const& initialValues, uint32_t sequenceNumber) :
    NotificationData(impl::call_factory<NotificationData, Windows::UI::Notifications::INotificationDataFactory>([&](auto&& f) { return f.CreateNotificationData(initialValues, sequenceNumber); }))
{}

inline NotificationData::NotificationData(param::iterable<Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const& initialValues) :
    NotificationData(impl::call_factory<NotificationData, Windows::UI::Notifications::INotificationDataFactory>([&](auto&& f) { return f.CreateNotificationData(initialValues); }))
{}

inline ScheduledTileNotification::ScheduledTileNotification(Windows::Data::Xml::Dom::XmlDocument const& content, Windows::Foundation::DateTime const& deliveryTime) :
    ScheduledTileNotification(impl::call_factory<ScheduledTileNotification, Windows::UI::Notifications::IScheduledTileNotificationFactory>([&](auto&& f) { return f.CreateScheduledTileNotification(content, deliveryTime); }))
{}

inline ScheduledToastNotification::ScheduledToastNotification(Windows::Data::Xml::Dom::XmlDocument const& content, Windows::Foundation::DateTime const& deliveryTime) :
    ScheduledToastNotification(impl::call_factory<ScheduledToastNotification, Windows::UI::Notifications::IScheduledToastNotificationFactory>([&](auto&& f) { return f.CreateScheduledToastNotification(content, deliveryTime); }))
{}

inline ScheduledToastNotification::ScheduledToastNotification(Windows::Data::Xml::Dom::XmlDocument const& content, Windows::Foundation::DateTime const& deliveryTime, Windows::Foundation::TimeSpan const& snoozeInterval, uint32_t maximumSnoozeCount) :
    ScheduledToastNotification(impl::call_factory<ScheduledToastNotification, Windows::UI::Notifications::IScheduledToastNotificationFactory>([&](auto&& f) { return f.CreateScheduledToastNotificationRecurring(content, deliveryTime, snoozeInterval, maximumSnoozeCount); }))
{}

inline TileFlyoutNotification::TileFlyoutNotification(Windows::Data::Xml::Dom::XmlDocument const& content) :
    TileFlyoutNotification(impl::call_factory<TileFlyoutNotification, Windows::UI::Notifications::ITileFlyoutNotificationFactory>([&](auto&& f) { return f.CreateTileFlyoutNotification(content); }))
{}

inline Windows::UI::Notifications::TileFlyoutUpdater TileFlyoutUpdateManager::CreateTileFlyoutUpdaterForApplication()
{
    return impl::call_factory<TileFlyoutUpdateManager, Windows::UI::Notifications::ITileFlyoutUpdateManagerStatics>([&](auto&& f) { return f.CreateTileFlyoutUpdaterForApplication(); });
}

inline Windows::UI::Notifications::TileFlyoutUpdater TileFlyoutUpdateManager::CreateTileFlyoutUpdaterForApplication(param::hstring const& applicationId)
{
    return impl::call_factory<TileFlyoutUpdateManager, Windows::UI::Notifications::ITileFlyoutUpdateManagerStatics>([&](auto&& f) { return f.CreateTileFlyoutUpdaterForApplication(applicationId); });
}

inline Windows::UI::Notifications::TileFlyoutUpdater TileFlyoutUpdateManager::CreateTileFlyoutUpdaterForSecondaryTile(param::hstring const& tileId)
{
    return impl::call_factory<TileFlyoutUpdateManager, Windows::UI::Notifications::ITileFlyoutUpdateManagerStatics>([&](auto&& f) { return f.CreateTileFlyoutUpdaterForSecondaryTile(tileId); });
}

inline Windows::Data::Xml::Dom::XmlDocument TileFlyoutUpdateManager::GetTemplateContent(Windows::UI::Notifications::TileFlyoutTemplateType const& type)
{
    return impl::call_factory<TileFlyoutUpdateManager, Windows::UI::Notifications::ITileFlyoutUpdateManagerStatics>([&](auto&& f) { return f.GetTemplateContent(type); });
}

inline TileNotification::TileNotification(Windows::Data::Xml::Dom::XmlDocument const& content) :
    TileNotification(impl::call_factory<TileNotification, Windows::UI::Notifications::ITileNotificationFactory>([&](auto&& f) { return f.CreateTileNotification(content); }))
{}

inline Windows::UI::Notifications::TileUpdater TileUpdateManager::CreateTileUpdaterForApplication()
{
    return impl::call_factory<TileUpdateManager, Windows::UI::Notifications::ITileUpdateManagerStatics>([&](auto&& f) { return f.CreateTileUpdaterForApplication(); });
}

inline Windows::UI::Notifications::TileUpdater TileUpdateManager::CreateTileUpdaterForApplication(param::hstring const& applicationId)
{
    return impl::call_factory<TileUpdateManager, Windows::UI::Notifications::ITileUpdateManagerStatics>([&](auto&& f) { return f.CreateTileUpdaterForApplication(applicationId); });
}

inline Windows::UI::Notifications::TileUpdater TileUpdateManager::CreateTileUpdaterForSecondaryTile(param::hstring const& tileId)
{
    return impl::call_factory<TileUpdateManager, Windows::UI::Notifications::ITileUpdateManagerStatics>([&](auto&& f) { return f.CreateTileUpdaterForSecondaryTile(tileId); });
}

inline Windows::Data::Xml::Dom::XmlDocument TileUpdateManager::GetTemplateContent(Windows::UI::Notifications::TileTemplateType const& type)
{
    return impl::call_factory<TileUpdateManager, Windows::UI::Notifications::ITileUpdateManagerStatics>([&](auto&& f) { return f.GetTemplateContent(type); });
}

inline Windows::UI::Notifications::TileUpdateManagerForUser TileUpdateManager::GetForUser(Windows::System::User const& user)
{
    return impl::call_factory<TileUpdateManager, Windows::UI::Notifications::ITileUpdateManagerStatics2>([&](auto&& f) { return f.GetForUser(user); });
}

inline ToastCollection::ToastCollection(param::hstring const& collectionId, param::hstring const& displayName, param::hstring const& launchArgs, Windows::Foundation::Uri const& iconUri) :
    ToastCollection(impl::call_factory<ToastCollection, Windows::UI::Notifications::IToastCollectionFactory>([&](auto&& f) { return f.CreateInstance(collectionId, displayName, launchArgs, iconUri); }))
{}

inline ToastNotification::ToastNotification(Windows::Data::Xml::Dom::XmlDocument const& content) :
    ToastNotification(impl::call_factory<ToastNotification, Windows::UI::Notifications::IToastNotificationFactory>([&](auto&& f) { return f.CreateToastNotification(content); }))
{}

inline Windows::UI::Notifications::ToastNotifier ToastNotificationManager::CreateToastNotifier()
{
    return impl::call_factory<ToastNotificationManager, Windows::UI::Notifications::IToastNotificationManagerStatics>([&](auto&& f) { return f.CreateToastNotifier(); });
}

inline Windows::UI::Notifications::ToastNotifier ToastNotificationManager::CreateToastNotifier(param::hstring const& applicationId)
{
    return impl::call_factory<ToastNotificationManager, Windows::UI::Notifications::IToastNotificationManagerStatics>([&](auto&& f) { return f.CreateToastNotifier(applicationId); });
}

inline Windows::Data::Xml::Dom::XmlDocument ToastNotificationManager::GetTemplateContent(Windows::UI::Notifications::ToastTemplateType const& type)
{
    return impl::call_factory<ToastNotificationManager, Windows::UI::Notifications::IToastNotificationManagerStatics>([&](auto&& f) { return f.GetTemplateContent(type); });
}

inline Windows::UI::Notifications::ToastNotificationHistory ToastNotificationManager::History()
{
    return impl::call_factory<ToastNotificationManager, Windows::UI::Notifications::IToastNotificationManagerStatics2>([&](auto&& f) { return f.History(); });
}

inline Windows::UI::Notifications::ToastNotificationManagerForUser ToastNotificationManager::GetForUser(Windows::System::User const& user)
{
    return impl::call_factory<ToastNotificationManager, Windows::UI::Notifications::IToastNotificationManagerStatics4>([&](auto&& f) { return f.GetForUser(user); });
}

inline void ToastNotificationManager::ConfigureNotificationMirroring(Windows::UI::Notifications::NotificationMirroring const& value)
{
    impl::call_factory<ToastNotificationManager, Windows::UI::Notifications::IToastNotificationManagerStatics4>([&](auto&& f) { return f.ConfigureNotificationMirroring(value); });
}

inline Windows::UI::Notifications::ToastNotificationManagerForUser ToastNotificationManager::GetDefault()
{
    return impl::call_factory<ToastNotificationManager, Windows::UI::Notifications::IToastNotificationManagerStatics5>([&](auto&& f) { return f.GetDefault(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Notifications::IAdaptiveNotificationContent> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IAdaptiveNotificationContent> {};
template<> struct hash<winrt::Windows::UI::Notifications::IAdaptiveNotificationText> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IAdaptiveNotificationText> {};
template<> struct hash<winrt::Windows::UI::Notifications::IBadgeNotification> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IBadgeNotification> {};
template<> struct hash<winrt::Windows::UI::Notifications::IBadgeNotificationFactory> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IBadgeNotificationFactory> {};
template<> struct hash<winrt::Windows::UI::Notifications::IBadgeUpdateManagerForUser> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IBadgeUpdateManagerForUser> {};
template<> struct hash<winrt::Windows::UI::Notifications::IBadgeUpdateManagerStatics> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IBadgeUpdateManagerStatics> {};
template<> struct hash<winrt::Windows::UI::Notifications::IBadgeUpdateManagerStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IBadgeUpdateManagerStatics2> {};
template<> struct hash<winrt::Windows::UI::Notifications::IBadgeUpdater> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IBadgeUpdater> {};
template<> struct hash<winrt::Windows::UI::Notifications::IKnownAdaptiveNotificationHintsStatics> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IKnownAdaptiveNotificationHintsStatics> {};
template<> struct hash<winrt::Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IKnownAdaptiveNotificationTextStylesStatics> {};
template<> struct hash<winrt::Windows::UI::Notifications::IKnownNotificationBindingsStatics> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IKnownNotificationBindingsStatics> {};
template<> struct hash<winrt::Windows::UI::Notifications::INotification> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::INotification> {};
template<> struct hash<winrt::Windows::UI::Notifications::INotificationBinding> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::INotificationBinding> {};
template<> struct hash<winrt::Windows::UI::Notifications::INotificationData> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::INotificationData> {};
template<> struct hash<winrt::Windows::UI::Notifications::INotificationDataFactory> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::INotificationDataFactory> {};
template<> struct hash<winrt::Windows::UI::Notifications::INotificationVisual> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::INotificationVisual> {};
template<> struct hash<winrt::Windows::UI::Notifications::IScheduledTileNotification> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IScheduledTileNotification> {};
template<> struct hash<winrt::Windows::UI::Notifications::IScheduledTileNotificationFactory> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IScheduledTileNotificationFactory> {};
template<> struct hash<winrt::Windows::UI::Notifications::IScheduledToastNotification> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IScheduledToastNotification> {};
template<> struct hash<winrt::Windows::UI::Notifications::IScheduledToastNotification2> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IScheduledToastNotification2> {};
template<> struct hash<winrt::Windows::UI::Notifications::IScheduledToastNotification3> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IScheduledToastNotification3> {};
template<> struct hash<winrt::Windows::UI::Notifications::IScheduledToastNotification4> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IScheduledToastNotification4> {};
template<> struct hash<winrt::Windows::UI::Notifications::IScheduledToastNotificationFactory> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IScheduledToastNotificationFactory> {};
template<> struct hash<winrt::Windows::UI::Notifications::IScheduledToastNotificationShowingEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IScheduledToastNotificationShowingEventArgs> {};
template<> struct hash<winrt::Windows::UI::Notifications::IShownTileNotification> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IShownTileNotification> {};
template<> struct hash<winrt::Windows::UI::Notifications::ITileFlyoutNotification> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::ITileFlyoutNotification> {};
template<> struct hash<winrt::Windows::UI::Notifications::ITileFlyoutNotificationFactory> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::ITileFlyoutNotificationFactory> {};
template<> struct hash<winrt::Windows::UI::Notifications::ITileFlyoutUpdateManagerStatics> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::ITileFlyoutUpdateManagerStatics> {};
template<> struct hash<winrt::Windows::UI::Notifications::ITileFlyoutUpdater> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::ITileFlyoutUpdater> {};
template<> struct hash<winrt::Windows::UI::Notifications::ITileNotification> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::ITileNotification> {};
template<> struct hash<winrt::Windows::UI::Notifications::ITileNotificationFactory> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::ITileNotificationFactory> {};
template<> struct hash<winrt::Windows::UI::Notifications::ITileUpdateManagerForUser> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::ITileUpdateManagerForUser> {};
template<> struct hash<winrt::Windows::UI::Notifications::ITileUpdateManagerStatics> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::ITileUpdateManagerStatics> {};
template<> struct hash<winrt::Windows::UI::Notifications::ITileUpdateManagerStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::ITileUpdateManagerStatics2> {};
template<> struct hash<winrt::Windows::UI::Notifications::ITileUpdater> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::ITileUpdater> {};
template<> struct hash<winrt::Windows::UI::Notifications::ITileUpdater2> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::ITileUpdater2> {};
template<> struct hash<winrt::Windows::UI::Notifications::IToastActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IToastActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Notifications::IToastActivatedEventArgs2> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IToastActivatedEventArgs2> {};
template<> struct hash<winrt::Windows::UI::Notifications::IToastCollection> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IToastCollection> {};
template<> struct hash<winrt::Windows::UI::Notifications::IToastCollectionFactory> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IToastCollectionFactory> {};
template<> struct hash<winrt::Windows::UI::Notifications::IToastCollectionManager> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IToastCollectionManager> {};
template<> struct hash<winrt::Windows::UI::Notifications::IToastDismissedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IToastDismissedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Notifications::IToastFailedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IToastFailedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Notifications::IToastNotification> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IToastNotification> {};
template<> struct hash<winrt::Windows::UI::Notifications::IToastNotification2> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IToastNotification2> {};
template<> struct hash<winrt::Windows::UI::Notifications::IToastNotification3> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IToastNotification3> {};
template<> struct hash<winrt::Windows::UI::Notifications::IToastNotification4> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IToastNotification4> {};
template<> struct hash<winrt::Windows::UI::Notifications::IToastNotification6> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IToastNotification6> {};
template<> struct hash<winrt::Windows::UI::Notifications::IToastNotificationActionTriggerDetail> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IToastNotificationActionTriggerDetail> {};
template<> struct hash<winrt::Windows::UI::Notifications::IToastNotificationFactory> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IToastNotificationFactory> {};
template<> struct hash<winrt::Windows::UI::Notifications::IToastNotificationHistory> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IToastNotificationHistory> {};
template<> struct hash<winrt::Windows::UI::Notifications::IToastNotificationHistory2> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IToastNotificationHistory2> {};
template<> struct hash<winrt::Windows::UI::Notifications::IToastNotificationHistoryChangedTriggerDetail> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IToastNotificationHistoryChangedTriggerDetail> {};
template<> struct hash<winrt::Windows::UI::Notifications::IToastNotificationHistoryChangedTriggerDetail2> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IToastNotificationHistoryChangedTriggerDetail2> {};
template<> struct hash<winrt::Windows::UI::Notifications::IToastNotificationManagerForUser> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IToastNotificationManagerForUser> {};
template<> struct hash<winrt::Windows::UI::Notifications::IToastNotificationManagerForUser2> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IToastNotificationManagerForUser2> {};
template<> struct hash<winrt::Windows::UI::Notifications::IToastNotificationManagerStatics> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IToastNotificationManagerStatics> {};
template<> struct hash<winrt::Windows::UI::Notifications::IToastNotificationManagerStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IToastNotificationManagerStatics2> {};
template<> struct hash<winrt::Windows::UI::Notifications::IToastNotificationManagerStatics4> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IToastNotificationManagerStatics4> {};
template<> struct hash<winrt::Windows::UI::Notifications::IToastNotificationManagerStatics5> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IToastNotificationManagerStatics5> {};
template<> struct hash<winrt::Windows::UI::Notifications::IToastNotifier> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IToastNotifier> {};
template<> struct hash<winrt::Windows::UI::Notifications::IToastNotifier2> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IToastNotifier2> {};
template<> struct hash<winrt::Windows::UI::Notifications::IToastNotifier3> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IToastNotifier3> {};
template<> struct hash<winrt::Windows::UI::Notifications::IUserNotification> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IUserNotification> {};
template<> struct hash<winrt::Windows::UI::Notifications::IUserNotificationChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::IUserNotificationChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Notifications::AdaptiveNotificationText> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::AdaptiveNotificationText> {};
template<> struct hash<winrt::Windows::UI::Notifications::BadgeNotification> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::BadgeNotification> {};
template<> struct hash<winrt::Windows::UI::Notifications::BadgeUpdateManager> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::BadgeUpdateManager> {};
template<> struct hash<winrt::Windows::UI::Notifications::BadgeUpdateManagerForUser> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::BadgeUpdateManagerForUser> {};
template<> struct hash<winrt::Windows::UI::Notifications::BadgeUpdater> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::BadgeUpdater> {};
template<> struct hash<winrt::Windows::UI::Notifications::KnownAdaptiveNotificationHints> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::KnownAdaptiveNotificationHints> {};
template<> struct hash<winrt::Windows::UI::Notifications::KnownAdaptiveNotificationTextStyles> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::KnownAdaptiveNotificationTextStyles> {};
template<> struct hash<winrt::Windows::UI::Notifications::KnownNotificationBindings> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::KnownNotificationBindings> {};
template<> struct hash<winrt::Windows::UI::Notifications::Notification> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::Notification> {};
template<> struct hash<winrt::Windows::UI::Notifications::NotificationBinding> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::NotificationBinding> {};
template<> struct hash<winrt::Windows::UI::Notifications::NotificationData> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::NotificationData> {};
template<> struct hash<winrt::Windows::UI::Notifications::NotificationVisual> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::NotificationVisual> {};
template<> struct hash<winrt::Windows::UI::Notifications::ScheduledTileNotification> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::ScheduledTileNotification> {};
template<> struct hash<winrt::Windows::UI::Notifications::ScheduledToastNotification> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::ScheduledToastNotification> {};
template<> struct hash<winrt::Windows::UI::Notifications::ScheduledToastNotificationShowingEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::ScheduledToastNotificationShowingEventArgs> {};
template<> struct hash<winrt::Windows::UI::Notifications::ShownTileNotification> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::ShownTileNotification> {};
template<> struct hash<winrt::Windows::UI::Notifications::TileFlyoutNotification> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::TileFlyoutNotification> {};
template<> struct hash<winrt::Windows::UI::Notifications::TileFlyoutUpdateManager> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::TileFlyoutUpdateManager> {};
template<> struct hash<winrt::Windows::UI::Notifications::TileFlyoutUpdater> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::TileFlyoutUpdater> {};
template<> struct hash<winrt::Windows::UI::Notifications::TileNotification> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::TileNotification> {};
template<> struct hash<winrt::Windows::UI::Notifications::TileUpdateManager> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::TileUpdateManager> {};
template<> struct hash<winrt::Windows::UI::Notifications::TileUpdateManagerForUser> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::TileUpdateManagerForUser> {};
template<> struct hash<winrt::Windows::UI::Notifications::TileUpdater> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::TileUpdater> {};
template<> struct hash<winrt::Windows::UI::Notifications::ToastActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::ToastActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Notifications::ToastCollection> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::ToastCollection> {};
template<> struct hash<winrt::Windows::UI::Notifications::ToastCollectionManager> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::ToastCollectionManager> {};
template<> struct hash<winrt::Windows::UI::Notifications::ToastDismissedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::ToastDismissedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Notifications::ToastFailedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::ToastFailedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Notifications::ToastNotification> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::ToastNotification> {};
template<> struct hash<winrt::Windows::UI::Notifications::ToastNotificationActionTriggerDetail> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::ToastNotificationActionTriggerDetail> {};
template<> struct hash<winrt::Windows::UI::Notifications::ToastNotificationHistory> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::ToastNotificationHistory> {};
template<> struct hash<winrt::Windows::UI::Notifications::ToastNotificationHistoryChangedTriggerDetail> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::ToastNotificationHistoryChangedTriggerDetail> {};
template<> struct hash<winrt::Windows::UI::Notifications::ToastNotificationManager> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::ToastNotificationManager> {};
template<> struct hash<winrt::Windows::UI::Notifications::ToastNotificationManagerForUser> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::ToastNotificationManagerForUser> {};
template<> struct hash<winrt::Windows::UI::Notifications::ToastNotifier> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::ToastNotifier> {};
template<> struct hash<winrt::Windows::UI::Notifications::UserNotification> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::UserNotification> {};
template<> struct hash<winrt::Windows::UI::Notifications::UserNotificationChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::UserNotificationChangedEventArgs> {};

}
