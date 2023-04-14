// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Devices::Geolocation {

struct BasicGeoposition;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IRandomAccessStreamReference;

}

WINRT_EXPORT namespace winrt::Windows::UI {

struct Color;

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Wallet {

enum class WalletActionKind : int32_t
{
    OpenItem = 0,
    Transaction = 1,
    MoreTransactions = 2,
    Message = 3,
    Verb = 4,
};

enum class WalletBarcodeSymbology : int32_t
{
    Invalid = 0,
    Upca = 1,
    Upce = 2,
    Ean13 = 3,
    Ean8 = 4,
    Itf = 5,
    Code39 = 6,
    Code128 = 7,
    Qr = 8,
    Pdf417 = 9,
    Aztec = 10,
    Custom = 100000,
};

enum class WalletDetailViewPosition : int32_t
{
    Hidden = 0,
    HeaderField1 = 1,
    HeaderField2 = 2,
    PrimaryField1 = 3,
    PrimaryField2 = 4,
    SecondaryField1 = 5,
    SecondaryField2 = 6,
    SecondaryField3 = 7,
    SecondaryField4 = 8,
    SecondaryField5 = 9,
    CenterField1 = 10,
    FooterField1 = 11,
    FooterField2 = 12,
    FooterField3 = 13,
    FooterField4 = 14,
};

enum class WalletItemKind : int32_t
{
    Invalid = 0,
    Deal = 1,
    General = 2,
    PaymentInstrument = 3,
    Ticket = 4,
    BoardingPass = 5,
    MembershipCard = 6,
};

enum class WalletSummaryViewPosition : int32_t
{
    Hidden = 0,
    Field1 = 1,
    Field2 = 2,
};

struct IWalletBarcode;
struct IWalletBarcodeFactory;
struct IWalletItem;
struct IWalletItemCustomProperty;
struct IWalletItemCustomPropertyFactory;
struct IWalletItemFactory;
struct IWalletItemStore;
struct IWalletItemStore2;
struct IWalletManagerStatics;
struct IWalletRelevantLocation;
struct IWalletTransaction;
struct IWalletVerb;
struct IWalletVerbFactory;
struct WalletBarcode;
struct WalletItem;
struct WalletItemCustomProperty;
struct WalletItemStore;
struct WalletManager;
struct WalletRelevantLocation;
struct WalletTransaction;
struct WalletVerb;

}

namespace winrt::impl {

template <> struct category<Windows::ApplicationModel::Wallet::IWalletBarcode>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Wallet::IWalletBarcodeFactory>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Wallet::IWalletItem>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Wallet::IWalletItemCustomProperty>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Wallet::IWalletItemCustomPropertyFactory>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Wallet::IWalletItemFactory>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Wallet::IWalletItemStore>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Wallet::IWalletItemStore2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Wallet::IWalletManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Wallet::IWalletRelevantLocation>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Wallet::IWalletTransaction>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Wallet::IWalletVerb>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Wallet::IWalletVerbFactory>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Wallet::WalletBarcode>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Wallet::WalletItem>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Wallet::WalletItemCustomProperty>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Wallet::WalletItemStore>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Wallet::WalletManager>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Wallet::WalletRelevantLocation>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Wallet::WalletTransaction>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Wallet::WalletVerb>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Wallet::WalletActionKind>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Wallet::WalletBarcodeSymbology>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Wallet::WalletDetailViewPosition>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Wallet::WalletItemKind>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::Wallet::WalletSummaryViewPosition>{ using type = enum_category; };
template <> struct name<Windows::ApplicationModel::Wallet::IWalletBarcode>{ static constexpr auto & value{ L"Windows.ApplicationModel.Wallet.IWalletBarcode" }; };
template <> struct name<Windows::ApplicationModel::Wallet::IWalletBarcodeFactory>{ static constexpr auto & value{ L"Windows.ApplicationModel.Wallet.IWalletBarcodeFactory" }; };
template <> struct name<Windows::ApplicationModel::Wallet::IWalletItem>{ static constexpr auto & value{ L"Windows.ApplicationModel.Wallet.IWalletItem" }; };
template <> struct name<Windows::ApplicationModel::Wallet::IWalletItemCustomProperty>{ static constexpr auto & value{ L"Windows.ApplicationModel.Wallet.IWalletItemCustomProperty" }; };
template <> struct name<Windows::ApplicationModel::Wallet::IWalletItemCustomPropertyFactory>{ static constexpr auto & value{ L"Windows.ApplicationModel.Wallet.IWalletItemCustomPropertyFactory" }; };
template <> struct name<Windows::ApplicationModel::Wallet::IWalletItemFactory>{ static constexpr auto & value{ L"Windows.ApplicationModel.Wallet.IWalletItemFactory" }; };
template <> struct name<Windows::ApplicationModel::Wallet::IWalletItemStore>{ static constexpr auto & value{ L"Windows.ApplicationModel.Wallet.IWalletItemStore" }; };
template <> struct name<Windows::ApplicationModel::Wallet::IWalletItemStore2>{ static constexpr auto & value{ L"Windows.ApplicationModel.Wallet.IWalletItemStore2" }; };
template <> struct name<Windows::ApplicationModel::Wallet::IWalletManagerStatics>{ static constexpr auto & value{ L"Windows.ApplicationModel.Wallet.IWalletManagerStatics" }; };
template <> struct name<Windows::ApplicationModel::Wallet::IWalletRelevantLocation>{ static constexpr auto & value{ L"Windows.ApplicationModel.Wallet.IWalletRelevantLocation" }; };
template <> struct name<Windows::ApplicationModel::Wallet::IWalletTransaction>{ static constexpr auto & value{ L"Windows.ApplicationModel.Wallet.IWalletTransaction" }; };
template <> struct name<Windows::ApplicationModel::Wallet::IWalletVerb>{ static constexpr auto & value{ L"Windows.ApplicationModel.Wallet.IWalletVerb" }; };
template <> struct name<Windows::ApplicationModel::Wallet::IWalletVerbFactory>{ static constexpr auto & value{ L"Windows.ApplicationModel.Wallet.IWalletVerbFactory" }; };
template <> struct name<Windows::ApplicationModel::Wallet::WalletBarcode>{ static constexpr auto & value{ L"Windows.ApplicationModel.Wallet.WalletBarcode" }; };
template <> struct name<Windows::ApplicationModel::Wallet::WalletItem>{ static constexpr auto & value{ L"Windows.ApplicationModel.Wallet.WalletItem" }; };
template <> struct name<Windows::ApplicationModel::Wallet::WalletItemCustomProperty>{ static constexpr auto & value{ L"Windows.ApplicationModel.Wallet.WalletItemCustomProperty" }; };
template <> struct name<Windows::ApplicationModel::Wallet::WalletItemStore>{ static constexpr auto & value{ L"Windows.ApplicationModel.Wallet.WalletItemStore" }; };
template <> struct name<Windows::ApplicationModel::Wallet::WalletManager>{ static constexpr auto & value{ L"Windows.ApplicationModel.Wallet.WalletManager" }; };
template <> struct name<Windows::ApplicationModel::Wallet::WalletRelevantLocation>{ static constexpr auto & value{ L"Windows.ApplicationModel.Wallet.WalletRelevantLocation" }; };
template <> struct name<Windows::ApplicationModel::Wallet::WalletTransaction>{ static constexpr auto & value{ L"Windows.ApplicationModel.Wallet.WalletTransaction" }; };
template <> struct name<Windows::ApplicationModel::Wallet::WalletVerb>{ static constexpr auto & value{ L"Windows.ApplicationModel.Wallet.WalletVerb" }; };
template <> struct name<Windows::ApplicationModel::Wallet::WalletActionKind>{ static constexpr auto & value{ L"Windows.ApplicationModel.Wallet.WalletActionKind" }; };
template <> struct name<Windows::ApplicationModel::Wallet::WalletBarcodeSymbology>{ static constexpr auto & value{ L"Windows.ApplicationModel.Wallet.WalletBarcodeSymbology" }; };
template <> struct name<Windows::ApplicationModel::Wallet::WalletDetailViewPosition>{ static constexpr auto & value{ L"Windows.ApplicationModel.Wallet.WalletDetailViewPosition" }; };
template <> struct name<Windows::ApplicationModel::Wallet::WalletItemKind>{ static constexpr auto & value{ L"Windows.ApplicationModel.Wallet.WalletItemKind" }; };
template <> struct name<Windows::ApplicationModel::Wallet::WalletSummaryViewPosition>{ static constexpr auto & value{ L"Windows.ApplicationModel.Wallet.WalletSummaryViewPosition" }; };
template <> struct guid_storage<Windows::ApplicationModel::Wallet::IWalletBarcode>{ static constexpr guid value{ 0x4F857B29,0xDE80,0x4EA4,{ 0xA1,0xCD,0x81,0xCD,0x08,0x4D,0xAC,0x27 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Wallet::IWalletBarcodeFactory>{ static constexpr guid value{ 0x30117161,0xED9C,0x469E,{ 0xBB,0xFD,0x30,0x6C,0x95,0xEA,0x71,0x08 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Wallet::IWalletItem>{ static constexpr guid value{ 0x20B54BE8,0x118D,0x4EC4,{ 0x99,0x6C,0xB9,0x63,0xE7,0xBD,0x3E,0x74 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Wallet::IWalletItemCustomProperty>{ static constexpr guid value{ 0xB94B40F3,0xFA00,0x40FD,{ 0x98,0xDC,0x9D,0xE4,0x66,0x97,0xF1,0xE7 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Wallet::IWalletItemCustomPropertyFactory>{ static constexpr guid value{ 0xD0046A44,0x61A1,0x41AA,{ 0xB2,0x59,0xA5,0x61,0x0A,0xB5,0xD5,0x75 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Wallet::IWalletItemFactory>{ static constexpr guid value{ 0x53E27470,0x4F0B,0x4A3E,{ 0x99,0xE5,0x0B,0xBB,0x1E,0xAB,0x38,0xD4 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Wallet::IWalletItemStore>{ static constexpr guid value{ 0x7160484B,0x6D49,0x48F8,{ 0x91,0xA9,0x40,0xA1,0xD0,0xF1,0x3E,0xF4 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Wallet::IWalletItemStore2>{ static constexpr guid value{ 0x65E682F0,0x7009,0x4A15,{ 0xBD,0x54,0x4F,0xFF,0x37,0x9B,0xFF,0xE2 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Wallet::IWalletManagerStatics>{ static constexpr guid value{ 0x5111D6B8,0xC9A4,0x4C64,{ 0xB4,0xDD,0xE1,0xE5,0x48,0x00,0x1C,0x0D } }; };
template <> struct guid_storage<Windows::ApplicationModel::Wallet::IWalletRelevantLocation>{ static constexpr guid value{ 0x9FD8782A,0xE3F9,0x4DE1,{ 0xBA,0xB3,0xBB,0x19,0x2E,0x46,0xB3,0xF3 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Wallet::IWalletTransaction>{ static constexpr guid value{ 0x40E1E940,0x2606,0x4519,{ 0x81,0xCB,0xBF,0xF1,0xC6,0x0D,0x1F,0x79 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Wallet::IWalletVerb>{ static constexpr guid value{ 0x17B826D6,0xE3C1,0x4C74,{ 0x8A,0x94,0x21,0x7A,0xAD,0xBC,0x48,0x84 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Wallet::IWalletVerbFactory>{ static constexpr guid value{ 0x76012771,0xBE58,0x4D5E,{ 0x83,0xED,0x58,0xB1,0x66,0x9C,0x7A,0xD9 } }; };
template <> struct default_interface<Windows::ApplicationModel::Wallet::WalletBarcode>{ using type = Windows::ApplicationModel::Wallet::IWalletBarcode; };
template <> struct default_interface<Windows::ApplicationModel::Wallet::WalletItem>{ using type = Windows::ApplicationModel::Wallet::IWalletItem; };
template <> struct default_interface<Windows::ApplicationModel::Wallet::WalletItemCustomProperty>{ using type = Windows::ApplicationModel::Wallet::IWalletItemCustomProperty; };
template <> struct default_interface<Windows::ApplicationModel::Wallet::WalletItemStore>{ using type = Windows::ApplicationModel::Wallet::IWalletItemStore; };
template <> struct default_interface<Windows::ApplicationModel::Wallet::WalletRelevantLocation>{ using type = Windows::ApplicationModel::Wallet::IWalletRelevantLocation; };
template <> struct default_interface<Windows::ApplicationModel::Wallet::WalletTransaction>{ using type = Windows::ApplicationModel::Wallet::IWalletTransaction; };
template <> struct default_interface<Windows::ApplicationModel::Wallet::WalletVerb>{ using type = Windows::ApplicationModel::Wallet::IWalletVerb; };

template <> struct abi<Windows::ApplicationModel::Wallet::IWalletBarcode>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Symbology(Windows::ApplicationModel::Wallet::WalletBarcodeSymbology* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Value(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetImageAsync(void** operation) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Wallet::IWalletBarcodeFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateWalletBarcode(Windows::ApplicationModel::Wallet::WalletBarcodeSymbology symbology, void* value, void** barcode) noexcept = 0;
    virtual int32_t WINRT_CALL CreateCustomWalletBarcode(void* streamToBarcodeImage, void** barcode) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Wallet::IWalletItem>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DisplayName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DisplayName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Id(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsAcknowledged(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsAcknowledged(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IssuerDisplayName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IssuerDisplayName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LastUpdated(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_LastUpdated(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Kind(Windows::ApplicationModel::Wallet::WalletItemKind* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Barcode(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Barcode(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExpirationDate(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ExpirationDate(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Logo159x159(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Logo159x159(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Logo336x336(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Logo336x336(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Logo99x99(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Logo99x99(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DisplayMessage(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DisplayMessage(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsDisplayMessageLaunchable(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsDisplayMessageLaunchable(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LogoText(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_LogoText(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HeaderColor(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_HeaderColor(struct struct_Windows_UI_Color value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BodyColor(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_BodyColor(struct struct_Windows_UI_Color value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HeaderFontColor(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_HeaderFontColor(struct struct_Windows_UI_Color value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BodyFontColor(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_BodyFontColor(struct struct_Windows_UI_Color value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HeaderBackgroundImage(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_HeaderBackgroundImage(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BodyBackgroundImage(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_BodyBackgroundImage(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LogoImage(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_LogoImage(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PromotionalImage(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_PromotionalImage(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RelevantDate(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RelevantDate(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RelevantDateDisplayMessage(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RelevantDateDisplayMessage(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TransactionHistory(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RelevantLocations(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsMoreTransactionHistoryLaunchable(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsMoreTransactionHistoryLaunchable(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DisplayProperties(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Verbs(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Wallet::IWalletItemCustomProperty>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Name(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Value(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Value(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AutoDetectLinks(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AutoDetectLinks(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DetailViewPosition(Windows::ApplicationModel::Wallet::WalletDetailViewPosition* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DetailViewPosition(Windows::ApplicationModel::Wallet::WalletDetailViewPosition value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SummaryViewPosition(Windows::ApplicationModel::Wallet::WalletSummaryViewPosition* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SummaryViewPosition(Windows::ApplicationModel::Wallet::WalletSummaryViewPosition value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Wallet::IWalletItemCustomPropertyFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateWalletItemCustomProperty(void* name, void* value, void** walletItemCustomProperty) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Wallet::IWalletItemFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateWalletItem(Windows::ApplicationModel::Wallet::WalletItemKind kind, void* displayName, void** walletItem) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Wallet::IWalletItemStore>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL AddAsync(void* id, void* item, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL ClearAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetWalletItemAsync(void* id, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetItemsAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetItemsWithKindAsync(Windows::ApplicationModel::Wallet::WalletItemKind kind, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL ImportItemAsync(void* stream, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL DeleteAsync(void* id, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL ShowAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL ShowItemAsync(void* id, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL UpdateAsync(void* item, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Wallet::IWalletItemStore2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_ItemsChanged(void* handler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ItemsChanged(winrt::event_token cookie) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Wallet::IWalletManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL RequestStoreAsync(void** operation) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Wallet::IWalletRelevantLocation>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Position(struct struct_Windows_Devices_Geolocation_BasicGeoposition* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Position(struct struct_Windows_Devices_Geolocation_BasicGeoposition value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DisplayMessage(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DisplayMessage(void* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Wallet::IWalletTransaction>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Description(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Description(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DisplayAmount(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DisplayAmount(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IgnoreTimeOfDay(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IgnoreTimeOfDay(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DisplayLocation(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DisplayLocation(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TransactionDate(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_TransactionDate(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsLaunchable(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsLaunchable(bool value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Wallet::IWalletVerb>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Name(void* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Wallet::IWalletVerbFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateWalletVerb(void* name, void** WalletVerb) noexcept = 0;
};};

template <typename D>
struct consume_Windows_ApplicationModel_Wallet_IWalletBarcode
{
    Windows::ApplicationModel::Wallet::WalletBarcodeSymbology Symbology() const;
    hstring Value() const;
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStreamReference> GetImageAsync() const;
};
template <> struct consume<Windows::ApplicationModel::Wallet::IWalletBarcode> { template <typename D> using type = consume_Windows_ApplicationModel_Wallet_IWalletBarcode<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Wallet_IWalletBarcodeFactory
{
    Windows::ApplicationModel::Wallet::WalletBarcode CreateWalletBarcode(Windows::ApplicationModel::Wallet::WalletBarcodeSymbology const& symbology, param::hstring const& value) const;
    Windows::ApplicationModel::Wallet::WalletBarcode CreateCustomWalletBarcode(Windows::Storage::Streams::IRandomAccessStreamReference const& streamToBarcodeImage) const;
};
template <> struct consume<Windows::ApplicationModel::Wallet::IWalletBarcodeFactory> { template <typename D> using type = consume_Windows_ApplicationModel_Wallet_IWalletBarcodeFactory<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Wallet_IWalletItem
{
    hstring DisplayName() const;
    void DisplayName(param::hstring const& value) const;
    hstring Id() const;
    bool IsAcknowledged() const;
    void IsAcknowledged(bool value) const;
    hstring IssuerDisplayName() const;
    void IssuerDisplayName(param::hstring const& value) const;
    Windows::Foundation::IReference<Windows::Foundation::DateTime> LastUpdated() const;
    void LastUpdated(optional<Windows::Foundation::DateTime> const& value) const;
    Windows::ApplicationModel::Wallet::WalletItemKind Kind() const;
    Windows::ApplicationModel::Wallet::WalletBarcode Barcode() const;
    void Barcode(Windows::ApplicationModel::Wallet::WalletBarcode const& value) const;
    Windows::Foundation::IReference<Windows::Foundation::DateTime> ExpirationDate() const;
    void ExpirationDate(optional<Windows::Foundation::DateTime> const& value) const;
    Windows::Storage::Streams::IRandomAccessStreamReference Logo159x159() const;
    void Logo159x159(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const;
    Windows::Storage::Streams::IRandomAccessStreamReference Logo336x336() const;
    void Logo336x336(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const;
    Windows::Storage::Streams::IRandomAccessStreamReference Logo99x99() const;
    void Logo99x99(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const;
    hstring DisplayMessage() const;
    void DisplayMessage(param::hstring const& value) const;
    bool IsDisplayMessageLaunchable() const;
    void IsDisplayMessageLaunchable(bool value) const;
    hstring LogoText() const;
    void LogoText(param::hstring const& value) const;
    Windows::UI::Color HeaderColor() const;
    void HeaderColor(Windows::UI::Color const& value) const;
    Windows::UI::Color BodyColor() const;
    void BodyColor(Windows::UI::Color const& value) const;
    Windows::UI::Color HeaderFontColor() const;
    void HeaderFontColor(Windows::UI::Color const& value) const;
    Windows::UI::Color BodyFontColor() const;
    void BodyFontColor(Windows::UI::Color const& value) const;
    Windows::Storage::Streams::IRandomAccessStreamReference HeaderBackgroundImage() const;
    void HeaderBackgroundImage(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const;
    Windows::Storage::Streams::IRandomAccessStreamReference BodyBackgroundImage() const;
    void BodyBackgroundImage(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const;
    Windows::Storage::Streams::IRandomAccessStreamReference LogoImage() const;
    void LogoImage(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const;
    Windows::Storage::Streams::IRandomAccessStreamReference PromotionalImage() const;
    void PromotionalImage(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const;
    Windows::Foundation::IReference<Windows::Foundation::DateTime> RelevantDate() const;
    void RelevantDate(optional<Windows::Foundation::DateTime> const& value) const;
    hstring RelevantDateDisplayMessage() const;
    void RelevantDateDisplayMessage(param::hstring const& value) const;
    Windows::Foundation::Collections::IMap<hstring, Windows::ApplicationModel::Wallet::WalletTransaction> TransactionHistory() const;
    Windows::Foundation::Collections::IMap<hstring, Windows::ApplicationModel::Wallet::WalletRelevantLocation> RelevantLocations() const;
    bool IsMoreTransactionHistoryLaunchable() const;
    void IsMoreTransactionHistoryLaunchable(bool value) const;
    Windows::Foundation::Collections::IMap<hstring, Windows::ApplicationModel::Wallet::WalletItemCustomProperty> DisplayProperties() const;
    Windows::Foundation::Collections::IMap<hstring, Windows::ApplicationModel::Wallet::WalletVerb> Verbs() const;
};
template <> struct consume<Windows::ApplicationModel::Wallet::IWalletItem> { template <typename D> using type = consume_Windows_ApplicationModel_Wallet_IWalletItem<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Wallet_IWalletItemCustomProperty
{
    hstring Name() const;
    void Name(param::hstring const& value) const;
    hstring Value() const;
    void Value(param::hstring const& value) const;
    bool AutoDetectLinks() const;
    void AutoDetectLinks(bool value) const;
    Windows::ApplicationModel::Wallet::WalletDetailViewPosition DetailViewPosition() const;
    void DetailViewPosition(Windows::ApplicationModel::Wallet::WalletDetailViewPosition const& value) const;
    Windows::ApplicationModel::Wallet::WalletSummaryViewPosition SummaryViewPosition() const;
    void SummaryViewPosition(Windows::ApplicationModel::Wallet::WalletSummaryViewPosition const& value) const;
};
template <> struct consume<Windows::ApplicationModel::Wallet::IWalletItemCustomProperty> { template <typename D> using type = consume_Windows_ApplicationModel_Wallet_IWalletItemCustomProperty<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Wallet_IWalletItemCustomPropertyFactory
{
    Windows::ApplicationModel::Wallet::WalletItemCustomProperty CreateWalletItemCustomProperty(param::hstring const& name, param::hstring const& value) const;
};
template <> struct consume<Windows::ApplicationModel::Wallet::IWalletItemCustomPropertyFactory> { template <typename D> using type = consume_Windows_ApplicationModel_Wallet_IWalletItemCustomPropertyFactory<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Wallet_IWalletItemFactory
{
    Windows::ApplicationModel::Wallet::WalletItem CreateWalletItem(Windows::ApplicationModel::Wallet::WalletItemKind const& kind, param::hstring const& displayName) const;
};
template <> struct consume<Windows::ApplicationModel::Wallet::IWalletItemFactory> { template <typename D> using type = consume_Windows_ApplicationModel_Wallet_IWalletItemFactory<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Wallet_IWalletItemStore
{
    Windows::Foundation::IAsyncAction AddAsync(param::hstring const& id, Windows::ApplicationModel::Wallet::WalletItem const& item) const;
    Windows::Foundation::IAsyncAction ClearAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Wallet::WalletItem> GetWalletItemAsync(param::hstring const& id) const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Wallet::WalletItem>> GetItemsAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Wallet::WalletItem>> GetItemsAsync(Windows::ApplicationModel::Wallet::WalletItemKind const& kind) const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Wallet::WalletItem> ImportItemAsync(Windows::Storage::Streams::IRandomAccessStreamReference const& stream) const;
    Windows::Foundation::IAsyncAction DeleteAsync(param::hstring const& id) const;
    Windows::Foundation::IAsyncAction ShowAsync() const;
    Windows::Foundation::IAsyncAction ShowAsync(param::hstring const& id) const;
    Windows::Foundation::IAsyncAction UpdateAsync(Windows::ApplicationModel::Wallet::WalletItem const& item) const;
};
template <> struct consume<Windows::ApplicationModel::Wallet::IWalletItemStore> { template <typename D> using type = consume_Windows_ApplicationModel_Wallet_IWalletItemStore<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Wallet_IWalletItemStore2
{
    winrt::event_token ItemsChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Wallet::WalletItemStore, Windows::Foundation::IInspectable> const& handler) const;
    using ItemsChanged_revoker = impl::event_revoker<Windows::ApplicationModel::Wallet::IWalletItemStore2, &impl::abi_t<Windows::ApplicationModel::Wallet::IWalletItemStore2>::remove_ItemsChanged>;
    ItemsChanged_revoker ItemsChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Wallet::WalletItemStore, Windows::Foundation::IInspectable> const& handler) const;
    void ItemsChanged(winrt::event_token const& cookie) const noexcept;
};
template <> struct consume<Windows::ApplicationModel::Wallet::IWalletItemStore2> { template <typename D> using type = consume_Windows_ApplicationModel_Wallet_IWalletItemStore2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Wallet_IWalletManagerStatics
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Wallet::WalletItemStore> RequestStoreAsync() const;
};
template <> struct consume<Windows::ApplicationModel::Wallet::IWalletManagerStatics> { template <typename D> using type = consume_Windows_ApplicationModel_Wallet_IWalletManagerStatics<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Wallet_IWalletRelevantLocation
{
    Windows::Devices::Geolocation::BasicGeoposition Position() const;
    void Position(Windows::Devices::Geolocation::BasicGeoposition const& value) const;
    hstring DisplayMessage() const;
    void DisplayMessage(param::hstring const& value) const;
};
template <> struct consume<Windows::ApplicationModel::Wallet::IWalletRelevantLocation> { template <typename D> using type = consume_Windows_ApplicationModel_Wallet_IWalletRelevantLocation<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Wallet_IWalletTransaction
{
    hstring Description() const;
    void Description(param::hstring const& value) const;
    hstring DisplayAmount() const;
    void DisplayAmount(param::hstring const& value) const;
    bool IgnoreTimeOfDay() const;
    void IgnoreTimeOfDay(bool value) const;
    hstring DisplayLocation() const;
    void DisplayLocation(param::hstring const& value) const;
    Windows::Foundation::IReference<Windows::Foundation::DateTime> TransactionDate() const;
    void TransactionDate(optional<Windows::Foundation::DateTime> const& value) const;
    bool IsLaunchable() const;
    void IsLaunchable(bool value) const;
};
template <> struct consume<Windows::ApplicationModel::Wallet::IWalletTransaction> { template <typename D> using type = consume_Windows_ApplicationModel_Wallet_IWalletTransaction<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Wallet_IWalletVerb
{
    hstring Name() const;
    void Name(param::hstring const& value) const;
};
template <> struct consume<Windows::ApplicationModel::Wallet::IWalletVerb> { template <typename D> using type = consume_Windows_ApplicationModel_Wallet_IWalletVerb<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Wallet_IWalletVerbFactory
{
    Windows::ApplicationModel::Wallet::WalletVerb CreateWalletVerb(param::hstring const& name) const;
};
template <> struct consume<Windows::ApplicationModel::Wallet::IWalletVerbFactory> { template <typename D> using type = consume_Windows_ApplicationModel_Wallet_IWalletVerbFactory<D>; };

}
