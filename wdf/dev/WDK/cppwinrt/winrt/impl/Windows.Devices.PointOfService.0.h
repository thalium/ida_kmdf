// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Graphics::Imaging {

struct BitmapFrame;

}

WINRT_EXPORT namespace winrt::Windows::Storage {

struct StorageFile;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IBuffer;
struct IRandomAccessStreamWithContentType;

}

WINRT_EXPORT namespace winrt::Windows::Devices::PointOfService {

enum class BarcodeScannerStatus : int32_t
{
    Online = 0,
    Off = 1,
    Offline = 2,
    OffOrOffline = 3,
    Extended = 4,
};

enum class BarcodeSymbologyDecodeLengthKind : int32_t
{
    AnyLength = 0,
    Discrete = 1,
    Range = 2,
};

enum class CashDrawerStatusKind : int32_t
{
    Online = 0,
    Off = 1,
    Offline = 2,
    OffOrOffline = 3,
    Extended = 4,
};

enum class LineDisplayCursorType : int32_t
{
    None = 0,
    Block = 1,
    HalfBlock = 2,
    Underline = 3,
    Reverse = 4,
    Other = 5,
};

enum class LineDisplayDescriptorState : int32_t
{
    Off = 0,
    On = 1,
    Blink = 2,
};

enum class LineDisplayHorizontalAlignment : int32_t
{
    Left = 0,
    Center = 1,
    Right = 2,
};

enum class LineDisplayMarqueeFormat : int32_t
{
    None = 0,
    Walk = 1,
    Place = 2,
};

enum class LineDisplayPowerStatus : int32_t
{
    Unknown = 0,
    Online = 1,
    Off = 2,
    Offline = 3,
    OffOrOffline = 4,
};

enum class LineDisplayScrollDirection : int32_t
{
    Up = 0,
    Down = 1,
    Left = 2,
    Right = 3,
};

enum class LineDisplayTextAttribute : int32_t
{
    Normal = 0,
    Blink = 1,
    Reverse = 2,
    ReverseBlink = 3,
};

enum class LineDisplayTextAttributeGranularity : int32_t
{
    NotSupported = 0,
    EntireDisplay = 1,
    PerCharacter = 2,
};

enum class LineDisplayVerticalAlignment : int32_t
{
    Top = 0,
    Center = 1,
    Bottom = 2,
};

enum class MagneticStripeReaderAuthenticationLevel : int32_t
{
    NotSupported = 0,
    Optional = 1,
    Required = 2,
};

enum class MagneticStripeReaderAuthenticationProtocol : int32_t
{
    None = 0,
    ChallengeResponse = 1,
};

enum class MagneticStripeReaderErrorReportingType : int32_t
{
    CardLevel = 0,
    TrackLevel = 1,
};

enum class MagneticStripeReaderStatus : int32_t
{
    Unauthenticated = 0,
    Authenticated = 1,
    Extended = 2,
};

enum class MagneticStripeReaderTrackErrorType : int32_t
{
    None = 0,
    StartSentinelError = 1,
    EndSentinelError = 2,
    ParityError = 3,
    LrcError = 4,
    Unknown = -1,
};

enum class MagneticStripeReaderTrackIds : int32_t
{
    None = 0,
    Track1 = 1,
    Track2 = 2,
    Track3 = 4,
    Track4 = 8,
};

enum class PosConnectionTypes : uint32_t
{
    Local = 0x1,
    IP = 0x2,
    Bluetooth = 0x4,
    All = 0xFFFFFFFF,
};

enum class PosPrinterAlignment : int32_t
{
    Left = 0,
    Center = 1,
    Right = 2,
};

enum class PosPrinterBarcodeTextPosition : int32_t
{
    None = 0,
    Above = 1,
    Below = 2,
};

enum class PosPrinterCartridgeSensors : uint32_t
{
    None = 0x0,
    Removed = 0x1,
    Empty = 0x2,
    HeadCleaning = 0x4,
    NearEnd = 0x8,
};

enum class PosPrinterColorCapabilities : uint32_t
{
    None = 0x0,
    Primary = 0x1,
    Custom1 = 0x2,
    Custom2 = 0x4,
    Custom3 = 0x8,
    Custom4 = 0x10,
    Custom5 = 0x20,
    Custom6 = 0x40,
    Cyan = 0x80,
    Magenta = 0x100,
    Yellow = 0x200,
    Full = 0x400,
};

enum class PosPrinterColorCartridge : int32_t
{
    Unknown = 0,
    Primary = 1,
    Custom1 = 2,
    Custom2 = 3,
    Custom3 = 4,
    Custom4 = 5,
    Custom5 = 6,
    Custom6 = 7,
    Cyan = 8,
    Magenta = 9,
    Yellow = 10,
};

enum class PosPrinterLineDirection : int32_t
{
    Horizontal = 0,
    Vertical = 1,
};

enum class PosPrinterLineStyle : int32_t
{
    SingleSolid = 0,
    DoubleSolid = 1,
    Broken = 2,
    Chain = 3,
};

enum class PosPrinterMapMode : int32_t
{
    Dots = 0,
    Twips = 1,
    English = 2,
    Metric = 3,
};

enum class PosPrinterMarkFeedCapabilities : uint32_t
{
    None = 0x0,
    ToTakeUp = 0x1,
    ToCutter = 0x2,
    ToCurrentTopOfForm = 0x4,
    ToNextTopOfForm = 0x8,
};

enum class PosPrinterMarkFeedKind : int32_t
{
    ToTakeUp = 0,
    ToCutter = 1,
    ToCurrentTopOfForm = 2,
    ToNextTopOfForm = 3,
};

enum class PosPrinterPrintSide : int32_t
{
    Unknown = 0,
    Side1 = 1,
    Side2 = 2,
};

enum class PosPrinterRotation : int32_t
{
    Normal = 0,
    Right90 = 1,
    Left90 = 2,
    Rotate180 = 3,
};

enum class PosPrinterRuledLineCapabilities : uint32_t
{
    None = 0x0,
    Horizontal = 0x1,
    Vertical = 0x2,
};

enum class PosPrinterStatusKind : int32_t
{
    Online = 0,
    Off = 1,
    Offline = 2,
    OffOrOffline = 3,
    Extended = 4,
};

enum class UnifiedPosErrorReason : int32_t
{
    UnknownErrorReason = 0,
    NoService = 1,
    Disabled = 2,
    Illegal = 3,
    NoHardware = 4,
    Closed = 5,
    Offline = 6,
    Failure = 7,
    Timeout = 8,
    Busy = 9,
    Extended = 10,
};

enum class UnifiedPosErrorSeverity : int32_t
{
    UnknownErrorSeverity = 0,
    Warning = 1,
    Recoverable = 2,
    Unrecoverable = 3,
    AssistanceRequired = 4,
    Fatal = 5,
};

enum class UnifiedPosHealthCheckLevel : int32_t
{
    UnknownHealthCheckLevel = 0,
    POSInternal = 1,
    External = 2,
    Interactive = 3,
};

enum class UnifiedPosPowerReportingType : int32_t
{
    UnknownPowerReportingType = 0,
    Standard = 1,
    Advanced = 2,
};

struct IBarcodeScanner;
struct IBarcodeScanner2;
struct IBarcodeScannerCapabilities;
struct IBarcodeScannerCapabilities1;
struct IBarcodeScannerCapabilities2;
struct IBarcodeScannerDataReceivedEventArgs;
struct IBarcodeScannerErrorOccurredEventArgs;
struct IBarcodeScannerImagePreviewReceivedEventArgs;
struct IBarcodeScannerReport;
struct IBarcodeScannerReportFactory;
struct IBarcodeScannerStatics;
struct IBarcodeScannerStatics2;
struct IBarcodeScannerStatusUpdatedEventArgs;
struct IBarcodeSymbologiesStatics;
struct IBarcodeSymbologiesStatics2;
struct IBarcodeSymbologyAttributes;
struct ICashDrawer;
struct ICashDrawerCapabilities;
struct ICashDrawerCloseAlarm;
struct ICashDrawerEventSource;
struct ICashDrawerEventSourceEventArgs;
struct ICashDrawerStatics;
struct ICashDrawerStatics2;
struct ICashDrawerStatus;
struct ICashDrawerStatusUpdatedEventArgs;
struct IClaimedBarcodeScanner;
struct IClaimedBarcodeScanner1;
struct IClaimedBarcodeScanner2;
struct IClaimedBarcodeScanner3;
struct IClaimedBarcodeScanner4;
struct IClaimedBarcodeScannerClosedEventArgs;
struct IClaimedCashDrawer;
struct IClaimedCashDrawer2;
struct IClaimedCashDrawerClosedEventArgs;
struct IClaimedJournalPrinter;
struct IClaimedLineDisplay;
struct IClaimedLineDisplay2;
struct IClaimedLineDisplay3;
struct IClaimedLineDisplayClosedEventArgs;
struct IClaimedLineDisplayStatics;
struct IClaimedMagneticStripeReader;
struct IClaimedMagneticStripeReader2;
struct IClaimedMagneticStripeReaderClosedEventArgs;
struct IClaimedPosPrinter;
struct IClaimedPosPrinter2;
struct IClaimedPosPrinterClosedEventArgs;
struct IClaimedReceiptPrinter;
struct IClaimedSlipPrinter;
struct ICommonClaimedPosPrinterStation;
struct ICommonPosPrintStationCapabilities;
struct ICommonReceiptSlipCapabilities;
struct IJournalPrintJob;
struct IJournalPrinterCapabilities;
struct IJournalPrinterCapabilities2;
struct ILineDisplay;
struct ILineDisplay2;
struct ILineDisplayAttributes;
struct ILineDisplayCapabilities;
struct ILineDisplayCursor;
struct ILineDisplayCursorAttributes;
struct ILineDisplayCustomGlyphs;
struct ILineDisplayMarquee;
struct ILineDisplayStatics;
struct ILineDisplayStatics2;
struct ILineDisplayStatisticsCategorySelector;
struct ILineDisplayStatusUpdatedEventArgs;
struct ILineDisplayStoredBitmap;
struct ILineDisplayWindow;
struct ILineDisplayWindow2;
struct IMagneticStripeReader;
struct IMagneticStripeReaderAamvaCardDataReceivedEventArgs;
struct IMagneticStripeReaderBankCardDataReceivedEventArgs;
struct IMagneticStripeReaderCapabilities;
struct IMagneticStripeReaderCardTypesStatics;
struct IMagneticStripeReaderEncryptionAlgorithmsStatics;
struct IMagneticStripeReaderErrorOccurredEventArgs;
struct IMagneticStripeReaderReport;
struct IMagneticStripeReaderStatics;
struct IMagneticStripeReaderStatics2;
struct IMagneticStripeReaderStatusUpdatedEventArgs;
struct IMagneticStripeReaderTrackData;
struct IMagneticStripeReaderVendorSpecificCardDataReceivedEventArgs;
struct IPosPrinter;
struct IPosPrinter2;
struct IPosPrinterCapabilities;
struct IPosPrinterCharacterSetIdsStatics;
struct IPosPrinterFontProperty;
struct IPosPrinterJob;
struct IPosPrinterPrintOptions;
struct IPosPrinterReleaseDeviceRequestedEventArgs;
struct IPosPrinterStatics;
struct IPosPrinterStatics2;
struct IPosPrinterStatus;
struct IPosPrinterStatusUpdatedEventArgs;
struct IReceiptOrSlipJob;
struct IReceiptPrintJob;
struct IReceiptPrintJob2;
struct IReceiptPrinterCapabilities;
struct IReceiptPrinterCapabilities2;
struct ISlipPrintJob;
struct ISlipPrinterCapabilities;
struct ISlipPrinterCapabilities2;
struct IUnifiedPosErrorData;
struct IUnifiedPosErrorDataFactory;
struct BarcodeScanner;
struct BarcodeScannerCapabilities;
struct BarcodeScannerDataReceivedEventArgs;
struct BarcodeScannerErrorOccurredEventArgs;
struct BarcodeScannerImagePreviewReceivedEventArgs;
struct BarcodeScannerReport;
struct BarcodeScannerStatusUpdatedEventArgs;
struct BarcodeSymbologies;
struct BarcodeSymbologyAttributes;
struct CashDrawer;
struct CashDrawerCapabilities;
struct CashDrawerCloseAlarm;
struct CashDrawerClosedEventArgs;
struct CashDrawerEventSource;
struct CashDrawerOpenedEventArgs;
struct CashDrawerStatus;
struct CashDrawerStatusUpdatedEventArgs;
struct ClaimedBarcodeScanner;
struct ClaimedBarcodeScannerClosedEventArgs;
struct ClaimedCashDrawer;
struct ClaimedCashDrawerClosedEventArgs;
struct ClaimedJournalPrinter;
struct ClaimedLineDisplay;
struct ClaimedLineDisplayClosedEventArgs;
struct ClaimedMagneticStripeReader;
struct ClaimedMagneticStripeReaderClosedEventArgs;
struct ClaimedPosPrinter;
struct ClaimedPosPrinterClosedEventArgs;
struct ClaimedReceiptPrinter;
struct ClaimedSlipPrinter;
struct JournalPrintJob;
struct JournalPrinterCapabilities;
struct LineDisplay;
struct LineDisplayAttributes;
struct LineDisplayCapabilities;
struct LineDisplayCursor;
struct LineDisplayCursorAttributes;
struct LineDisplayCustomGlyphs;
struct LineDisplayMarquee;
struct LineDisplayStatisticsCategorySelector;
struct LineDisplayStatusUpdatedEventArgs;
struct LineDisplayStoredBitmap;
struct LineDisplayWindow;
struct MagneticStripeReader;
struct MagneticStripeReaderAamvaCardDataReceivedEventArgs;
struct MagneticStripeReaderBankCardDataReceivedEventArgs;
struct MagneticStripeReaderCapabilities;
struct MagneticStripeReaderCardTypes;
struct MagneticStripeReaderEncryptionAlgorithms;
struct MagneticStripeReaderErrorOccurredEventArgs;
struct MagneticStripeReaderReport;
struct MagneticStripeReaderStatusUpdatedEventArgs;
struct MagneticStripeReaderTrackData;
struct MagneticStripeReaderVendorSpecificCardDataReceivedEventArgs;
struct PosPrinter;
struct PosPrinterCapabilities;
struct PosPrinterCharacterSetIds;
struct PosPrinterFontProperty;
struct PosPrinterPrintOptions;
struct PosPrinterReleaseDeviceRequestedEventArgs;
struct PosPrinterStatus;
struct PosPrinterStatusUpdatedEventArgs;
struct ReceiptPrintJob;
struct ReceiptPrinterCapabilities;
struct SlipPrintJob;
struct SlipPrinterCapabilities;
struct UnifiedPosErrorData;
struct SizeUInt32;

}

namespace winrt::impl {

template<> struct is_enum_flag<Windows::Devices::PointOfService::PosConnectionTypes> : std::true_type {};
template<> struct is_enum_flag<Windows::Devices::PointOfService::PosPrinterCartridgeSensors> : std::true_type {};
template<> struct is_enum_flag<Windows::Devices::PointOfService::PosPrinterColorCapabilities> : std::true_type {};
template<> struct is_enum_flag<Windows::Devices::PointOfService::PosPrinterMarkFeedCapabilities> : std::true_type {};
template<> struct is_enum_flag<Windows::Devices::PointOfService::PosPrinterRuledLineCapabilities> : std::true_type {};
template <> struct category<Windows::Devices::PointOfService::IBarcodeScanner>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IBarcodeScanner2>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IBarcodeScannerCapabilities>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IBarcodeScannerCapabilities1>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IBarcodeScannerCapabilities2>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IBarcodeScannerDataReceivedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IBarcodeScannerErrorOccurredEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IBarcodeScannerImagePreviewReceivedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IBarcodeScannerReport>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IBarcodeScannerReportFactory>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IBarcodeScannerStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IBarcodeScannerStatics2>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IBarcodeScannerStatusUpdatedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IBarcodeSymbologiesStatics2>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IBarcodeSymbologyAttributes>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::ICashDrawer>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::ICashDrawerCapabilities>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::ICashDrawerCloseAlarm>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::ICashDrawerEventSource>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::ICashDrawerEventSourceEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::ICashDrawerStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::ICashDrawerStatics2>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::ICashDrawerStatus>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::ICashDrawerStatusUpdatedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IClaimedBarcodeScanner>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IClaimedBarcodeScanner1>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IClaimedBarcodeScanner2>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IClaimedBarcodeScanner3>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IClaimedBarcodeScanner4>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IClaimedBarcodeScannerClosedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IClaimedCashDrawer>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IClaimedCashDrawer2>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IClaimedCashDrawerClosedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IClaimedJournalPrinter>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IClaimedLineDisplay>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IClaimedLineDisplay2>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IClaimedLineDisplay3>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IClaimedLineDisplayClosedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IClaimedLineDisplayStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IClaimedMagneticStripeReader>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IClaimedMagneticStripeReader2>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IClaimedMagneticStripeReaderClosedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IClaimedPosPrinter>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IClaimedPosPrinter2>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IClaimedPosPrinterClosedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IClaimedReceiptPrinter>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IClaimedSlipPrinter>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::ICommonReceiptSlipCapabilities>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IJournalPrintJob>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IJournalPrinterCapabilities>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IJournalPrinterCapabilities2>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::ILineDisplay>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::ILineDisplay2>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::ILineDisplayAttributes>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::ILineDisplayCapabilities>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::ILineDisplayCursor>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::ILineDisplayCursorAttributes>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::ILineDisplayCustomGlyphs>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::ILineDisplayMarquee>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::ILineDisplayStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::ILineDisplayStatics2>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::ILineDisplayStatisticsCategorySelector>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::ILineDisplayStatusUpdatedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::ILineDisplayStoredBitmap>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::ILineDisplayWindow>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::ILineDisplayWindow2>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IMagneticStripeReader>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IMagneticStripeReaderCardTypesStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IMagneticStripeReaderEncryptionAlgorithmsStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IMagneticStripeReaderErrorOccurredEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IMagneticStripeReaderReport>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IMagneticStripeReaderStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IMagneticStripeReaderStatics2>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IMagneticStripeReaderStatusUpdatedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IMagneticStripeReaderTrackData>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IMagneticStripeReaderVendorSpecificCardDataReceivedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IPosPrinter>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IPosPrinter2>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IPosPrinterCapabilities>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IPosPrinterCharacterSetIdsStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IPosPrinterFontProperty>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IPosPrinterJob>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IPosPrinterPrintOptions>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IPosPrinterReleaseDeviceRequestedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IPosPrinterStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IPosPrinterStatics2>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IPosPrinterStatus>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IPosPrinterStatusUpdatedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IReceiptOrSlipJob>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IReceiptPrintJob>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IReceiptPrintJob2>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IReceiptPrinterCapabilities>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IReceiptPrinterCapabilities2>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::ISlipPrintJob>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::ISlipPrinterCapabilities>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::ISlipPrinterCapabilities2>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IUnifiedPosErrorData>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::IUnifiedPosErrorDataFactory>{ using type = interface_category; };
template <> struct category<Windows::Devices::PointOfService::BarcodeScanner>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::BarcodeScannerCapabilities>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::BarcodeScannerDataReceivedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::BarcodeScannerErrorOccurredEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::BarcodeScannerImagePreviewReceivedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::BarcodeScannerReport>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::BarcodeScannerStatusUpdatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::BarcodeSymbologies>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::BarcodeSymbologyAttributes>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::CashDrawer>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::CashDrawerCapabilities>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::CashDrawerCloseAlarm>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::CashDrawerClosedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::CashDrawerEventSource>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::CashDrawerOpenedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::CashDrawerStatus>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::CashDrawerStatusUpdatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::ClaimedBarcodeScanner>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::ClaimedBarcodeScannerClosedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::ClaimedCashDrawer>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::ClaimedCashDrawerClosedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::ClaimedJournalPrinter>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::ClaimedLineDisplay>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::ClaimedLineDisplayClosedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::ClaimedMagneticStripeReader>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::ClaimedMagneticStripeReaderClosedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::ClaimedPosPrinter>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::ClaimedPosPrinterClosedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::ClaimedReceiptPrinter>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::ClaimedSlipPrinter>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::JournalPrintJob>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::JournalPrinterCapabilities>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::LineDisplay>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::LineDisplayAttributes>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::LineDisplayCapabilities>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::LineDisplayCursor>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::LineDisplayCursorAttributes>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::LineDisplayCustomGlyphs>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::LineDisplayMarquee>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::LineDisplayStatisticsCategorySelector>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::LineDisplayStatusUpdatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::LineDisplayStoredBitmap>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::LineDisplayWindow>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::MagneticStripeReader>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::MagneticStripeReaderAamvaCardDataReceivedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::MagneticStripeReaderBankCardDataReceivedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::MagneticStripeReaderCapabilities>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::MagneticStripeReaderCardTypes>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::MagneticStripeReaderEncryptionAlgorithms>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::MagneticStripeReaderErrorOccurredEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::MagneticStripeReaderReport>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::MagneticStripeReaderStatusUpdatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::MagneticStripeReaderTrackData>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::MagneticStripeReaderVendorSpecificCardDataReceivedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::PosPrinter>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::PosPrinterCapabilities>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::PosPrinterCharacterSetIds>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::PosPrinterFontProperty>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::PosPrinterPrintOptions>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::PosPrinterReleaseDeviceRequestedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::PosPrinterStatus>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::PosPrinterStatusUpdatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::ReceiptPrintJob>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::ReceiptPrinterCapabilities>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::SlipPrintJob>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::SlipPrinterCapabilities>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::UnifiedPosErrorData>{ using type = class_category; };
template <> struct category<Windows::Devices::PointOfService::BarcodeScannerStatus>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::BarcodeSymbologyDecodeLengthKind>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::CashDrawerStatusKind>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::LineDisplayCursorType>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::LineDisplayDescriptorState>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::LineDisplayHorizontalAlignment>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::LineDisplayMarqueeFormat>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::LineDisplayPowerStatus>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::LineDisplayScrollDirection>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::LineDisplayTextAttribute>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::LineDisplayTextAttributeGranularity>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::LineDisplayVerticalAlignment>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::MagneticStripeReaderAuthenticationLevel>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::MagneticStripeReaderAuthenticationProtocol>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::MagneticStripeReaderErrorReportingType>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::MagneticStripeReaderStatus>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::MagneticStripeReaderTrackIds>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::PosConnectionTypes>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::PosPrinterAlignment>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::PosPrinterBarcodeTextPosition>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::PosPrinterCartridgeSensors>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::PosPrinterColorCapabilities>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::PosPrinterColorCartridge>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::PosPrinterLineDirection>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::PosPrinterLineStyle>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::PosPrinterMapMode>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::PosPrinterMarkFeedCapabilities>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::PosPrinterMarkFeedKind>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::PosPrinterPrintSide>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::PosPrinterRotation>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::PosPrinterRuledLineCapabilities>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::PosPrinterStatusKind>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::UnifiedPosErrorReason>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::UnifiedPosErrorSeverity>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::UnifiedPosPowerReportingType>{ using type = enum_category; };
template <> struct category<Windows::Devices::PointOfService::SizeUInt32>{ using type = struct_category<uint32_t,uint32_t>; };
template <> struct name<Windows::Devices::PointOfService::IBarcodeScanner>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IBarcodeScanner" }; };
template <> struct name<Windows::Devices::PointOfService::IBarcodeScanner2>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IBarcodeScanner2" }; };
template <> struct name<Windows::Devices::PointOfService::IBarcodeScannerCapabilities>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IBarcodeScannerCapabilities" }; };
template <> struct name<Windows::Devices::PointOfService::IBarcodeScannerCapabilities1>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IBarcodeScannerCapabilities1" }; };
template <> struct name<Windows::Devices::PointOfService::IBarcodeScannerCapabilities2>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IBarcodeScannerCapabilities2" }; };
template <> struct name<Windows::Devices::PointOfService::IBarcodeScannerDataReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IBarcodeScannerDataReceivedEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::IBarcodeScannerErrorOccurredEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IBarcodeScannerErrorOccurredEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::IBarcodeScannerImagePreviewReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IBarcodeScannerImagePreviewReceivedEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::IBarcodeScannerReport>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IBarcodeScannerReport" }; };
template <> struct name<Windows::Devices::PointOfService::IBarcodeScannerReportFactory>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IBarcodeScannerReportFactory" }; };
template <> struct name<Windows::Devices::PointOfService::IBarcodeScannerStatics>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IBarcodeScannerStatics" }; };
template <> struct name<Windows::Devices::PointOfService::IBarcodeScannerStatics2>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IBarcodeScannerStatics2" }; };
template <> struct name<Windows::Devices::PointOfService::IBarcodeScannerStatusUpdatedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IBarcodeScannerStatusUpdatedEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IBarcodeSymbologiesStatics" }; };
template <> struct name<Windows::Devices::PointOfService::IBarcodeSymbologiesStatics2>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IBarcodeSymbologiesStatics2" }; };
template <> struct name<Windows::Devices::PointOfService::IBarcodeSymbologyAttributes>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IBarcodeSymbologyAttributes" }; };
template <> struct name<Windows::Devices::PointOfService::ICashDrawer>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ICashDrawer" }; };
template <> struct name<Windows::Devices::PointOfService::ICashDrawerCapabilities>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ICashDrawerCapabilities" }; };
template <> struct name<Windows::Devices::PointOfService::ICashDrawerCloseAlarm>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ICashDrawerCloseAlarm" }; };
template <> struct name<Windows::Devices::PointOfService::ICashDrawerEventSource>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ICashDrawerEventSource" }; };
template <> struct name<Windows::Devices::PointOfService::ICashDrawerEventSourceEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ICashDrawerEventSourceEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::ICashDrawerStatics>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ICashDrawerStatics" }; };
template <> struct name<Windows::Devices::PointOfService::ICashDrawerStatics2>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ICashDrawerStatics2" }; };
template <> struct name<Windows::Devices::PointOfService::ICashDrawerStatus>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ICashDrawerStatus" }; };
template <> struct name<Windows::Devices::PointOfService::ICashDrawerStatusUpdatedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ICashDrawerStatusUpdatedEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::IClaimedBarcodeScanner>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IClaimedBarcodeScanner" }; };
template <> struct name<Windows::Devices::PointOfService::IClaimedBarcodeScanner1>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IClaimedBarcodeScanner1" }; };
template <> struct name<Windows::Devices::PointOfService::IClaimedBarcodeScanner2>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IClaimedBarcodeScanner2" }; };
template <> struct name<Windows::Devices::PointOfService::IClaimedBarcodeScanner3>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IClaimedBarcodeScanner3" }; };
template <> struct name<Windows::Devices::PointOfService::IClaimedBarcodeScanner4>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IClaimedBarcodeScanner4" }; };
template <> struct name<Windows::Devices::PointOfService::IClaimedBarcodeScannerClosedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IClaimedBarcodeScannerClosedEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::IClaimedCashDrawer>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IClaimedCashDrawer" }; };
template <> struct name<Windows::Devices::PointOfService::IClaimedCashDrawer2>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IClaimedCashDrawer2" }; };
template <> struct name<Windows::Devices::PointOfService::IClaimedCashDrawerClosedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IClaimedCashDrawerClosedEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::IClaimedJournalPrinter>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IClaimedJournalPrinter" }; };
template <> struct name<Windows::Devices::PointOfService::IClaimedLineDisplay>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IClaimedLineDisplay" }; };
template <> struct name<Windows::Devices::PointOfService::IClaimedLineDisplay2>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IClaimedLineDisplay2" }; };
template <> struct name<Windows::Devices::PointOfService::IClaimedLineDisplay3>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IClaimedLineDisplay3" }; };
template <> struct name<Windows::Devices::PointOfService::IClaimedLineDisplayClosedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IClaimedLineDisplayClosedEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::IClaimedLineDisplayStatics>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IClaimedLineDisplayStatics" }; };
template <> struct name<Windows::Devices::PointOfService::IClaimedMagneticStripeReader>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IClaimedMagneticStripeReader" }; };
template <> struct name<Windows::Devices::PointOfService::IClaimedMagneticStripeReader2>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IClaimedMagneticStripeReader2" }; };
template <> struct name<Windows::Devices::PointOfService::IClaimedMagneticStripeReaderClosedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IClaimedMagneticStripeReaderClosedEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::IClaimedPosPrinter>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IClaimedPosPrinter" }; };
template <> struct name<Windows::Devices::PointOfService::IClaimedPosPrinter2>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IClaimedPosPrinter2" }; };
template <> struct name<Windows::Devices::PointOfService::IClaimedPosPrinterClosedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IClaimedPosPrinterClosedEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::IClaimedReceiptPrinter>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IClaimedReceiptPrinter" }; };
template <> struct name<Windows::Devices::PointOfService::IClaimedSlipPrinter>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IClaimedSlipPrinter" }; };
template <> struct name<Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ICommonClaimedPosPrinterStation" }; };
template <> struct name<Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ICommonPosPrintStationCapabilities" }; };
template <> struct name<Windows::Devices::PointOfService::ICommonReceiptSlipCapabilities>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ICommonReceiptSlipCapabilities" }; };
template <> struct name<Windows::Devices::PointOfService::IJournalPrintJob>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IJournalPrintJob" }; };
template <> struct name<Windows::Devices::PointOfService::IJournalPrinterCapabilities>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IJournalPrinterCapabilities" }; };
template <> struct name<Windows::Devices::PointOfService::IJournalPrinterCapabilities2>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IJournalPrinterCapabilities2" }; };
template <> struct name<Windows::Devices::PointOfService::ILineDisplay>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ILineDisplay" }; };
template <> struct name<Windows::Devices::PointOfService::ILineDisplay2>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ILineDisplay2" }; };
template <> struct name<Windows::Devices::PointOfService::ILineDisplayAttributes>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ILineDisplayAttributes" }; };
template <> struct name<Windows::Devices::PointOfService::ILineDisplayCapabilities>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ILineDisplayCapabilities" }; };
template <> struct name<Windows::Devices::PointOfService::ILineDisplayCursor>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ILineDisplayCursor" }; };
template <> struct name<Windows::Devices::PointOfService::ILineDisplayCursorAttributes>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ILineDisplayCursorAttributes" }; };
template <> struct name<Windows::Devices::PointOfService::ILineDisplayCustomGlyphs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ILineDisplayCustomGlyphs" }; };
template <> struct name<Windows::Devices::PointOfService::ILineDisplayMarquee>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ILineDisplayMarquee" }; };
template <> struct name<Windows::Devices::PointOfService::ILineDisplayStatics>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ILineDisplayStatics" }; };
template <> struct name<Windows::Devices::PointOfService::ILineDisplayStatics2>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ILineDisplayStatics2" }; };
template <> struct name<Windows::Devices::PointOfService::ILineDisplayStatisticsCategorySelector>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ILineDisplayStatisticsCategorySelector" }; };
template <> struct name<Windows::Devices::PointOfService::ILineDisplayStatusUpdatedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ILineDisplayStatusUpdatedEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::ILineDisplayStoredBitmap>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ILineDisplayStoredBitmap" }; };
template <> struct name<Windows::Devices::PointOfService::ILineDisplayWindow>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ILineDisplayWindow" }; };
template <> struct name<Windows::Devices::PointOfService::ILineDisplayWindow2>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ILineDisplayWindow2" }; };
template <> struct name<Windows::Devices::PointOfService::IMagneticStripeReader>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IMagneticStripeReader" }; };
template <> struct name<Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IMagneticStripeReaderAamvaCardDataReceivedEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IMagneticStripeReaderBankCardDataReceivedEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IMagneticStripeReaderCapabilities" }; };
template <> struct name<Windows::Devices::PointOfService::IMagneticStripeReaderCardTypesStatics>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IMagneticStripeReaderCardTypesStatics" }; };
template <> struct name<Windows::Devices::PointOfService::IMagneticStripeReaderEncryptionAlgorithmsStatics>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IMagneticStripeReaderEncryptionAlgorithmsStatics" }; };
template <> struct name<Windows::Devices::PointOfService::IMagneticStripeReaderErrorOccurredEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IMagneticStripeReaderErrorOccurredEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::IMagneticStripeReaderReport>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IMagneticStripeReaderReport" }; };
template <> struct name<Windows::Devices::PointOfService::IMagneticStripeReaderStatics>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IMagneticStripeReaderStatics" }; };
template <> struct name<Windows::Devices::PointOfService::IMagneticStripeReaderStatics2>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IMagneticStripeReaderStatics2" }; };
template <> struct name<Windows::Devices::PointOfService::IMagneticStripeReaderStatusUpdatedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IMagneticStripeReaderStatusUpdatedEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::IMagneticStripeReaderTrackData>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IMagneticStripeReaderTrackData" }; };
template <> struct name<Windows::Devices::PointOfService::IMagneticStripeReaderVendorSpecificCardDataReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IMagneticStripeReaderVendorSpecificCardDataReceivedEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::IPosPrinter>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IPosPrinter" }; };
template <> struct name<Windows::Devices::PointOfService::IPosPrinter2>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IPosPrinter2" }; };
template <> struct name<Windows::Devices::PointOfService::IPosPrinterCapabilities>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IPosPrinterCapabilities" }; };
template <> struct name<Windows::Devices::PointOfService::IPosPrinterCharacterSetIdsStatics>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IPosPrinterCharacterSetIdsStatics" }; };
template <> struct name<Windows::Devices::PointOfService::IPosPrinterFontProperty>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IPosPrinterFontProperty" }; };
template <> struct name<Windows::Devices::PointOfService::IPosPrinterJob>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IPosPrinterJob" }; };
template <> struct name<Windows::Devices::PointOfService::IPosPrinterPrintOptions>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IPosPrinterPrintOptions" }; };
template <> struct name<Windows::Devices::PointOfService::IPosPrinterReleaseDeviceRequestedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IPosPrinterReleaseDeviceRequestedEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::IPosPrinterStatics>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IPosPrinterStatics" }; };
template <> struct name<Windows::Devices::PointOfService::IPosPrinterStatics2>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IPosPrinterStatics2" }; };
template <> struct name<Windows::Devices::PointOfService::IPosPrinterStatus>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IPosPrinterStatus" }; };
template <> struct name<Windows::Devices::PointOfService::IPosPrinterStatusUpdatedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IPosPrinterStatusUpdatedEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::IReceiptOrSlipJob>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IReceiptOrSlipJob" }; };
template <> struct name<Windows::Devices::PointOfService::IReceiptPrintJob>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IReceiptPrintJob" }; };
template <> struct name<Windows::Devices::PointOfService::IReceiptPrintJob2>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IReceiptPrintJob2" }; };
template <> struct name<Windows::Devices::PointOfService::IReceiptPrinterCapabilities>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IReceiptPrinterCapabilities" }; };
template <> struct name<Windows::Devices::PointOfService::IReceiptPrinterCapabilities2>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IReceiptPrinterCapabilities2" }; };
template <> struct name<Windows::Devices::PointOfService::ISlipPrintJob>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ISlipPrintJob" }; };
template <> struct name<Windows::Devices::PointOfService::ISlipPrinterCapabilities>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ISlipPrinterCapabilities" }; };
template <> struct name<Windows::Devices::PointOfService::ISlipPrinterCapabilities2>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ISlipPrinterCapabilities2" }; };
template <> struct name<Windows::Devices::PointOfService::IUnifiedPosErrorData>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IUnifiedPosErrorData" }; };
template <> struct name<Windows::Devices::PointOfService::IUnifiedPosErrorDataFactory>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.IUnifiedPosErrorDataFactory" }; };
template <> struct name<Windows::Devices::PointOfService::BarcodeScanner>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.BarcodeScanner" }; };
template <> struct name<Windows::Devices::PointOfService::BarcodeScannerCapabilities>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.BarcodeScannerCapabilities" }; };
template <> struct name<Windows::Devices::PointOfService::BarcodeScannerDataReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.BarcodeScannerDataReceivedEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::BarcodeScannerErrorOccurredEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.BarcodeScannerErrorOccurredEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::BarcodeScannerImagePreviewReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.BarcodeScannerImagePreviewReceivedEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::BarcodeScannerReport>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.BarcodeScannerReport" }; };
template <> struct name<Windows::Devices::PointOfService::BarcodeScannerStatusUpdatedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.BarcodeScannerStatusUpdatedEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::BarcodeSymbologies>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.BarcodeSymbologies" }; };
template <> struct name<Windows::Devices::PointOfService::BarcodeSymbologyAttributes>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.BarcodeSymbologyAttributes" }; };
template <> struct name<Windows::Devices::PointOfService::CashDrawer>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.CashDrawer" }; };
template <> struct name<Windows::Devices::PointOfService::CashDrawerCapabilities>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.CashDrawerCapabilities" }; };
template <> struct name<Windows::Devices::PointOfService::CashDrawerCloseAlarm>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.CashDrawerCloseAlarm" }; };
template <> struct name<Windows::Devices::PointOfService::CashDrawerClosedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.CashDrawerClosedEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::CashDrawerEventSource>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.CashDrawerEventSource" }; };
template <> struct name<Windows::Devices::PointOfService::CashDrawerOpenedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.CashDrawerOpenedEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::CashDrawerStatus>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.CashDrawerStatus" }; };
template <> struct name<Windows::Devices::PointOfService::CashDrawerStatusUpdatedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.CashDrawerStatusUpdatedEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::ClaimedBarcodeScanner>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ClaimedBarcodeScanner" }; };
template <> struct name<Windows::Devices::PointOfService::ClaimedBarcodeScannerClosedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ClaimedBarcodeScannerClosedEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::ClaimedCashDrawer>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ClaimedCashDrawer" }; };
template <> struct name<Windows::Devices::PointOfService::ClaimedCashDrawerClosedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ClaimedCashDrawerClosedEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::ClaimedJournalPrinter>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ClaimedJournalPrinter" }; };
template <> struct name<Windows::Devices::PointOfService::ClaimedLineDisplay>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ClaimedLineDisplay" }; };
template <> struct name<Windows::Devices::PointOfService::ClaimedLineDisplayClosedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ClaimedLineDisplayClosedEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::ClaimedMagneticStripeReader>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ClaimedMagneticStripeReader" }; };
template <> struct name<Windows::Devices::PointOfService::ClaimedMagneticStripeReaderClosedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ClaimedMagneticStripeReaderClosedEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::ClaimedPosPrinter>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ClaimedPosPrinter" }; };
template <> struct name<Windows::Devices::PointOfService::ClaimedPosPrinterClosedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ClaimedPosPrinterClosedEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::ClaimedReceiptPrinter>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ClaimedReceiptPrinter" }; };
template <> struct name<Windows::Devices::PointOfService::ClaimedSlipPrinter>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ClaimedSlipPrinter" }; };
template <> struct name<Windows::Devices::PointOfService::JournalPrintJob>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.JournalPrintJob" }; };
template <> struct name<Windows::Devices::PointOfService::JournalPrinterCapabilities>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.JournalPrinterCapabilities" }; };
template <> struct name<Windows::Devices::PointOfService::LineDisplay>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.LineDisplay" }; };
template <> struct name<Windows::Devices::PointOfService::LineDisplayAttributes>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.LineDisplayAttributes" }; };
template <> struct name<Windows::Devices::PointOfService::LineDisplayCapabilities>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.LineDisplayCapabilities" }; };
template <> struct name<Windows::Devices::PointOfService::LineDisplayCursor>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.LineDisplayCursor" }; };
template <> struct name<Windows::Devices::PointOfService::LineDisplayCursorAttributes>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.LineDisplayCursorAttributes" }; };
template <> struct name<Windows::Devices::PointOfService::LineDisplayCustomGlyphs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.LineDisplayCustomGlyphs" }; };
template <> struct name<Windows::Devices::PointOfService::LineDisplayMarquee>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.LineDisplayMarquee" }; };
template <> struct name<Windows::Devices::PointOfService::LineDisplayStatisticsCategorySelector>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.LineDisplayStatisticsCategorySelector" }; };
template <> struct name<Windows::Devices::PointOfService::LineDisplayStatusUpdatedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.LineDisplayStatusUpdatedEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::LineDisplayStoredBitmap>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.LineDisplayStoredBitmap" }; };
template <> struct name<Windows::Devices::PointOfService::LineDisplayWindow>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.LineDisplayWindow" }; };
template <> struct name<Windows::Devices::PointOfService::MagneticStripeReader>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.MagneticStripeReader" }; };
template <> struct name<Windows::Devices::PointOfService::MagneticStripeReaderAamvaCardDataReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.MagneticStripeReaderAamvaCardDataReceivedEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::MagneticStripeReaderBankCardDataReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.MagneticStripeReaderBankCardDataReceivedEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::MagneticStripeReaderCapabilities>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.MagneticStripeReaderCapabilities" }; };
template <> struct name<Windows::Devices::PointOfService::MagneticStripeReaderCardTypes>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.MagneticStripeReaderCardTypes" }; };
template <> struct name<Windows::Devices::PointOfService::MagneticStripeReaderEncryptionAlgorithms>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.MagneticStripeReaderEncryptionAlgorithms" }; };
template <> struct name<Windows::Devices::PointOfService::MagneticStripeReaderErrorOccurredEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.MagneticStripeReaderErrorOccurredEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::MagneticStripeReaderReport>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.MagneticStripeReaderReport" }; };
template <> struct name<Windows::Devices::PointOfService::MagneticStripeReaderStatusUpdatedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.MagneticStripeReaderStatusUpdatedEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::MagneticStripeReaderTrackData>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.MagneticStripeReaderTrackData" }; };
template <> struct name<Windows::Devices::PointOfService::MagneticStripeReaderVendorSpecificCardDataReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.MagneticStripeReaderVendorSpecificCardDataReceivedEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::PosPrinter>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.PosPrinter" }; };
template <> struct name<Windows::Devices::PointOfService::PosPrinterCapabilities>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.PosPrinterCapabilities" }; };
template <> struct name<Windows::Devices::PointOfService::PosPrinterCharacterSetIds>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.PosPrinterCharacterSetIds" }; };
template <> struct name<Windows::Devices::PointOfService::PosPrinterFontProperty>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.PosPrinterFontProperty" }; };
template <> struct name<Windows::Devices::PointOfService::PosPrinterPrintOptions>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.PosPrinterPrintOptions" }; };
template <> struct name<Windows::Devices::PointOfService::PosPrinterReleaseDeviceRequestedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.PosPrinterReleaseDeviceRequestedEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::PosPrinterStatus>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.PosPrinterStatus" }; };
template <> struct name<Windows::Devices::PointOfService::PosPrinterStatusUpdatedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.PosPrinterStatusUpdatedEventArgs" }; };
template <> struct name<Windows::Devices::PointOfService::ReceiptPrintJob>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ReceiptPrintJob" }; };
template <> struct name<Windows::Devices::PointOfService::ReceiptPrinterCapabilities>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.ReceiptPrinterCapabilities" }; };
template <> struct name<Windows::Devices::PointOfService::SlipPrintJob>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.SlipPrintJob" }; };
template <> struct name<Windows::Devices::PointOfService::SlipPrinterCapabilities>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.SlipPrinterCapabilities" }; };
template <> struct name<Windows::Devices::PointOfService::UnifiedPosErrorData>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.UnifiedPosErrorData" }; };
template <> struct name<Windows::Devices::PointOfService::BarcodeScannerStatus>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.BarcodeScannerStatus" }; };
template <> struct name<Windows::Devices::PointOfService::BarcodeSymbologyDecodeLengthKind>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.BarcodeSymbologyDecodeLengthKind" }; };
template <> struct name<Windows::Devices::PointOfService::CashDrawerStatusKind>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.CashDrawerStatusKind" }; };
template <> struct name<Windows::Devices::PointOfService::LineDisplayCursorType>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.LineDisplayCursorType" }; };
template <> struct name<Windows::Devices::PointOfService::LineDisplayDescriptorState>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.LineDisplayDescriptorState" }; };
template <> struct name<Windows::Devices::PointOfService::LineDisplayHorizontalAlignment>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.LineDisplayHorizontalAlignment" }; };
template <> struct name<Windows::Devices::PointOfService::LineDisplayMarqueeFormat>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.LineDisplayMarqueeFormat" }; };
template <> struct name<Windows::Devices::PointOfService::LineDisplayPowerStatus>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.LineDisplayPowerStatus" }; };
template <> struct name<Windows::Devices::PointOfService::LineDisplayScrollDirection>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.LineDisplayScrollDirection" }; };
template <> struct name<Windows::Devices::PointOfService::LineDisplayTextAttribute>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.LineDisplayTextAttribute" }; };
template <> struct name<Windows::Devices::PointOfService::LineDisplayTextAttributeGranularity>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.LineDisplayTextAttributeGranularity" }; };
template <> struct name<Windows::Devices::PointOfService::LineDisplayVerticalAlignment>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.LineDisplayVerticalAlignment" }; };
template <> struct name<Windows::Devices::PointOfService::MagneticStripeReaderAuthenticationLevel>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.MagneticStripeReaderAuthenticationLevel" }; };
template <> struct name<Windows::Devices::PointOfService::MagneticStripeReaderAuthenticationProtocol>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.MagneticStripeReaderAuthenticationProtocol" }; };
template <> struct name<Windows::Devices::PointOfService::MagneticStripeReaderErrorReportingType>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.MagneticStripeReaderErrorReportingType" }; };
template <> struct name<Windows::Devices::PointOfService::MagneticStripeReaderStatus>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.MagneticStripeReaderStatus" }; };
template <> struct name<Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.MagneticStripeReaderTrackErrorType" }; };
template <> struct name<Windows::Devices::PointOfService::MagneticStripeReaderTrackIds>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.MagneticStripeReaderTrackIds" }; };
template <> struct name<Windows::Devices::PointOfService::PosConnectionTypes>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.PosConnectionTypes" }; };
template <> struct name<Windows::Devices::PointOfService::PosPrinterAlignment>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.PosPrinterAlignment" }; };
template <> struct name<Windows::Devices::PointOfService::PosPrinterBarcodeTextPosition>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.PosPrinterBarcodeTextPosition" }; };
template <> struct name<Windows::Devices::PointOfService::PosPrinterCartridgeSensors>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.PosPrinterCartridgeSensors" }; };
template <> struct name<Windows::Devices::PointOfService::PosPrinterColorCapabilities>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.PosPrinterColorCapabilities" }; };
template <> struct name<Windows::Devices::PointOfService::PosPrinterColorCartridge>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.PosPrinterColorCartridge" }; };
template <> struct name<Windows::Devices::PointOfService::PosPrinterLineDirection>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.PosPrinterLineDirection" }; };
template <> struct name<Windows::Devices::PointOfService::PosPrinterLineStyle>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.PosPrinterLineStyle" }; };
template <> struct name<Windows::Devices::PointOfService::PosPrinterMapMode>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.PosPrinterMapMode" }; };
template <> struct name<Windows::Devices::PointOfService::PosPrinterMarkFeedCapabilities>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.PosPrinterMarkFeedCapabilities" }; };
template <> struct name<Windows::Devices::PointOfService::PosPrinterMarkFeedKind>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.PosPrinterMarkFeedKind" }; };
template <> struct name<Windows::Devices::PointOfService::PosPrinterPrintSide>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.PosPrinterPrintSide" }; };
template <> struct name<Windows::Devices::PointOfService::PosPrinterRotation>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.PosPrinterRotation" }; };
template <> struct name<Windows::Devices::PointOfService::PosPrinterRuledLineCapabilities>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.PosPrinterRuledLineCapabilities" }; };
template <> struct name<Windows::Devices::PointOfService::PosPrinterStatusKind>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.PosPrinterStatusKind" }; };
template <> struct name<Windows::Devices::PointOfService::UnifiedPosErrorReason>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.UnifiedPosErrorReason" }; };
template <> struct name<Windows::Devices::PointOfService::UnifiedPosErrorSeverity>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.UnifiedPosErrorSeverity" }; };
template <> struct name<Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.UnifiedPosHealthCheckLevel" }; };
template <> struct name<Windows::Devices::PointOfService::UnifiedPosPowerReportingType>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.UnifiedPosPowerReportingType" }; };
template <> struct name<Windows::Devices::PointOfService::SizeUInt32>{ static constexpr auto & value{ L"Windows.Devices.PointOfService.SizeUInt32" }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IBarcodeScanner>{ static constexpr guid value{ 0xBEA33E06,0xB264,0x4F03,{ 0xA9,0xC1,0x45,0xB2,0x0F,0x01,0x13,0x4F } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IBarcodeScanner2>{ static constexpr guid value{ 0x89215167,0x8CEE,0x436D,{ 0x89,0xAB,0x8D,0xFB,0x43,0xBB,0x42,0x86 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IBarcodeScannerCapabilities>{ static constexpr guid value{ 0xC60691E4,0xF2C8,0x4420,{ 0xA3,0x07,0xB1,0x2E,0xF6,0x62,0x28,0x57 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IBarcodeScannerCapabilities1>{ static constexpr guid value{ 0x8E5AB3E9,0x0E2C,0x472F,{ 0xA1,0xCC,0xEE,0x80,0x54,0xB6,0xA6,0x84 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IBarcodeScannerCapabilities2>{ static constexpr guid value{ 0xF211CFEC,0xE1A1,0x4EA8,{ 0x9A,0xBC,0x92,0xB1,0x59,0x62,0x70,0xAB } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IBarcodeScannerDataReceivedEventArgs>{ static constexpr guid value{ 0x4234A7E2,0xED97,0x467D,{ 0xAD,0x2B,0x01,0xE4,0x43,0x13,0xA9,0x29 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IBarcodeScannerErrorOccurredEventArgs>{ static constexpr guid value{ 0x2CD2602F,0xCF3A,0x4002,{ 0xA7,0x5A,0xC5,0xEC,0x46,0x8F,0x0A,0x20 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IBarcodeScannerImagePreviewReceivedEventArgs>{ static constexpr guid value{ 0xF3B7DE85,0x6E8B,0x434E,{ 0x9F,0x58,0x06,0xEF,0x26,0xBC,0x4B,0xAF } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IBarcodeScannerReport>{ static constexpr guid value{ 0x5CE4D8B0,0xA489,0x4B96,{ 0x86,0xC4,0xF0,0xBF,0x8A,0x37,0x75,0x3D } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IBarcodeScannerReportFactory>{ static constexpr guid value{ 0xA2547326,0x2013,0x457C,{ 0x89,0x63,0x49,0xC1,0x5D,0xCA,0x78,0xCE } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IBarcodeScannerStatics>{ static constexpr guid value{ 0x5D115F6F,0xDA49,0x41E8,{ 0x8C,0x8C,0xF0,0xCB,0x62,0xA9,0xC4,0xFC } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IBarcodeScannerStatics2>{ static constexpr guid value{ 0xB8652473,0xA36F,0x4007,{ 0xB1,0xD0,0x27,0x9E,0xBE,0x92,0xA6,0x56 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IBarcodeScannerStatusUpdatedEventArgs>{ static constexpr guid value{ 0x355D8586,0x9C43,0x462B,{ 0xA9,0x1A,0x81,0x6D,0xC9,0x7F,0x45,0x2C } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>{ static constexpr guid value{ 0xCA8549BB,0x06D2,0x43F4,{ 0xA4,0x4B,0xC6,0x20,0x67,0x9F,0xD8,0xD0 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IBarcodeSymbologiesStatics2>{ static constexpr guid value{ 0x8B7518F4,0x99D0,0x40BF,{ 0x94,0x24,0xB9,0x1D,0x6D,0xD4,0xC6,0xE0 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IBarcodeSymbologyAttributes>{ static constexpr guid value{ 0x66413A78,0xAB7A,0x4ADA,{ 0x8E,0xCE,0x93,0x60,0x14,0xB2,0xEA,0xD7 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::ICashDrawer>{ static constexpr guid value{ 0x9F88F5C8,0xDE54,0x4AEE,{ 0xA8,0x90,0x92,0x0B,0xCB,0xFE,0x30,0xFC } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::ICashDrawerCapabilities>{ static constexpr guid value{ 0x0BC6DE0B,0xE8E7,0x4B1F,{ 0xB1,0xD1,0x3E,0x50,0x1A,0xD0,0x82,0x47 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::ICashDrawerCloseAlarm>{ static constexpr guid value{ 0x6BF88CC7,0x6F63,0x430E,{ 0xAB,0x3B,0x95,0xD7,0x5F,0xFB,0xE8,0x7F } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::ICashDrawerEventSource>{ static constexpr guid value{ 0xE006E46C,0xF2F9,0x442F,{ 0x8D,0xD6,0x06,0xC1,0x0A,0x42,0x27,0xBA } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::ICashDrawerEventSourceEventArgs>{ static constexpr guid value{ 0x69CB3BC1,0x147F,0x421C,{ 0x9C,0x23,0x09,0x01,0x23,0xBB,0x78,0x6C } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::ICashDrawerStatics>{ static constexpr guid value{ 0xDFA0955A,0xD437,0x4FFF,{ 0xB5,0x47,0xDD,0xA9,0x69,0xA4,0xF8,0x83 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::ICashDrawerStatics2>{ static constexpr guid value{ 0x3E818121,0x8C42,0x40E8,{ 0x9C,0x0E,0x40,0x29,0x70,0x48,0x10,0x4C } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::ICashDrawerStatus>{ static constexpr guid value{ 0x6BBD78BF,0xDCA1,0x4E06,{ 0x99,0xEB,0x5A,0xF6,0xA5,0xAE,0xC1,0x08 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::ICashDrawerStatusUpdatedEventArgs>{ static constexpr guid value{ 0x30AAE98A,0x0D70,0x459C,{ 0x95,0x53,0x87,0xE1,0x24,0xC5,0x24,0x88 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IClaimedBarcodeScanner>{ static constexpr guid value{ 0x4A63B49C,0x8FA4,0x4332,{ 0xBB,0x26,0x94,0x5D,0x11,0xD8,0x1E,0x0F } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IClaimedBarcodeScanner1>{ static constexpr guid value{ 0xF61AAD0C,0x8551,0x42B4,{ 0x99,0x8C,0x97,0x0C,0x20,0x21,0x0A,0x22 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IClaimedBarcodeScanner2>{ static constexpr guid value{ 0xE3B59E8C,0x2D8B,0x4F70,{ 0x8A,0xF3,0x34,0x48,0xBE,0xDD,0x5F,0xE2 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IClaimedBarcodeScanner3>{ static constexpr guid value{ 0xE6CEB430,0x712E,0x45FC,{ 0x8B,0x86,0xCD,0x55,0xF5,0xAE,0xF7,0x9D } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IClaimedBarcodeScanner4>{ static constexpr guid value{ 0x5D501F97,0x376A,0x41A8,{ 0xA2,0x30,0x2F,0x37,0xC1,0x94,0x9D,0xDE } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IClaimedBarcodeScannerClosedEventArgs>{ static constexpr guid value{ 0xCF7D5489,0xA22C,0x4C65,{ 0xA9,0x01,0x88,0xD7,0x7D,0x83,0x39,0x54 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IClaimedCashDrawer>{ static constexpr guid value{ 0xCA3F99AF,0xABB8,0x42C1,{ 0x8A,0x84,0x5C,0x66,0x51,0x2F,0x5A,0x75 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IClaimedCashDrawer2>{ static constexpr guid value{ 0x9CBAB5A2,0xDE42,0x4D5B,{ 0xB0,0xC1,0x9B,0x57,0xA2,0xBA,0x89,0xC3 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IClaimedCashDrawerClosedEventArgs>{ static constexpr guid value{ 0xCC573F33,0x3F34,0x4C5C,{ 0xBA,0xAE,0xDE,0xAD,0xF1,0x6C,0xD7,0xFA } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IClaimedJournalPrinter>{ static constexpr guid value{ 0x67EA0630,0x517D,0x487F,{ 0x9F,0xDF,0xD2,0xE0,0xA0,0xA2,0x64,0xA5 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IClaimedLineDisplay>{ static constexpr guid value{ 0x120AC970,0x9A75,0x4ACF,{ 0xAA,0xE7,0x09,0x97,0x2B,0xCF,0x87,0x94 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IClaimedLineDisplay2>{ static constexpr guid value{ 0xA31C75ED,0x41F5,0x4E76,{ 0xA0,0x74,0x79,0x5E,0x47,0xA4,0x6E,0x97 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IClaimedLineDisplay3>{ static constexpr guid value{ 0x642ECD92,0xE9D4,0x4ECC,{ 0xAF,0x75,0x32,0x9C,0x27,0x4C,0xD1,0x8F } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IClaimedLineDisplayClosedEventArgs>{ static constexpr guid value{ 0xF915F364,0xD3D5,0x4F10,{ 0xB5,0x11,0x90,0x93,0x9E,0xDF,0xAC,0xD8 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IClaimedLineDisplayStatics>{ static constexpr guid value{ 0x78CA98FB,0x8B6B,0x4973,{ 0x86,0xF0,0x3E,0x57,0x0C,0x35,0x18,0x25 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IClaimedMagneticStripeReader>{ static constexpr guid value{ 0x475CA8F3,0x9417,0x48BC,{ 0xB9,0xD7,0x41,0x63,0xA7,0x84,0x4C,0x02 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IClaimedMagneticStripeReader2>{ static constexpr guid value{ 0x236FAFDF,0xE2DC,0x4D7D,{ 0x9C,0x78,0x06,0x0D,0xF2,0xBF,0x29,0x28 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IClaimedMagneticStripeReaderClosedEventArgs>{ static constexpr guid value{ 0x14ADA93A,0xADCD,0x4C80,{ 0xAC,0xDA,0xC3,0xEA,0xED,0x26,0x47,0xE1 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IClaimedPosPrinter>{ static constexpr guid value{ 0x6D64CE0C,0xE03E,0x4B14,{ 0xA3,0x8E,0xC2,0x8C,0x34,0xB8,0x63,0x53 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IClaimedPosPrinter2>{ static constexpr guid value{ 0x5BF7A3D5,0x5198,0x437A,{ 0x82,0xDF,0x58,0x99,0x93,0xFA,0x77,0xE1 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IClaimedPosPrinterClosedEventArgs>{ static constexpr guid value{ 0xE2B7A27B,0x4D40,0x471D,{ 0x92,0xED,0x63,0x37,0x5B,0x18,0xC7,0x88 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IClaimedReceiptPrinter>{ static constexpr guid value{ 0x9AD27A74,0xDD61,0x4EE2,{ 0x98,0x37,0x5B,0x5D,0x72,0xD5,0x38,0xB9 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IClaimedSlipPrinter>{ static constexpr guid value{ 0xBD5DEFF2,0xAF90,0x4E8A,{ 0xB7,0x7B,0xE3,0xAE,0x9C,0xA6,0x3A,0x7F } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation>{ static constexpr guid value{ 0xB7EB66A8,0xFE8A,0x4CFB,{ 0x8B,0x42,0xE3,0x5B,0x28,0x0C,0xB2,0x7C } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities>{ static constexpr guid value{ 0xDE5B52CA,0xE02E,0x40E9,{ 0x9E,0x5E,0x1B,0x48,0x8E,0x6A,0xAC,0xFC } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::ICommonReceiptSlipCapabilities>{ static constexpr guid value{ 0x09286B8B,0x9873,0x4D05,{ 0xBF,0xBE,0x47,0x27,0xA6,0x03,0x8F,0x69 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IJournalPrintJob>{ static constexpr guid value{ 0x9F4F2864,0xF3F0,0x55D0,{ 0x8C,0x39,0x74,0xCC,0x91,0x78,0x3E,0xED } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IJournalPrinterCapabilities>{ static constexpr guid value{ 0x3B5CCC43,0xE047,0x4463,{ 0xBB,0x58,0x17,0xB5,0xBA,0x1D,0x80,0x56 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IJournalPrinterCapabilities2>{ static constexpr guid value{ 0x03B0B645,0x33B8,0x533B,{ 0xBA,0xAA,0xA4,0x38,0x92,0x83,0xAB,0x0A } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::ILineDisplay>{ static constexpr guid value{ 0x24F5DF4E,0x3C99,0x44E2,{ 0xB7,0x3F,0xE5,0x1B,0xE3,0x63,0x7A,0x8C } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::ILineDisplay2>{ static constexpr guid value{ 0xC296A628,0xEF44,0x40F3,{ 0xBD,0x1C,0xB0,0x4C,0x6A,0x5C,0xDC,0x7D } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::ILineDisplayAttributes>{ static constexpr guid value{ 0xC17DE99C,0x229A,0x4C14,{ 0xA6,0xF1,0xB4,0xE4,0xB1,0xFE,0xAD,0x92 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::ILineDisplayCapabilities>{ static constexpr guid value{ 0x5A15B5D1,0x8DC5,0x4B9C,{ 0x91,0x72,0x30,0x3E,0x47,0xB7,0x0C,0x55 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::ILineDisplayCursor>{ static constexpr guid value{ 0xECDFFC45,0x754A,0x4E3B,{ 0xAB,0x2B,0x15,0x11,0x81,0x08,0x56,0x05 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::ILineDisplayCursorAttributes>{ static constexpr guid value{ 0x4E2D54FE,0x4FFD,0x4190,{ 0xAA,0xE1,0xCE,0x28,0x5F,0x20,0xC8,0x96 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::ILineDisplayCustomGlyphs>{ static constexpr guid value{ 0x2257F63C,0xF263,0x44F1,{ 0xA1,0xA0,0xE7,0x50,0xA6,0xA0,0xEC,0x54 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::ILineDisplayMarquee>{ static constexpr guid value{ 0xA3D33E3E,0xF46A,0x4B7A,{ 0xBC,0x21,0x53,0xEB,0x3B,0x57,0xF8,0xB4 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::ILineDisplayStatics>{ static constexpr guid value{ 0x022DC0B6,0x11B0,0x4690,{ 0x95,0x47,0x0B,0x39,0xC5,0xAF,0x21,0x14 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::ILineDisplayStatics2>{ static constexpr guid value{ 0x600C3F1C,0x77AB,0x4968,{ 0xA7,0xDE,0xC0,0x2F,0xF1,0x69,0xF2,0xCC } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::ILineDisplayStatisticsCategorySelector>{ static constexpr guid value{ 0xB521C46B,0x9274,0x4D24,{ 0x94,0xF3,0xB6,0x01,0x7B,0x83,0x24,0x44 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::ILineDisplayStatusUpdatedEventArgs>{ static constexpr guid value{ 0xDDD57C1A,0x86FB,0x4EBA,{ 0x93,0xD1,0x6F,0x5E,0xDA,0x52,0xB7,0x52 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::ILineDisplayStoredBitmap>{ static constexpr guid value{ 0xF621515B,0xD81E,0x43BA,{ 0xBF,0x1B,0xBC,0xFA,0x3C,0x78,0x5B,0xA0 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::ILineDisplayWindow>{ static constexpr guid value{ 0xD21FEEF4,0x2364,0x4BE5,{ 0xBE,0xE1,0x85,0x16,0x80,0xAF,0x49,0x64 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::ILineDisplayWindow2>{ static constexpr guid value{ 0xA95CE2E6,0xBDD8,0x4365,{ 0x8E,0x11,0xDE,0x94,0xDE,0x8D,0xFF,0x02 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IMagneticStripeReader>{ static constexpr guid value{ 0x1A92B015,0x47C3,0x468A,{ 0x93,0x33,0x0C,0x65,0x17,0x57,0x48,0x83 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs>{ static constexpr guid value{ 0x0A4BBD51,0xC316,0x4910,{ 0x87,0xF3,0x7A,0x62,0xBA,0x86,0x2D,0x31 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs>{ static constexpr guid value{ 0x2E958823,0xA31A,0x4763,{ 0x88,0x2C,0x23,0x72,0x5E,0x39,0xB0,0x8E } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities>{ static constexpr guid value{ 0x7128809C,0xC440,0x44A2,{ 0xA4,0x67,0x46,0x91,0x75,0xD0,0x28,0x96 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IMagneticStripeReaderCardTypesStatics>{ static constexpr guid value{ 0x528F2C5D,0x2986,0x474F,{ 0x84,0x54,0x7C,0xCD,0x05,0x92,0x8D,0x5F } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IMagneticStripeReaderEncryptionAlgorithmsStatics>{ static constexpr guid value{ 0x53B57350,0xC3DB,0x4754,{ 0x9C,0x00,0x41,0x39,0x23,0x74,0xA1,0x09 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IMagneticStripeReaderErrorOccurredEventArgs>{ static constexpr guid value{ 0x1FEDF95D,0x2C84,0x41AD,{ 0xB7,0x78,0xF2,0x35,0x6A,0x78,0x9A,0xB1 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IMagneticStripeReaderReport>{ static constexpr guid value{ 0x6A5B6047,0x99B0,0x4188,{ 0xBE,0xF1,0xED,0xDF,0x79,0xF7,0x8F,0xE6 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IMagneticStripeReaderStatics>{ static constexpr guid value{ 0xC45FAB4A,0xEFD7,0x4760,{ 0xA5,0xCE,0x15,0xB0,0xE4,0x7E,0x94,0xEB } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IMagneticStripeReaderStatics2>{ static constexpr guid value{ 0x8CADC362,0xD667,0x48FA,{ 0x86,0xBC,0xF5,0xAE,0x11,0x89,0x26,0x2B } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IMagneticStripeReaderStatusUpdatedEventArgs>{ static constexpr guid value{ 0x09CC6BB0,0x3262,0x401D,{ 0x9E,0x8A,0xE8,0x0D,0x63,0x58,0x90,0x6B } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IMagneticStripeReaderTrackData>{ static constexpr guid value{ 0x104CF671,0x4A9D,0x446E,{ 0xAB,0xC5,0x20,0x40,0x23,0x07,0xBA,0x36 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IMagneticStripeReaderVendorSpecificCardDataReceivedEventArgs>{ static constexpr guid value{ 0xAF0A5514,0x59CC,0x4A60,{ 0x99,0xE8,0x99,0xA5,0x3D,0xAC,0xE5,0xAA } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IPosPrinter>{ static constexpr guid value{ 0x2A03C10E,0x9A19,0x4A01,{ 0x99,0x4F,0x12,0xDF,0xAD,0x6A,0xDC,0xBF } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IPosPrinter2>{ static constexpr guid value{ 0x248475E8,0x8B98,0x5517,{ 0x8E,0x48,0x76,0x0E,0x86,0xF6,0x89,0x87 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IPosPrinterCapabilities>{ static constexpr guid value{ 0xCDE95721,0x4380,0x4985,{ 0xAD,0xC5,0x39,0xDB,0x30,0xCD,0x93,0xBC } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IPosPrinterCharacterSetIdsStatics>{ static constexpr guid value{ 0x5C709EFF,0x709A,0x4FE7,{ 0xB2,0x15,0x06,0xA7,0x48,0xA3,0x8B,0x39 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IPosPrinterFontProperty>{ static constexpr guid value{ 0xA7F4E93A,0xF8AC,0x5F04,{ 0x84,0xD2,0x29,0xB1,0x6D,0x8A,0x63,0x3C } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IPosPrinterJob>{ static constexpr guid value{ 0x9A94005C,0x0615,0x4591,{ 0xA5,0x8F,0x30,0xF8,0x7E,0xDF,0xE2,0xE4 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IPosPrinterPrintOptions>{ static constexpr guid value{ 0x0A2E16FD,0x1D02,0x5A58,{ 0x9D,0x59,0xBF,0xCD,0xE7,0x6F,0xDE,0x86 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IPosPrinterReleaseDeviceRequestedEventArgs>{ static constexpr guid value{ 0x2BCBA359,0x1CEF,0x40B2,{ 0x9E,0xCB,0xF9,0x27,0xF8,0x56,0xAE,0x3C } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IPosPrinterStatics>{ static constexpr guid value{ 0x8CE0D4EA,0x132F,0x4CDF,{ 0xA6,0x4A,0x2D,0x0D,0x7C,0x96,0xA8,0x5B } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IPosPrinterStatics2>{ static constexpr guid value{ 0xEECD2C1C,0xB0D0,0x42E7,{ 0xB1,0x37,0xB8,0x9B,0x16,0x24,0x4D,0x41 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IPosPrinterStatus>{ static constexpr guid value{ 0xD1F0C730,0xDA40,0x4328,{ 0xBF,0x76,0x51,0x56,0xFA,0x33,0xB7,0x47 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IPosPrinterStatusUpdatedEventArgs>{ static constexpr guid value{ 0x2EDB87DF,0x13A6,0x428D,{ 0xBA,0x81,0xB0,0xE7,0xC3,0xE5,0xA3,0xCD } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IReceiptOrSlipJob>{ static constexpr guid value{ 0x532199BE,0xC8C3,0x4DC2,{ 0x89,0xE9,0x5C,0x4A,0x37,0xB3,0x4D,0xDC } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IReceiptPrintJob>{ static constexpr guid value{ 0xAA96066E,0xACAD,0x4B79,{ 0x9D,0x0F,0xC0,0xCF,0xC0,0x8D,0xC7,0x7B } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IReceiptPrintJob2>{ static constexpr guid value{ 0x0CBC12E3,0x9E29,0x5179,{ 0xBC,0xD8,0x18,0x11,0xD3,0xB9,0xA1,0x0E } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IReceiptPrinterCapabilities>{ static constexpr guid value{ 0xB8F0B58F,0x51A8,0x43FC,{ 0x9B,0xD5,0x8D,0xE2,0x72,0xA6,0x41,0x5B } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IReceiptPrinterCapabilities2>{ static constexpr guid value{ 0x20030638,0x8A2C,0x55AC,{ 0x9A,0x7B,0x75,0x76,0xD8,0x86,0x9E,0x99 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::ISlipPrintJob>{ static constexpr guid value{ 0x5D88F95D,0x6131,0x5A4B,{ 0xB7,0xD5,0x8E,0xF2,0xDA,0x7B,0x41,0x65 } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::ISlipPrinterCapabilities>{ static constexpr guid value{ 0x99B16399,0x488C,0x4157,{ 0x8A,0xC2,0x9F,0x57,0xF7,0x08,0xD3,0xDB } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::ISlipPrinterCapabilities2>{ static constexpr guid value{ 0x6FF89671,0x2D1A,0x5000,{ 0x87,0xC2,0xB0,0x85,0x1B,0xFD,0xF0,0x7E } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IUnifiedPosErrorData>{ static constexpr guid value{ 0x2B998C3A,0x555C,0x4889,{ 0x8E,0xD8,0xC5,0x99,0xBB,0x3A,0x71,0x2A } }; };
template <> struct guid_storage<Windows::Devices::PointOfService::IUnifiedPosErrorDataFactory>{ static constexpr guid value{ 0x4B982551,0x1FFE,0x451B,{ 0xA3,0x68,0x63,0xE0,0xCE,0x46,0x5F,0x5A } }; };
template <> struct default_interface<Windows::Devices::PointOfService::BarcodeScanner>{ using type = Windows::Devices::PointOfService::IBarcodeScanner; };
template <> struct default_interface<Windows::Devices::PointOfService::BarcodeScannerCapabilities>{ using type = Windows::Devices::PointOfService::IBarcodeScannerCapabilities; };
template <> struct default_interface<Windows::Devices::PointOfService::BarcodeScannerDataReceivedEventArgs>{ using type = Windows::Devices::PointOfService::IBarcodeScannerDataReceivedEventArgs; };
template <> struct default_interface<Windows::Devices::PointOfService::BarcodeScannerErrorOccurredEventArgs>{ using type = Windows::Devices::PointOfService::IBarcodeScannerErrorOccurredEventArgs; };
template <> struct default_interface<Windows::Devices::PointOfService::BarcodeScannerImagePreviewReceivedEventArgs>{ using type = Windows::Devices::PointOfService::IBarcodeScannerImagePreviewReceivedEventArgs; };
template <> struct default_interface<Windows::Devices::PointOfService::BarcodeScannerReport>{ using type = Windows::Devices::PointOfService::IBarcodeScannerReport; };
template <> struct default_interface<Windows::Devices::PointOfService::BarcodeScannerStatusUpdatedEventArgs>{ using type = Windows::Devices::PointOfService::IBarcodeScannerStatusUpdatedEventArgs; };
template <> struct default_interface<Windows::Devices::PointOfService::BarcodeSymbologyAttributes>{ using type = Windows::Devices::PointOfService::IBarcodeSymbologyAttributes; };
template <> struct default_interface<Windows::Devices::PointOfService::CashDrawer>{ using type = Windows::Devices::PointOfService::ICashDrawer; };
template <> struct default_interface<Windows::Devices::PointOfService::CashDrawerCapabilities>{ using type = Windows::Devices::PointOfService::ICashDrawerCapabilities; };
template <> struct default_interface<Windows::Devices::PointOfService::CashDrawerCloseAlarm>{ using type = Windows::Devices::PointOfService::ICashDrawerCloseAlarm; };
template <> struct default_interface<Windows::Devices::PointOfService::CashDrawerClosedEventArgs>{ using type = Windows::Devices::PointOfService::ICashDrawerEventSourceEventArgs; };
template <> struct default_interface<Windows::Devices::PointOfService::CashDrawerEventSource>{ using type = Windows::Devices::PointOfService::ICashDrawerEventSource; };
template <> struct default_interface<Windows::Devices::PointOfService::CashDrawerOpenedEventArgs>{ using type = Windows::Devices::PointOfService::ICashDrawerEventSourceEventArgs; };
template <> struct default_interface<Windows::Devices::PointOfService::CashDrawerStatus>{ using type = Windows::Devices::PointOfService::ICashDrawerStatus; };
template <> struct default_interface<Windows::Devices::PointOfService::CashDrawerStatusUpdatedEventArgs>{ using type = Windows::Devices::PointOfService::ICashDrawerStatusUpdatedEventArgs; };
template <> struct default_interface<Windows::Devices::PointOfService::ClaimedBarcodeScanner>{ using type = Windows::Devices::PointOfService::IClaimedBarcodeScanner; };
template <> struct default_interface<Windows::Devices::PointOfService::ClaimedBarcodeScannerClosedEventArgs>{ using type = Windows::Devices::PointOfService::IClaimedBarcodeScannerClosedEventArgs; };
template <> struct default_interface<Windows::Devices::PointOfService::ClaimedCashDrawer>{ using type = Windows::Devices::PointOfService::IClaimedCashDrawer; };
template <> struct default_interface<Windows::Devices::PointOfService::ClaimedCashDrawerClosedEventArgs>{ using type = Windows::Devices::PointOfService::IClaimedCashDrawerClosedEventArgs; };
template <> struct default_interface<Windows::Devices::PointOfService::ClaimedJournalPrinter>{ using type = Windows::Devices::PointOfService::IClaimedJournalPrinter; };
template <> struct default_interface<Windows::Devices::PointOfService::ClaimedLineDisplay>{ using type = Windows::Devices::PointOfService::IClaimedLineDisplay; };
template <> struct default_interface<Windows::Devices::PointOfService::ClaimedLineDisplayClosedEventArgs>{ using type = Windows::Devices::PointOfService::IClaimedLineDisplayClosedEventArgs; };
template <> struct default_interface<Windows::Devices::PointOfService::ClaimedMagneticStripeReader>{ using type = Windows::Devices::PointOfService::IClaimedMagneticStripeReader; };
template <> struct default_interface<Windows::Devices::PointOfService::ClaimedMagneticStripeReaderClosedEventArgs>{ using type = Windows::Devices::PointOfService::IClaimedMagneticStripeReaderClosedEventArgs; };
template <> struct default_interface<Windows::Devices::PointOfService::ClaimedPosPrinter>{ using type = Windows::Devices::PointOfService::IClaimedPosPrinter; };
template <> struct default_interface<Windows::Devices::PointOfService::ClaimedPosPrinterClosedEventArgs>{ using type = Windows::Devices::PointOfService::IClaimedPosPrinterClosedEventArgs; };
template <> struct default_interface<Windows::Devices::PointOfService::ClaimedReceiptPrinter>{ using type = Windows::Devices::PointOfService::IClaimedReceiptPrinter; };
template <> struct default_interface<Windows::Devices::PointOfService::ClaimedSlipPrinter>{ using type = Windows::Devices::PointOfService::IClaimedSlipPrinter; };
template <> struct default_interface<Windows::Devices::PointOfService::JournalPrintJob>{ using type = Windows::Devices::PointOfService::IPosPrinterJob; };
template <> struct default_interface<Windows::Devices::PointOfService::JournalPrinterCapabilities>{ using type = Windows::Devices::PointOfService::IJournalPrinterCapabilities; };
template <> struct default_interface<Windows::Devices::PointOfService::LineDisplay>{ using type = Windows::Devices::PointOfService::ILineDisplay; };
template <> struct default_interface<Windows::Devices::PointOfService::LineDisplayAttributes>{ using type = Windows::Devices::PointOfService::ILineDisplayAttributes; };
template <> struct default_interface<Windows::Devices::PointOfService::LineDisplayCapabilities>{ using type = Windows::Devices::PointOfService::ILineDisplayCapabilities; };
template <> struct default_interface<Windows::Devices::PointOfService::LineDisplayCursor>{ using type = Windows::Devices::PointOfService::ILineDisplayCursor; };
template <> struct default_interface<Windows::Devices::PointOfService::LineDisplayCursorAttributes>{ using type = Windows::Devices::PointOfService::ILineDisplayCursorAttributes; };
template <> struct default_interface<Windows::Devices::PointOfService::LineDisplayCustomGlyphs>{ using type = Windows::Devices::PointOfService::ILineDisplayCustomGlyphs; };
template <> struct default_interface<Windows::Devices::PointOfService::LineDisplayMarquee>{ using type = Windows::Devices::PointOfService::ILineDisplayMarquee; };
template <> struct default_interface<Windows::Devices::PointOfService::LineDisplayStatisticsCategorySelector>{ using type = Windows::Devices::PointOfService::ILineDisplayStatisticsCategorySelector; };
template <> struct default_interface<Windows::Devices::PointOfService::LineDisplayStatusUpdatedEventArgs>{ using type = Windows::Devices::PointOfService::ILineDisplayStatusUpdatedEventArgs; };
template <> struct default_interface<Windows::Devices::PointOfService::LineDisplayStoredBitmap>{ using type = Windows::Devices::PointOfService::ILineDisplayStoredBitmap; };
template <> struct default_interface<Windows::Devices::PointOfService::LineDisplayWindow>{ using type = Windows::Devices::PointOfService::ILineDisplayWindow; };
template <> struct default_interface<Windows::Devices::PointOfService::MagneticStripeReader>{ using type = Windows::Devices::PointOfService::IMagneticStripeReader; };
template <> struct default_interface<Windows::Devices::PointOfService::MagneticStripeReaderAamvaCardDataReceivedEventArgs>{ using type = Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs; };
template <> struct default_interface<Windows::Devices::PointOfService::MagneticStripeReaderBankCardDataReceivedEventArgs>{ using type = Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs; };
template <> struct default_interface<Windows::Devices::PointOfService::MagneticStripeReaderCapabilities>{ using type = Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities; };
template <> struct default_interface<Windows::Devices::PointOfService::MagneticStripeReaderErrorOccurredEventArgs>{ using type = Windows::Devices::PointOfService::IMagneticStripeReaderErrorOccurredEventArgs; };
template <> struct default_interface<Windows::Devices::PointOfService::MagneticStripeReaderReport>{ using type = Windows::Devices::PointOfService::IMagneticStripeReaderReport; };
template <> struct default_interface<Windows::Devices::PointOfService::MagneticStripeReaderStatusUpdatedEventArgs>{ using type = Windows::Devices::PointOfService::IMagneticStripeReaderStatusUpdatedEventArgs; };
template <> struct default_interface<Windows::Devices::PointOfService::MagneticStripeReaderTrackData>{ using type = Windows::Devices::PointOfService::IMagneticStripeReaderTrackData; };
template <> struct default_interface<Windows::Devices::PointOfService::MagneticStripeReaderVendorSpecificCardDataReceivedEventArgs>{ using type = Windows::Devices::PointOfService::IMagneticStripeReaderVendorSpecificCardDataReceivedEventArgs; };
template <> struct default_interface<Windows::Devices::PointOfService::PosPrinter>{ using type = Windows::Devices::PointOfService::IPosPrinter; };
template <> struct default_interface<Windows::Devices::PointOfService::PosPrinterCapabilities>{ using type = Windows::Devices::PointOfService::IPosPrinterCapabilities; };
template <> struct default_interface<Windows::Devices::PointOfService::PosPrinterFontProperty>{ using type = Windows::Devices::PointOfService::IPosPrinterFontProperty; };
template <> struct default_interface<Windows::Devices::PointOfService::PosPrinterPrintOptions>{ using type = Windows::Devices::PointOfService::IPosPrinterPrintOptions; };
template <> struct default_interface<Windows::Devices::PointOfService::PosPrinterReleaseDeviceRequestedEventArgs>{ using type = Windows::Devices::PointOfService::IPosPrinterReleaseDeviceRequestedEventArgs; };
template <> struct default_interface<Windows::Devices::PointOfService::PosPrinterStatus>{ using type = Windows::Devices::PointOfService::IPosPrinterStatus; };
template <> struct default_interface<Windows::Devices::PointOfService::PosPrinterStatusUpdatedEventArgs>{ using type = Windows::Devices::PointOfService::IPosPrinterStatusUpdatedEventArgs; };
template <> struct default_interface<Windows::Devices::PointOfService::ReceiptPrintJob>{ using type = Windows::Devices::PointOfService::IReceiptPrintJob; };
template <> struct default_interface<Windows::Devices::PointOfService::ReceiptPrinterCapabilities>{ using type = Windows::Devices::PointOfService::IReceiptPrinterCapabilities; };
template <> struct default_interface<Windows::Devices::PointOfService::SlipPrintJob>{ using type = Windows::Devices::PointOfService::IReceiptOrSlipJob; };
template <> struct default_interface<Windows::Devices::PointOfService::SlipPrinterCapabilities>{ using type = Windows::Devices::PointOfService::ISlipPrinterCapabilities; };
template <> struct default_interface<Windows::Devices::PointOfService::UnifiedPosErrorData>{ using type = Windows::Devices::PointOfService::IUnifiedPosErrorData; };

template <> struct abi<Windows::Devices::PointOfService::IBarcodeScanner>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DeviceId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Capabilities(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL ClaimScannerAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL CheckHealthAsync(Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel level, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetSupportedSymbologiesAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL IsSymbologySupportedAsync(uint32_t barcodeSymbology, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RetrieveStatisticsAsync(void* statisticsCategories, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetSupportedProfiles(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL IsProfileSupported(void* profile, bool* isSupported) noexcept = 0;
    virtual int32_t WINRT_CALL add_StatusUpdated(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_StatusUpdated(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IBarcodeScanner2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_VideoDeviceId(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IBarcodeScannerCapabilities>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_PowerReportingType(Windows::Devices::PointOfService::UnifiedPosPowerReportingType* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsStatisticsReportingSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsStatisticsUpdatingSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsImagePreviewSupported(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IBarcodeScannerCapabilities1>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsSoftwareTriggerSupported(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IBarcodeScannerCapabilities2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsVideoPreviewSupported(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IBarcodeScannerDataReceivedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Report(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IBarcodeScannerErrorOccurredEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_PartialInputData(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsRetriable(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ErrorData(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IBarcodeScannerImagePreviewReceivedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Preview(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IBarcodeScannerReport>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ScanDataType(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ScanData(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ScanDataLabel(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IBarcodeScannerReportFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateInstance(uint32_t scanDataType, void* scanData, void* scanDataLabel, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IBarcodeScannerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDefaultAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL FromIdAsync(void* deviceId, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeviceSelector(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IBarcodeScannerStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDeviceSelectorWithConnectionTypes(Windows::Devices::PointOfService::PosConnectionTypes connectionTypes, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IBarcodeScannerStatusUpdatedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Devices::PointOfService::BarcodeScannerStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedStatus(uint32_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Unknown(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Ean8(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Ean8Add2(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Ean8Add5(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Eanv(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EanvAdd2(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EanvAdd5(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Ean13(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Ean13Add2(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Ean13Add5(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Isbn(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsbnAdd5(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Ismn(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsmnAdd2(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsmnAdd5(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Issn(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IssnAdd2(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IssnAdd5(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Ean99(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Ean99Add2(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Ean99Add5(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Upca(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UpcaAdd2(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UpcaAdd5(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Upce(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UpceAdd2(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UpceAdd5(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UpcCoupon(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TfStd(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TfDis(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TfInt(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TfInd(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TfMat(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TfIata(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Gs1DatabarType1(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Gs1DatabarType2(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Gs1DatabarType3(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Code39(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Code39Ex(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Trioptic39(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Code32(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Pzn(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Code93(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Code93Ex(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Code128(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Gs1128(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Gs1128Coupon(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UccEan128(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Sisac(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Isbt(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Codabar(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Code11(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Msi(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Plessey(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Telepen(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Code16k(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CodablockA(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CodablockF(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Codablock128(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Code49(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Aztec(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DataCode(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DataMatrix(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HanXin(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Maxicode(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MicroPdf417(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MicroQr(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Pdf417(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Qr(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MsTag(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Ccab(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Ccc(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Tlc39(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AusPost(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CanPost(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ChinaPost(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DutchKix(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InfoMail(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ItalianPost25(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ItalianPost39(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_JapanPost(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KoreanPost(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SwedenPost(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UkPost(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UsIntelligent(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UsIntelligentPkg(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UsPlanet(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UsPostNet(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Us4StateFics(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OcrA(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OcrB(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Micr(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedBase(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetName(uint32_t scanDataType, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IBarcodeSymbologiesStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Gs1DWCode(uint32_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IBarcodeSymbologyAttributes>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsCheckDigitValidationEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsCheckDigitValidationEnabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsCheckDigitValidationSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsCheckDigitTransmissionEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsCheckDigitTransmissionEnabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsCheckDigitTransmissionSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DecodeLength1(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DecodeLength1(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DecodeLength2(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DecodeLength2(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DecodeLengthKind(Windows::Devices::PointOfService::BarcodeSymbologyDecodeLengthKind* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DecodeLengthKind(Windows::Devices::PointOfService::BarcodeSymbologyDecodeLengthKind value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsDecodeLengthSupported(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::ICashDrawer>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DeviceId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Capabilities(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Status(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsDrawerOpen(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DrawerEventSource(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL ClaimDrawerAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL CheckHealthAsync(Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel level, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetStatisticsAsync(void* statisticsCategories, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL add_StatusUpdated(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_StatusUpdated(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::ICashDrawerCapabilities>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_PowerReportingType(Windows::Devices::PointOfService::UnifiedPosPowerReportingType* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsStatisticsReportingSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsStatisticsUpdatingSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsStatusReportingSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsStatusMultiDrawerDetectSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsDrawerOpenSensorAvailable(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::ICashDrawerCloseAlarm>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL put_AlarmTimeout(Windows::Foundation::TimeSpan value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AlarmTimeout(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_BeepFrequency(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BeepFrequency(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_BeepDuration(Windows::Foundation::TimeSpan value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BeepDuration(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_BeepDelay(Windows::Foundation::TimeSpan value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BeepDelay(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_AlarmTimeoutExpired(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_AlarmTimeoutExpired(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL StartAsync(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::ICashDrawerEventSource>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_DrawerClosed(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_DrawerClosed(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_DrawerOpened(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_DrawerOpened(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::ICashDrawerEventSourceEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CashDrawer(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::ICashDrawerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDefaultAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL FromIdAsync(void* deviceId, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeviceSelector(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::ICashDrawerStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDeviceSelectorWithConnectionTypes(Windows::Devices::PointOfService::PosConnectionTypes connectionTypes, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::ICashDrawerStatus>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_StatusKind(Windows::Devices::PointOfService::CashDrawerStatusKind* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedStatus(uint32_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::ICashDrawerStatusUpdatedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IClaimedBarcodeScanner>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DeviceId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsDisabledOnDataReceived(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsDisabledOnDataReceived(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsDecodeDataEnabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsDecodeDataEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL EnableAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL DisableAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL RetainDevice() noexcept = 0;
    virtual int32_t WINRT_CALL SetActiveSymbologiesAsync(void* symbologies, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL ResetStatisticsAsync(void* statisticsCategories, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL UpdateStatisticsAsync(void* statistics, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL SetActiveProfileAsync(void* profile, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL add_DataReceived(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_DataReceived(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_TriggerPressed(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_TriggerPressed(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_TriggerReleased(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_TriggerReleased(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_ReleaseDeviceRequested(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ReleaseDeviceRequested(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_ImagePreviewReceived(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ImagePreviewReceived(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_ErrorOccurred(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ErrorOccurred(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IClaimedBarcodeScanner1>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL StartSoftwareTriggerAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL StopSoftwareTriggerAsync(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IClaimedBarcodeScanner2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetSymbologyAttributesAsync(uint32_t barcodeSymbology, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL SetSymbologyAttributesAsync(uint32_t barcodeSymbology, void* attributes, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IClaimedBarcodeScanner3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ShowVideoPreviewAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL HideVideoPreview() noexcept = 0;
    virtual int32_t WINRT_CALL put_IsVideoPreviewShownOnEnable(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsVideoPreviewShownOnEnable(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IClaimedBarcodeScanner4>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_Closed(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Closed(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IClaimedBarcodeScannerClosedEventArgs>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::Devices::PointOfService::IClaimedCashDrawer>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DeviceId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsDrawerOpen(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CloseAlarm(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL OpenDrawerAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL EnableAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL DisableAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL RetainDeviceAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL ResetStatisticsAsync(void* statisticsCategories, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL UpdateStatisticsAsync(void* statistics, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL add_ReleaseDeviceRequested(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ReleaseDeviceRequested(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IClaimedCashDrawer2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_Closed(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Closed(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IClaimedCashDrawerClosedEventArgs>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::Devices::PointOfService::IClaimedJournalPrinter>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateJob(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IClaimedLineDisplay>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DeviceId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Capabilities(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PhysicalDeviceName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PhysicalDeviceDescription(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DeviceControlDescription(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DeviceControlVersion(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DeviceServiceVersion(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DefaultWindow(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL RetainDevice() noexcept = 0;
    virtual int32_t WINRT_CALL add_ReleaseDeviceRequested(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ReleaseDeviceRequested(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IClaimedLineDisplay2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetStatisticsAsync(void* statisticsCategories, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CheckHealthAsync(Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel level, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CheckPowerStatusAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL add_StatusUpdated(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_StatusUpdated(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL get_SupportedScreenSizesInCharacters(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxBitmapSizeInPixels(Windows::Foundation::Size* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SupportedCharacterSets(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CustomGlyphs(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetAttributes(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL TryUpdateAttributesAsync(void* attributes, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TrySetDescriptorAsync(uint32_t descriptor, Windows::Devices::PointOfService::LineDisplayDescriptorState descriptorState, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryClearDescriptorsAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryCreateWindowAsync(Windows::Foundation::Rect viewport, Windows::Foundation::Size windowSize, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TryStoreStorageFileBitmapAsync(void* bitmap, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TryStoreStorageFileBitmapWithAlignmentAsync(void* bitmap, Windows::Devices::PointOfService::LineDisplayHorizontalAlignment horizontalAlignment, Windows::Devices::PointOfService::LineDisplayVerticalAlignment verticalAlignment, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TryStoreStorageFileBitmapWithAlignmentAndWidthAsync(void* bitmap, Windows::Devices::PointOfService::LineDisplayHorizontalAlignment horizontalAlignment, Windows::Devices::PointOfService::LineDisplayVerticalAlignment verticalAlignment, int32_t widthInPixels, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IClaimedLineDisplay3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_Closed(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Closed(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IClaimedLineDisplayClosedEventArgs>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::Devices::PointOfService::IClaimedLineDisplayStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL FromIdAsync(void* deviceId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeviceSelector(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeviceSelectorWithConnectionTypes(Windows::Devices::PointOfService::PosConnectionTypes connectionTypes, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IClaimedMagneticStripeReader>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DeviceId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsDisabledOnDataReceived(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsDisabledOnDataReceived(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsDecodeDataEnabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsDecodeDataEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsDeviceAuthenticated(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DataEncryptionAlgorithm(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DataEncryptionAlgorithm(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_TracksToRead(Windows::Devices::PointOfService::MagneticStripeReaderTrackIds value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TracksToRead(Windows::Devices::PointOfService::MagneticStripeReaderTrackIds* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsTransmitSentinelsEnabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsTransmitSentinelsEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL EnableAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL DisableAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL RetainDevice() noexcept = 0;
    virtual int32_t WINRT_CALL SetErrorReportingType(Windows::Devices::PointOfService::MagneticStripeReaderErrorReportingType value) noexcept = 0;
    virtual int32_t WINRT_CALL RetrieveDeviceAuthenticationDataAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL AuthenticateDeviceAsync(uint32_t __responseTokenSize, uint8_t* responseToken, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL DeAuthenticateDeviceAsync(uint32_t __responseTokenSize, uint8_t* responseToken, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL UpdateKeyAsync(void* key, void* keyName, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL ResetStatisticsAsync(void* statisticsCategories, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL UpdateStatisticsAsync(void* statistics, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL add_BankCardDataReceived(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_BankCardDataReceived(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_AamvaCardDataReceived(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_AamvaCardDataReceived(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_VendorSpecificDataReceived(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_VendorSpecificDataReceived(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_ReleaseDeviceRequested(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ReleaseDeviceRequested(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_ErrorOccurred(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ErrorOccurred(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IClaimedMagneticStripeReader2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_Closed(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Closed(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IClaimedMagneticStripeReaderClosedEventArgs>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::Devices::PointOfService::IClaimedPosPrinter>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DeviceId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CharacterSet(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CharacterSet(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsCoverOpen(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsCharacterSetMappingEnabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsCharacterSetMappingEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MapMode(Windows::Devices::PointOfService::PosPrinterMapMode value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MapMode(Windows::Devices::PointOfService::PosPrinterMapMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Receipt(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Slip(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Journal(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL EnableAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL DisableAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL RetainDeviceAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL ResetStatisticsAsync(void* statisticsCategories, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL UpdateStatisticsAsync(void* statistics, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL add_ReleaseDeviceRequested(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ReleaseDeviceRequested(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IClaimedPosPrinter2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_Closed(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Closed(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IClaimedPosPrinterClosedEventArgs>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::Devices::PointOfService::IClaimedReceiptPrinter>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SidewaysMaxLines(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SidewaysMaxChars(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LinesToPaperCut(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PageSize(Windows::Foundation::Size* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PrintArea(Windows::Foundation::Rect* value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateJob(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IClaimedSlipPrinter>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SidewaysMaxLines(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SidewaysMaxChars(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxLines(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LinesNearEndToEnd(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PrintSide(Windows::Devices::PointOfService::PosPrinterPrintSide* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PageSize(Windows::Foundation::Size* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PrintArea(Windows::Foundation::Rect* value) noexcept = 0;
    virtual int32_t WINRT_CALL OpenJaws() noexcept = 0;
    virtual int32_t WINRT_CALL CloseJaws() noexcept = 0;
    virtual int32_t WINRT_CALL InsertSlipAsync(Windows::Foundation::TimeSpan timeout, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL RemoveSlipAsync(Windows::Foundation::TimeSpan timeout, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL ChangePrintSide(Windows::Devices::PointOfService::PosPrinterPrintSide printSide) noexcept = 0;
    virtual int32_t WINRT_CALL CreateJob(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL put_CharactersPerLine(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CharactersPerLine(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_LineHeight(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LineHeight(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_LineSpacing(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LineSpacing(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LineWidth(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsLetterQuality(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsLetterQuality(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsPaperNearEnd(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ColorCartridge(Windows::Devices::PointOfService::PosPrinterColorCartridge value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ColorCartridge(Windows::Devices::PointOfService::PosPrinterColorCartridge* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsCoverOpen(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsCartridgeRemoved(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsCartridgeEmpty(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsHeadCleaning(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsPaperEmpty(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsReadyToPrint(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL ValidateData(void* data, bool* result) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsPrinterPresent(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsDualColorSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ColorCartridgeCapabilities(Windows::Devices::PointOfService::PosPrinterColorCapabilities* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CartridgeSensors(Windows::Devices::PointOfService::PosPrinterCartridgeSensors* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsBoldSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsItalicSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsUnderlineSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsDoubleHighPrintSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsDoubleWidePrintSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsDoubleHighDoubleWidePrintSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsPaperEmptySensorSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsPaperNearEndSensorSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SupportedCharactersPerLine(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::ICommonReceiptSlipCapabilities>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsBarcodeSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsBitmapSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsLeft90RotationSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsRight90RotationSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Is180RotationSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsPrintAreaSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RuledLineCapabilities(Windows::Devices::PointOfService::PosPrinterRuledLineCapabilities* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SupportedBarcodeRotations(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SupportedBitmapRotations(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IJournalPrintJob>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Print(void* data, void* printOptions) noexcept = 0;
    virtual int32_t WINRT_CALL FeedPaperByLine(int32_t lineCount) noexcept = 0;
    virtual int32_t WINRT_CALL FeedPaperByMapModeUnit(int32_t distance) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IJournalPrinterCapabilities>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::Devices::PointOfService::IJournalPrinterCapabilities2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsReverseVideoSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsStrikethroughSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsSuperscriptSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsSubscriptSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsReversePaperFeedByLineSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsReversePaperFeedByMapModeUnitSupported(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::ILineDisplay>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DeviceId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Capabilities(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PhysicalDeviceName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PhysicalDeviceDescription(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DeviceControlDescription(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DeviceControlVersion(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DeviceServiceVersion(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL ClaimAsync(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::ILineDisplay2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CheckPowerStatusAsync(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::ILineDisplayAttributes>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsPowerNotifyEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsPowerNotifyEnabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Brightness(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Brightness(int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BlinkRate(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_BlinkRate(Windows::Foundation::TimeSpan value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ScreenSizeInCharacters(Windows::Foundation::Size* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ScreenSizeInCharacters(Windows::Foundation::Size value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CharacterSet(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CharacterSet(int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsCharacterSetMappingEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsCharacterSetMappingEnabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CurrentWindow(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CurrentWindow(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::ILineDisplayCapabilities>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsStatisticsReportingSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsStatisticsUpdatingSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PowerReportingType(Windows::Devices::PointOfService::UnifiedPosPowerReportingType* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CanChangeScreenSize(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CanDisplayBitmaps(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CanReadCharacterAtCursor(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CanMapCharacterSets(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CanDisplayCustomGlyphs(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CanReverse(Windows::Devices::PointOfService::LineDisplayTextAttributeGranularity* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CanBlink(Windows::Devices::PointOfService::LineDisplayTextAttributeGranularity* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CanChangeBlinkRate(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsBrightnessSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsCursorSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsHorizontalMarqueeSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsVerticalMarqueeSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsInterCharacterWaitSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SupportedDescriptors(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SupportedWindows(uint32_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::ILineDisplayCursor>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CanCustomize(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsBlinkSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsBlockSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsHalfBlockSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsUnderlineSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsReverseSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsOtherSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetAttributes(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TryUpdateAttributesAsync(void* attributes, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::ILineDisplayCursorAttributes>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsBlinkEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsBlinkEnabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CursorType(Windows::Devices::PointOfService::LineDisplayCursorType* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CursorType(Windows::Devices::PointOfService::LineDisplayCursorType value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsAutoAdvanceEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsAutoAdvanceEnabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Position(Windows::Foundation::Point* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Position(Windows::Foundation::Point value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::ILineDisplayCustomGlyphs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SizeInPixels(Windows::Foundation::Size* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SupportedGlyphCodes(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL TryRedefineAsync(uint32_t glyphCode, void* glyphData, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::ILineDisplayMarquee>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Format(Windows::Devices::PointOfService::LineDisplayMarqueeFormat* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Format(Windows::Devices::PointOfService::LineDisplayMarqueeFormat value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RepeatWaitInterval(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RepeatWaitInterval(Windows::Foundation::TimeSpan value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ScrollWaitInterval(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ScrollWaitInterval(Windows::Foundation::TimeSpan value) noexcept = 0;
    virtual int32_t WINRT_CALL TryStartScrollingAsync(Windows::Devices::PointOfService::LineDisplayScrollDirection direction, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryStopScrollingAsync(void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::ILineDisplayStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL FromIdAsync(void* deviceId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetDefaultAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeviceSelector(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeviceSelectorWithConnectionTypes(Windows::Devices::PointOfService::PosConnectionTypes connectionTypes, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::ILineDisplayStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_StatisticsCategorySelector(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::ILineDisplayStatisticsCategorySelector>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AllStatistics(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UnifiedPosStatistics(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ManufacturerStatistics(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::ILineDisplayStatusUpdatedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Devices::PointOfService::LineDisplayPowerStatus* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::ILineDisplayStoredBitmap>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_EscapeSequence(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL TryDeleteAsync(void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::ILineDisplayWindow>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SizeInCharacters(Windows::Foundation::Size* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InterCharacterWaitInterval(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_InterCharacterWaitInterval(Windows::Foundation::TimeSpan value) noexcept = 0;
    virtual int32_t WINRT_CALL TryRefreshAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryDisplayTextAsync(void* text, Windows::Devices::PointOfService::LineDisplayTextAttribute displayAttribute, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryDisplayTextAtPositionAsync(void* text, Windows::Devices::PointOfService::LineDisplayTextAttribute displayAttribute, Windows::Foundation::Point startPosition, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryDisplayTextNormalAsync(void* text, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryScrollTextAsync(Windows::Devices::PointOfService::LineDisplayScrollDirection direction, uint32_t numberOfColumnsOrRows, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryClearTextAsync(void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::ILineDisplayWindow2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Cursor(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Marquee(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL ReadCharacterAtCursorAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TryDisplayStoredBitmapAtCursorAsync(void* bitmap, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryDisplayStorageFileBitmapAtCursorAsync(void* bitmap, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryDisplayStorageFileBitmapAtCursorWithAlignmentAsync(void* bitmap, Windows::Devices::PointOfService::LineDisplayHorizontalAlignment horizontalAlignment, Windows::Devices::PointOfService::LineDisplayVerticalAlignment verticalAlignment, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryDisplayStorageFileBitmapAtCursorWithAlignmentAndWidthAsync(void* bitmap, Windows::Devices::PointOfService::LineDisplayHorizontalAlignment horizontalAlignment, Windows::Devices::PointOfService::LineDisplayVerticalAlignment verticalAlignment, int32_t widthInPixels, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryDisplayStorageFileBitmapAtPointAsync(void* bitmap, Windows::Foundation::Point offsetInPixels, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryDisplayStorageFileBitmapAtPointWithWidthAsync(void* bitmap, Windows::Foundation::Point offsetInPixels, int32_t widthInPixels, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IMagneticStripeReader>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DeviceId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Capabilities(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SupportedCardTypes(uint32_t* __valueSize, uint32_t** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DeviceAuthenticationProtocol(Windows::Devices::PointOfService::MagneticStripeReaderAuthenticationProtocol* value) noexcept = 0;
    virtual int32_t WINRT_CALL CheckHealthAsync(Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel level, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL ClaimReaderAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RetrieveStatisticsAsync(void* statisticsCategories, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetErrorReportingType(Windows::Devices::PointOfService::MagneticStripeReaderErrorReportingType* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_StatusUpdated(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_StatusUpdated(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Report(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LicenseNumber(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExpirationDate(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Restrictions(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Class(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Endorsements(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BirthDate(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FirstName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Surname(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Suffix(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Gender(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HairColor(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EyeColor(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Height(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Weight(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Address(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_City(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_State(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PostalCode(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Report(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AccountNumber(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExpirationDate(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ServiceCode(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Title(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FirstName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MiddleInitial(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Surname(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Suffix(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CardAuthentication(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SupportedEncryptionAlgorithms(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AuthenticationLevel(Windows::Devices::PointOfService::MagneticStripeReaderAuthenticationLevel* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsIsoSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsJisOneSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsJisTwoSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PowerReportingType(Windows::Devices::PointOfService::UnifiedPosPowerReportingType* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsStatisticsReportingSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsStatisticsUpdatingSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsTrackDataMaskingSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsTransmitSentinelsSupported(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IMagneticStripeReaderCardTypesStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Unknown(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Bank(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Aamva(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedBase(uint32_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IMagneticStripeReaderEncryptionAlgorithmsStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_None(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TripleDesDukpt(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedBase(uint32_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IMagneticStripeReaderErrorOccurredEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Track1Status(Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Track2Status(Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Track3Status(Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Track4Status(Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ErrorData(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PartialInputData(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IMagneticStripeReaderReport>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CardType(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Track1(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Track2(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Track3(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Track4(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Properties(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CardAuthenticationData(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CardAuthenticationDataLength(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AdditionalSecurityInformation(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IMagneticStripeReaderStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDefaultAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL FromIdAsync(void* deviceId, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeviceSelector(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IMagneticStripeReaderStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDeviceSelectorWithConnectionTypes(Windows::Devices::PointOfService::PosConnectionTypes connectionTypes, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IMagneticStripeReaderStatusUpdatedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Devices::PointOfService::MagneticStripeReaderStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedStatus(uint32_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IMagneticStripeReaderTrackData>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Data(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DiscretionaryData(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EncryptedData(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IMagneticStripeReaderVendorSpecificCardDataReceivedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Report(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IPosPrinter>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DeviceId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Capabilities(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SupportedCharacterSets(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SupportedTypeFaces(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Status(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL ClaimPrinterAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL CheckHealthAsync(Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel level, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetStatisticsAsync(void* statisticsCategories, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL add_StatusUpdated(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_StatusUpdated(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IPosPrinter2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SupportedBarcodeSymbologies(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetFontProperty(void* typeface, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IPosPrinterCapabilities>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_PowerReportingType(Windows::Devices::PointOfService::UnifiedPosPowerReportingType* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsStatisticsReportingSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsStatisticsUpdatingSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DefaultCharacterSet(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HasCoverSensor(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CanMapCharacterSet(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsTransactionSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Receipt(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Slip(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Journal(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IPosPrinterCharacterSetIdsStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Utf16LE(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Ascii(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Ansi(uint32_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IPosPrinterFontProperty>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_TypeFace(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsScalableToAnySize(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CharacterSizes(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IPosPrinterJob>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Print(void* data) noexcept = 0;
    virtual int32_t WINRT_CALL PrintLine(void* data) noexcept = 0;
    virtual int32_t WINRT_CALL PrintNewline() noexcept = 0;
    virtual int32_t WINRT_CALL ExecuteAsync(void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IPosPrinterPrintOptions>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_TypeFace(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_TypeFace(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CharacterHeight(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CharacterHeight(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Bold(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Bold(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Italic(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Italic(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Underline(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Underline(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ReverseVideo(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ReverseVideo(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Strikethrough(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Strikethrough(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Superscript(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Superscript(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Subscript(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Subscript(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DoubleWide(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DoubleWide(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DoubleHigh(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DoubleHigh(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Alignment(Windows::Devices::PointOfService::PosPrinterAlignment* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Alignment(Windows::Devices::PointOfService::PosPrinterAlignment value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CharacterSet(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CharacterSet(uint32_t value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IPosPrinterReleaseDeviceRequestedEventArgs>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::Devices::PointOfService::IPosPrinterStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDefaultAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL FromIdAsync(void* deviceId, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeviceSelector(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IPosPrinterStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDeviceSelectorWithConnectionTypes(Windows::Devices::PointOfService::PosConnectionTypes connectionTypes, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IPosPrinterStatus>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_StatusKind(Windows::Devices::PointOfService::PosPrinterStatusKind* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedStatus(uint32_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IPosPrinterStatusUpdatedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IReceiptOrSlipJob>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL SetBarcodeRotation(Windows::Devices::PointOfService::PosPrinterRotation value) noexcept = 0;
    virtual int32_t WINRT_CALL SetPrintRotation(Windows::Devices::PointOfService::PosPrinterRotation value, bool includeBitmaps) noexcept = 0;
    virtual int32_t WINRT_CALL SetPrintArea(Windows::Foundation::Rect value) noexcept = 0;
    virtual int32_t WINRT_CALL SetBitmap(uint32_t bitmapNumber, void* bitmap, Windows::Devices::PointOfService::PosPrinterAlignment alignment) noexcept = 0;
    virtual int32_t WINRT_CALL SetBitmapCustomWidthStandardAlign(uint32_t bitmapNumber, void* bitmap, Windows::Devices::PointOfService::PosPrinterAlignment alignment, uint32_t width) noexcept = 0;
    virtual int32_t WINRT_CALL SetCustomAlignedBitmap(uint32_t bitmapNumber, void* bitmap, uint32_t alignmentDistance) noexcept = 0;
    virtual int32_t WINRT_CALL SetBitmapCustomWidthCustomAlign(uint32_t bitmapNumber, void* bitmap, uint32_t alignmentDistance, uint32_t width) noexcept = 0;
    virtual int32_t WINRT_CALL PrintSavedBitmap(uint32_t bitmapNumber) noexcept = 0;
    virtual int32_t WINRT_CALL DrawRuledLine(void* positionList, Windows::Devices::PointOfService::PosPrinterLineDirection lineDirection, uint32_t lineWidth, Windows::Devices::PointOfService::PosPrinterLineStyle lineStyle, uint32_t lineColor) noexcept = 0;
    virtual int32_t WINRT_CALL PrintBarcode(void* data, uint32_t symbology, uint32_t height, uint32_t width, Windows::Devices::PointOfService::PosPrinterBarcodeTextPosition textPosition, Windows::Devices::PointOfService::PosPrinterAlignment alignment) noexcept = 0;
    virtual int32_t WINRT_CALL PrintBarcodeCustomAlign(void* data, uint32_t symbology, uint32_t height, uint32_t width, Windows::Devices::PointOfService::PosPrinterBarcodeTextPosition textPosition, uint32_t alignmentDistance) noexcept = 0;
    virtual int32_t WINRT_CALL PrintBitmap(void* bitmap, Windows::Devices::PointOfService::PosPrinterAlignment alignment) noexcept = 0;
    virtual int32_t WINRT_CALL PrintBitmapCustomWidthStandardAlign(void* bitmap, Windows::Devices::PointOfService::PosPrinterAlignment alignment, uint32_t width) noexcept = 0;
    virtual int32_t WINRT_CALL PrintCustomAlignedBitmap(void* bitmap, uint32_t alignmentDistance) noexcept = 0;
    virtual int32_t WINRT_CALL PrintBitmapCustomWidthCustomAlign(void* bitmap, uint32_t alignmentDistance, uint32_t width) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IReceiptPrintJob>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL MarkFeed(Windows::Devices::PointOfService::PosPrinterMarkFeedKind kind) noexcept = 0;
    virtual int32_t WINRT_CALL CutPaper(double percentage) noexcept = 0;
    virtual int32_t WINRT_CALL CutPaperDefault() noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IReceiptPrintJob2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL StampPaper() noexcept = 0;
    virtual int32_t WINRT_CALL Print(void* data, void* printOptions) noexcept = 0;
    virtual int32_t WINRT_CALL FeedPaperByLine(int32_t lineCount) noexcept = 0;
    virtual int32_t WINRT_CALL FeedPaperByMapModeUnit(int32_t distance) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IReceiptPrinterCapabilities>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CanCutPaper(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsStampSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MarkFeedCapabilities(Windows::Devices::PointOfService::PosPrinterMarkFeedCapabilities* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IReceiptPrinterCapabilities2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsReverseVideoSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsStrikethroughSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsSuperscriptSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsSubscriptSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsReversePaperFeedByLineSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsReversePaperFeedByMapModeUnitSupported(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::ISlipPrintJob>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Print(void* data, void* printOptions) noexcept = 0;
    virtual int32_t WINRT_CALL FeedPaperByLine(int32_t lineCount) noexcept = 0;
    virtual int32_t WINRT_CALL FeedPaperByMapModeUnit(int32_t distance) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::ISlipPrinterCapabilities>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsFullLengthSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsBothSidesPrintingSupported(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::ISlipPrinterCapabilities2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsReverseVideoSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsStrikethroughSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsSuperscriptSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsSubscriptSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsReversePaperFeedByLineSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsReversePaperFeedByMapModeUnitSupported(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IUnifiedPosErrorData>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Message(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Severity(Windows::Devices::PointOfService::UnifiedPosErrorSeverity* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Reason(Windows::Devices::PointOfService::UnifiedPosErrorReason* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedReason(uint32_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::PointOfService::IUnifiedPosErrorDataFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateInstance(void* message, Windows::Devices::PointOfService::UnifiedPosErrorSeverity severity, Windows::Devices::PointOfService::UnifiedPosErrorReason reason, uint32_t extendedReason, void** result) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Devices_PointOfService_IBarcodeScanner
{
    hstring DeviceId() const;
    Windows::Devices::PointOfService::BarcodeScannerCapabilities Capabilities() const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::ClaimedBarcodeScanner> ClaimScannerAsync() const;
    Windows::Foundation::IAsyncOperation<hstring> CheckHealthAsync(Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel const& level) const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<uint32_t>> GetSupportedSymbologiesAsync() const;
    Windows::Foundation::IAsyncOperation<bool> IsSymbologySupportedAsync(uint32_t barcodeSymbology) const;
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> RetrieveStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const;
    Windows::Foundation::Collections::IVectorView<hstring> GetSupportedProfiles() const;
    bool IsProfileSupported(param::hstring const& profile) const;
    winrt::event_token StatusUpdated(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::BarcodeScanner, Windows::Devices::PointOfService::BarcodeScannerStatusUpdatedEventArgs> const& handler) const;
    using StatusUpdated_revoker = impl::event_revoker<Windows::Devices::PointOfService::IBarcodeScanner, &impl::abi_t<Windows::Devices::PointOfService::IBarcodeScanner>::remove_StatusUpdated>;
    StatusUpdated_revoker StatusUpdated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::BarcodeScanner, Windows::Devices::PointOfService::BarcodeScannerStatusUpdatedEventArgs> const& handler) const;
    void StatusUpdated(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Devices::PointOfService::IBarcodeScanner> { template <typename D> using type = consume_Windows_Devices_PointOfService_IBarcodeScanner<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IBarcodeScanner2
{
    hstring VideoDeviceId() const;
};
template <> struct consume<Windows::Devices::PointOfService::IBarcodeScanner2> { template <typename D> using type = consume_Windows_Devices_PointOfService_IBarcodeScanner2<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IBarcodeScannerCapabilities
{
    Windows::Devices::PointOfService::UnifiedPosPowerReportingType PowerReportingType() const;
    bool IsStatisticsReportingSupported() const;
    bool IsStatisticsUpdatingSupported() const;
    bool IsImagePreviewSupported() const;
};
template <> struct consume<Windows::Devices::PointOfService::IBarcodeScannerCapabilities> { template <typename D> using type = consume_Windows_Devices_PointOfService_IBarcodeScannerCapabilities<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IBarcodeScannerCapabilities1
{
    bool IsSoftwareTriggerSupported() const;
};
template <> struct consume<Windows::Devices::PointOfService::IBarcodeScannerCapabilities1> { template <typename D> using type = consume_Windows_Devices_PointOfService_IBarcodeScannerCapabilities1<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IBarcodeScannerCapabilities2
{
    bool IsVideoPreviewSupported() const;
};
template <> struct consume<Windows::Devices::PointOfService::IBarcodeScannerCapabilities2> { template <typename D> using type = consume_Windows_Devices_PointOfService_IBarcodeScannerCapabilities2<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IBarcodeScannerDataReceivedEventArgs
{
    Windows::Devices::PointOfService::BarcodeScannerReport Report() const;
};
template <> struct consume<Windows::Devices::PointOfService::IBarcodeScannerDataReceivedEventArgs> { template <typename D> using type = consume_Windows_Devices_PointOfService_IBarcodeScannerDataReceivedEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IBarcodeScannerErrorOccurredEventArgs
{
    Windows::Devices::PointOfService::BarcodeScannerReport PartialInputData() const;
    bool IsRetriable() const;
    Windows::Devices::PointOfService::UnifiedPosErrorData ErrorData() const;
};
template <> struct consume<Windows::Devices::PointOfService::IBarcodeScannerErrorOccurredEventArgs> { template <typename D> using type = consume_Windows_Devices_PointOfService_IBarcodeScannerErrorOccurredEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IBarcodeScannerImagePreviewReceivedEventArgs
{
    Windows::Storage::Streams::IRandomAccessStreamWithContentType Preview() const;
};
template <> struct consume<Windows::Devices::PointOfService::IBarcodeScannerImagePreviewReceivedEventArgs> { template <typename D> using type = consume_Windows_Devices_PointOfService_IBarcodeScannerImagePreviewReceivedEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IBarcodeScannerReport
{
    uint32_t ScanDataType() const;
    Windows::Storage::Streams::IBuffer ScanData() const;
    Windows::Storage::Streams::IBuffer ScanDataLabel() const;
};
template <> struct consume<Windows::Devices::PointOfService::IBarcodeScannerReport> { template <typename D> using type = consume_Windows_Devices_PointOfService_IBarcodeScannerReport<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IBarcodeScannerReportFactory
{
    Windows::Devices::PointOfService::BarcodeScannerReport CreateInstance(uint32_t scanDataType, Windows::Storage::Streams::IBuffer const& scanData, Windows::Storage::Streams::IBuffer const& scanDataLabel) const;
};
template <> struct consume<Windows::Devices::PointOfService::IBarcodeScannerReportFactory> { template <typename D> using type = consume_Windows_Devices_PointOfService_IBarcodeScannerReportFactory<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IBarcodeScannerStatics
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::BarcodeScanner> GetDefaultAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::BarcodeScanner> FromIdAsync(param::hstring const& deviceId) const;
    hstring GetDeviceSelector() const;
};
template <> struct consume<Windows::Devices::PointOfService::IBarcodeScannerStatics> { template <typename D> using type = consume_Windows_Devices_PointOfService_IBarcodeScannerStatics<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IBarcodeScannerStatics2
{
    hstring GetDeviceSelector(Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes) const;
};
template <> struct consume<Windows::Devices::PointOfService::IBarcodeScannerStatics2> { template <typename D> using type = consume_Windows_Devices_PointOfService_IBarcodeScannerStatics2<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IBarcodeScannerStatusUpdatedEventArgs
{
    Windows::Devices::PointOfService::BarcodeScannerStatus Status() const;
    uint32_t ExtendedStatus() const;
};
template <> struct consume<Windows::Devices::PointOfService::IBarcodeScannerStatusUpdatedEventArgs> { template <typename D> using type = consume_Windows_Devices_PointOfService_IBarcodeScannerStatusUpdatedEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics
{
    uint32_t Unknown() const;
    uint32_t Ean8() const;
    uint32_t Ean8Add2() const;
    uint32_t Ean8Add5() const;
    uint32_t Eanv() const;
    uint32_t EanvAdd2() const;
    uint32_t EanvAdd5() const;
    uint32_t Ean13() const;
    uint32_t Ean13Add2() const;
    uint32_t Ean13Add5() const;
    uint32_t Isbn() const;
    uint32_t IsbnAdd5() const;
    uint32_t Ismn() const;
    uint32_t IsmnAdd2() const;
    uint32_t IsmnAdd5() const;
    uint32_t Issn() const;
    uint32_t IssnAdd2() const;
    uint32_t IssnAdd5() const;
    uint32_t Ean99() const;
    uint32_t Ean99Add2() const;
    uint32_t Ean99Add5() const;
    uint32_t Upca() const;
    uint32_t UpcaAdd2() const;
    uint32_t UpcaAdd5() const;
    uint32_t Upce() const;
    uint32_t UpceAdd2() const;
    uint32_t UpceAdd5() const;
    uint32_t UpcCoupon() const;
    uint32_t TfStd() const;
    uint32_t TfDis() const;
    uint32_t TfInt() const;
    uint32_t TfInd() const;
    uint32_t TfMat() const;
    uint32_t TfIata() const;
    uint32_t Gs1DatabarType1() const;
    uint32_t Gs1DatabarType2() const;
    uint32_t Gs1DatabarType3() const;
    uint32_t Code39() const;
    uint32_t Code39Ex() const;
    uint32_t Trioptic39() const;
    uint32_t Code32() const;
    uint32_t Pzn() const;
    uint32_t Code93() const;
    uint32_t Code93Ex() const;
    uint32_t Code128() const;
    uint32_t Gs1128() const;
    uint32_t Gs1128Coupon() const;
    uint32_t UccEan128() const;
    uint32_t Sisac() const;
    uint32_t Isbt() const;
    uint32_t Codabar() const;
    uint32_t Code11() const;
    uint32_t Msi() const;
    uint32_t Plessey() const;
    uint32_t Telepen() const;
    uint32_t Code16k() const;
    uint32_t CodablockA() const;
    uint32_t CodablockF() const;
    uint32_t Codablock128() const;
    uint32_t Code49() const;
    uint32_t Aztec() const;
    uint32_t DataCode() const;
    uint32_t DataMatrix() const;
    uint32_t HanXin() const;
    uint32_t Maxicode() const;
    uint32_t MicroPdf417() const;
    uint32_t MicroQr() const;
    uint32_t Pdf417() const;
    uint32_t Qr() const;
    uint32_t MsTag() const;
    uint32_t Ccab() const;
    uint32_t Ccc() const;
    uint32_t Tlc39() const;
    uint32_t AusPost() const;
    uint32_t CanPost() const;
    uint32_t ChinaPost() const;
    uint32_t DutchKix() const;
    uint32_t InfoMail() const;
    uint32_t ItalianPost25() const;
    uint32_t ItalianPost39() const;
    uint32_t JapanPost() const;
    uint32_t KoreanPost() const;
    uint32_t SwedenPost() const;
    uint32_t UkPost() const;
    uint32_t UsIntelligent() const;
    uint32_t UsIntelligentPkg() const;
    uint32_t UsPlanet() const;
    uint32_t UsPostNet() const;
    uint32_t Us4StateFics() const;
    uint32_t OcrA() const;
    uint32_t OcrB() const;
    uint32_t Micr() const;
    uint32_t ExtendedBase() const;
    hstring GetName(uint32_t scanDataType) const;
};
template <> struct consume<Windows::Devices::PointOfService::IBarcodeSymbologiesStatics> { template <typename D> using type = consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics2
{
    uint32_t Gs1DWCode() const;
};
template <> struct consume<Windows::Devices::PointOfService::IBarcodeSymbologiesStatics2> { template <typename D> using type = consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics2<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IBarcodeSymbologyAttributes
{
    bool IsCheckDigitValidationEnabled() const;
    void IsCheckDigitValidationEnabled(bool value) const;
    bool IsCheckDigitValidationSupported() const;
    bool IsCheckDigitTransmissionEnabled() const;
    void IsCheckDigitTransmissionEnabled(bool value) const;
    bool IsCheckDigitTransmissionSupported() const;
    uint32_t DecodeLength1() const;
    void DecodeLength1(uint32_t value) const;
    uint32_t DecodeLength2() const;
    void DecodeLength2(uint32_t value) const;
    Windows::Devices::PointOfService::BarcodeSymbologyDecodeLengthKind DecodeLengthKind() const;
    void DecodeLengthKind(Windows::Devices::PointOfService::BarcodeSymbologyDecodeLengthKind const& value) const;
    bool IsDecodeLengthSupported() const;
};
template <> struct consume<Windows::Devices::PointOfService::IBarcodeSymbologyAttributes> { template <typename D> using type = consume_Windows_Devices_PointOfService_IBarcodeSymbologyAttributes<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_ICashDrawer
{
    hstring DeviceId() const;
    Windows::Devices::PointOfService::CashDrawerCapabilities Capabilities() const;
    Windows::Devices::PointOfService::CashDrawerStatus Status() const;
    bool IsDrawerOpen() const;
    Windows::Devices::PointOfService::CashDrawerEventSource DrawerEventSource() const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::ClaimedCashDrawer> ClaimDrawerAsync() const;
    Windows::Foundation::IAsyncOperation<hstring> CheckHealthAsync(Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel const& level) const;
    Windows::Foundation::IAsyncOperation<hstring> GetStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const;
    winrt::event_token StatusUpdated(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::CashDrawer, Windows::Devices::PointOfService::CashDrawerStatusUpdatedEventArgs> const& handler) const;
    using StatusUpdated_revoker = impl::event_revoker<Windows::Devices::PointOfService::ICashDrawer, &impl::abi_t<Windows::Devices::PointOfService::ICashDrawer>::remove_StatusUpdated>;
    StatusUpdated_revoker StatusUpdated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::CashDrawer, Windows::Devices::PointOfService::CashDrawerStatusUpdatedEventArgs> const& handler) const;
    void StatusUpdated(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Devices::PointOfService::ICashDrawer> { template <typename D> using type = consume_Windows_Devices_PointOfService_ICashDrawer<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_ICashDrawerCapabilities
{
    Windows::Devices::PointOfService::UnifiedPosPowerReportingType PowerReportingType() const;
    bool IsStatisticsReportingSupported() const;
    bool IsStatisticsUpdatingSupported() const;
    bool IsStatusReportingSupported() const;
    bool IsStatusMultiDrawerDetectSupported() const;
    bool IsDrawerOpenSensorAvailable() const;
};
template <> struct consume<Windows::Devices::PointOfService::ICashDrawerCapabilities> { template <typename D> using type = consume_Windows_Devices_PointOfService_ICashDrawerCapabilities<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_ICashDrawerCloseAlarm
{
    void AlarmTimeout(Windows::Foundation::TimeSpan const& value) const;
    Windows::Foundation::TimeSpan AlarmTimeout() const;
    void BeepFrequency(uint32_t value) const;
    uint32_t BeepFrequency() const;
    void BeepDuration(Windows::Foundation::TimeSpan const& value) const;
    Windows::Foundation::TimeSpan BeepDuration() const;
    void BeepDelay(Windows::Foundation::TimeSpan const& value) const;
    Windows::Foundation::TimeSpan BeepDelay() const;
    winrt::event_token AlarmTimeoutExpired(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::CashDrawerCloseAlarm, Windows::Foundation::IInspectable> const& handler) const;
    using AlarmTimeoutExpired_revoker = impl::event_revoker<Windows::Devices::PointOfService::ICashDrawerCloseAlarm, &impl::abi_t<Windows::Devices::PointOfService::ICashDrawerCloseAlarm>::remove_AlarmTimeoutExpired>;
    AlarmTimeoutExpired_revoker AlarmTimeoutExpired(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::CashDrawerCloseAlarm, Windows::Foundation::IInspectable> const& handler) const;
    void AlarmTimeoutExpired(winrt::event_token const& token) const noexcept;
    Windows::Foundation::IAsyncOperation<bool> StartAsync() const;
};
template <> struct consume<Windows::Devices::PointOfService::ICashDrawerCloseAlarm> { template <typename D> using type = consume_Windows_Devices_PointOfService_ICashDrawerCloseAlarm<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_ICashDrawerEventSource
{
    winrt::event_token DrawerClosed(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::CashDrawerEventSource, Windows::Devices::PointOfService::CashDrawerClosedEventArgs> const& handler) const;
    using DrawerClosed_revoker = impl::event_revoker<Windows::Devices::PointOfService::ICashDrawerEventSource, &impl::abi_t<Windows::Devices::PointOfService::ICashDrawerEventSource>::remove_DrawerClosed>;
    DrawerClosed_revoker DrawerClosed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::CashDrawerEventSource, Windows::Devices::PointOfService::CashDrawerClosedEventArgs> const& handler) const;
    void DrawerClosed(winrt::event_token const& token) const noexcept;
    winrt::event_token DrawerOpened(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::CashDrawerEventSource, Windows::Devices::PointOfService::CashDrawerOpenedEventArgs> const& handler) const;
    using DrawerOpened_revoker = impl::event_revoker<Windows::Devices::PointOfService::ICashDrawerEventSource, &impl::abi_t<Windows::Devices::PointOfService::ICashDrawerEventSource>::remove_DrawerOpened>;
    DrawerOpened_revoker DrawerOpened(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::CashDrawerEventSource, Windows::Devices::PointOfService::CashDrawerOpenedEventArgs> const& handler) const;
    void DrawerOpened(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Devices::PointOfService::ICashDrawerEventSource> { template <typename D> using type = consume_Windows_Devices_PointOfService_ICashDrawerEventSource<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_ICashDrawerEventSourceEventArgs
{
    Windows::Devices::PointOfService::CashDrawer CashDrawer() const;
};
template <> struct consume<Windows::Devices::PointOfService::ICashDrawerEventSourceEventArgs> { template <typename D> using type = consume_Windows_Devices_PointOfService_ICashDrawerEventSourceEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_ICashDrawerStatics
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::CashDrawer> GetDefaultAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::CashDrawer> FromIdAsync(param::hstring const& deviceId) const;
    hstring GetDeviceSelector() const;
};
template <> struct consume<Windows::Devices::PointOfService::ICashDrawerStatics> { template <typename D> using type = consume_Windows_Devices_PointOfService_ICashDrawerStatics<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_ICashDrawerStatics2
{
    hstring GetDeviceSelector(Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes) const;
};
template <> struct consume<Windows::Devices::PointOfService::ICashDrawerStatics2> { template <typename D> using type = consume_Windows_Devices_PointOfService_ICashDrawerStatics2<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_ICashDrawerStatus
{
    Windows::Devices::PointOfService::CashDrawerStatusKind StatusKind() const;
    uint32_t ExtendedStatus() const;
};
template <> struct consume<Windows::Devices::PointOfService::ICashDrawerStatus> { template <typename D> using type = consume_Windows_Devices_PointOfService_ICashDrawerStatus<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_ICashDrawerStatusUpdatedEventArgs
{
    Windows::Devices::PointOfService::CashDrawerStatus Status() const;
};
template <> struct consume<Windows::Devices::PointOfService::ICashDrawerStatusUpdatedEventArgs> { template <typename D> using type = consume_Windows_Devices_PointOfService_ICashDrawerStatusUpdatedEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner
{
    hstring DeviceId() const;
    bool IsEnabled() const;
    void IsDisabledOnDataReceived(bool value) const;
    bool IsDisabledOnDataReceived() const;
    void IsDecodeDataEnabled(bool value) const;
    bool IsDecodeDataEnabled() const;
    Windows::Foundation::IAsyncAction EnableAsync() const;
    Windows::Foundation::IAsyncAction DisableAsync() const;
    void RetainDevice() const;
    Windows::Foundation::IAsyncAction SetActiveSymbologiesAsync(param::async_iterable<uint32_t> const& symbologies) const;
    Windows::Foundation::IAsyncAction ResetStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const;
    Windows::Foundation::IAsyncAction UpdateStatisticsAsync(param::async_iterable<Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const& statistics) const;
    Windows::Foundation::IAsyncAction SetActiveProfileAsync(param::hstring const& profile) const;
    winrt::event_token DataReceived(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner, Windows::Devices::PointOfService::BarcodeScannerDataReceivedEventArgs> const& handler) const;
    using DataReceived_revoker = impl::event_revoker<Windows::Devices::PointOfService::IClaimedBarcodeScanner, &impl::abi_t<Windows::Devices::PointOfService::IClaimedBarcodeScanner>::remove_DataReceived>;
    DataReceived_revoker DataReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner, Windows::Devices::PointOfService::BarcodeScannerDataReceivedEventArgs> const& handler) const;
    void DataReceived(winrt::event_token const& token) const noexcept;
    winrt::event_token TriggerPressed(Windows::Foundation::EventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner> const& handler) const;
    using TriggerPressed_revoker = impl::event_revoker<Windows::Devices::PointOfService::IClaimedBarcodeScanner, &impl::abi_t<Windows::Devices::PointOfService::IClaimedBarcodeScanner>::remove_TriggerPressed>;
    TriggerPressed_revoker TriggerPressed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner> const& handler) const;
    void TriggerPressed(winrt::event_token const& token) const noexcept;
    winrt::event_token TriggerReleased(Windows::Foundation::EventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner> const& handler) const;
    using TriggerReleased_revoker = impl::event_revoker<Windows::Devices::PointOfService::IClaimedBarcodeScanner, &impl::abi_t<Windows::Devices::PointOfService::IClaimedBarcodeScanner>::remove_TriggerReleased>;
    TriggerReleased_revoker TriggerReleased(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner> const& handler) const;
    void TriggerReleased(winrt::event_token const& token) const noexcept;
    winrt::event_token ReleaseDeviceRequested(Windows::Foundation::EventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner> const& handler) const;
    using ReleaseDeviceRequested_revoker = impl::event_revoker<Windows::Devices::PointOfService::IClaimedBarcodeScanner, &impl::abi_t<Windows::Devices::PointOfService::IClaimedBarcodeScanner>::remove_ReleaseDeviceRequested>;
    ReleaseDeviceRequested_revoker ReleaseDeviceRequested(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner> const& handler) const;
    void ReleaseDeviceRequested(winrt::event_token const& token) const noexcept;
    winrt::event_token ImagePreviewReceived(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner, Windows::Devices::PointOfService::BarcodeScannerImagePreviewReceivedEventArgs> const& handler) const;
    using ImagePreviewReceived_revoker = impl::event_revoker<Windows::Devices::PointOfService::IClaimedBarcodeScanner, &impl::abi_t<Windows::Devices::PointOfService::IClaimedBarcodeScanner>::remove_ImagePreviewReceived>;
    ImagePreviewReceived_revoker ImagePreviewReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner, Windows::Devices::PointOfService::BarcodeScannerImagePreviewReceivedEventArgs> const& handler) const;
    void ImagePreviewReceived(winrt::event_token const& token) const noexcept;
    winrt::event_token ErrorOccurred(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner, Windows::Devices::PointOfService::BarcodeScannerErrorOccurredEventArgs> const& handler) const;
    using ErrorOccurred_revoker = impl::event_revoker<Windows::Devices::PointOfService::IClaimedBarcodeScanner, &impl::abi_t<Windows::Devices::PointOfService::IClaimedBarcodeScanner>::remove_ErrorOccurred>;
    ErrorOccurred_revoker ErrorOccurred(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner, Windows::Devices::PointOfService::BarcodeScannerErrorOccurredEventArgs> const& handler) const;
    void ErrorOccurred(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Devices::PointOfService::IClaimedBarcodeScanner> { template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner1
{
    Windows::Foundation::IAsyncAction StartSoftwareTriggerAsync() const;
    Windows::Foundation::IAsyncAction StopSoftwareTriggerAsync() const;
};
template <> struct consume<Windows::Devices::PointOfService::IClaimedBarcodeScanner1> { template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner1<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner2
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::BarcodeSymbologyAttributes> GetSymbologyAttributesAsync(uint32_t barcodeSymbology) const;
    Windows::Foundation::IAsyncOperation<bool> SetSymbologyAttributesAsync(uint32_t barcodeSymbology, Windows::Devices::PointOfService::BarcodeSymbologyAttributes const& attributes) const;
};
template <> struct consume<Windows::Devices::PointOfService::IClaimedBarcodeScanner2> { template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner2<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner3
{
    Windows::Foundation::IAsyncOperation<bool> ShowVideoPreviewAsync() const;
    void HideVideoPreview() const;
    void IsVideoPreviewShownOnEnable(bool value) const;
    bool IsVideoPreviewShownOnEnable() const;
};
template <> struct consume<Windows::Devices::PointOfService::IClaimedBarcodeScanner3> { template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner3<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner4
{
    winrt::event_token Closed(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner, Windows::Devices::PointOfService::ClaimedBarcodeScannerClosedEventArgs> const& handler) const;
    using Closed_revoker = impl::event_revoker<Windows::Devices::PointOfService::IClaimedBarcodeScanner4, &impl::abi_t<Windows::Devices::PointOfService::IClaimedBarcodeScanner4>::remove_Closed>;
    Closed_revoker Closed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner, Windows::Devices::PointOfService::ClaimedBarcodeScannerClosedEventArgs> const& handler) const;
    void Closed(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Devices::PointOfService::IClaimedBarcodeScanner4> { template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner4<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IClaimedBarcodeScannerClosedEventArgs
{
};
template <> struct consume<Windows::Devices::PointOfService::IClaimedBarcodeScannerClosedEventArgs> { template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedBarcodeScannerClosedEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IClaimedCashDrawer
{
    hstring DeviceId() const;
    bool IsEnabled() const;
    bool IsDrawerOpen() const;
    Windows::Devices::PointOfService::CashDrawerCloseAlarm CloseAlarm() const;
    Windows::Foundation::IAsyncOperation<bool> OpenDrawerAsync() const;
    Windows::Foundation::IAsyncOperation<bool> EnableAsync() const;
    Windows::Foundation::IAsyncOperation<bool> DisableAsync() const;
    Windows::Foundation::IAsyncOperation<bool> RetainDeviceAsync() const;
    Windows::Foundation::IAsyncOperation<bool> ResetStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const;
    Windows::Foundation::IAsyncOperation<bool> UpdateStatisticsAsync(param::async_iterable<Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const& statistics) const;
    winrt::event_token ReleaseDeviceRequested(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedCashDrawer, Windows::Foundation::IInspectable> const& handler) const;
    using ReleaseDeviceRequested_revoker = impl::event_revoker<Windows::Devices::PointOfService::IClaimedCashDrawer, &impl::abi_t<Windows::Devices::PointOfService::IClaimedCashDrawer>::remove_ReleaseDeviceRequested>;
    ReleaseDeviceRequested_revoker ReleaseDeviceRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedCashDrawer, Windows::Foundation::IInspectable> const& handler) const;
    void ReleaseDeviceRequested(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Devices::PointOfService::IClaimedCashDrawer> { template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedCashDrawer<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IClaimedCashDrawer2
{
    winrt::event_token Closed(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedCashDrawer, Windows::Devices::PointOfService::ClaimedCashDrawerClosedEventArgs> const& handler) const;
    using Closed_revoker = impl::event_revoker<Windows::Devices::PointOfService::IClaimedCashDrawer2, &impl::abi_t<Windows::Devices::PointOfService::IClaimedCashDrawer2>::remove_Closed>;
    Closed_revoker Closed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedCashDrawer, Windows::Devices::PointOfService::ClaimedCashDrawerClosedEventArgs> const& handler) const;
    void Closed(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Devices::PointOfService::IClaimedCashDrawer2> { template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedCashDrawer2<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IClaimedCashDrawerClosedEventArgs
{
};
template <> struct consume<Windows::Devices::PointOfService::IClaimedCashDrawerClosedEventArgs> { template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedCashDrawerClosedEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IClaimedJournalPrinter
{
    Windows::Devices::PointOfService::JournalPrintJob CreateJob() const;
};
template <> struct consume<Windows::Devices::PointOfService::IClaimedJournalPrinter> { template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedJournalPrinter<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IClaimedLineDisplay
{
    hstring DeviceId() const;
    Windows::Devices::PointOfService::LineDisplayCapabilities Capabilities() const;
    hstring PhysicalDeviceName() const;
    hstring PhysicalDeviceDescription() const;
    hstring DeviceControlDescription() const;
    hstring DeviceControlVersion() const;
    hstring DeviceServiceVersion() const;
    Windows::Devices::PointOfService::LineDisplayWindow DefaultWindow() const;
    void RetainDevice() const;
    winrt::event_token ReleaseDeviceRequested(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedLineDisplay, Windows::Foundation::IInspectable> const& handler) const;
    using ReleaseDeviceRequested_revoker = impl::event_revoker<Windows::Devices::PointOfService::IClaimedLineDisplay, &impl::abi_t<Windows::Devices::PointOfService::IClaimedLineDisplay>::remove_ReleaseDeviceRequested>;
    ReleaseDeviceRequested_revoker ReleaseDeviceRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedLineDisplay, Windows::Foundation::IInspectable> const& handler) const;
    void ReleaseDeviceRequested(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Devices::PointOfService::IClaimedLineDisplay> { template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedLineDisplay<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IClaimedLineDisplay2
{
    Windows::Foundation::IAsyncOperation<hstring> GetStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const;
    Windows::Foundation::IAsyncOperation<hstring> CheckHealthAsync(Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel const& level) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplayPowerStatus> CheckPowerStatusAsync() const;
    winrt::event_token StatusUpdated(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedLineDisplay, Windows::Devices::PointOfService::LineDisplayStatusUpdatedEventArgs> const& handler) const;
    using StatusUpdated_revoker = impl::event_revoker<Windows::Devices::PointOfService::IClaimedLineDisplay2, &impl::abi_t<Windows::Devices::PointOfService::IClaimedLineDisplay2>::remove_StatusUpdated>;
    StatusUpdated_revoker StatusUpdated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedLineDisplay, Windows::Devices::PointOfService::LineDisplayStatusUpdatedEventArgs> const& handler) const;
    void StatusUpdated(winrt::event_token const& token) const noexcept;
    Windows::Foundation::Collections::IVectorView<Windows::Foundation::Size> SupportedScreenSizesInCharacters() const;
    Windows::Foundation::Size MaxBitmapSizeInPixels() const;
    Windows::Foundation::Collections::IVectorView<int32_t> SupportedCharacterSets() const;
    Windows::Devices::PointOfService::LineDisplayCustomGlyphs CustomGlyphs() const;
    Windows::Devices::PointOfService::LineDisplayAttributes GetAttributes() const;
    Windows::Foundation::IAsyncOperation<bool> TryUpdateAttributesAsync(Windows::Devices::PointOfService::LineDisplayAttributes const& attributes) const;
    Windows::Foundation::IAsyncOperation<bool> TrySetDescriptorAsync(uint32_t descriptor, Windows::Devices::PointOfService::LineDisplayDescriptorState const& descriptorState) const;
    Windows::Foundation::IAsyncOperation<bool> TryClearDescriptorsAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplayWindow> TryCreateWindowAsync(Windows::Foundation::Rect const& viewport, Windows::Foundation::Size const& windowSize) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplayStoredBitmap> TryStoreStorageFileBitmapAsync(Windows::Storage::StorageFile const& bitmap) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplayStoredBitmap> TryStoreStorageFileBitmapAsync(Windows::Storage::StorageFile const& bitmap, Windows::Devices::PointOfService::LineDisplayHorizontalAlignment const& horizontalAlignment, Windows::Devices::PointOfService::LineDisplayVerticalAlignment const& verticalAlignment) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplayStoredBitmap> TryStoreStorageFileBitmapAsync(Windows::Storage::StorageFile const& bitmap, Windows::Devices::PointOfService::LineDisplayHorizontalAlignment const& horizontalAlignment, Windows::Devices::PointOfService::LineDisplayVerticalAlignment const& verticalAlignment, int32_t widthInPixels) const;
};
template <> struct consume<Windows::Devices::PointOfService::IClaimedLineDisplay2> { template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IClaimedLineDisplay3
{
    winrt::event_token Closed(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedLineDisplay, Windows::Devices::PointOfService::ClaimedLineDisplayClosedEventArgs> const& handler) const;
    using Closed_revoker = impl::event_revoker<Windows::Devices::PointOfService::IClaimedLineDisplay3, &impl::abi_t<Windows::Devices::PointOfService::IClaimedLineDisplay3>::remove_Closed>;
    Closed_revoker Closed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedLineDisplay, Windows::Devices::PointOfService::ClaimedLineDisplayClosedEventArgs> const& handler) const;
    void Closed(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Devices::PointOfService::IClaimedLineDisplay3> { template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedLineDisplay3<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IClaimedLineDisplayClosedEventArgs
{
};
template <> struct consume<Windows::Devices::PointOfService::IClaimedLineDisplayClosedEventArgs> { template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedLineDisplayClosedEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IClaimedLineDisplayStatics
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::ClaimedLineDisplay> FromIdAsync(param::hstring const& deviceId) const;
    hstring GetDeviceSelector() const;
    hstring GetDeviceSelector(Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes) const;
};
template <> struct consume<Windows::Devices::PointOfService::IClaimedLineDisplayStatics> { template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedLineDisplayStatics<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader
{
    hstring DeviceId() const;
    bool IsEnabled() const;
    void IsDisabledOnDataReceived(bool value) const;
    bool IsDisabledOnDataReceived() const;
    void IsDecodeDataEnabled(bool value) const;
    bool IsDecodeDataEnabled() const;
    bool IsDeviceAuthenticated() const;
    void DataEncryptionAlgorithm(uint32_t value) const;
    uint32_t DataEncryptionAlgorithm() const;
    void TracksToRead(Windows::Devices::PointOfService::MagneticStripeReaderTrackIds const& value) const;
    Windows::Devices::PointOfService::MagneticStripeReaderTrackIds TracksToRead() const;
    void IsTransmitSentinelsEnabled(bool value) const;
    bool IsTransmitSentinelsEnabled() const;
    Windows::Foundation::IAsyncAction EnableAsync() const;
    Windows::Foundation::IAsyncAction DisableAsync() const;
    void RetainDevice() const;
    void SetErrorReportingType(Windows::Devices::PointOfService::MagneticStripeReaderErrorReportingType const& value) const;
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> RetrieveDeviceAuthenticationDataAsync() const;
    Windows::Foundation::IAsyncAction AuthenticateDeviceAsync(array_view<uint8_t const> responseToken) const;
    Windows::Foundation::IAsyncAction DeAuthenticateDeviceAsync(array_view<uint8_t const> responseToken) const;
    Windows::Foundation::IAsyncAction UpdateKeyAsync(param::hstring const& key, param::hstring const& keyName) const;
    Windows::Foundation::IAsyncAction ResetStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const;
    Windows::Foundation::IAsyncAction UpdateStatisticsAsync(param::async_iterable<Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const& statistics) const;
    winrt::event_token BankCardDataReceived(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader, Windows::Devices::PointOfService::MagneticStripeReaderBankCardDataReceivedEventArgs> const& handler) const;
    using BankCardDataReceived_revoker = impl::event_revoker<Windows::Devices::PointOfService::IClaimedMagneticStripeReader, &impl::abi_t<Windows::Devices::PointOfService::IClaimedMagneticStripeReader>::remove_BankCardDataReceived>;
    BankCardDataReceived_revoker BankCardDataReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader, Windows::Devices::PointOfService::MagneticStripeReaderBankCardDataReceivedEventArgs> const& handler) const;
    void BankCardDataReceived(winrt::event_token const& token) const noexcept;
    winrt::event_token AamvaCardDataReceived(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader, Windows::Devices::PointOfService::MagneticStripeReaderAamvaCardDataReceivedEventArgs> const& handler) const;
    using AamvaCardDataReceived_revoker = impl::event_revoker<Windows::Devices::PointOfService::IClaimedMagneticStripeReader, &impl::abi_t<Windows::Devices::PointOfService::IClaimedMagneticStripeReader>::remove_AamvaCardDataReceived>;
    AamvaCardDataReceived_revoker AamvaCardDataReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader, Windows::Devices::PointOfService::MagneticStripeReaderAamvaCardDataReceivedEventArgs> const& handler) const;
    void AamvaCardDataReceived(winrt::event_token const& token) const noexcept;
    winrt::event_token VendorSpecificDataReceived(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader, Windows::Devices::PointOfService::MagneticStripeReaderVendorSpecificCardDataReceivedEventArgs> const& handler) const;
    using VendorSpecificDataReceived_revoker = impl::event_revoker<Windows::Devices::PointOfService::IClaimedMagneticStripeReader, &impl::abi_t<Windows::Devices::PointOfService::IClaimedMagneticStripeReader>::remove_VendorSpecificDataReceived>;
    VendorSpecificDataReceived_revoker VendorSpecificDataReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader, Windows::Devices::PointOfService::MagneticStripeReaderVendorSpecificCardDataReceivedEventArgs> const& handler) const;
    void VendorSpecificDataReceived(winrt::event_token const& token) const noexcept;
    winrt::event_token ReleaseDeviceRequested(Windows::Foundation::EventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader> const& handler) const;
    using ReleaseDeviceRequested_revoker = impl::event_revoker<Windows::Devices::PointOfService::IClaimedMagneticStripeReader, &impl::abi_t<Windows::Devices::PointOfService::IClaimedMagneticStripeReader>::remove_ReleaseDeviceRequested>;
    ReleaseDeviceRequested_revoker ReleaseDeviceRequested(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader> const& handler) const;
    void ReleaseDeviceRequested(winrt::event_token const& token) const noexcept;
    winrt::event_token ErrorOccurred(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader, Windows::Devices::PointOfService::MagneticStripeReaderErrorOccurredEventArgs> const& handler) const;
    using ErrorOccurred_revoker = impl::event_revoker<Windows::Devices::PointOfService::IClaimedMagneticStripeReader, &impl::abi_t<Windows::Devices::PointOfService::IClaimedMagneticStripeReader>::remove_ErrorOccurred>;
    ErrorOccurred_revoker ErrorOccurred(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader, Windows::Devices::PointOfService::MagneticStripeReaderErrorOccurredEventArgs> const& handler) const;
    void ErrorOccurred(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Devices::PointOfService::IClaimedMagneticStripeReader> { template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader2
{
    winrt::event_token Closed(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader, Windows::Devices::PointOfService::ClaimedMagneticStripeReaderClosedEventArgs> const& handler) const;
    using Closed_revoker = impl::event_revoker<Windows::Devices::PointOfService::IClaimedMagneticStripeReader2, &impl::abi_t<Windows::Devices::PointOfService::IClaimedMagneticStripeReader2>::remove_Closed>;
    Closed_revoker Closed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader, Windows::Devices::PointOfService::ClaimedMagneticStripeReaderClosedEventArgs> const& handler) const;
    void Closed(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Devices::PointOfService::IClaimedMagneticStripeReader2> { template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader2<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReaderClosedEventArgs
{
};
template <> struct consume<Windows::Devices::PointOfService::IClaimedMagneticStripeReaderClosedEventArgs> { template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReaderClosedEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IClaimedPosPrinter
{
    hstring DeviceId() const;
    bool IsEnabled() const;
    void CharacterSet(uint32_t value) const;
    uint32_t CharacterSet() const;
    bool IsCoverOpen() const;
    void IsCharacterSetMappingEnabled(bool value) const;
    bool IsCharacterSetMappingEnabled() const;
    void MapMode(Windows::Devices::PointOfService::PosPrinterMapMode const& value) const;
    Windows::Devices::PointOfService::PosPrinterMapMode MapMode() const;
    Windows::Devices::PointOfService::ClaimedReceiptPrinter Receipt() const;
    Windows::Devices::PointOfService::ClaimedSlipPrinter Slip() const;
    Windows::Devices::PointOfService::ClaimedJournalPrinter Journal() const;
    Windows::Foundation::IAsyncOperation<bool> EnableAsync() const;
    Windows::Foundation::IAsyncOperation<bool> DisableAsync() const;
    Windows::Foundation::IAsyncOperation<bool> RetainDeviceAsync() const;
    Windows::Foundation::IAsyncOperation<bool> ResetStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const;
    Windows::Foundation::IAsyncOperation<bool> UpdateStatisticsAsync(param::async_iterable<Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const& statistics) const;
    winrt::event_token ReleaseDeviceRequested(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedPosPrinter, Windows::Devices::PointOfService::PosPrinterReleaseDeviceRequestedEventArgs> const& handler) const;
    using ReleaseDeviceRequested_revoker = impl::event_revoker<Windows::Devices::PointOfService::IClaimedPosPrinter, &impl::abi_t<Windows::Devices::PointOfService::IClaimedPosPrinter>::remove_ReleaseDeviceRequested>;
    ReleaseDeviceRequested_revoker ReleaseDeviceRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedPosPrinter, Windows::Devices::PointOfService::PosPrinterReleaseDeviceRequestedEventArgs> const& handler) const;
    void ReleaseDeviceRequested(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Devices::PointOfService::IClaimedPosPrinter> { template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IClaimedPosPrinter2
{
    winrt::event_token Closed(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedPosPrinter, Windows::Devices::PointOfService::ClaimedPosPrinterClosedEventArgs> const& handler) const;
    using Closed_revoker = impl::event_revoker<Windows::Devices::PointOfService::IClaimedPosPrinter2, &impl::abi_t<Windows::Devices::PointOfService::IClaimedPosPrinter2>::remove_Closed>;
    Closed_revoker Closed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedPosPrinter, Windows::Devices::PointOfService::ClaimedPosPrinterClosedEventArgs> const& handler) const;
    void Closed(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Devices::PointOfService::IClaimedPosPrinter2> { template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedPosPrinter2<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IClaimedPosPrinterClosedEventArgs
{
};
template <> struct consume<Windows::Devices::PointOfService::IClaimedPosPrinterClosedEventArgs> { template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedPosPrinterClosedEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IClaimedReceiptPrinter
{
    uint32_t SidewaysMaxLines() const;
    uint32_t SidewaysMaxChars() const;
    uint32_t LinesToPaperCut() const;
    Windows::Foundation::Size PageSize() const;
    Windows::Foundation::Rect PrintArea() const;
    Windows::Devices::PointOfService::ReceiptPrintJob CreateJob() const;
};
template <> struct consume<Windows::Devices::PointOfService::IClaimedReceiptPrinter> { template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedReceiptPrinter<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IClaimedSlipPrinter
{
    uint32_t SidewaysMaxLines() const;
    uint32_t SidewaysMaxChars() const;
    uint32_t MaxLines() const;
    uint32_t LinesNearEndToEnd() const;
    Windows::Devices::PointOfService::PosPrinterPrintSide PrintSide() const;
    Windows::Foundation::Size PageSize() const;
    Windows::Foundation::Rect PrintArea() const;
    void OpenJaws() const;
    void CloseJaws() const;
    Windows::Foundation::IAsyncOperation<bool> InsertSlipAsync(Windows::Foundation::TimeSpan const& timeout) const;
    Windows::Foundation::IAsyncOperation<bool> RemoveSlipAsync(Windows::Foundation::TimeSpan const& timeout) const;
    void ChangePrintSide(Windows::Devices::PointOfService::PosPrinterPrintSide const& printSide) const;
    Windows::Devices::PointOfService::SlipPrintJob CreateJob() const;
};
template <> struct consume<Windows::Devices::PointOfService::IClaimedSlipPrinter> { template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedSlipPrinter<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation
{
    void CharactersPerLine(uint32_t value) const;
    uint32_t CharactersPerLine() const;
    void LineHeight(uint32_t value) const;
    uint32_t LineHeight() const;
    void LineSpacing(uint32_t value) const;
    uint32_t LineSpacing() const;
    uint32_t LineWidth() const;
    void IsLetterQuality(bool value) const;
    bool IsLetterQuality() const;
    bool IsPaperNearEnd() const;
    void ColorCartridge(Windows::Devices::PointOfService::PosPrinterColorCartridge const& value) const;
    Windows::Devices::PointOfService::PosPrinterColorCartridge ColorCartridge() const;
    bool IsCoverOpen() const;
    bool IsCartridgeRemoved() const;
    bool IsCartridgeEmpty() const;
    bool IsHeadCleaning() const;
    bool IsPaperEmpty() const;
    bool IsReadyToPrint() const;
    bool ValidateData(param::hstring const& data) const;
};
template <> struct consume<Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation> { template <typename D> using type = consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_ICommonPosPrintStationCapabilities
{
    bool IsPrinterPresent() const;
    bool IsDualColorSupported() const;
    Windows::Devices::PointOfService::PosPrinterColorCapabilities ColorCartridgeCapabilities() const;
    Windows::Devices::PointOfService::PosPrinterCartridgeSensors CartridgeSensors() const;
    bool IsBoldSupported() const;
    bool IsItalicSupported() const;
    bool IsUnderlineSupported() const;
    bool IsDoubleHighPrintSupported() const;
    bool IsDoubleWidePrintSupported() const;
    bool IsDoubleHighDoubleWidePrintSupported() const;
    bool IsPaperEmptySensorSupported() const;
    bool IsPaperNearEndSensorSupported() const;
    Windows::Foundation::Collections::IVectorView<uint32_t> SupportedCharactersPerLine() const;
};
template <> struct consume<Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities> { template <typename D> using type = consume_Windows_Devices_PointOfService_ICommonPosPrintStationCapabilities<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_ICommonReceiptSlipCapabilities
{
    bool IsBarcodeSupported() const;
    bool IsBitmapSupported() const;
    bool IsLeft90RotationSupported() const;
    bool IsRight90RotationSupported() const;
    bool Is180RotationSupported() const;
    bool IsPrintAreaSupported() const;
    Windows::Devices::PointOfService::PosPrinterRuledLineCapabilities RuledLineCapabilities() const;
    Windows::Foundation::Collections::IVectorView<Windows::Devices::PointOfService::PosPrinterRotation> SupportedBarcodeRotations() const;
    Windows::Foundation::Collections::IVectorView<Windows::Devices::PointOfService::PosPrinterRotation> SupportedBitmapRotations() const;
};
template <> struct consume<Windows::Devices::PointOfService::ICommonReceiptSlipCapabilities> { template <typename D> using type = consume_Windows_Devices_PointOfService_ICommonReceiptSlipCapabilities<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IJournalPrintJob
{
    void Print(param::hstring const& data, Windows::Devices::PointOfService::PosPrinterPrintOptions const& printOptions) const;
    void FeedPaperByLine(int32_t lineCount) const;
    void FeedPaperByMapModeUnit(int32_t distance) const;
};
template <> struct consume<Windows::Devices::PointOfService::IJournalPrintJob> { template <typename D> using type = consume_Windows_Devices_PointOfService_IJournalPrintJob<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IJournalPrinterCapabilities
{
};
template <> struct consume<Windows::Devices::PointOfService::IJournalPrinterCapabilities> { template <typename D> using type = consume_Windows_Devices_PointOfService_IJournalPrinterCapabilities<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IJournalPrinterCapabilities2
{
    bool IsReverseVideoSupported() const;
    bool IsStrikethroughSupported() const;
    bool IsSuperscriptSupported() const;
    bool IsSubscriptSupported() const;
    bool IsReversePaperFeedByLineSupported() const;
    bool IsReversePaperFeedByMapModeUnitSupported() const;
};
template <> struct consume<Windows::Devices::PointOfService::IJournalPrinterCapabilities2> { template <typename D> using type = consume_Windows_Devices_PointOfService_IJournalPrinterCapabilities2<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_ILineDisplay
{
    hstring DeviceId() const;
    Windows::Devices::PointOfService::LineDisplayCapabilities Capabilities() const;
    hstring PhysicalDeviceName() const;
    hstring PhysicalDeviceDescription() const;
    hstring DeviceControlDescription() const;
    hstring DeviceControlVersion() const;
    hstring DeviceServiceVersion() const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::ClaimedLineDisplay> ClaimAsync() const;
};
template <> struct consume<Windows::Devices::PointOfService::ILineDisplay> { template <typename D> using type = consume_Windows_Devices_PointOfService_ILineDisplay<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_ILineDisplay2
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplayPowerStatus> CheckPowerStatusAsync() const;
};
template <> struct consume<Windows::Devices::PointOfService::ILineDisplay2> { template <typename D> using type = consume_Windows_Devices_PointOfService_ILineDisplay2<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_ILineDisplayAttributes
{
    bool IsPowerNotifyEnabled() const;
    void IsPowerNotifyEnabled(bool value) const;
    int32_t Brightness() const;
    void Brightness(int32_t value) const;
    Windows::Foundation::TimeSpan BlinkRate() const;
    void BlinkRate(Windows::Foundation::TimeSpan const& value) const;
    Windows::Foundation::Size ScreenSizeInCharacters() const;
    void ScreenSizeInCharacters(Windows::Foundation::Size const& value) const;
    int32_t CharacterSet() const;
    void CharacterSet(int32_t value) const;
    bool IsCharacterSetMappingEnabled() const;
    void IsCharacterSetMappingEnabled(bool value) const;
    Windows::Devices::PointOfService::LineDisplayWindow CurrentWindow() const;
    void CurrentWindow(Windows::Devices::PointOfService::LineDisplayWindow const& value) const;
};
template <> struct consume<Windows::Devices::PointOfService::ILineDisplayAttributes> { template <typename D> using type = consume_Windows_Devices_PointOfService_ILineDisplayAttributes<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_ILineDisplayCapabilities
{
    bool IsStatisticsReportingSupported() const;
    bool IsStatisticsUpdatingSupported() const;
    Windows::Devices::PointOfService::UnifiedPosPowerReportingType PowerReportingType() const;
    bool CanChangeScreenSize() const;
    bool CanDisplayBitmaps() const;
    bool CanReadCharacterAtCursor() const;
    bool CanMapCharacterSets() const;
    bool CanDisplayCustomGlyphs() const;
    Windows::Devices::PointOfService::LineDisplayTextAttributeGranularity CanReverse() const;
    Windows::Devices::PointOfService::LineDisplayTextAttributeGranularity CanBlink() const;
    bool CanChangeBlinkRate() const;
    bool IsBrightnessSupported() const;
    bool IsCursorSupported() const;
    bool IsHorizontalMarqueeSupported() const;
    bool IsVerticalMarqueeSupported() const;
    bool IsInterCharacterWaitSupported() const;
    uint32_t SupportedDescriptors() const;
    uint32_t SupportedWindows() const;
};
template <> struct consume<Windows::Devices::PointOfService::ILineDisplayCapabilities> { template <typename D> using type = consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_ILineDisplayCursor
{
    bool CanCustomize() const;
    bool IsBlinkSupported() const;
    bool IsBlockSupported() const;
    bool IsHalfBlockSupported() const;
    bool IsUnderlineSupported() const;
    bool IsReverseSupported() const;
    bool IsOtherSupported() const;
    Windows::Devices::PointOfService::LineDisplayCursorAttributes GetAttributes() const;
    Windows::Foundation::IAsyncOperation<bool> TryUpdateAttributesAsync(Windows::Devices::PointOfService::LineDisplayCursorAttributes const& attributes) const;
};
template <> struct consume<Windows::Devices::PointOfService::ILineDisplayCursor> { template <typename D> using type = consume_Windows_Devices_PointOfService_ILineDisplayCursor<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_ILineDisplayCursorAttributes
{
    bool IsBlinkEnabled() const;
    void IsBlinkEnabled(bool value) const;
    Windows::Devices::PointOfService::LineDisplayCursorType CursorType() const;
    void CursorType(Windows::Devices::PointOfService::LineDisplayCursorType const& value) const;
    bool IsAutoAdvanceEnabled() const;
    void IsAutoAdvanceEnabled(bool value) const;
    Windows::Foundation::Point Position() const;
    void Position(Windows::Foundation::Point const& value) const;
};
template <> struct consume<Windows::Devices::PointOfService::ILineDisplayCursorAttributes> { template <typename D> using type = consume_Windows_Devices_PointOfService_ILineDisplayCursorAttributes<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_ILineDisplayCustomGlyphs
{
    Windows::Foundation::Size SizeInPixels() const;
    Windows::Foundation::Collections::IVectorView<uint32_t> SupportedGlyphCodes() const;
    Windows::Foundation::IAsyncOperation<bool> TryRedefineAsync(uint32_t glyphCode, Windows::Storage::Streams::IBuffer const& glyphData) const;
};
template <> struct consume<Windows::Devices::PointOfService::ILineDisplayCustomGlyphs> { template <typename D> using type = consume_Windows_Devices_PointOfService_ILineDisplayCustomGlyphs<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_ILineDisplayMarquee
{
    Windows::Devices::PointOfService::LineDisplayMarqueeFormat Format() const;
    void Format(Windows::Devices::PointOfService::LineDisplayMarqueeFormat const& value) const;
    Windows::Foundation::TimeSpan RepeatWaitInterval() const;
    void RepeatWaitInterval(Windows::Foundation::TimeSpan const& value) const;
    Windows::Foundation::TimeSpan ScrollWaitInterval() const;
    void ScrollWaitInterval(Windows::Foundation::TimeSpan const& value) const;
    Windows::Foundation::IAsyncOperation<bool> TryStartScrollingAsync(Windows::Devices::PointOfService::LineDisplayScrollDirection const& direction) const;
    Windows::Foundation::IAsyncOperation<bool> TryStopScrollingAsync() const;
};
template <> struct consume<Windows::Devices::PointOfService::ILineDisplayMarquee> { template <typename D> using type = consume_Windows_Devices_PointOfService_ILineDisplayMarquee<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_ILineDisplayStatics
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplay> FromIdAsync(param::hstring const& deviceId) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplay> GetDefaultAsync() const;
    hstring GetDeviceSelector() const;
    hstring GetDeviceSelector(Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes) const;
};
template <> struct consume<Windows::Devices::PointOfService::ILineDisplayStatics> { template <typename D> using type = consume_Windows_Devices_PointOfService_ILineDisplayStatics<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_ILineDisplayStatics2
{
    Windows::Devices::PointOfService::LineDisplayStatisticsCategorySelector StatisticsCategorySelector() const;
};
template <> struct consume<Windows::Devices::PointOfService::ILineDisplayStatics2> { template <typename D> using type = consume_Windows_Devices_PointOfService_ILineDisplayStatics2<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_ILineDisplayStatisticsCategorySelector
{
    hstring AllStatistics() const;
    hstring UnifiedPosStatistics() const;
    hstring ManufacturerStatistics() const;
};
template <> struct consume<Windows::Devices::PointOfService::ILineDisplayStatisticsCategorySelector> { template <typename D> using type = consume_Windows_Devices_PointOfService_ILineDisplayStatisticsCategorySelector<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_ILineDisplayStatusUpdatedEventArgs
{
    Windows::Devices::PointOfService::LineDisplayPowerStatus Status() const;
};
template <> struct consume<Windows::Devices::PointOfService::ILineDisplayStatusUpdatedEventArgs> { template <typename D> using type = consume_Windows_Devices_PointOfService_ILineDisplayStatusUpdatedEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_ILineDisplayStoredBitmap
{
    hstring EscapeSequence() const;
    Windows::Foundation::IAsyncOperation<bool> TryDeleteAsync() const;
};
template <> struct consume<Windows::Devices::PointOfService::ILineDisplayStoredBitmap> { template <typename D> using type = consume_Windows_Devices_PointOfService_ILineDisplayStoredBitmap<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_ILineDisplayWindow
{
    Windows::Foundation::Size SizeInCharacters() const;
    Windows::Foundation::TimeSpan InterCharacterWaitInterval() const;
    void InterCharacterWaitInterval(Windows::Foundation::TimeSpan const& value) const;
    Windows::Foundation::IAsyncOperation<bool> TryRefreshAsync() const;
    Windows::Foundation::IAsyncOperation<bool> TryDisplayTextAsync(param::hstring const& text, Windows::Devices::PointOfService::LineDisplayTextAttribute const& displayAttribute) const;
    Windows::Foundation::IAsyncOperation<bool> TryDisplayTextAsync(param::hstring const& text, Windows::Devices::PointOfService::LineDisplayTextAttribute const& displayAttribute, Windows::Foundation::Point const& startPosition) const;
    Windows::Foundation::IAsyncOperation<bool> TryDisplayTextAsync(param::hstring const& text) const;
    Windows::Foundation::IAsyncOperation<bool> TryScrollTextAsync(Windows::Devices::PointOfService::LineDisplayScrollDirection const& direction, uint32_t numberOfColumnsOrRows) const;
    Windows::Foundation::IAsyncOperation<bool> TryClearTextAsync() const;
};
template <> struct consume<Windows::Devices::PointOfService::ILineDisplayWindow> { template <typename D> using type = consume_Windows_Devices_PointOfService_ILineDisplayWindow<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_ILineDisplayWindow2
{
    Windows::Devices::PointOfService::LineDisplayCursor Cursor() const;
    Windows::Devices::PointOfService::LineDisplayMarquee Marquee() const;
    Windows::Foundation::IAsyncOperation<uint32_t> ReadCharacterAtCursorAsync() const;
    Windows::Foundation::IAsyncOperation<bool> TryDisplayStoredBitmapAtCursorAsync(Windows::Devices::PointOfService::LineDisplayStoredBitmap const& bitmap) const;
    Windows::Foundation::IAsyncOperation<bool> TryDisplayStorageFileBitmapAtCursorAsync(Windows::Storage::StorageFile const& bitmap) const;
    Windows::Foundation::IAsyncOperation<bool> TryDisplayStorageFileBitmapAtCursorAsync(Windows::Storage::StorageFile const& bitmap, Windows::Devices::PointOfService::LineDisplayHorizontalAlignment const& horizontalAlignment, Windows::Devices::PointOfService::LineDisplayVerticalAlignment const& verticalAlignment) const;
    Windows::Foundation::IAsyncOperation<bool> TryDisplayStorageFileBitmapAtCursorAsync(Windows::Storage::StorageFile const& bitmap, Windows::Devices::PointOfService::LineDisplayHorizontalAlignment const& horizontalAlignment, Windows::Devices::PointOfService::LineDisplayVerticalAlignment const& verticalAlignment, int32_t widthInPixels) const;
    Windows::Foundation::IAsyncOperation<bool> TryDisplayStorageFileBitmapAtPointAsync(Windows::Storage::StorageFile const& bitmap, Windows::Foundation::Point const& offsetInPixels) const;
    Windows::Foundation::IAsyncOperation<bool> TryDisplayStorageFileBitmapAtPointAsync(Windows::Storage::StorageFile const& bitmap, Windows::Foundation::Point const& offsetInPixels, int32_t widthInPixels) const;
};
template <> struct consume<Windows::Devices::PointOfService::ILineDisplayWindow2> { template <typename D> using type = consume_Windows_Devices_PointOfService_ILineDisplayWindow2<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IMagneticStripeReader
{
    hstring DeviceId() const;
    Windows::Devices::PointOfService::MagneticStripeReaderCapabilities Capabilities() const;
    com_array<uint32_t> SupportedCardTypes() const;
    Windows::Devices::PointOfService::MagneticStripeReaderAuthenticationProtocol DeviceAuthenticationProtocol() const;
    Windows::Foundation::IAsyncOperation<hstring> CheckHealthAsync(Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel const& level) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::ClaimedMagneticStripeReader> ClaimReaderAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> RetrieveStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const;
    Windows::Devices::PointOfService::MagneticStripeReaderErrorReportingType GetErrorReportingType() const;
    winrt::event_token StatusUpdated(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::MagneticStripeReader, Windows::Devices::PointOfService::MagneticStripeReaderStatusUpdatedEventArgs> const& handler) const;
    using StatusUpdated_revoker = impl::event_revoker<Windows::Devices::PointOfService::IMagneticStripeReader, &impl::abi_t<Windows::Devices::PointOfService::IMagneticStripeReader>::remove_StatusUpdated>;
    StatusUpdated_revoker StatusUpdated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::MagneticStripeReader, Windows::Devices::PointOfService::MagneticStripeReaderStatusUpdatedEventArgs> const& handler) const;
    void StatusUpdated(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Devices::PointOfService::IMagneticStripeReader> { template <typename D> using type = consume_Windows_Devices_PointOfService_IMagneticStripeReader<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs
{
    Windows::Devices::PointOfService::MagneticStripeReaderReport Report() const;
    hstring LicenseNumber() const;
    hstring ExpirationDate() const;
    hstring Restrictions() const;
    hstring Class() const;
    hstring Endorsements() const;
    hstring BirthDate() const;
    hstring FirstName() const;
    hstring Surname() const;
    hstring Suffix() const;
    hstring Gender() const;
    hstring HairColor() const;
    hstring EyeColor() const;
    hstring Height() const;
    hstring Weight() const;
    hstring Address() const;
    hstring City() const;
    hstring State() const;
    hstring PostalCode() const;
};
template <> struct consume<Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs> { template <typename D> using type = consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IMagneticStripeReaderBankCardDataReceivedEventArgs
{
    Windows::Devices::PointOfService::MagneticStripeReaderReport Report() const;
    hstring AccountNumber() const;
    hstring ExpirationDate() const;
    hstring ServiceCode() const;
    hstring Title() const;
    hstring FirstName() const;
    hstring MiddleInitial() const;
    hstring Surname() const;
    hstring Suffix() const;
};
template <> struct consume<Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs> { template <typename D> using type = consume_Windows_Devices_PointOfService_IMagneticStripeReaderBankCardDataReceivedEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IMagneticStripeReaderCapabilities
{
    hstring CardAuthentication() const;
    uint32_t SupportedEncryptionAlgorithms() const;
    Windows::Devices::PointOfService::MagneticStripeReaderAuthenticationLevel AuthenticationLevel() const;
    bool IsIsoSupported() const;
    bool IsJisOneSupported() const;
    bool IsJisTwoSupported() const;
    Windows::Devices::PointOfService::UnifiedPosPowerReportingType PowerReportingType() const;
    bool IsStatisticsReportingSupported() const;
    bool IsStatisticsUpdatingSupported() const;
    bool IsTrackDataMaskingSupported() const;
    bool IsTransmitSentinelsSupported() const;
};
template <> struct consume<Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities> { template <typename D> using type = consume_Windows_Devices_PointOfService_IMagneticStripeReaderCapabilities<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IMagneticStripeReaderCardTypesStatics
{
    uint32_t Unknown() const;
    uint32_t Bank() const;
    uint32_t Aamva() const;
    uint32_t ExtendedBase() const;
};
template <> struct consume<Windows::Devices::PointOfService::IMagneticStripeReaderCardTypesStatics> { template <typename D> using type = consume_Windows_Devices_PointOfService_IMagneticStripeReaderCardTypesStatics<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IMagneticStripeReaderEncryptionAlgorithmsStatics
{
    uint32_t None() const;
    uint32_t TripleDesDukpt() const;
    uint32_t ExtendedBase() const;
};
template <> struct consume<Windows::Devices::PointOfService::IMagneticStripeReaderEncryptionAlgorithmsStatics> { template <typename D> using type = consume_Windows_Devices_PointOfService_IMagneticStripeReaderEncryptionAlgorithmsStatics<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IMagneticStripeReaderErrorOccurredEventArgs
{
    Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType Track1Status() const;
    Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType Track2Status() const;
    Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType Track3Status() const;
    Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType Track4Status() const;
    Windows::Devices::PointOfService::UnifiedPosErrorData ErrorData() const;
    Windows::Devices::PointOfService::MagneticStripeReaderReport PartialInputData() const;
};
template <> struct consume<Windows::Devices::PointOfService::IMagneticStripeReaderErrorOccurredEventArgs> { template <typename D> using type = consume_Windows_Devices_PointOfService_IMagneticStripeReaderErrorOccurredEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IMagneticStripeReaderReport
{
    uint32_t CardType() const;
    Windows::Devices::PointOfService::MagneticStripeReaderTrackData Track1() const;
    Windows::Devices::PointOfService::MagneticStripeReaderTrackData Track2() const;
    Windows::Devices::PointOfService::MagneticStripeReaderTrackData Track3() const;
    Windows::Devices::PointOfService::MagneticStripeReaderTrackData Track4() const;
    Windows::Foundation::Collections::IMapView<hstring, hstring> Properties() const;
    Windows::Storage::Streams::IBuffer CardAuthenticationData() const;
    uint32_t CardAuthenticationDataLength() const;
    Windows::Storage::Streams::IBuffer AdditionalSecurityInformation() const;
};
template <> struct consume<Windows::Devices::PointOfService::IMagneticStripeReaderReport> { template <typename D> using type = consume_Windows_Devices_PointOfService_IMagneticStripeReaderReport<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IMagneticStripeReaderStatics
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::MagneticStripeReader> GetDefaultAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::MagneticStripeReader> FromIdAsync(param::hstring const& deviceId) const;
    hstring GetDeviceSelector() const;
};
template <> struct consume<Windows::Devices::PointOfService::IMagneticStripeReaderStatics> { template <typename D> using type = consume_Windows_Devices_PointOfService_IMagneticStripeReaderStatics<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IMagneticStripeReaderStatics2
{
    hstring GetDeviceSelector(Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes) const;
};
template <> struct consume<Windows::Devices::PointOfService::IMagneticStripeReaderStatics2> { template <typename D> using type = consume_Windows_Devices_PointOfService_IMagneticStripeReaderStatics2<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IMagneticStripeReaderStatusUpdatedEventArgs
{
    Windows::Devices::PointOfService::MagneticStripeReaderStatus Status() const;
    uint32_t ExtendedStatus() const;
};
template <> struct consume<Windows::Devices::PointOfService::IMagneticStripeReaderStatusUpdatedEventArgs> { template <typename D> using type = consume_Windows_Devices_PointOfService_IMagneticStripeReaderStatusUpdatedEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IMagneticStripeReaderTrackData
{
    Windows::Storage::Streams::IBuffer Data() const;
    Windows::Storage::Streams::IBuffer DiscretionaryData() const;
    Windows::Storage::Streams::IBuffer EncryptedData() const;
};
template <> struct consume<Windows::Devices::PointOfService::IMagneticStripeReaderTrackData> { template <typename D> using type = consume_Windows_Devices_PointOfService_IMagneticStripeReaderTrackData<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IMagneticStripeReaderVendorSpecificCardDataReceivedEventArgs
{
    Windows::Devices::PointOfService::MagneticStripeReaderReport Report() const;
};
template <> struct consume<Windows::Devices::PointOfService::IMagneticStripeReaderVendorSpecificCardDataReceivedEventArgs> { template <typename D> using type = consume_Windows_Devices_PointOfService_IMagneticStripeReaderVendorSpecificCardDataReceivedEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IPosPrinter
{
    hstring DeviceId() const;
    Windows::Devices::PointOfService::PosPrinterCapabilities Capabilities() const;
    Windows::Foundation::Collections::IVectorView<uint32_t> SupportedCharacterSets() const;
    Windows::Foundation::Collections::IVectorView<hstring> SupportedTypeFaces() const;
    Windows::Devices::PointOfService::PosPrinterStatus Status() const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::ClaimedPosPrinter> ClaimPrinterAsync() const;
    Windows::Foundation::IAsyncOperation<hstring> CheckHealthAsync(Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel const& level) const;
    Windows::Foundation::IAsyncOperation<hstring> GetStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const;
    winrt::event_token StatusUpdated(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::PosPrinter, Windows::Devices::PointOfService::PosPrinterStatusUpdatedEventArgs> const& handler) const;
    using StatusUpdated_revoker = impl::event_revoker<Windows::Devices::PointOfService::IPosPrinter, &impl::abi_t<Windows::Devices::PointOfService::IPosPrinter>::remove_StatusUpdated>;
    StatusUpdated_revoker StatusUpdated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::PosPrinter, Windows::Devices::PointOfService::PosPrinterStatusUpdatedEventArgs> const& handler) const;
    void StatusUpdated(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Devices::PointOfService::IPosPrinter> { template <typename D> using type = consume_Windows_Devices_PointOfService_IPosPrinter<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IPosPrinter2
{
    Windows::Foundation::Collections::IVectorView<uint32_t> SupportedBarcodeSymbologies() const;
    Windows::Devices::PointOfService::PosPrinterFontProperty GetFontProperty(param::hstring const& typeface) const;
};
template <> struct consume<Windows::Devices::PointOfService::IPosPrinter2> { template <typename D> using type = consume_Windows_Devices_PointOfService_IPosPrinter2<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IPosPrinterCapabilities
{
    Windows::Devices::PointOfService::UnifiedPosPowerReportingType PowerReportingType() const;
    bool IsStatisticsReportingSupported() const;
    bool IsStatisticsUpdatingSupported() const;
    uint32_t DefaultCharacterSet() const;
    bool HasCoverSensor() const;
    bool CanMapCharacterSet() const;
    bool IsTransactionSupported() const;
    Windows::Devices::PointOfService::ReceiptPrinterCapabilities Receipt() const;
    Windows::Devices::PointOfService::SlipPrinterCapabilities Slip() const;
    Windows::Devices::PointOfService::JournalPrinterCapabilities Journal() const;
};
template <> struct consume<Windows::Devices::PointOfService::IPosPrinterCapabilities> { template <typename D> using type = consume_Windows_Devices_PointOfService_IPosPrinterCapabilities<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IPosPrinterCharacterSetIdsStatics
{
    uint32_t Utf16LE() const;
    uint32_t Ascii() const;
    uint32_t Ansi() const;
};
template <> struct consume<Windows::Devices::PointOfService::IPosPrinterCharacterSetIdsStatics> { template <typename D> using type = consume_Windows_Devices_PointOfService_IPosPrinterCharacterSetIdsStatics<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IPosPrinterFontProperty
{
    hstring TypeFace() const;
    bool IsScalableToAnySize() const;
    Windows::Foundation::Collections::IVectorView<Windows::Devices::PointOfService::SizeUInt32> CharacterSizes() const;
};
template <> struct consume<Windows::Devices::PointOfService::IPosPrinterFontProperty> { template <typename D> using type = consume_Windows_Devices_PointOfService_IPosPrinterFontProperty<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IPosPrinterJob
{
    void Print(param::hstring const& data) const;
    void PrintLine(param::hstring const& data) const;
    void PrintLine() const;
    Windows::Foundation::IAsyncOperation<bool> ExecuteAsync() const;
};
template <> struct consume<Windows::Devices::PointOfService::IPosPrinterJob> { template <typename D> using type = consume_Windows_Devices_PointOfService_IPosPrinterJob<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions
{
    hstring TypeFace() const;
    void TypeFace(param::hstring const& value) const;
    uint32_t CharacterHeight() const;
    void CharacterHeight(uint32_t value) const;
    bool Bold() const;
    void Bold(bool value) const;
    bool Italic() const;
    void Italic(bool value) const;
    bool Underline() const;
    void Underline(bool value) const;
    bool ReverseVideo() const;
    void ReverseVideo(bool value) const;
    bool Strikethrough() const;
    void Strikethrough(bool value) const;
    bool Superscript() const;
    void Superscript(bool value) const;
    bool Subscript() const;
    void Subscript(bool value) const;
    bool DoubleWide() const;
    void DoubleWide(bool value) const;
    bool DoubleHigh() const;
    void DoubleHigh(bool value) const;
    Windows::Devices::PointOfService::PosPrinterAlignment Alignment() const;
    void Alignment(Windows::Devices::PointOfService::PosPrinterAlignment const& value) const;
    uint32_t CharacterSet() const;
    void CharacterSet(uint32_t value) const;
};
template <> struct consume<Windows::Devices::PointOfService::IPosPrinterPrintOptions> { template <typename D> using type = consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IPosPrinterReleaseDeviceRequestedEventArgs
{
};
template <> struct consume<Windows::Devices::PointOfService::IPosPrinterReleaseDeviceRequestedEventArgs> { template <typename D> using type = consume_Windows_Devices_PointOfService_IPosPrinterReleaseDeviceRequestedEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IPosPrinterStatics
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::PosPrinter> GetDefaultAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::PosPrinter> FromIdAsync(param::hstring const& deviceId) const;
    hstring GetDeviceSelector() const;
};
template <> struct consume<Windows::Devices::PointOfService::IPosPrinterStatics> { template <typename D> using type = consume_Windows_Devices_PointOfService_IPosPrinterStatics<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IPosPrinterStatics2
{
    hstring GetDeviceSelector(Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes) const;
};
template <> struct consume<Windows::Devices::PointOfService::IPosPrinterStatics2> { template <typename D> using type = consume_Windows_Devices_PointOfService_IPosPrinterStatics2<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IPosPrinterStatus
{
    Windows::Devices::PointOfService::PosPrinterStatusKind StatusKind() const;
    uint32_t ExtendedStatus() const;
};
template <> struct consume<Windows::Devices::PointOfService::IPosPrinterStatus> { template <typename D> using type = consume_Windows_Devices_PointOfService_IPosPrinterStatus<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IPosPrinterStatusUpdatedEventArgs
{
    Windows::Devices::PointOfService::PosPrinterStatus Status() const;
};
template <> struct consume<Windows::Devices::PointOfService::IPosPrinterStatusUpdatedEventArgs> { template <typename D> using type = consume_Windows_Devices_PointOfService_IPosPrinterStatusUpdatedEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IReceiptOrSlipJob
{
    void SetBarcodeRotation(Windows::Devices::PointOfService::PosPrinterRotation const& value) const;
    void SetPrintRotation(Windows::Devices::PointOfService::PosPrinterRotation const& value, bool includeBitmaps) const;
    void SetPrintArea(Windows::Foundation::Rect const& value) const;
    void SetBitmap(uint32_t bitmapNumber, Windows::Graphics::Imaging::BitmapFrame const& bitmap, Windows::Devices::PointOfService::PosPrinterAlignment const& alignment) const;
    void SetBitmap(uint32_t bitmapNumber, Windows::Graphics::Imaging::BitmapFrame const& bitmap, Windows::Devices::PointOfService::PosPrinterAlignment const& alignment, uint32_t width) const;
    void SetCustomAlignedBitmap(uint32_t bitmapNumber, Windows::Graphics::Imaging::BitmapFrame const& bitmap, uint32_t alignmentDistance) const;
    void SetCustomAlignedBitmap(uint32_t bitmapNumber, Windows::Graphics::Imaging::BitmapFrame const& bitmap, uint32_t alignmentDistance, uint32_t width) const;
    void PrintSavedBitmap(uint32_t bitmapNumber) const;
    void DrawRuledLine(param::hstring const& positionList, Windows::Devices::PointOfService::PosPrinterLineDirection const& lineDirection, uint32_t lineWidth, Windows::Devices::PointOfService::PosPrinterLineStyle const& lineStyle, uint32_t lineColor) const;
    void PrintBarcode(param::hstring const& data, uint32_t symbology, uint32_t height, uint32_t width, Windows::Devices::PointOfService::PosPrinterBarcodeTextPosition const& textPosition, Windows::Devices::PointOfService::PosPrinterAlignment const& alignment) const;
    void PrintBarcodeCustomAlign(param::hstring const& data, uint32_t symbology, uint32_t height, uint32_t width, Windows::Devices::PointOfService::PosPrinterBarcodeTextPosition const& textPosition, uint32_t alignmentDistance) const;
    void PrintBitmap(Windows::Graphics::Imaging::BitmapFrame const& bitmap, Windows::Devices::PointOfService::PosPrinterAlignment const& alignment) const;
    void PrintBitmap(Windows::Graphics::Imaging::BitmapFrame const& bitmap, Windows::Devices::PointOfService::PosPrinterAlignment const& alignment, uint32_t width) const;
    void PrintCustomAlignedBitmap(Windows::Graphics::Imaging::BitmapFrame const& bitmap, uint32_t alignmentDistance) const;
    void PrintCustomAlignedBitmap(Windows::Graphics::Imaging::BitmapFrame const& bitmap, uint32_t alignmentDistance, uint32_t width) const;
};
template <> struct consume<Windows::Devices::PointOfService::IReceiptOrSlipJob> { template <typename D> using type = consume_Windows_Devices_PointOfService_IReceiptOrSlipJob<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IReceiptPrintJob
{
    void MarkFeed(Windows::Devices::PointOfService::PosPrinterMarkFeedKind const& kind) const;
    void CutPaper(double percentage) const;
    void CutPaper() const;
};
template <> struct consume<Windows::Devices::PointOfService::IReceiptPrintJob> { template <typename D> using type = consume_Windows_Devices_PointOfService_IReceiptPrintJob<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IReceiptPrintJob2
{
    void StampPaper() const;
    void Print(param::hstring const& data, Windows::Devices::PointOfService::PosPrinterPrintOptions const& printOptions) const;
    void FeedPaperByLine(int32_t lineCount) const;
    void FeedPaperByMapModeUnit(int32_t distance) const;
};
template <> struct consume<Windows::Devices::PointOfService::IReceiptPrintJob2> { template <typename D> using type = consume_Windows_Devices_PointOfService_IReceiptPrintJob2<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IReceiptPrinterCapabilities
{
    bool CanCutPaper() const;
    bool IsStampSupported() const;
    Windows::Devices::PointOfService::PosPrinterMarkFeedCapabilities MarkFeedCapabilities() const;
};
template <> struct consume<Windows::Devices::PointOfService::IReceiptPrinterCapabilities> { template <typename D> using type = consume_Windows_Devices_PointOfService_IReceiptPrinterCapabilities<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IReceiptPrinterCapabilities2
{
    bool IsReverseVideoSupported() const;
    bool IsStrikethroughSupported() const;
    bool IsSuperscriptSupported() const;
    bool IsSubscriptSupported() const;
    bool IsReversePaperFeedByLineSupported() const;
    bool IsReversePaperFeedByMapModeUnitSupported() const;
};
template <> struct consume<Windows::Devices::PointOfService::IReceiptPrinterCapabilities2> { template <typename D> using type = consume_Windows_Devices_PointOfService_IReceiptPrinterCapabilities2<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_ISlipPrintJob
{
    void Print(param::hstring const& data, Windows::Devices::PointOfService::PosPrinterPrintOptions const& printOptions) const;
    void FeedPaperByLine(int32_t lineCount) const;
    void FeedPaperByMapModeUnit(int32_t distance) const;
};
template <> struct consume<Windows::Devices::PointOfService::ISlipPrintJob> { template <typename D> using type = consume_Windows_Devices_PointOfService_ISlipPrintJob<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_ISlipPrinterCapabilities
{
    bool IsFullLengthSupported() const;
    bool IsBothSidesPrintingSupported() const;
};
template <> struct consume<Windows::Devices::PointOfService::ISlipPrinterCapabilities> { template <typename D> using type = consume_Windows_Devices_PointOfService_ISlipPrinterCapabilities<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_ISlipPrinterCapabilities2
{
    bool IsReverseVideoSupported() const;
    bool IsStrikethroughSupported() const;
    bool IsSuperscriptSupported() const;
    bool IsSubscriptSupported() const;
    bool IsReversePaperFeedByLineSupported() const;
    bool IsReversePaperFeedByMapModeUnitSupported() const;
};
template <> struct consume<Windows::Devices::PointOfService::ISlipPrinterCapabilities2> { template <typename D> using type = consume_Windows_Devices_PointOfService_ISlipPrinterCapabilities2<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IUnifiedPosErrorData
{
    hstring Message() const;
    Windows::Devices::PointOfService::UnifiedPosErrorSeverity Severity() const;
    Windows::Devices::PointOfService::UnifiedPosErrorReason Reason() const;
    uint32_t ExtendedReason() const;
};
template <> struct consume<Windows::Devices::PointOfService::IUnifiedPosErrorData> { template <typename D> using type = consume_Windows_Devices_PointOfService_IUnifiedPosErrorData<D>; };

template <typename D>
struct consume_Windows_Devices_PointOfService_IUnifiedPosErrorDataFactory
{
    Windows::Devices::PointOfService::UnifiedPosErrorData CreateInstance(param::hstring const& message, Windows::Devices::PointOfService::UnifiedPosErrorSeverity const& severity, Windows::Devices::PointOfService::UnifiedPosErrorReason const& reason, uint32_t extendedReason) const;
};
template <> struct consume<Windows::Devices::PointOfService::IUnifiedPosErrorDataFactory> { template <typename D> using type = consume_Windows_Devices_PointOfService_IUnifiedPosErrorDataFactory<D>; };

struct struct_Windows_Devices_PointOfService_SizeUInt32
{
    uint32_t Width;
    uint32_t Height;
};
template <> struct abi<Windows::Devices::PointOfService::SizeUInt32>{ using type = struct_Windows_Devices_PointOfService_SizeUInt32; };


}
