// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Graphics.Imaging.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Devices.PointOfService.2.h"
#include "winrt/Windows.Devices.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_Devices_PointOfService_IBarcodeScanner<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeScanner)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::BarcodeScannerCapabilities consume_Windows_Devices_PointOfService_IBarcodeScanner<D>::Capabilities() const
{
    Windows::Devices::PointOfService::BarcodeScannerCapabilities value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeScanner)->get_Capabilities(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::ClaimedBarcodeScanner> consume_Windows_Devices_PointOfService_IBarcodeScanner<D>::ClaimScannerAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::ClaimedBarcodeScanner> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeScanner)->ClaimScannerAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_Devices_PointOfService_IBarcodeScanner<D>::CheckHealthAsync(Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel const& level) const
{
    Windows::Foundation::IAsyncOperation<hstring> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeScanner)->CheckHealthAsync(get_abi(level), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<uint32_t>> consume_Windows_Devices_PointOfService_IBarcodeScanner<D>::GetSupportedSymbologiesAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<uint32_t>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeScanner)->GetSupportedSymbologiesAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_IBarcodeScanner<D>::IsSymbologySupportedAsync(uint32_t barcodeSymbology) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeScanner)->IsSymbologySupportedAsync(barcodeSymbology, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> consume_Windows_Devices_PointOfService_IBarcodeScanner<D>::RetrieveStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeScanner)->RetrieveStatisticsAsync(get_abi(statisticsCategories), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_Devices_PointOfService_IBarcodeScanner<D>::GetSupportedProfiles() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeScanner)->GetSupportedProfiles(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IBarcodeScanner<D>::IsProfileSupported(param::hstring const& profile) const
{
    bool isSupported{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeScanner)->IsProfileSupported(get_abi(profile), &isSupported));
    return isSupported;
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_IBarcodeScanner<D>::StatusUpdated(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::BarcodeScanner, Windows::Devices::PointOfService::BarcodeScannerStatusUpdatedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeScanner)->add_StatusUpdated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_IBarcodeScanner<D>::StatusUpdated_revoker consume_Windows_Devices_PointOfService_IBarcodeScanner<D>::StatusUpdated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::BarcodeScanner, Windows::Devices::PointOfService::BarcodeScannerStatusUpdatedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, StatusUpdated_revoker>(this, StatusUpdated(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_IBarcodeScanner<D>::StatusUpdated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeScanner)->remove_StatusUpdated(get_abi(token)));
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IBarcodeScanner2<D>::VideoDeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeScanner2)->get_VideoDeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::UnifiedPosPowerReportingType consume_Windows_Devices_PointOfService_IBarcodeScannerCapabilities<D>::PowerReportingType() const
{
    Windows::Devices::PointOfService::UnifiedPosPowerReportingType value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeScannerCapabilities)->get_PowerReportingType(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IBarcodeScannerCapabilities<D>::IsStatisticsReportingSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeScannerCapabilities)->get_IsStatisticsReportingSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IBarcodeScannerCapabilities<D>::IsStatisticsUpdatingSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeScannerCapabilities)->get_IsStatisticsUpdatingSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IBarcodeScannerCapabilities<D>::IsImagePreviewSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeScannerCapabilities)->get_IsImagePreviewSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IBarcodeScannerCapabilities1<D>::IsSoftwareTriggerSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeScannerCapabilities1)->get_IsSoftwareTriggerSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IBarcodeScannerCapabilities2<D>::IsVideoPreviewSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeScannerCapabilities2)->get_IsVideoPreviewSupported(&value));
    return value;
}

template <typename D> Windows::Devices::PointOfService::BarcodeScannerReport consume_Windows_Devices_PointOfService_IBarcodeScannerDataReceivedEventArgs<D>::Report() const
{
    Windows::Devices::PointOfService::BarcodeScannerReport value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeScannerDataReceivedEventArgs)->get_Report(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::BarcodeScannerReport consume_Windows_Devices_PointOfService_IBarcodeScannerErrorOccurredEventArgs<D>::PartialInputData() const
{
    Windows::Devices::PointOfService::BarcodeScannerReport value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeScannerErrorOccurredEventArgs)->get_PartialInputData(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IBarcodeScannerErrorOccurredEventArgs<D>::IsRetriable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeScannerErrorOccurredEventArgs)->get_IsRetriable(&value));
    return value;
}

template <typename D> Windows::Devices::PointOfService::UnifiedPosErrorData consume_Windows_Devices_PointOfService_IBarcodeScannerErrorOccurredEventArgs<D>::ErrorData() const
{
    Windows::Devices::PointOfService::UnifiedPosErrorData value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeScannerErrorOccurredEventArgs)->get_ErrorData(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamWithContentType consume_Windows_Devices_PointOfService_IBarcodeScannerImagePreviewReceivedEventArgs<D>::Preview() const
{
    Windows::Storage::Streams::IRandomAccessStreamWithContentType value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeScannerImagePreviewReceivedEventArgs)->get_Preview(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeScannerReport<D>::ScanDataType() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeScannerReport)->get_ScanDataType(&value));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_PointOfService_IBarcodeScannerReport<D>::ScanData() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeScannerReport)->get_ScanData(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_PointOfService_IBarcodeScannerReport<D>::ScanDataLabel() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeScannerReport)->get_ScanDataLabel(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::BarcodeScannerReport consume_Windows_Devices_PointOfService_IBarcodeScannerReportFactory<D>::CreateInstance(uint32_t scanDataType, Windows::Storage::Streams::IBuffer const& scanData, Windows::Storage::Streams::IBuffer const& scanDataLabel) const
{
    Windows::Devices::PointOfService::BarcodeScannerReport result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeScannerReportFactory)->CreateInstance(scanDataType, get_abi(scanData), get_abi(scanDataLabel), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::BarcodeScanner> consume_Windows_Devices_PointOfService_IBarcodeScannerStatics<D>::GetDefaultAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::BarcodeScanner> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeScannerStatics)->GetDefaultAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::BarcodeScanner> consume_Windows_Devices_PointOfService_IBarcodeScannerStatics<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::BarcodeScanner> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeScannerStatics)->FromIdAsync(get_abi(deviceId), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IBarcodeScannerStatics<D>::GetDeviceSelector() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeScannerStatics)->GetDeviceSelector(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IBarcodeScannerStatics2<D>::GetDeviceSelector(Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes) const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeScannerStatics2)->GetDeviceSelectorWithConnectionTypes(get_abi(connectionTypes), put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::BarcodeScannerStatus consume_Windows_Devices_PointOfService_IBarcodeScannerStatusUpdatedEventArgs<D>::Status() const
{
    Windows::Devices::PointOfService::BarcodeScannerStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeScannerStatusUpdatedEventArgs)->get_Status(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeScannerStatusUpdatedEventArgs<D>::ExtendedStatus() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeScannerStatusUpdatedEventArgs)->get_ExtendedStatus(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Unknown() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Unknown(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Ean8() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Ean8(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Ean8Add2() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Ean8Add2(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Ean8Add5() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Ean8Add5(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Eanv() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Eanv(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::EanvAdd2() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_EanvAdd2(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::EanvAdd5() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_EanvAdd5(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Ean13() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Ean13(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Ean13Add2() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Ean13Add2(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Ean13Add5() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Ean13Add5(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Isbn() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Isbn(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::IsbnAdd5() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_IsbnAdd5(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Ismn() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Ismn(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::IsmnAdd2() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_IsmnAdd2(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::IsmnAdd5() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_IsmnAdd5(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Issn() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Issn(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::IssnAdd2() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_IssnAdd2(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::IssnAdd5() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_IssnAdd5(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Ean99() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Ean99(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Ean99Add2() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Ean99Add2(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Ean99Add5() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Ean99Add5(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Upca() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Upca(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::UpcaAdd2() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_UpcaAdd2(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::UpcaAdd5() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_UpcaAdd5(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Upce() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Upce(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::UpceAdd2() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_UpceAdd2(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::UpceAdd5() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_UpceAdd5(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::UpcCoupon() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_UpcCoupon(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::TfStd() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_TfStd(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::TfDis() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_TfDis(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::TfInt() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_TfInt(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::TfInd() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_TfInd(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::TfMat() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_TfMat(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::TfIata() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_TfIata(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Gs1DatabarType1() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Gs1DatabarType1(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Gs1DatabarType2() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Gs1DatabarType2(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Gs1DatabarType3() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Gs1DatabarType3(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Code39() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Code39(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Code39Ex() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Code39Ex(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Trioptic39() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Trioptic39(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Code32() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Code32(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Pzn() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Pzn(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Code93() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Code93(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Code93Ex() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Code93Ex(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Code128() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Code128(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Gs1128() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Gs1128(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Gs1128Coupon() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Gs1128Coupon(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::UccEan128() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_UccEan128(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Sisac() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Sisac(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Isbt() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Isbt(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Codabar() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Codabar(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Code11() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Code11(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Msi() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Msi(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Plessey() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Plessey(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Telepen() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Telepen(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Code16k() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Code16k(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::CodablockA() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_CodablockA(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::CodablockF() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_CodablockF(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Codablock128() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Codablock128(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Code49() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Code49(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Aztec() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Aztec(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::DataCode() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_DataCode(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::DataMatrix() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_DataMatrix(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::HanXin() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_HanXin(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Maxicode() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Maxicode(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::MicroPdf417() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_MicroPdf417(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::MicroQr() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_MicroQr(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Pdf417() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Pdf417(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Qr() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Qr(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::MsTag() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_MsTag(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Ccab() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Ccab(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Ccc() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Ccc(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Tlc39() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Tlc39(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::AusPost() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_AusPost(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::CanPost() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_CanPost(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::ChinaPost() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_ChinaPost(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::DutchKix() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_DutchKix(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::InfoMail() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_InfoMail(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::ItalianPost25() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_ItalianPost25(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::ItalianPost39() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_ItalianPost39(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::JapanPost() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_JapanPost(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::KoreanPost() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_KoreanPost(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::SwedenPost() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_SwedenPost(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::UkPost() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_UkPost(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::UsIntelligent() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_UsIntelligent(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::UsIntelligentPkg() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_UsIntelligentPkg(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::UsPlanet() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_UsPlanet(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::UsPostNet() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_UsPostNet(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Us4StateFics() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Us4StateFics(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::OcrA() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_OcrA(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::OcrB() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_OcrB(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Micr() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Micr(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::ExtendedBase() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_ExtendedBase(&value));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::GetName(uint32_t scanDataType) const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->GetName(scanDataType, put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics2<D>::Gs1DWCode() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologiesStatics2)->get_Gs1DWCode(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IBarcodeSymbologyAttributes<D>::IsCheckDigitValidationEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologyAttributes)->get_IsCheckDigitValidationEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_IBarcodeSymbologyAttributes<D>::IsCheckDigitValidationEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologyAttributes)->put_IsCheckDigitValidationEnabled(value));
}

template <typename D> bool consume_Windows_Devices_PointOfService_IBarcodeSymbologyAttributes<D>::IsCheckDigitValidationSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologyAttributes)->get_IsCheckDigitValidationSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IBarcodeSymbologyAttributes<D>::IsCheckDigitTransmissionEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologyAttributes)->get_IsCheckDigitTransmissionEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_IBarcodeSymbologyAttributes<D>::IsCheckDigitTransmissionEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologyAttributes)->put_IsCheckDigitTransmissionEnabled(value));
}

template <typename D> bool consume_Windows_Devices_PointOfService_IBarcodeSymbologyAttributes<D>::IsCheckDigitTransmissionSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologyAttributes)->get_IsCheckDigitTransmissionSupported(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologyAttributes<D>::DecodeLength1() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologyAttributes)->get_DecodeLength1(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_IBarcodeSymbologyAttributes<D>::DecodeLength1(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologyAttributes)->put_DecodeLength1(value));
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IBarcodeSymbologyAttributes<D>::DecodeLength2() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologyAttributes)->get_DecodeLength2(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_IBarcodeSymbologyAttributes<D>::DecodeLength2(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologyAttributes)->put_DecodeLength2(value));
}

template <typename D> Windows::Devices::PointOfService::BarcodeSymbologyDecodeLengthKind consume_Windows_Devices_PointOfService_IBarcodeSymbologyAttributes<D>::DecodeLengthKind() const
{
    Windows::Devices::PointOfService::BarcodeSymbologyDecodeLengthKind value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologyAttributes)->get_DecodeLengthKind(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_IBarcodeSymbologyAttributes<D>::DecodeLengthKind(Windows::Devices::PointOfService::BarcodeSymbologyDecodeLengthKind const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologyAttributes)->put_DecodeLengthKind(get_abi(value)));
}

template <typename D> bool consume_Windows_Devices_PointOfService_IBarcodeSymbologyAttributes<D>::IsDecodeLengthSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IBarcodeSymbologyAttributes)->get_IsDecodeLengthSupported(&value));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_ICashDrawer<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawer)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::CashDrawerCapabilities consume_Windows_Devices_PointOfService_ICashDrawer<D>::Capabilities() const
{
    Windows::Devices::PointOfService::CashDrawerCapabilities value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawer)->get_Capabilities(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::CashDrawerStatus consume_Windows_Devices_PointOfService_ICashDrawer<D>::Status() const
{
    Windows::Devices::PointOfService::CashDrawerStatus value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawer)->get_Status(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ICashDrawer<D>::IsDrawerOpen() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawer)->get_IsDrawerOpen(&value));
    return value;
}

template <typename D> Windows::Devices::PointOfService::CashDrawerEventSource consume_Windows_Devices_PointOfService_ICashDrawer<D>::DrawerEventSource() const
{
    Windows::Devices::PointOfService::CashDrawerEventSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawer)->get_DrawerEventSource(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::ClaimedCashDrawer> consume_Windows_Devices_PointOfService_ICashDrawer<D>::ClaimDrawerAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::ClaimedCashDrawer> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawer)->ClaimDrawerAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_Devices_PointOfService_ICashDrawer<D>::CheckHealthAsync(Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel const& level) const
{
    Windows::Foundation::IAsyncOperation<hstring> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawer)->CheckHealthAsync(get_abi(level), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_Devices_PointOfService_ICashDrawer<D>::GetStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const
{
    Windows::Foundation::IAsyncOperation<hstring> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawer)->GetStatisticsAsync(get_abi(statisticsCategories), put_abi(operation)));
    return operation;
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_ICashDrawer<D>::StatusUpdated(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::CashDrawer, Windows::Devices::PointOfService::CashDrawerStatusUpdatedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawer)->add_StatusUpdated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_ICashDrawer<D>::StatusUpdated_revoker consume_Windows_Devices_PointOfService_ICashDrawer<D>::StatusUpdated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::CashDrawer, Windows::Devices::PointOfService::CashDrawerStatusUpdatedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, StatusUpdated_revoker>(this, StatusUpdated(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_ICashDrawer<D>::StatusUpdated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawer)->remove_StatusUpdated(get_abi(token)));
}

template <typename D> Windows::Devices::PointOfService::UnifiedPosPowerReportingType consume_Windows_Devices_PointOfService_ICashDrawerCapabilities<D>::PowerReportingType() const
{
    Windows::Devices::PointOfService::UnifiedPosPowerReportingType value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawerCapabilities)->get_PowerReportingType(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ICashDrawerCapabilities<D>::IsStatisticsReportingSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawerCapabilities)->get_IsStatisticsReportingSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ICashDrawerCapabilities<D>::IsStatisticsUpdatingSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawerCapabilities)->get_IsStatisticsUpdatingSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ICashDrawerCapabilities<D>::IsStatusReportingSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawerCapabilities)->get_IsStatusReportingSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ICashDrawerCapabilities<D>::IsStatusMultiDrawerDetectSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawerCapabilities)->get_IsStatusMultiDrawerDetectSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ICashDrawerCapabilities<D>::IsDrawerOpenSensorAvailable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawerCapabilities)->get_IsDrawerOpenSensorAvailable(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_ICashDrawerCloseAlarm<D>::AlarmTimeout(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawerCloseAlarm)->put_AlarmTimeout(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_PointOfService_ICashDrawerCloseAlarm<D>::AlarmTimeout() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawerCloseAlarm)->get_AlarmTimeout(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_ICashDrawerCloseAlarm<D>::BeepFrequency(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawerCloseAlarm)->put_BeepFrequency(value));
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_ICashDrawerCloseAlarm<D>::BeepFrequency() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawerCloseAlarm)->get_BeepFrequency(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_ICashDrawerCloseAlarm<D>::BeepDuration(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawerCloseAlarm)->put_BeepDuration(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_PointOfService_ICashDrawerCloseAlarm<D>::BeepDuration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawerCloseAlarm)->get_BeepDuration(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_ICashDrawerCloseAlarm<D>::BeepDelay(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawerCloseAlarm)->put_BeepDelay(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_PointOfService_ICashDrawerCloseAlarm<D>::BeepDelay() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawerCloseAlarm)->get_BeepDelay(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_ICashDrawerCloseAlarm<D>::AlarmTimeoutExpired(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::CashDrawerCloseAlarm, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawerCloseAlarm)->add_AlarmTimeoutExpired(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_ICashDrawerCloseAlarm<D>::AlarmTimeoutExpired_revoker consume_Windows_Devices_PointOfService_ICashDrawerCloseAlarm<D>::AlarmTimeoutExpired(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::CashDrawerCloseAlarm, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, AlarmTimeoutExpired_revoker>(this, AlarmTimeoutExpired(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_ICashDrawerCloseAlarm<D>::AlarmTimeoutExpired(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawerCloseAlarm)->remove_AlarmTimeoutExpired(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_ICashDrawerCloseAlarm<D>::StartAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawerCloseAlarm)->StartAsync(put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_ICashDrawerEventSource<D>::DrawerClosed(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::CashDrawerEventSource, Windows::Devices::PointOfService::CashDrawerClosedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawerEventSource)->add_DrawerClosed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_ICashDrawerEventSource<D>::DrawerClosed_revoker consume_Windows_Devices_PointOfService_ICashDrawerEventSource<D>::DrawerClosed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::CashDrawerEventSource, Windows::Devices::PointOfService::CashDrawerClosedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, DrawerClosed_revoker>(this, DrawerClosed(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_ICashDrawerEventSource<D>::DrawerClosed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawerEventSource)->remove_DrawerClosed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_ICashDrawerEventSource<D>::DrawerOpened(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::CashDrawerEventSource, Windows::Devices::PointOfService::CashDrawerOpenedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawerEventSource)->add_DrawerOpened(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_ICashDrawerEventSource<D>::DrawerOpened_revoker consume_Windows_Devices_PointOfService_ICashDrawerEventSource<D>::DrawerOpened(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::CashDrawerEventSource, Windows::Devices::PointOfService::CashDrawerOpenedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, DrawerOpened_revoker>(this, DrawerOpened(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_ICashDrawerEventSource<D>::DrawerOpened(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawerEventSource)->remove_DrawerOpened(get_abi(token)));
}

template <typename D> Windows::Devices::PointOfService::CashDrawer consume_Windows_Devices_PointOfService_ICashDrawerEventSourceEventArgs<D>::CashDrawer() const
{
    Windows::Devices::PointOfService::CashDrawer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawerEventSourceEventArgs)->get_CashDrawer(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::CashDrawer> consume_Windows_Devices_PointOfService_ICashDrawerStatics<D>::GetDefaultAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::CashDrawer> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawerStatics)->GetDefaultAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::CashDrawer> consume_Windows_Devices_PointOfService_ICashDrawerStatics<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::CashDrawer> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawerStatics)->FromIdAsync(get_abi(deviceId), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_ICashDrawerStatics<D>::GetDeviceSelector() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawerStatics)->GetDeviceSelector(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_ICashDrawerStatics2<D>::GetDeviceSelector(Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes) const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawerStatics2)->GetDeviceSelectorWithConnectionTypes(get_abi(connectionTypes), put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::CashDrawerStatusKind consume_Windows_Devices_PointOfService_ICashDrawerStatus<D>::StatusKind() const
{
    Windows::Devices::PointOfService::CashDrawerStatusKind value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawerStatus)->get_StatusKind(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_ICashDrawerStatus<D>::ExtendedStatus() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawerStatus)->get_ExtendedStatus(&value));
    return value;
}

template <typename D> Windows::Devices::PointOfService::CashDrawerStatus consume_Windows_Devices_PointOfService_ICashDrawerStatusUpdatedEventArgs<D>::Status() const
{
    Windows::Devices::PointOfService::CashDrawerStatus value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICashDrawerStatusUpdatedEventArgs)->get_Status(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedBarcodeScanner)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::IsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedBarcodeScanner)->get_IsEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::IsDisabledOnDataReceived(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedBarcodeScanner)->put_IsDisabledOnDataReceived(value));
}

template <typename D> bool consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::IsDisabledOnDataReceived() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedBarcodeScanner)->get_IsDisabledOnDataReceived(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::IsDecodeDataEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedBarcodeScanner)->put_IsDecodeDataEnabled(value));
}

template <typename D> bool consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::IsDecodeDataEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedBarcodeScanner)->get_IsDecodeDataEnabled(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::EnableAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedBarcodeScanner)->EnableAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::DisableAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedBarcodeScanner)->DisableAsync(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::RetainDevice() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedBarcodeScanner)->RetainDevice());
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::SetActiveSymbologiesAsync(param::async_iterable<uint32_t> const& symbologies) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedBarcodeScanner)->SetActiveSymbologiesAsync(get_abi(symbologies), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::ResetStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedBarcodeScanner)->ResetStatisticsAsync(get_abi(statisticsCategories), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::UpdateStatisticsAsync(param::async_iterable<Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const& statistics) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedBarcodeScanner)->UpdateStatisticsAsync(get_abi(statistics), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::SetActiveProfileAsync(param::hstring const& profile) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedBarcodeScanner)->SetActiveProfileAsync(get_abi(profile), put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::DataReceived(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner, Windows::Devices::PointOfService::BarcodeScannerDataReceivedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedBarcodeScanner)->add_DataReceived(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::DataReceived_revoker consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::DataReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner, Windows::Devices::PointOfService::BarcodeScannerDataReceivedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, DataReceived_revoker>(this, DataReceived(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::DataReceived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::IClaimedBarcodeScanner)->remove_DataReceived(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::TriggerPressed(Windows::Foundation::EventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedBarcodeScanner)->add_TriggerPressed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::TriggerPressed_revoker consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::TriggerPressed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner> const& handler) const
{
    return impl::make_event_revoker<D, TriggerPressed_revoker>(this, TriggerPressed(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::TriggerPressed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::IClaimedBarcodeScanner)->remove_TriggerPressed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::TriggerReleased(Windows::Foundation::EventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedBarcodeScanner)->add_TriggerReleased(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::TriggerReleased_revoker consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::TriggerReleased(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner> const& handler) const
{
    return impl::make_event_revoker<D, TriggerReleased_revoker>(this, TriggerReleased(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::TriggerReleased(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::IClaimedBarcodeScanner)->remove_TriggerReleased(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::ReleaseDeviceRequested(Windows::Foundation::EventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedBarcodeScanner)->add_ReleaseDeviceRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::ReleaseDeviceRequested_revoker consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::ReleaseDeviceRequested(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner> const& handler) const
{
    return impl::make_event_revoker<D, ReleaseDeviceRequested_revoker>(this, ReleaseDeviceRequested(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::ReleaseDeviceRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::IClaimedBarcodeScanner)->remove_ReleaseDeviceRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::ImagePreviewReceived(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner, Windows::Devices::PointOfService::BarcodeScannerImagePreviewReceivedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedBarcodeScanner)->add_ImagePreviewReceived(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::ImagePreviewReceived_revoker consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::ImagePreviewReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner, Windows::Devices::PointOfService::BarcodeScannerImagePreviewReceivedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ImagePreviewReceived_revoker>(this, ImagePreviewReceived(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::ImagePreviewReceived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::IClaimedBarcodeScanner)->remove_ImagePreviewReceived(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::ErrorOccurred(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner, Windows::Devices::PointOfService::BarcodeScannerErrorOccurredEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedBarcodeScanner)->add_ErrorOccurred(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::ErrorOccurred_revoker consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::ErrorOccurred(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner, Windows::Devices::PointOfService::BarcodeScannerErrorOccurredEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ErrorOccurred_revoker>(this, ErrorOccurred(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::ErrorOccurred(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::IClaimedBarcodeScanner)->remove_ErrorOccurred(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner1<D>::StartSoftwareTriggerAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedBarcodeScanner1)->StartSoftwareTriggerAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner1<D>::StopSoftwareTriggerAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedBarcodeScanner1)->StopSoftwareTriggerAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::BarcodeSymbologyAttributes> consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner2<D>::GetSymbologyAttributesAsync(uint32_t barcodeSymbology) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::BarcodeSymbologyAttributes> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedBarcodeScanner2)->GetSymbologyAttributesAsync(barcodeSymbology, put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner2<D>::SetSymbologyAttributesAsync(uint32_t barcodeSymbology, Windows::Devices::PointOfService::BarcodeSymbologyAttributes const& attributes) const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedBarcodeScanner2)->SetSymbologyAttributesAsync(barcodeSymbology, get_abi(attributes), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner3<D>::ShowVideoPreviewAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedBarcodeScanner3)->ShowVideoPreviewAsync(put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner3<D>::HideVideoPreview() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedBarcodeScanner3)->HideVideoPreview());
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner3<D>::IsVideoPreviewShownOnEnable(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedBarcodeScanner3)->put_IsVideoPreviewShownOnEnable(value));
}

template <typename D> bool consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner3<D>::IsVideoPreviewShownOnEnable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedBarcodeScanner3)->get_IsVideoPreviewShownOnEnable(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner4<D>::Closed(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner, Windows::Devices::PointOfService::ClaimedBarcodeScannerClosedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedBarcodeScanner4)->add_Closed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner4<D>::Closed_revoker consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner4<D>::Closed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner, Windows::Devices::PointOfService::ClaimedBarcodeScannerClosedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Closed_revoker>(this, Closed(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner4<D>::Closed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::IClaimedBarcodeScanner4)->remove_Closed(get_abi(token)));
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IClaimedCashDrawer<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedCashDrawer)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IClaimedCashDrawer<D>::IsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedCashDrawer)->get_IsEnabled(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IClaimedCashDrawer<D>::IsDrawerOpen() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedCashDrawer)->get_IsDrawerOpen(&value));
    return value;
}

template <typename D> Windows::Devices::PointOfService::CashDrawerCloseAlarm consume_Windows_Devices_PointOfService_IClaimedCashDrawer<D>::CloseAlarm() const
{
    Windows::Devices::PointOfService::CashDrawerCloseAlarm value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedCashDrawer)->get_CloseAlarm(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_IClaimedCashDrawer<D>::OpenDrawerAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedCashDrawer)->OpenDrawerAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_IClaimedCashDrawer<D>::EnableAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedCashDrawer)->EnableAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_IClaimedCashDrawer<D>::DisableAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedCashDrawer)->DisableAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_IClaimedCashDrawer<D>::RetainDeviceAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedCashDrawer)->RetainDeviceAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_IClaimedCashDrawer<D>::ResetStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedCashDrawer)->ResetStatisticsAsync(get_abi(statisticsCategories), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_IClaimedCashDrawer<D>::UpdateStatisticsAsync(param::async_iterable<Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const& statistics) const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedCashDrawer)->UpdateStatisticsAsync(get_abi(statistics), put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_IClaimedCashDrawer<D>::ReleaseDeviceRequested(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedCashDrawer, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedCashDrawer)->add_ReleaseDeviceRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedCashDrawer<D>::ReleaseDeviceRequested_revoker consume_Windows_Devices_PointOfService_IClaimedCashDrawer<D>::ReleaseDeviceRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedCashDrawer, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, ReleaseDeviceRequested_revoker>(this, ReleaseDeviceRequested(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedCashDrawer<D>::ReleaseDeviceRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::IClaimedCashDrawer)->remove_ReleaseDeviceRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_IClaimedCashDrawer2<D>::Closed(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedCashDrawer, Windows::Devices::PointOfService::ClaimedCashDrawerClosedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedCashDrawer2)->add_Closed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedCashDrawer2<D>::Closed_revoker consume_Windows_Devices_PointOfService_IClaimedCashDrawer2<D>::Closed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedCashDrawer, Windows::Devices::PointOfService::ClaimedCashDrawerClosedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Closed_revoker>(this, Closed(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedCashDrawer2<D>::Closed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::IClaimedCashDrawer2)->remove_Closed(get_abi(token)));
}

template <typename D> Windows::Devices::PointOfService::JournalPrintJob consume_Windows_Devices_PointOfService_IClaimedJournalPrinter<D>::CreateJob() const
{
    Windows::Devices::PointOfService::JournalPrintJob value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedJournalPrinter)->CreateJob(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IClaimedLineDisplay<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedLineDisplay)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::LineDisplayCapabilities consume_Windows_Devices_PointOfService_IClaimedLineDisplay<D>::Capabilities() const
{
    Windows::Devices::PointOfService::LineDisplayCapabilities value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedLineDisplay)->get_Capabilities(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IClaimedLineDisplay<D>::PhysicalDeviceName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedLineDisplay)->get_PhysicalDeviceName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IClaimedLineDisplay<D>::PhysicalDeviceDescription() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedLineDisplay)->get_PhysicalDeviceDescription(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IClaimedLineDisplay<D>::DeviceControlDescription() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedLineDisplay)->get_DeviceControlDescription(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IClaimedLineDisplay<D>::DeviceControlVersion() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedLineDisplay)->get_DeviceControlVersion(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IClaimedLineDisplay<D>::DeviceServiceVersion() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedLineDisplay)->get_DeviceServiceVersion(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::LineDisplayWindow consume_Windows_Devices_PointOfService_IClaimedLineDisplay<D>::DefaultWindow() const
{
    Windows::Devices::PointOfService::LineDisplayWindow value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedLineDisplay)->get_DefaultWindow(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedLineDisplay<D>::RetainDevice() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedLineDisplay)->RetainDevice());
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_IClaimedLineDisplay<D>::ReleaseDeviceRequested(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedLineDisplay, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedLineDisplay)->add_ReleaseDeviceRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedLineDisplay<D>::ReleaseDeviceRequested_revoker consume_Windows_Devices_PointOfService_IClaimedLineDisplay<D>::ReleaseDeviceRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedLineDisplay, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, ReleaseDeviceRequested_revoker>(this, ReleaseDeviceRequested(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedLineDisplay<D>::ReleaseDeviceRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::IClaimedLineDisplay)->remove_ReleaseDeviceRequested(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::GetStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const
{
    Windows::Foundation::IAsyncOperation<hstring> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedLineDisplay2)->GetStatisticsAsync(get_abi(statisticsCategories), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::CheckHealthAsync(Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel const& level) const
{
    Windows::Foundation::IAsyncOperation<hstring> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedLineDisplay2)->CheckHealthAsync(get_abi(level), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplayPowerStatus> consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::CheckPowerStatusAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplayPowerStatus> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedLineDisplay2)->CheckPowerStatusAsync(put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::StatusUpdated(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedLineDisplay, Windows::Devices::PointOfService::LineDisplayStatusUpdatedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedLineDisplay2)->add_StatusUpdated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::StatusUpdated_revoker consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::StatusUpdated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedLineDisplay, Windows::Devices::PointOfService::LineDisplayStatusUpdatedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, StatusUpdated_revoker>(this, StatusUpdated(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::StatusUpdated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::IClaimedLineDisplay2)->remove_StatusUpdated(get_abi(token)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Foundation::Size> consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::SupportedScreenSizesInCharacters() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Foundation::Size> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedLineDisplay2)->get_SupportedScreenSizesInCharacters(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Size consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::MaxBitmapSizeInPixels() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedLineDisplay2)->get_MaxBitmapSizeInPixels(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<int32_t> consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::SupportedCharacterSets() const
{
    Windows::Foundation::Collections::IVectorView<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedLineDisplay2)->get_SupportedCharacterSets(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::LineDisplayCustomGlyphs consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::CustomGlyphs() const
{
    Windows::Devices::PointOfService::LineDisplayCustomGlyphs value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedLineDisplay2)->get_CustomGlyphs(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::LineDisplayAttributes consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::GetAttributes() const
{
    Windows::Devices::PointOfService::LineDisplayAttributes value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedLineDisplay2)->GetAttributes(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::TryUpdateAttributesAsync(Windows::Devices::PointOfService::LineDisplayAttributes const& attributes) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedLineDisplay2)->TryUpdateAttributesAsync(get_abi(attributes), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::TrySetDescriptorAsync(uint32_t descriptor, Windows::Devices::PointOfService::LineDisplayDescriptorState const& descriptorState) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedLineDisplay2)->TrySetDescriptorAsync(descriptor, get_abi(descriptorState), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::TryClearDescriptorsAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedLineDisplay2)->TryClearDescriptorsAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplayWindow> consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::TryCreateWindowAsync(Windows::Foundation::Rect const& viewport, Windows::Foundation::Size const& windowSize) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplayWindow> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedLineDisplay2)->TryCreateWindowAsync(get_abi(viewport), get_abi(windowSize), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplayStoredBitmap> consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::TryStoreStorageFileBitmapAsync(Windows::Storage::StorageFile const& bitmap) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplayStoredBitmap> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedLineDisplay2)->TryStoreStorageFileBitmapAsync(get_abi(bitmap), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplayStoredBitmap> consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::TryStoreStorageFileBitmapAsync(Windows::Storage::StorageFile const& bitmap, Windows::Devices::PointOfService::LineDisplayHorizontalAlignment const& horizontalAlignment, Windows::Devices::PointOfService::LineDisplayVerticalAlignment const& verticalAlignment) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplayStoredBitmap> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedLineDisplay2)->TryStoreStorageFileBitmapWithAlignmentAsync(get_abi(bitmap), get_abi(horizontalAlignment), get_abi(verticalAlignment), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplayStoredBitmap> consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::TryStoreStorageFileBitmapAsync(Windows::Storage::StorageFile const& bitmap, Windows::Devices::PointOfService::LineDisplayHorizontalAlignment const& horizontalAlignment, Windows::Devices::PointOfService::LineDisplayVerticalAlignment const& verticalAlignment, int32_t widthInPixels) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplayStoredBitmap> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedLineDisplay2)->TryStoreStorageFileBitmapWithAlignmentAndWidthAsync(get_abi(bitmap), get_abi(horizontalAlignment), get_abi(verticalAlignment), widthInPixels, put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_IClaimedLineDisplay3<D>::Closed(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedLineDisplay, Windows::Devices::PointOfService::ClaimedLineDisplayClosedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedLineDisplay3)->add_Closed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedLineDisplay3<D>::Closed_revoker consume_Windows_Devices_PointOfService_IClaimedLineDisplay3<D>::Closed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedLineDisplay, Windows::Devices::PointOfService::ClaimedLineDisplayClosedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Closed_revoker>(this, Closed(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedLineDisplay3<D>::Closed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::IClaimedLineDisplay3)->remove_Closed(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::ClaimedLineDisplay> consume_Windows_Devices_PointOfService_IClaimedLineDisplayStatics<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::ClaimedLineDisplay> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedLineDisplayStatics)->FromIdAsync(get_abi(deviceId), put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IClaimedLineDisplayStatics<D>::GetDeviceSelector() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedLineDisplayStatics)->GetDeviceSelector(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IClaimedLineDisplayStatics<D>::GetDeviceSelector(Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes) const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedLineDisplayStatics)->GetDeviceSelectorWithConnectionTypes(get_abi(connectionTypes), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::IsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->get_IsEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::IsDisabledOnDataReceived(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->put_IsDisabledOnDataReceived(value));
}

template <typename D> bool consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::IsDisabledOnDataReceived() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->get_IsDisabledOnDataReceived(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::IsDecodeDataEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->put_IsDecodeDataEnabled(value));
}

template <typename D> bool consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::IsDecodeDataEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->get_IsDecodeDataEnabled(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::IsDeviceAuthenticated() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->get_IsDeviceAuthenticated(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::DataEncryptionAlgorithm(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->put_DataEncryptionAlgorithm(value));
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::DataEncryptionAlgorithm() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->get_DataEncryptionAlgorithm(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::TracksToRead(Windows::Devices::PointOfService::MagneticStripeReaderTrackIds const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->put_TracksToRead(get_abi(value)));
}

template <typename D> Windows::Devices::PointOfService::MagneticStripeReaderTrackIds consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::TracksToRead() const
{
    Windows::Devices::PointOfService::MagneticStripeReaderTrackIds value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->get_TracksToRead(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::IsTransmitSentinelsEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->put_IsTransmitSentinelsEnabled(value));
}

template <typename D> bool consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::IsTransmitSentinelsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->get_IsTransmitSentinelsEnabled(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::EnableAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->EnableAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::DisableAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->DisableAsync(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::RetainDevice() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->RetainDevice());
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::SetErrorReportingType(Windows::Devices::PointOfService::MagneticStripeReaderErrorReportingType const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->SetErrorReportingType(get_abi(value)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::RetrieveDeviceAuthenticationDataAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->RetrieveDeviceAuthenticationDataAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::AuthenticateDeviceAsync(array_view<uint8_t const> responseToken) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->AuthenticateDeviceAsync(responseToken.size(), get_abi(responseToken), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::DeAuthenticateDeviceAsync(array_view<uint8_t const> responseToken) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->DeAuthenticateDeviceAsync(responseToken.size(), get_abi(responseToken), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::UpdateKeyAsync(param::hstring const& key, param::hstring const& keyName) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->UpdateKeyAsync(get_abi(key), get_abi(keyName), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::ResetStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->ResetStatisticsAsync(get_abi(statisticsCategories), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::UpdateStatisticsAsync(param::async_iterable<Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const& statistics) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->UpdateStatisticsAsync(get_abi(statistics), put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::BankCardDataReceived(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader, Windows::Devices::PointOfService::MagneticStripeReaderBankCardDataReceivedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->add_BankCardDataReceived(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::BankCardDataReceived_revoker consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::BankCardDataReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader, Windows::Devices::PointOfService::MagneticStripeReaderBankCardDataReceivedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, BankCardDataReceived_revoker>(this, BankCardDataReceived(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::BankCardDataReceived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->remove_BankCardDataReceived(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::AamvaCardDataReceived(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader, Windows::Devices::PointOfService::MagneticStripeReaderAamvaCardDataReceivedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->add_AamvaCardDataReceived(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::AamvaCardDataReceived_revoker consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::AamvaCardDataReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader, Windows::Devices::PointOfService::MagneticStripeReaderAamvaCardDataReceivedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, AamvaCardDataReceived_revoker>(this, AamvaCardDataReceived(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::AamvaCardDataReceived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->remove_AamvaCardDataReceived(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::VendorSpecificDataReceived(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader, Windows::Devices::PointOfService::MagneticStripeReaderVendorSpecificCardDataReceivedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->add_VendorSpecificDataReceived(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::VendorSpecificDataReceived_revoker consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::VendorSpecificDataReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader, Windows::Devices::PointOfService::MagneticStripeReaderVendorSpecificCardDataReceivedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, VendorSpecificDataReceived_revoker>(this, VendorSpecificDataReceived(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::VendorSpecificDataReceived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->remove_VendorSpecificDataReceived(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::ReleaseDeviceRequested(Windows::Foundation::EventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->add_ReleaseDeviceRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::ReleaseDeviceRequested_revoker consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::ReleaseDeviceRequested(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader> const& handler) const
{
    return impl::make_event_revoker<D, ReleaseDeviceRequested_revoker>(this, ReleaseDeviceRequested(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::ReleaseDeviceRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->remove_ReleaseDeviceRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::ErrorOccurred(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader, Windows::Devices::PointOfService::MagneticStripeReaderErrorOccurredEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->add_ErrorOccurred(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::ErrorOccurred_revoker consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::ErrorOccurred(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader, Windows::Devices::PointOfService::MagneticStripeReaderErrorOccurredEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ErrorOccurred_revoker>(this, ErrorOccurred(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::ErrorOccurred(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->remove_ErrorOccurred(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader2<D>::Closed(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader, Windows::Devices::PointOfService::ClaimedMagneticStripeReaderClosedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedMagneticStripeReader2)->add_Closed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader2<D>::Closed_revoker consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader2<D>::Closed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader, Windows::Devices::PointOfService::ClaimedMagneticStripeReaderClosedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Closed_revoker>(this, Closed(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader2<D>::Closed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::IClaimedMagneticStripeReader2)->remove_Closed(get_abi(token)));
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedPosPrinter)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::IsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedPosPrinter)->get_IsEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::CharacterSet(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedPosPrinter)->put_CharacterSet(value));
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::CharacterSet() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedPosPrinter)->get_CharacterSet(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::IsCoverOpen() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedPosPrinter)->get_IsCoverOpen(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::IsCharacterSetMappingEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedPosPrinter)->put_IsCharacterSetMappingEnabled(value));
}

template <typename D> bool consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::IsCharacterSetMappingEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedPosPrinter)->get_IsCharacterSetMappingEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::MapMode(Windows::Devices::PointOfService::PosPrinterMapMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedPosPrinter)->put_MapMode(get_abi(value)));
}

template <typename D> Windows::Devices::PointOfService::PosPrinterMapMode consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::MapMode() const
{
    Windows::Devices::PointOfService::PosPrinterMapMode value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedPosPrinter)->get_MapMode(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::ClaimedReceiptPrinter consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::Receipt() const
{
    Windows::Devices::PointOfService::ClaimedReceiptPrinter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedPosPrinter)->get_Receipt(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::ClaimedSlipPrinter consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::Slip() const
{
    Windows::Devices::PointOfService::ClaimedSlipPrinter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedPosPrinter)->get_Slip(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::ClaimedJournalPrinter consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::Journal() const
{
    Windows::Devices::PointOfService::ClaimedJournalPrinter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedPosPrinter)->get_Journal(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::EnableAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedPosPrinter)->EnableAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::DisableAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedPosPrinter)->DisableAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::RetainDeviceAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedPosPrinter)->RetainDeviceAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::ResetStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedPosPrinter)->ResetStatisticsAsync(get_abi(statisticsCategories), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::UpdateStatisticsAsync(param::async_iterable<Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const& statistics) const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedPosPrinter)->UpdateStatisticsAsync(get_abi(statistics), put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::ReleaseDeviceRequested(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedPosPrinter, Windows::Devices::PointOfService::PosPrinterReleaseDeviceRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedPosPrinter)->add_ReleaseDeviceRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::ReleaseDeviceRequested_revoker consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::ReleaseDeviceRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedPosPrinter, Windows::Devices::PointOfService::PosPrinterReleaseDeviceRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ReleaseDeviceRequested_revoker>(this, ReleaseDeviceRequested(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::ReleaseDeviceRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::IClaimedPosPrinter)->remove_ReleaseDeviceRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_IClaimedPosPrinter2<D>::Closed(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedPosPrinter, Windows::Devices::PointOfService::ClaimedPosPrinterClosedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedPosPrinter2)->add_Closed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedPosPrinter2<D>::Closed_revoker consume_Windows_Devices_PointOfService_IClaimedPosPrinter2<D>::Closed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedPosPrinter, Windows::Devices::PointOfService::ClaimedPosPrinterClosedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Closed_revoker>(this, Closed(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedPosPrinter2<D>::Closed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::IClaimedPosPrinter2)->remove_Closed(get_abi(token)));
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IClaimedReceiptPrinter<D>::SidewaysMaxLines() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedReceiptPrinter)->get_SidewaysMaxLines(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IClaimedReceiptPrinter<D>::SidewaysMaxChars() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedReceiptPrinter)->get_SidewaysMaxChars(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IClaimedReceiptPrinter<D>::LinesToPaperCut() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedReceiptPrinter)->get_LinesToPaperCut(&value));
    return value;
}

template <typename D> Windows::Foundation::Size consume_Windows_Devices_PointOfService_IClaimedReceiptPrinter<D>::PageSize() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedReceiptPrinter)->get_PageSize(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Rect consume_Windows_Devices_PointOfService_IClaimedReceiptPrinter<D>::PrintArea() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedReceiptPrinter)->get_PrintArea(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::ReceiptPrintJob consume_Windows_Devices_PointOfService_IClaimedReceiptPrinter<D>::CreateJob() const
{
    Windows::Devices::PointOfService::ReceiptPrintJob value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedReceiptPrinter)->CreateJob(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IClaimedSlipPrinter<D>::SidewaysMaxLines() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedSlipPrinter)->get_SidewaysMaxLines(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IClaimedSlipPrinter<D>::SidewaysMaxChars() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedSlipPrinter)->get_SidewaysMaxChars(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IClaimedSlipPrinter<D>::MaxLines() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedSlipPrinter)->get_MaxLines(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IClaimedSlipPrinter<D>::LinesNearEndToEnd() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedSlipPrinter)->get_LinesNearEndToEnd(&value));
    return value;
}

template <typename D> Windows::Devices::PointOfService::PosPrinterPrintSide consume_Windows_Devices_PointOfService_IClaimedSlipPrinter<D>::PrintSide() const
{
    Windows::Devices::PointOfService::PosPrinterPrintSide value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedSlipPrinter)->get_PrintSide(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Size consume_Windows_Devices_PointOfService_IClaimedSlipPrinter<D>::PageSize() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedSlipPrinter)->get_PageSize(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Rect consume_Windows_Devices_PointOfService_IClaimedSlipPrinter<D>::PrintArea() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedSlipPrinter)->get_PrintArea(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedSlipPrinter<D>::OpenJaws() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedSlipPrinter)->OpenJaws());
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedSlipPrinter<D>::CloseJaws() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedSlipPrinter)->CloseJaws());
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_IClaimedSlipPrinter<D>::InsertSlipAsync(Windows::Foundation::TimeSpan const& timeout) const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedSlipPrinter)->InsertSlipAsync(get_abi(timeout), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_IClaimedSlipPrinter<D>::RemoveSlipAsync(Windows::Foundation::TimeSpan const& timeout) const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedSlipPrinter)->RemoveSlipAsync(get_abi(timeout), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Devices_PointOfService_IClaimedSlipPrinter<D>::ChangePrintSide(Windows::Devices::PointOfService::PosPrinterPrintSide const& printSide) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedSlipPrinter)->ChangePrintSide(get_abi(printSide)));
}

template <typename D> Windows::Devices::PointOfService::SlipPrintJob consume_Windows_Devices_PointOfService_IClaimedSlipPrinter<D>::CreateJob() const
{
    Windows::Devices::PointOfService::SlipPrintJob value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IClaimedSlipPrinter)->CreateJob(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::CharactersPerLine(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->put_CharactersPerLine(value));
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::CharactersPerLine() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->get_CharactersPerLine(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::LineHeight(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->put_LineHeight(value));
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::LineHeight() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->get_LineHeight(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::LineSpacing(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->put_LineSpacing(value));
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::LineSpacing() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->get_LineSpacing(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::LineWidth() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->get_LineWidth(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::IsLetterQuality(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->put_IsLetterQuality(value));
}

template <typename D> bool consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::IsLetterQuality() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->get_IsLetterQuality(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::IsPaperNearEnd() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->get_IsPaperNearEnd(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::ColorCartridge(Windows::Devices::PointOfService::PosPrinterColorCartridge const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->put_ColorCartridge(get_abi(value)));
}

template <typename D> Windows::Devices::PointOfService::PosPrinterColorCartridge consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::ColorCartridge() const
{
    Windows::Devices::PointOfService::PosPrinterColorCartridge value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->get_ColorCartridge(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::IsCoverOpen() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->get_IsCoverOpen(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::IsCartridgeRemoved() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->get_IsCartridgeRemoved(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::IsCartridgeEmpty() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->get_IsCartridgeEmpty(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::IsHeadCleaning() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->get_IsHeadCleaning(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::IsPaperEmpty() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->get_IsPaperEmpty(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::IsReadyToPrint() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->get_IsReadyToPrint(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::ValidateData(param::hstring const& data) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->ValidateData(get_abi(data), &result));
    return result;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ICommonPosPrintStationCapabilities<D>::IsPrinterPresent() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities)->get_IsPrinterPresent(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ICommonPosPrintStationCapabilities<D>::IsDualColorSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities)->get_IsDualColorSupported(&value));
    return value;
}

template <typename D> Windows::Devices::PointOfService::PosPrinterColorCapabilities consume_Windows_Devices_PointOfService_ICommonPosPrintStationCapabilities<D>::ColorCartridgeCapabilities() const
{
    Windows::Devices::PointOfService::PosPrinterColorCapabilities value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities)->get_ColorCartridgeCapabilities(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::PosPrinterCartridgeSensors consume_Windows_Devices_PointOfService_ICommonPosPrintStationCapabilities<D>::CartridgeSensors() const
{
    Windows::Devices::PointOfService::PosPrinterCartridgeSensors value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities)->get_CartridgeSensors(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ICommonPosPrintStationCapabilities<D>::IsBoldSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities)->get_IsBoldSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ICommonPosPrintStationCapabilities<D>::IsItalicSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities)->get_IsItalicSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ICommonPosPrintStationCapabilities<D>::IsUnderlineSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities)->get_IsUnderlineSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ICommonPosPrintStationCapabilities<D>::IsDoubleHighPrintSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities)->get_IsDoubleHighPrintSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ICommonPosPrintStationCapabilities<D>::IsDoubleWidePrintSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities)->get_IsDoubleWidePrintSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ICommonPosPrintStationCapabilities<D>::IsDoubleHighDoubleWidePrintSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities)->get_IsDoubleHighDoubleWidePrintSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ICommonPosPrintStationCapabilities<D>::IsPaperEmptySensorSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities)->get_IsPaperEmptySensorSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ICommonPosPrintStationCapabilities<D>::IsPaperNearEndSensorSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities)->get_IsPaperNearEndSensorSupported(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<uint32_t> consume_Windows_Devices_PointOfService_ICommonPosPrintStationCapabilities<D>::SupportedCharactersPerLine() const
{
    Windows::Foundation::Collections::IVectorView<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities)->get_SupportedCharactersPerLine(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ICommonReceiptSlipCapabilities<D>::IsBarcodeSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonReceiptSlipCapabilities)->get_IsBarcodeSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ICommonReceiptSlipCapabilities<D>::IsBitmapSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonReceiptSlipCapabilities)->get_IsBitmapSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ICommonReceiptSlipCapabilities<D>::IsLeft90RotationSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonReceiptSlipCapabilities)->get_IsLeft90RotationSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ICommonReceiptSlipCapabilities<D>::IsRight90RotationSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonReceiptSlipCapabilities)->get_IsRight90RotationSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ICommonReceiptSlipCapabilities<D>::Is180RotationSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonReceiptSlipCapabilities)->get_Is180RotationSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ICommonReceiptSlipCapabilities<D>::IsPrintAreaSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonReceiptSlipCapabilities)->get_IsPrintAreaSupported(&value));
    return value;
}

template <typename D> Windows::Devices::PointOfService::PosPrinterRuledLineCapabilities consume_Windows_Devices_PointOfService_ICommonReceiptSlipCapabilities<D>::RuledLineCapabilities() const
{
    Windows::Devices::PointOfService::PosPrinterRuledLineCapabilities value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonReceiptSlipCapabilities)->get_RuledLineCapabilities(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::PointOfService::PosPrinterRotation> consume_Windows_Devices_PointOfService_ICommonReceiptSlipCapabilities<D>::SupportedBarcodeRotations() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::PointOfService::PosPrinterRotation> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonReceiptSlipCapabilities)->get_SupportedBarcodeRotations(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::PointOfService::PosPrinterRotation> consume_Windows_Devices_PointOfService_ICommonReceiptSlipCapabilities<D>::SupportedBitmapRotations() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::PointOfService::PosPrinterRotation> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ICommonReceiptSlipCapabilities)->get_SupportedBitmapRotations(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_IJournalPrintJob<D>::Print(param::hstring const& data, Windows::Devices::PointOfService::PosPrinterPrintOptions const& printOptions) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IJournalPrintJob)->Print(get_abi(data), get_abi(printOptions)));
}

template <typename D> void consume_Windows_Devices_PointOfService_IJournalPrintJob<D>::FeedPaperByLine(int32_t lineCount) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IJournalPrintJob)->FeedPaperByLine(lineCount));
}

template <typename D> void consume_Windows_Devices_PointOfService_IJournalPrintJob<D>::FeedPaperByMapModeUnit(int32_t distance) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IJournalPrintJob)->FeedPaperByMapModeUnit(distance));
}

template <typename D> bool consume_Windows_Devices_PointOfService_IJournalPrinterCapabilities2<D>::IsReverseVideoSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IJournalPrinterCapabilities2)->get_IsReverseVideoSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IJournalPrinterCapabilities2<D>::IsStrikethroughSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IJournalPrinterCapabilities2)->get_IsStrikethroughSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IJournalPrinterCapabilities2<D>::IsSuperscriptSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IJournalPrinterCapabilities2)->get_IsSuperscriptSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IJournalPrinterCapabilities2<D>::IsSubscriptSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IJournalPrinterCapabilities2)->get_IsSubscriptSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IJournalPrinterCapabilities2<D>::IsReversePaperFeedByLineSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IJournalPrinterCapabilities2)->get_IsReversePaperFeedByLineSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IJournalPrinterCapabilities2<D>::IsReversePaperFeedByMapModeUnitSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IJournalPrinterCapabilities2)->get_IsReversePaperFeedByMapModeUnitSupported(&value));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_ILineDisplay<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplay)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::LineDisplayCapabilities consume_Windows_Devices_PointOfService_ILineDisplay<D>::Capabilities() const
{
    Windows::Devices::PointOfService::LineDisplayCapabilities value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplay)->get_Capabilities(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_ILineDisplay<D>::PhysicalDeviceName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplay)->get_PhysicalDeviceName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_ILineDisplay<D>::PhysicalDeviceDescription() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplay)->get_PhysicalDeviceDescription(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_ILineDisplay<D>::DeviceControlDescription() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplay)->get_DeviceControlDescription(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_ILineDisplay<D>::DeviceControlVersion() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplay)->get_DeviceControlVersion(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_ILineDisplay<D>::DeviceServiceVersion() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplay)->get_DeviceServiceVersion(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::ClaimedLineDisplay> consume_Windows_Devices_PointOfService_ILineDisplay<D>::ClaimAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::ClaimedLineDisplay> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplay)->ClaimAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplayPowerStatus> consume_Windows_Devices_PointOfService_ILineDisplay2<D>::CheckPowerStatusAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplayPowerStatus> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplay2)->CheckPowerStatusAsync(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ILineDisplayAttributes<D>::IsPowerNotifyEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayAttributes)->get_IsPowerNotifyEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_ILineDisplayAttributes<D>::IsPowerNotifyEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayAttributes)->put_IsPowerNotifyEnabled(value));
}

template <typename D> int32_t consume_Windows_Devices_PointOfService_ILineDisplayAttributes<D>::Brightness() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayAttributes)->get_Brightness(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_ILineDisplayAttributes<D>::Brightness(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayAttributes)->put_Brightness(value));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_PointOfService_ILineDisplayAttributes<D>::BlinkRate() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayAttributes)->get_BlinkRate(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_ILineDisplayAttributes<D>::BlinkRate(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayAttributes)->put_BlinkRate(get_abi(value)));
}

template <typename D> Windows::Foundation::Size consume_Windows_Devices_PointOfService_ILineDisplayAttributes<D>::ScreenSizeInCharacters() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayAttributes)->get_ScreenSizeInCharacters(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_ILineDisplayAttributes<D>::ScreenSizeInCharacters(Windows::Foundation::Size const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayAttributes)->put_ScreenSizeInCharacters(get_abi(value)));
}

template <typename D> int32_t consume_Windows_Devices_PointOfService_ILineDisplayAttributes<D>::CharacterSet() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayAttributes)->get_CharacterSet(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_ILineDisplayAttributes<D>::CharacterSet(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayAttributes)->put_CharacterSet(value));
}

template <typename D> bool consume_Windows_Devices_PointOfService_ILineDisplayAttributes<D>::IsCharacterSetMappingEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayAttributes)->get_IsCharacterSetMappingEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_ILineDisplayAttributes<D>::IsCharacterSetMappingEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayAttributes)->put_IsCharacterSetMappingEnabled(value));
}

template <typename D> Windows::Devices::PointOfService::LineDisplayWindow consume_Windows_Devices_PointOfService_ILineDisplayAttributes<D>::CurrentWindow() const
{
    Windows::Devices::PointOfService::LineDisplayWindow value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayAttributes)->get_CurrentWindow(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_ILineDisplayAttributes<D>::CurrentWindow(Windows::Devices::PointOfService::LineDisplayWindow const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayAttributes)->put_CurrentWindow(get_abi(value)));
}

template <typename D> bool consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::IsStatisticsReportingSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_IsStatisticsReportingSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::IsStatisticsUpdatingSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_IsStatisticsUpdatingSupported(&value));
    return value;
}

template <typename D> Windows::Devices::PointOfService::UnifiedPosPowerReportingType consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::PowerReportingType() const
{
    Windows::Devices::PointOfService::UnifiedPosPowerReportingType value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_PowerReportingType(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::CanChangeScreenSize() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_CanChangeScreenSize(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::CanDisplayBitmaps() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_CanDisplayBitmaps(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::CanReadCharacterAtCursor() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_CanReadCharacterAtCursor(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::CanMapCharacterSets() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_CanMapCharacterSets(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::CanDisplayCustomGlyphs() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_CanDisplayCustomGlyphs(&value));
    return value;
}

template <typename D> Windows::Devices::PointOfService::LineDisplayTextAttributeGranularity consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::CanReverse() const
{
    Windows::Devices::PointOfService::LineDisplayTextAttributeGranularity value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_CanReverse(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::LineDisplayTextAttributeGranularity consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::CanBlink() const
{
    Windows::Devices::PointOfService::LineDisplayTextAttributeGranularity value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_CanBlink(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::CanChangeBlinkRate() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_CanChangeBlinkRate(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::IsBrightnessSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_IsBrightnessSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::IsCursorSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_IsCursorSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::IsHorizontalMarqueeSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_IsHorizontalMarqueeSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::IsVerticalMarqueeSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_IsVerticalMarqueeSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::IsInterCharacterWaitSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_IsInterCharacterWaitSupported(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::SupportedDescriptors() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_SupportedDescriptors(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::SupportedWindows() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_SupportedWindows(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ILineDisplayCursor<D>::CanCustomize() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCursor)->get_CanCustomize(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ILineDisplayCursor<D>::IsBlinkSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCursor)->get_IsBlinkSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ILineDisplayCursor<D>::IsBlockSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCursor)->get_IsBlockSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ILineDisplayCursor<D>::IsHalfBlockSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCursor)->get_IsHalfBlockSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ILineDisplayCursor<D>::IsUnderlineSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCursor)->get_IsUnderlineSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ILineDisplayCursor<D>::IsReverseSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCursor)->get_IsReverseSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ILineDisplayCursor<D>::IsOtherSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCursor)->get_IsOtherSupported(&value));
    return value;
}

template <typename D> Windows::Devices::PointOfService::LineDisplayCursorAttributes consume_Windows_Devices_PointOfService_ILineDisplayCursor<D>::GetAttributes() const
{
    Windows::Devices::PointOfService::LineDisplayCursorAttributes result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCursor)->GetAttributes(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_ILineDisplayCursor<D>::TryUpdateAttributesAsync(Windows::Devices::PointOfService::LineDisplayCursorAttributes const& attributes) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCursor)->TryUpdateAttributesAsync(get_abi(attributes), put_abi(operation)));
    return operation;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ILineDisplayCursorAttributes<D>::IsBlinkEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCursorAttributes)->get_IsBlinkEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_ILineDisplayCursorAttributes<D>::IsBlinkEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCursorAttributes)->put_IsBlinkEnabled(value));
}

template <typename D> Windows::Devices::PointOfService::LineDisplayCursorType consume_Windows_Devices_PointOfService_ILineDisplayCursorAttributes<D>::CursorType() const
{
    Windows::Devices::PointOfService::LineDisplayCursorType value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCursorAttributes)->get_CursorType(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_ILineDisplayCursorAttributes<D>::CursorType(Windows::Devices::PointOfService::LineDisplayCursorType const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCursorAttributes)->put_CursorType(get_abi(value)));
}

template <typename D> bool consume_Windows_Devices_PointOfService_ILineDisplayCursorAttributes<D>::IsAutoAdvanceEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCursorAttributes)->get_IsAutoAdvanceEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_ILineDisplayCursorAttributes<D>::IsAutoAdvanceEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCursorAttributes)->put_IsAutoAdvanceEnabled(value));
}

template <typename D> Windows::Foundation::Point consume_Windows_Devices_PointOfService_ILineDisplayCursorAttributes<D>::Position() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCursorAttributes)->get_Position(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_ILineDisplayCursorAttributes<D>::Position(Windows::Foundation::Point const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCursorAttributes)->put_Position(get_abi(value)));
}

template <typename D> Windows::Foundation::Size consume_Windows_Devices_PointOfService_ILineDisplayCustomGlyphs<D>::SizeInPixels() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCustomGlyphs)->get_SizeInPixels(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<uint32_t> consume_Windows_Devices_PointOfService_ILineDisplayCustomGlyphs<D>::SupportedGlyphCodes() const
{
    Windows::Foundation::Collections::IVectorView<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCustomGlyphs)->get_SupportedGlyphCodes(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_ILineDisplayCustomGlyphs<D>::TryRedefineAsync(uint32_t glyphCode, Windows::Storage::Streams::IBuffer const& glyphData) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayCustomGlyphs)->TryRedefineAsync(glyphCode, get_abi(glyphData), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Devices::PointOfService::LineDisplayMarqueeFormat consume_Windows_Devices_PointOfService_ILineDisplayMarquee<D>::Format() const
{
    Windows::Devices::PointOfService::LineDisplayMarqueeFormat value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayMarquee)->get_Format(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_ILineDisplayMarquee<D>::Format(Windows::Devices::PointOfService::LineDisplayMarqueeFormat const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayMarquee)->put_Format(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_PointOfService_ILineDisplayMarquee<D>::RepeatWaitInterval() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayMarquee)->get_RepeatWaitInterval(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_ILineDisplayMarquee<D>::RepeatWaitInterval(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayMarquee)->put_RepeatWaitInterval(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_PointOfService_ILineDisplayMarquee<D>::ScrollWaitInterval() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayMarquee)->get_ScrollWaitInterval(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_ILineDisplayMarquee<D>::ScrollWaitInterval(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayMarquee)->put_ScrollWaitInterval(get_abi(value)));
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_ILineDisplayMarquee<D>::TryStartScrollingAsync(Windows::Devices::PointOfService::LineDisplayScrollDirection const& direction) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayMarquee)->TryStartScrollingAsync(get_abi(direction), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_ILineDisplayMarquee<D>::TryStopScrollingAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayMarquee)->TryStopScrollingAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplay> consume_Windows_Devices_PointOfService_ILineDisplayStatics<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplay> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayStatics)->FromIdAsync(get_abi(deviceId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplay> consume_Windows_Devices_PointOfService_ILineDisplayStatics<D>::GetDefaultAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplay> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayStatics)->GetDefaultAsync(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_ILineDisplayStatics<D>::GetDeviceSelector() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayStatics)->GetDeviceSelector(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_ILineDisplayStatics<D>::GetDeviceSelector(Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes) const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayStatics)->GetDeviceSelectorWithConnectionTypes(get_abi(connectionTypes), put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::LineDisplayStatisticsCategorySelector consume_Windows_Devices_PointOfService_ILineDisplayStatics2<D>::StatisticsCategorySelector() const
{
    Windows::Devices::PointOfService::LineDisplayStatisticsCategorySelector value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayStatics2)->get_StatisticsCategorySelector(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_ILineDisplayStatisticsCategorySelector<D>::AllStatistics() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayStatisticsCategorySelector)->get_AllStatistics(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_ILineDisplayStatisticsCategorySelector<D>::UnifiedPosStatistics() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayStatisticsCategorySelector)->get_UnifiedPosStatistics(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_ILineDisplayStatisticsCategorySelector<D>::ManufacturerStatistics() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayStatisticsCategorySelector)->get_ManufacturerStatistics(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::LineDisplayPowerStatus consume_Windows_Devices_PointOfService_ILineDisplayStatusUpdatedEventArgs<D>::Status() const
{
    Windows::Devices::PointOfService::LineDisplayPowerStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayStatusUpdatedEventArgs)->get_Status(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_ILineDisplayStoredBitmap<D>::EscapeSequence() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayStoredBitmap)->get_EscapeSequence(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_ILineDisplayStoredBitmap<D>::TryDeleteAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayStoredBitmap)->TryDeleteAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::Size consume_Windows_Devices_PointOfService_ILineDisplayWindow<D>::SizeInCharacters() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayWindow)->get_SizeInCharacters(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_PointOfService_ILineDisplayWindow<D>::InterCharacterWaitInterval() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayWindow)->get_InterCharacterWaitInterval(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_ILineDisplayWindow<D>::InterCharacterWaitInterval(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayWindow)->put_InterCharacterWaitInterval(get_abi(value)));
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_ILineDisplayWindow<D>::TryRefreshAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayWindow)->TryRefreshAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_ILineDisplayWindow<D>::TryDisplayTextAsync(param::hstring const& text, Windows::Devices::PointOfService::LineDisplayTextAttribute const& displayAttribute) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayWindow)->TryDisplayTextAsync(get_abi(text), get_abi(displayAttribute), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_ILineDisplayWindow<D>::TryDisplayTextAsync(param::hstring const& text, Windows::Devices::PointOfService::LineDisplayTextAttribute const& displayAttribute, Windows::Foundation::Point const& startPosition) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayWindow)->TryDisplayTextAtPositionAsync(get_abi(text), get_abi(displayAttribute), get_abi(startPosition), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_ILineDisplayWindow<D>::TryDisplayTextAsync(param::hstring const& text) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayWindow)->TryDisplayTextNormalAsync(get_abi(text), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_ILineDisplayWindow<D>::TryScrollTextAsync(Windows::Devices::PointOfService::LineDisplayScrollDirection const& direction, uint32_t numberOfColumnsOrRows) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayWindow)->TryScrollTextAsync(get_abi(direction), numberOfColumnsOrRows, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_ILineDisplayWindow<D>::TryClearTextAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayWindow)->TryClearTextAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Devices::PointOfService::LineDisplayCursor consume_Windows_Devices_PointOfService_ILineDisplayWindow2<D>::Cursor() const
{
    Windows::Devices::PointOfService::LineDisplayCursor value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayWindow2)->get_Cursor(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::LineDisplayMarquee consume_Windows_Devices_PointOfService_ILineDisplayWindow2<D>::Marquee() const
{
    Windows::Devices::PointOfService::LineDisplayMarquee value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayWindow2)->get_Marquee(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<uint32_t> consume_Windows_Devices_PointOfService_ILineDisplayWindow2<D>::ReadCharacterAtCursorAsync() const
{
    Windows::Foundation::IAsyncOperation<uint32_t> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayWindow2)->ReadCharacterAtCursorAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_ILineDisplayWindow2<D>::TryDisplayStoredBitmapAtCursorAsync(Windows::Devices::PointOfService::LineDisplayStoredBitmap const& bitmap) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayWindow2)->TryDisplayStoredBitmapAtCursorAsync(get_abi(bitmap), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_ILineDisplayWindow2<D>::TryDisplayStorageFileBitmapAtCursorAsync(Windows::Storage::StorageFile const& bitmap) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayWindow2)->TryDisplayStorageFileBitmapAtCursorAsync(get_abi(bitmap), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_ILineDisplayWindow2<D>::TryDisplayStorageFileBitmapAtCursorAsync(Windows::Storage::StorageFile const& bitmap, Windows::Devices::PointOfService::LineDisplayHorizontalAlignment const& horizontalAlignment, Windows::Devices::PointOfService::LineDisplayVerticalAlignment const& verticalAlignment) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayWindow2)->TryDisplayStorageFileBitmapAtCursorWithAlignmentAsync(get_abi(bitmap), get_abi(horizontalAlignment), get_abi(verticalAlignment), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_ILineDisplayWindow2<D>::TryDisplayStorageFileBitmapAtCursorAsync(Windows::Storage::StorageFile const& bitmap, Windows::Devices::PointOfService::LineDisplayHorizontalAlignment const& horizontalAlignment, Windows::Devices::PointOfService::LineDisplayVerticalAlignment const& verticalAlignment, int32_t widthInPixels) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayWindow2)->TryDisplayStorageFileBitmapAtCursorWithAlignmentAndWidthAsync(get_abi(bitmap), get_abi(horizontalAlignment), get_abi(verticalAlignment), widthInPixels, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_ILineDisplayWindow2<D>::TryDisplayStorageFileBitmapAtPointAsync(Windows::Storage::StorageFile const& bitmap, Windows::Foundation::Point const& offsetInPixels) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayWindow2)->TryDisplayStorageFileBitmapAtPointAsync(get_abi(bitmap), get_abi(offsetInPixels), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_ILineDisplayWindow2<D>::TryDisplayStorageFileBitmapAtPointAsync(Windows::Storage::StorageFile const& bitmap, Windows::Foundation::Point const& offsetInPixels, int32_t widthInPixels) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ILineDisplayWindow2)->TryDisplayStorageFileBitmapAtPointWithWidthAsync(get_abi(bitmap), get_abi(offsetInPixels), widthInPixels, put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IMagneticStripeReader<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReader)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::MagneticStripeReaderCapabilities consume_Windows_Devices_PointOfService_IMagneticStripeReader<D>::Capabilities() const
{
    Windows::Devices::PointOfService::MagneticStripeReaderCapabilities value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReader)->get_Capabilities(put_abi(value)));
    return value;
}

template <typename D> com_array<uint32_t> consume_Windows_Devices_PointOfService_IMagneticStripeReader<D>::SupportedCardTypes() const
{
    com_array<uint32_t> value;
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReader)->get_SupportedCardTypes(impl::put_size_abi(value), put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::MagneticStripeReaderAuthenticationProtocol consume_Windows_Devices_PointOfService_IMagneticStripeReader<D>::DeviceAuthenticationProtocol() const
{
    Windows::Devices::PointOfService::MagneticStripeReaderAuthenticationProtocol value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReader)->get_DeviceAuthenticationProtocol(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_Devices_PointOfService_IMagneticStripeReader<D>::CheckHealthAsync(Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel const& level) const
{
    Windows::Foundation::IAsyncOperation<hstring> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReader)->CheckHealthAsync(get_abi(level), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::ClaimedMagneticStripeReader> consume_Windows_Devices_PointOfService_IMagneticStripeReader<D>::ClaimReaderAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::ClaimedMagneticStripeReader> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReader)->ClaimReaderAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> consume_Windows_Devices_PointOfService_IMagneticStripeReader<D>::RetrieveStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReader)->RetrieveStatisticsAsync(get_abi(statisticsCategories), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Devices::PointOfService::MagneticStripeReaderErrorReportingType consume_Windows_Devices_PointOfService_IMagneticStripeReader<D>::GetErrorReportingType() const
{
    Windows::Devices::PointOfService::MagneticStripeReaderErrorReportingType value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReader)->GetErrorReportingType(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_IMagneticStripeReader<D>::StatusUpdated(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::MagneticStripeReader, Windows::Devices::PointOfService::MagneticStripeReaderStatusUpdatedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReader)->add_StatusUpdated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_IMagneticStripeReader<D>::StatusUpdated_revoker consume_Windows_Devices_PointOfService_IMagneticStripeReader<D>::StatusUpdated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::MagneticStripeReader, Windows::Devices::PointOfService::MagneticStripeReaderStatusUpdatedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, StatusUpdated_revoker>(this, StatusUpdated(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_IMagneticStripeReader<D>::StatusUpdated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReader)->remove_StatusUpdated(get_abi(token)));
}

template <typename D> Windows::Devices::PointOfService::MagneticStripeReaderReport consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::Report() const
{
    Windows::Devices::PointOfService::MagneticStripeReaderReport value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_Report(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::LicenseNumber() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_LicenseNumber(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::ExpirationDate() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_ExpirationDate(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::Restrictions() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_Restrictions(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::Class() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_Class(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::Endorsements() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_Endorsements(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::BirthDate() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_BirthDate(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::FirstName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_FirstName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::Surname() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_Surname(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::Suffix() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_Suffix(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::Gender() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_Gender(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::HairColor() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_HairColor(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::EyeColor() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_EyeColor(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::Height() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_Height(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::Weight() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_Weight(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::Address() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_Address(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::City() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_City(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::State() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_State(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::PostalCode() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_PostalCode(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::MagneticStripeReaderReport consume_Windows_Devices_PointOfService_IMagneticStripeReaderBankCardDataReceivedEventArgs<D>::Report() const
{
    Windows::Devices::PointOfService::MagneticStripeReaderReport value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs)->get_Report(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IMagneticStripeReaderBankCardDataReceivedEventArgs<D>::AccountNumber() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs)->get_AccountNumber(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IMagneticStripeReaderBankCardDataReceivedEventArgs<D>::ExpirationDate() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs)->get_ExpirationDate(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IMagneticStripeReaderBankCardDataReceivedEventArgs<D>::ServiceCode() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs)->get_ServiceCode(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IMagneticStripeReaderBankCardDataReceivedEventArgs<D>::Title() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs)->get_Title(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IMagneticStripeReaderBankCardDataReceivedEventArgs<D>::FirstName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs)->get_FirstName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IMagneticStripeReaderBankCardDataReceivedEventArgs<D>::MiddleInitial() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs)->get_MiddleInitial(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IMagneticStripeReaderBankCardDataReceivedEventArgs<D>::Surname() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs)->get_Surname(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IMagneticStripeReaderBankCardDataReceivedEventArgs<D>::Suffix() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs)->get_Suffix(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IMagneticStripeReaderCapabilities<D>::CardAuthentication() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities)->get_CardAuthentication(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IMagneticStripeReaderCapabilities<D>::SupportedEncryptionAlgorithms() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities)->get_SupportedEncryptionAlgorithms(&value));
    return value;
}

template <typename D> Windows::Devices::PointOfService::MagneticStripeReaderAuthenticationLevel consume_Windows_Devices_PointOfService_IMagneticStripeReaderCapabilities<D>::AuthenticationLevel() const
{
    Windows::Devices::PointOfService::MagneticStripeReaderAuthenticationLevel value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities)->get_AuthenticationLevel(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IMagneticStripeReaderCapabilities<D>::IsIsoSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities)->get_IsIsoSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IMagneticStripeReaderCapabilities<D>::IsJisOneSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities)->get_IsJisOneSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IMagneticStripeReaderCapabilities<D>::IsJisTwoSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities)->get_IsJisTwoSupported(&value));
    return value;
}

template <typename D> Windows::Devices::PointOfService::UnifiedPosPowerReportingType consume_Windows_Devices_PointOfService_IMagneticStripeReaderCapabilities<D>::PowerReportingType() const
{
    Windows::Devices::PointOfService::UnifiedPosPowerReportingType value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities)->get_PowerReportingType(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IMagneticStripeReaderCapabilities<D>::IsStatisticsReportingSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities)->get_IsStatisticsReportingSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IMagneticStripeReaderCapabilities<D>::IsStatisticsUpdatingSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities)->get_IsStatisticsUpdatingSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IMagneticStripeReaderCapabilities<D>::IsTrackDataMaskingSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities)->get_IsTrackDataMaskingSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IMagneticStripeReaderCapabilities<D>::IsTransmitSentinelsSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities)->get_IsTransmitSentinelsSupported(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IMagneticStripeReaderCardTypesStatics<D>::Unknown() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderCardTypesStatics)->get_Unknown(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IMagneticStripeReaderCardTypesStatics<D>::Bank() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderCardTypesStatics)->get_Bank(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IMagneticStripeReaderCardTypesStatics<D>::Aamva() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderCardTypesStatics)->get_Aamva(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IMagneticStripeReaderCardTypesStatics<D>::ExtendedBase() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderCardTypesStatics)->get_ExtendedBase(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IMagneticStripeReaderEncryptionAlgorithmsStatics<D>::None() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderEncryptionAlgorithmsStatics)->get_None(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IMagneticStripeReaderEncryptionAlgorithmsStatics<D>::TripleDesDukpt() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderEncryptionAlgorithmsStatics)->get_TripleDesDukpt(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IMagneticStripeReaderEncryptionAlgorithmsStatics<D>::ExtendedBase() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderEncryptionAlgorithmsStatics)->get_ExtendedBase(&value));
    return value;
}

template <typename D> Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType consume_Windows_Devices_PointOfService_IMagneticStripeReaderErrorOccurredEventArgs<D>::Track1Status() const
{
    Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderErrorOccurredEventArgs)->get_Track1Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType consume_Windows_Devices_PointOfService_IMagneticStripeReaderErrorOccurredEventArgs<D>::Track2Status() const
{
    Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderErrorOccurredEventArgs)->get_Track2Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType consume_Windows_Devices_PointOfService_IMagneticStripeReaderErrorOccurredEventArgs<D>::Track3Status() const
{
    Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderErrorOccurredEventArgs)->get_Track3Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType consume_Windows_Devices_PointOfService_IMagneticStripeReaderErrorOccurredEventArgs<D>::Track4Status() const
{
    Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderErrorOccurredEventArgs)->get_Track4Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::UnifiedPosErrorData consume_Windows_Devices_PointOfService_IMagneticStripeReaderErrorOccurredEventArgs<D>::ErrorData() const
{
    Windows::Devices::PointOfService::UnifiedPosErrorData value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderErrorOccurredEventArgs)->get_ErrorData(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::MagneticStripeReaderReport consume_Windows_Devices_PointOfService_IMagneticStripeReaderErrorOccurredEventArgs<D>::PartialInputData() const
{
    Windows::Devices::PointOfService::MagneticStripeReaderReport value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderErrorOccurredEventArgs)->get_PartialInputData(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IMagneticStripeReaderReport<D>::CardType() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderReport)->get_CardType(&value));
    return value;
}

template <typename D> Windows::Devices::PointOfService::MagneticStripeReaderTrackData consume_Windows_Devices_PointOfService_IMagneticStripeReaderReport<D>::Track1() const
{
    Windows::Devices::PointOfService::MagneticStripeReaderTrackData value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderReport)->get_Track1(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::MagneticStripeReaderTrackData consume_Windows_Devices_PointOfService_IMagneticStripeReaderReport<D>::Track2() const
{
    Windows::Devices::PointOfService::MagneticStripeReaderTrackData value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderReport)->get_Track2(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::MagneticStripeReaderTrackData consume_Windows_Devices_PointOfService_IMagneticStripeReaderReport<D>::Track3() const
{
    Windows::Devices::PointOfService::MagneticStripeReaderTrackData value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderReport)->get_Track3(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::MagneticStripeReaderTrackData consume_Windows_Devices_PointOfService_IMagneticStripeReaderReport<D>::Track4() const
{
    Windows::Devices::PointOfService::MagneticStripeReaderTrackData value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderReport)->get_Track4(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, hstring> consume_Windows_Devices_PointOfService_IMagneticStripeReaderReport<D>::Properties() const
{
    Windows::Foundation::Collections::IMapView<hstring, hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderReport)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_PointOfService_IMagneticStripeReaderReport<D>::CardAuthenticationData() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderReport)->get_CardAuthenticationData(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IMagneticStripeReaderReport<D>::CardAuthenticationDataLength() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderReport)->get_CardAuthenticationDataLength(&value));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_PointOfService_IMagneticStripeReaderReport<D>::AdditionalSecurityInformation() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderReport)->get_AdditionalSecurityInformation(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::MagneticStripeReader> consume_Windows_Devices_PointOfService_IMagneticStripeReaderStatics<D>::GetDefaultAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::MagneticStripeReader> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderStatics)->GetDefaultAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::MagneticStripeReader> consume_Windows_Devices_PointOfService_IMagneticStripeReaderStatics<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::MagneticStripeReader> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderStatics)->FromIdAsync(get_abi(deviceId), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IMagneticStripeReaderStatics<D>::GetDeviceSelector() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderStatics)->GetDeviceSelector(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IMagneticStripeReaderStatics2<D>::GetDeviceSelector(Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes) const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderStatics2)->GetDeviceSelectorWithConnectionTypes(get_abi(connectionTypes), put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::MagneticStripeReaderStatus consume_Windows_Devices_PointOfService_IMagneticStripeReaderStatusUpdatedEventArgs<D>::Status() const
{
    Windows::Devices::PointOfService::MagneticStripeReaderStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderStatusUpdatedEventArgs)->get_Status(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IMagneticStripeReaderStatusUpdatedEventArgs<D>::ExtendedStatus() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderStatusUpdatedEventArgs)->get_ExtendedStatus(&value));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_PointOfService_IMagneticStripeReaderTrackData<D>::Data() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderTrackData)->get_Data(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_PointOfService_IMagneticStripeReaderTrackData<D>::DiscretionaryData() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderTrackData)->get_DiscretionaryData(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_PointOfService_IMagneticStripeReaderTrackData<D>::EncryptedData() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderTrackData)->get_EncryptedData(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::MagneticStripeReaderReport consume_Windows_Devices_PointOfService_IMagneticStripeReaderVendorSpecificCardDataReceivedEventArgs<D>::Report() const
{
    Windows::Devices::PointOfService::MagneticStripeReaderReport value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IMagneticStripeReaderVendorSpecificCardDataReceivedEventArgs)->get_Report(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IPosPrinter<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinter)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::PosPrinterCapabilities consume_Windows_Devices_PointOfService_IPosPrinter<D>::Capabilities() const
{
    Windows::Devices::PointOfService::PosPrinterCapabilities value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinter)->get_Capabilities(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<uint32_t> consume_Windows_Devices_PointOfService_IPosPrinter<D>::SupportedCharacterSets() const
{
    Windows::Foundation::Collections::IVectorView<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinter)->get_SupportedCharacterSets(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_Devices_PointOfService_IPosPrinter<D>::SupportedTypeFaces() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinter)->get_SupportedTypeFaces(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::PosPrinterStatus consume_Windows_Devices_PointOfService_IPosPrinter<D>::Status() const
{
    Windows::Devices::PointOfService::PosPrinterStatus value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinter)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::ClaimedPosPrinter> consume_Windows_Devices_PointOfService_IPosPrinter<D>::ClaimPrinterAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::ClaimedPosPrinter> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinter)->ClaimPrinterAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_Devices_PointOfService_IPosPrinter<D>::CheckHealthAsync(Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel const& level) const
{
    Windows::Foundation::IAsyncOperation<hstring> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinter)->CheckHealthAsync(get_abi(level), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_Devices_PointOfService_IPosPrinter<D>::GetStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const
{
    Windows::Foundation::IAsyncOperation<hstring> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinter)->GetStatisticsAsync(get_abi(statisticsCategories), put_abi(operation)));
    return operation;
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_IPosPrinter<D>::StatusUpdated(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::PosPrinter, Windows::Devices::PointOfService::PosPrinterStatusUpdatedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinter)->add_StatusUpdated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_IPosPrinter<D>::StatusUpdated_revoker consume_Windows_Devices_PointOfService_IPosPrinter<D>::StatusUpdated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::PosPrinter, Windows::Devices::PointOfService::PosPrinterStatusUpdatedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, StatusUpdated_revoker>(this, StatusUpdated(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_IPosPrinter<D>::StatusUpdated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinter)->remove_StatusUpdated(get_abi(token)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<uint32_t> consume_Windows_Devices_PointOfService_IPosPrinter2<D>::SupportedBarcodeSymbologies() const
{
    Windows::Foundation::Collections::IVectorView<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinter2)->get_SupportedBarcodeSymbologies(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::PosPrinterFontProperty consume_Windows_Devices_PointOfService_IPosPrinter2<D>::GetFontProperty(param::hstring const& typeface) const
{
    Windows::Devices::PointOfService::PosPrinterFontProperty result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinter2)->GetFontProperty(get_abi(typeface), put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::PointOfService::UnifiedPosPowerReportingType consume_Windows_Devices_PointOfService_IPosPrinterCapabilities<D>::PowerReportingType() const
{
    Windows::Devices::PointOfService::UnifiedPosPowerReportingType value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterCapabilities)->get_PowerReportingType(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IPosPrinterCapabilities<D>::IsStatisticsReportingSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterCapabilities)->get_IsStatisticsReportingSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IPosPrinterCapabilities<D>::IsStatisticsUpdatingSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterCapabilities)->get_IsStatisticsUpdatingSupported(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IPosPrinterCapabilities<D>::DefaultCharacterSet() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterCapabilities)->get_DefaultCharacterSet(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IPosPrinterCapabilities<D>::HasCoverSensor() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterCapabilities)->get_HasCoverSensor(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IPosPrinterCapabilities<D>::CanMapCharacterSet() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterCapabilities)->get_CanMapCharacterSet(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IPosPrinterCapabilities<D>::IsTransactionSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterCapabilities)->get_IsTransactionSupported(&value));
    return value;
}

template <typename D> Windows::Devices::PointOfService::ReceiptPrinterCapabilities consume_Windows_Devices_PointOfService_IPosPrinterCapabilities<D>::Receipt() const
{
    Windows::Devices::PointOfService::ReceiptPrinterCapabilities value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterCapabilities)->get_Receipt(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::SlipPrinterCapabilities consume_Windows_Devices_PointOfService_IPosPrinterCapabilities<D>::Slip() const
{
    Windows::Devices::PointOfService::SlipPrinterCapabilities value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterCapabilities)->get_Slip(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::JournalPrinterCapabilities consume_Windows_Devices_PointOfService_IPosPrinterCapabilities<D>::Journal() const
{
    Windows::Devices::PointOfService::JournalPrinterCapabilities value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterCapabilities)->get_Journal(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IPosPrinterCharacterSetIdsStatics<D>::Utf16LE() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterCharacterSetIdsStatics)->get_Utf16LE(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IPosPrinterCharacterSetIdsStatics<D>::Ascii() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterCharacterSetIdsStatics)->get_Ascii(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IPosPrinterCharacterSetIdsStatics<D>::Ansi() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterCharacterSetIdsStatics)->get_Ansi(&value));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IPosPrinterFontProperty<D>::TypeFace() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterFontProperty)->get_TypeFace(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IPosPrinterFontProperty<D>::IsScalableToAnySize() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterFontProperty)->get_IsScalableToAnySize(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::PointOfService::SizeUInt32> consume_Windows_Devices_PointOfService_IPosPrinterFontProperty<D>::CharacterSizes() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::PointOfService::SizeUInt32> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterFontProperty)->get_CharacterSizes(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_IPosPrinterJob<D>::Print(param::hstring const& data) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterJob)->Print(get_abi(data)));
}

template <typename D> void consume_Windows_Devices_PointOfService_IPosPrinterJob<D>::PrintLine(param::hstring const& data) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterJob)->PrintLine(get_abi(data)));
}

template <typename D> void consume_Windows_Devices_PointOfService_IPosPrinterJob<D>::PrintLine() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterJob)->PrintNewline());
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_IPosPrinterJob<D>::ExecuteAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterJob)->ExecuteAsync(put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::TypeFace() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterPrintOptions)->get_TypeFace(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::TypeFace(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterPrintOptions)->put_TypeFace(get_abi(value)));
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::CharacterHeight() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterPrintOptions)->get_CharacterHeight(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::CharacterHeight(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterPrintOptions)->put_CharacterHeight(value));
}

template <typename D> bool consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::Bold() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterPrintOptions)->get_Bold(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::Bold(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterPrintOptions)->put_Bold(value));
}

template <typename D> bool consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::Italic() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterPrintOptions)->get_Italic(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::Italic(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterPrintOptions)->put_Italic(value));
}

template <typename D> bool consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::Underline() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterPrintOptions)->get_Underline(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::Underline(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterPrintOptions)->put_Underline(value));
}

template <typename D> bool consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::ReverseVideo() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterPrintOptions)->get_ReverseVideo(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::ReverseVideo(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterPrintOptions)->put_ReverseVideo(value));
}

template <typename D> bool consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::Strikethrough() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterPrintOptions)->get_Strikethrough(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::Strikethrough(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterPrintOptions)->put_Strikethrough(value));
}

template <typename D> bool consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::Superscript() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterPrintOptions)->get_Superscript(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::Superscript(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterPrintOptions)->put_Superscript(value));
}

template <typename D> bool consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::Subscript() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterPrintOptions)->get_Subscript(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::Subscript(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterPrintOptions)->put_Subscript(value));
}

template <typename D> bool consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::DoubleWide() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterPrintOptions)->get_DoubleWide(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::DoubleWide(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterPrintOptions)->put_DoubleWide(value));
}

template <typename D> bool consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::DoubleHigh() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterPrintOptions)->get_DoubleHigh(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::DoubleHigh(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterPrintOptions)->put_DoubleHigh(value));
}

template <typename D> Windows::Devices::PointOfService::PosPrinterAlignment consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::Alignment() const
{
    Windows::Devices::PointOfService::PosPrinterAlignment value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterPrintOptions)->get_Alignment(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::Alignment(Windows::Devices::PointOfService::PosPrinterAlignment const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterPrintOptions)->put_Alignment(get_abi(value)));
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::CharacterSet() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterPrintOptions)->get_CharacterSet(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::CharacterSet(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterPrintOptions)->put_CharacterSet(value));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::PosPrinter> consume_Windows_Devices_PointOfService_IPosPrinterStatics<D>::GetDefaultAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::PosPrinter> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterStatics)->GetDefaultAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::PosPrinter> consume_Windows_Devices_PointOfService_IPosPrinterStatics<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::PosPrinter> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterStatics)->FromIdAsync(get_abi(deviceId), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IPosPrinterStatics<D>::GetDeviceSelector() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterStatics)->GetDeviceSelector(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IPosPrinterStatics2<D>::GetDeviceSelector(Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes) const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterStatics2)->GetDeviceSelectorWithConnectionTypes(get_abi(connectionTypes), put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::PosPrinterStatusKind consume_Windows_Devices_PointOfService_IPosPrinterStatus<D>::StatusKind() const
{
    Windows::Devices::PointOfService::PosPrinterStatusKind value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterStatus)->get_StatusKind(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IPosPrinterStatus<D>::ExtendedStatus() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterStatus)->get_ExtendedStatus(&value));
    return value;
}

template <typename D> Windows::Devices::PointOfService::PosPrinterStatus consume_Windows_Devices_PointOfService_IPosPrinterStatusUpdatedEventArgs<D>::Status() const
{
    Windows::Devices::PointOfService::PosPrinterStatus value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IPosPrinterStatusUpdatedEventArgs)->get_Status(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_IReceiptOrSlipJob<D>::SetBarcodeRotation(Windows::Devices::PointOfService::PosPrinterRotation const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IReceiptOrSlipJob)->SetBarcodeRotation(get_abi(value)));
}

template <typename D> void consume_Windows_Devices_PointOfService_IReceiptOrSlipJob<D>::SetPrintRotation(Windows::Devices::PointOfService::PosPrinterRotation const& value, bool includeBitmaps) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IReceiptOrSlipJob)->SetPrintRotation(get_abi(value), includeBitmaps));
}

template <typename D> void consume_Windows_Devices_PointOfService_IReceiptOrSlipJob<D>::SetPrintArea(Windows::Foundation::Rect const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IReceiptOrSlipJob)->SetPrintArea(get_abi(value)));
}

template <typename D> void consume_Windows_Devices_PointOfService_IReceiptOrSlipJob<D>::SetBitmap(uint32_t bitmapNumber, Windows::Graphics::Imaging::BitmapFrame const& bitmap, Windows::Devices::PointOfService::PosPrinterAlignment const& alignment) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IReceiptOrSlipJob)->SetBitmap(bitmapNumber, get_abi(bitmap), get_abi(alignment)));
}

template <typename D> void consume_Windows_Devices_PointOfService_IReceiptOrSlipJob<D>::SetBitmap(uint32_t bitmapNumber, Windows::Graphics::Imaging::BitmapFrame const& bitmap, Windows::Devices::PointOfService::PosPrinterAlignment const& alignment, uint32_t width) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IReceiptOrSlipJob)->SetBitmapCustomWidthStandardAlign(bitmapNumber, get_abi(bitmap), get_abi(alignment), width));
}

template <typename D> void consume_Windows_Devices_PointOfService_IReceiptOrSlipJob<D>::SetCustomAlignedBitmap(uint32_t bitmapNumber, Windows::Graphics::Imaging::BitmapFrame const& bitmap, uint32_t alignmentDistance) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IReceiptOrSlipJob)->SetCustomAlignedBitmap(bitmapNumber, get_abi(bitmap), alignmentDistance));
}

template <typename D> void consume_Windows_Devices_PointOfService_IReceiptOrSlipJob<D>::SetCustomAlignedBitmap(uint32_t bitmapNumber, Windows::Graphics::Imaging::BitmapFrame const& bitmap, uint32_t alignmentDistance, uint32_t width) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IReceiptOrSlipJob)->SetBitmapCustomWidthCustomAlign(bitmapNumber, get_abi(bitmap), alignmentDistance, width));
}

template <typename D> void consume_Windows_Devices_PointOfService_IReceiptOrSlipJob<D>::PrintSavedBitmap(uint32_t bitmapNumber) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IReceiptOrSlipJob)->PrintSavedBitmap(bitmapNumber));
}

template <typename D> void consume_Windows_Devices_PointOfService_IReceiptOrSlipJob<D>::DrawRuledLine(param::hstring const& positionList, Windows::Devices::PointOfService::PosPrinterLineDirection const& lineDirection, uint32_t lineWidth, Windows::Devices::PointOfService::PosPrinterLineStyle const& lineStyle, uint32_t lineColor) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IReceiptOrSlipJob)->DrawRuledLine(get_abi(positionList), get_abi(lineDirection), lineWidth, get_abi(lineStyle), lineColor));
}

template <typename D> void consume_Windows_Devices_PointOfService_IReceiptOrSlipJob<D>::PrintBarcode(param::hstring const& data, uint32_t symbology, uint32_t height, uint32_t width, Windows::Devices::PointOfService::PosPrinterBarcodeTextPosition const& textPosition, Windows::Devices::PointOfService::PosPrinterAlignment const& alignment) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IReceiptOrSlipJob)->PrintBarcode(get_abi(data), symbology, height, width, get_abi(textPosition), get_abi(alignment)));
}

template <typename D> void consume_Windows_Devices_PointOfService_IReceiptOrSlipJob<D>::PrintBarcodeCustomAlign(param::hstring const& data, uint32_t symbology, uint32_t height, uint32_t width, Windows::Devices::PointOfService::PosPrinterBarcodeTextPosition const& textPosition, uint32_t alignmentDistance) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IReceiptOrSlipJob)->PrintBarcodeCustomAlign(get_abi(data), symbology, height, width, get_abi(textPosition), alignmentDistance));
}

template <typename D> void consume_Windows_Devices_PointOfService_IReceiptOrSlipJob<D>::PrintBitmap(Windows::Graphics::Imaging::BitmapFrame const& bitmap, Windows::Devices::PointOfService::PosPrinterAlignment const& alignment) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IReceiptOrSlipJob)->PrintBitmap(get_abi(bitmap), get_abi(alignment)));
}

template <typename D> void consume_Windows_Devices_PointOfService_IReceiptOrSlipJob<D>::PrintBitmap(Windows::Graphics::Imaging::BitmapFrame const& bitmap, Windows::Devices::PointOfService::PosPrinterAlignment const& alignment, uint32_t width) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IReceiptOrSlipJob)->PrintBitmapCustomWidthStandardAlign(get_abi(bitmap), get_abi(alignment), width));
}

template <typename D> void consume_Windows_Devices_PointOfService_IReceiptOrSlipJob<D>::PrintCustomAlignedBitmap(Windows::Graphics::Imaging::BitmapFrame const& bitmap, uint32_t alignmentDistance) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IReceiptOrSlipJob)->PrintCustomAlignedBitmap(get_abi(bitmap), alignmentDistance));
}

template <typename D> void consume_Windows_Devices_PointOfService_IReceiptOrSlipJob<D>::PrintCustomAlignedBitmap(Windows::Graphics::Imaging::BitmapFrame const& bitmap, uint32_t alignmentDistance, uint32_t width) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IReceiptOrSlipJob)->PrintBitmapCustomWidthCustomAlign(get_abi(bitmap), alignmentDistance, width));
}

template <typename D> void consume_Windows_Devices_PointOfService_IReceiptPrintJob<D>::MarkFeed(Windows::Devices::PointOfService::PosPrinterMarkFeedKind const& kind) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IReceiptPrintJob)->MarkFeed(get_abi(kind)));
}

template <typename D> void consume_Windows_Devices_PointOfService_IReceiptPrintJob<D>::CutPaper(double percentage) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IReceiptPrintJob)->CutPaper(percentage));
}

template <typename D> void consume_Windows_Devices_PointOfService_IReceiptPrintJob<D>::CutPaper() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IReceiptPrintJob)->CutPaperDefault());
}

template <typename D> void consume_Windows_Devices_PointOfService_IReceiptPrintJob2<D>::StampPaper() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IReceiptPrintJob2)->StampPaper());
}

template <typename D> void consume_Windows_Devices_PointOfService_IReceiptPrintJob2<D>::Print(param::hstring const& data, Windows::Devices::PointOfService::PosPrinterPrintOptions const& printOptions) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IReceiptPrintJob2)->Print(get_abi(data), get_abi(printOptions)));
}

template <typename D> void consume_Windows_Devices_PointOfService_IReceiptPrintJob2<D>::FeedPaperByLine(int32_t lineCount) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IReceiptPrintJob2)->FeedPaperByLine(lineCount));
}

template <typename D> void consume_Windows_Devices_PointOfService_IReceiptPrintJob2<D>::FeedPaperByMapModeUnit(int32_t distance) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IReceiptPrintJob2)->FeedPaperByMapModeUnit(distance));
}

template <typename D> bool consume_Windows_Devices_PointOfService_IReceiptPrinterCapabilities<D>::CanCutPaper() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IReceiptPrinterCapabilities)->get_CanCutPaper(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IReceiptPrinterCapabilities<D>::IsStampSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IReceiptPrinterCapabilities)->get_IsStampSupported(&value));
    return value;
}

template <typename D> Windows::Devices::PointOfService::PosPrinterMarkFeedCapabilities consume_Windows_Devices_PointOfService_IReceiptPrinterCapabilities<D>::MarkFeedCapabilities() const
{
    Windows::Devices::PointOfService::PosPrinterMarkFeedCapabilities value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IReceiptPrinterCapabilities)->get_MarkFeedCapabilities(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IReceiptPrinterCapabilities2<D>::IsReverseVideoSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IReceiptPrinterCapabilities2)->get_IsReverseVideoSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IReceiptPrinterCapabilities2<D>::IsStrikethroughSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IReceiptPrinterCapabilities2)->get_IsStrikethroughSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IReceiptPrinterCapabilities2<D>::IsSuperscriptSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IReceiptPrinterCapabilities2)->get_IsSuperscriptSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IReceiptPrinterCapabilities2<D>::IsSubscriptSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IReceiptPrinterCapabilities2)->get_IsSubscriptSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IReceiptPrinterCapabilities2<D>::IsReversePaperFeedByLineSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IReceiptPrinterCapabilities2)->get_IsReversePaperFeedByLineSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_IReceiptPrinterCapabilities2<D>::IsReversePaperFeedByMapModeUnitSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IReceiptPrinterCapabilities2)->get_IsReversePaperFeedByMapModeUnitSupported(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_ISlipPrintJob<D>::Print(param::hstring const& data, Windows::Devices::PointOfService::PosPrinterPrintOptions const& printOptions) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ISlipPrintJob)->Print(get_abi(data), get_abi(printOptions)));
}

template <typename D> void consume_Windows_Devices_PointOfService_ISlipPrintJob<D>::FeedPaperByLine(int32_t lineCount) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ISlipPrintJob)->FeedPaperByLine(lineCount));
}

template <typename D> void consume_Windows_Devices_PointOfService_ISlipPrintJob<D>::FeedPaperByMapModeUnit(int32_t distance) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ISlipPrintJob)->FeedPaperByMapModeUnit(distance));
}

template <typename D> bool consume_Windows_Devices_PointOfService_ISlipPrinterCapabilities<D>::IsFullLengthSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ISlipPrinterCapabilities)->get_IsFullLengthSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ISlipPrinterCapabilities<D>::IsBothSidesPrintingSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ISlipPrinterCapabilities)->get_IsBothSidesPrintingSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ISlipPrinterCapabilities2<D>::IsReverseVideoSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ISlipPrinterCapabilities2)->get_IsReverseVideoSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ISlipPrinterCapabilities2<D>::IsStrikethroughSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ISlipPrinterCapabilities2)->get_IsStrikethroughSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ISlipPrinterCapabilities2<D>::IsSuperscriptSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ISlipPrinterCapabilities2)->get_IsSuperscriptSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ISlipPrinterCapabilities2<D>::IsSubscriptSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ISlipPrinterCapabilities2)->get_IsSubscriptSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ISlipPrinterCapabilities2<D>::IsReversePaperFeedByLineSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ISlipPrinterCapabilities2)->get_IsReversePaperFeedByLineSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_ISlipPrinterCapabilities2<D>::IsReversePaperFeedByMapModeUnitSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::ISlipPrinterCapabilities2)->get_IsReversePaperFeedByMapModeUnitSupported(&value));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_IUnifiedPosErrorData<D>::Message() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IUnifiedPosErrorData)->get_Message(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::UnifiedPosErrorSeverity consume_Windows_Devices_PointOfService_IUnifiedPosErrorData<D>::Severity() const
{
    Windows::Devices::PointOfService::UnifiedPosErrorSeverity value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IUnifiedPosErrorData)->get_Severity(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::PointOfService::UnifiedPosErrorReason consume_Windows_Devices_PointOfService_IUnifiedPosErrorData<D>::Reason() const
{
    Windows::Devices::PointOfService::UnifiedPosErrorReason value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IUnifiedPosErrorData)->get_Reason(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_IUnifiedPosErrorData<D>::ExtendedReason() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IUnifiedPosErrorData)->get_ExtendedReason(&value));
    return value;
}

template <typename D> Windows::Devices::PointOfService::UnifiedPosErrorData consume_Windows_Devices_PointOfService_IUnifiedPosErrorDataFactory<D>::CreateInstance(param::hstring const& message, Windows::Devices::PointOfService::UnifiedPosErrorSeverity const& severity, Windows::Devices::PointOfService::UnifiedPosErrorReason const& reason, uint32_t extendedReason) const
{
    Windows::Devices::PointOfService::UnifiedPosErrorData result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::IUnifiedPosErrorDataFactory)->CreateInstance(get_abi(message), get_abi(severity), get_abi(reason), extendedReason, put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IBarcodeScanner> : produce_base<D, Windows::Devices::PointOfService::IBarcodeScanner>
{
    int32_t WINRT_CALL get_DeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Capabilities(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Capabilities, WINRT_WRAP(Windows::Devices::PointOfService::BarcodeScannerCapabilities));
            *value = detach_from<Windows::Devices::PointOfService::BarcodeScannerCapabilities>(this->shim().Capabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClaimScannerAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClaimScannerAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::ClaimedBarcodeScanner>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::ClaimedBarcodeScanner>>(this->shim().ClaimScannerAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CheckHealthAsync(Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel level, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckHealthAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>), Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().CheckHealthAsync(*reinterpret_cast<Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel const*>(&level)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSupportedSymbologiesAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSupportedSymbologiesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<uint32_t>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<uint32_t>>>(this->shim().GetSupportedSymbologiesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsSymbologySupportedAsync(uint32_t barcodeSymbology, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSymbologySupportedAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), uint32_t);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().IsSymbologySupportedAsync(barcodeSymbology));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RetrieveStatisticsAsync(void* statisticsCategories, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RetrieveStatisticsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer>), Windows::Foundation::Collections::IIterable<hstring> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer>>(this->shim().RetrieveStatisticsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&statisticsCategories)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSupportedProfiles(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSupportedProfiles, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().GetSupportedProfiles());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsProfileSupported(void* profile, bool* isSupported) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsProfileSupported, WINRT_WRAP(bool), hstring const&);
            *isSupported = detach_from<bool>(this->shim().IsProfileSupported(*reinterpret_cast<hstring const*>(&profile)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_StatusUpdated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StatusUpdated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::BarcodeScanner, Windows::Devices::PointOfService::BarcodeScannerStatusUpdatedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().StatusUpdated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::BarcodeScanner, Windows::Devices::PointOfService::BarcodeScannerStatusUpdatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_StatusUpdated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(StatusUpdated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().StatusUpdated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IBarcodeScanner2> : produce_base<D, Windows::Devices::PointOfService::IBarcodeScanner2>
{
    int32_t WINRT_CALL get_VideoDeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoDeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoDeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IBarcodeScannerCapabilities> : produce_base<D, Windows::Devices::PointOfService::IBarcodeScannerCapabilities>
{
    int32_t WINRT_CALL get_PowerReportingType(Windows::Devices::PointOfService::UnifiedPosPowerReportingType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PowerReportingType, WINRT_WRAP(Windows::Devices::PointOfService::UnifiedPosPowerReportingType));
            *value = detach_from<Windows::Devices::PointOfService::UnifiedPosPowerReportingType>(this->shim().PowerReportingType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsStatisticsReportingSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStatisticsReportingSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsStatisticsReportingSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsStatisticsUpdatingSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStatisticsUpdatingSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsStatisticsUpdatingSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsImagePreviewSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsImagePreviewSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsImagePreviewSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IBarcodeScannerCapabilities1> : produce_base<D, Windows::Devices::PointOfService::IBarcodeScannerCapabilities1>
{
    int32_t WINRT_CALL get_IsSoftwareTriggerSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSoftwareTriggerSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSoftwareTriggerSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IBarcodeScannerCapabilities2> : produce_base<D, Windows::Devices::PointOfService::IBarcodeScannerCapabilities2>
{
    int32_t WINRT_CALL get_IsVideoPreviewSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsVideoPreviewSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsVideoPreviewSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IBarcodeScannerDataReceivedEventArgs> : produce_base<D, Windows::Devices::PointOfService::IBarcodeScannerDataReceivedEventArgs>
{
    int32_t WINRT_CALL get_Report(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Report, WINRT_WRAP(Windows::Devices::PointOfService::BarcodeScannerReport));
            *value = detach_from<Windows::Devices::PointOfService::BarcodeScannerReport>(this->shim().Report());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IBarcodeScannerErrorOccurredEventArgs> : produce_base<D, Windows::Devices::PointOfService::IBarcodeScannerErrorOccurredEventArgs>
{
    int32_t WINRT_CALL get_PartialInputData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PartialInputData, WINRT_WRAP(Windows::Devices::PointOfService::BarcodeScannerReport));
            *value = detach_from<Windows::Devices::PointOfService::BarcodeScannerReport>(this->shim().PartialInputData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsRetriable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRetriable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsRetriable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ErrorData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ErrorData, WINRT_WRAP(Windows::Devices::PointOfService::UnifiedPosErrorData));
            *value = detach_from<Windows::Devices::PointOfService::UnifiedPosErrorData>(this->shim().ErrorData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IBarcodeScannerImagePreviewReceivedEventArgs> : produce_base<D, Windows::Devices::PointOfService::IBarcodeScannerImagePreviewReceivedEventArgs>
{
    int32_t WINRT_CALL get_Preview(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Preview, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamWithContentType));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamWithContentType>(this->shim().Preview());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IBarcodeScannerReport> : produce_base<D, Windows::Devices::PointOfService::IBarcodeScannerReport>
{
    int32_t WINRT_CALL get_ScanDataType(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScanDataType, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ScanDataType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScanData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScanData, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().ScanData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScanDataLabel(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScanDataLabel, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().ScanDataLabel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IBarcodeScannerReportFactory> : produce_base<D, Windows::Devices::PointOfService::IBarcodeScannerReportFactory>
{
    int32_t WINRT_CALL CreateInstance(uint32_t scanDataType, void* scanData, void* scanDataLabel, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::Devices::PointOfService::BarcodeScannerReport), uint32_t, Windows::Storage::Streams::IBuffer const&, Windows::Storage::Streams::IBuffer const&);
            *result = detach_from<Windows::Devices::PointOfService::BarcodeScannerReport>(this->shim().CreateInstance(scanDataType, *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&scanData), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&scanDataLabel)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IBarcodeScannerStatics> : produce_base<D, Windows::Devices::PointOfService::IBarcodeScannerStatics>
{
    int32_t WINRT_CALL GetDefaultAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefaultAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::BarcodeScanner>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::BarcodeScanner>>(this->shim().GetDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromIdAsync(void* deviceId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::BarcodeScanner>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::BarcodeScanner>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelector(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IBarcodeScannerStatics2> : produce_base<D, Windows::Devices::PointOfService::IBarcodeScannerStatics2>
{
    int32_t WINRT_CALL GetDeviceSelectorWithConnectionTypes(Windows::Devices::PointOfService::PosConnectionTypes connectionTypes, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring), Windows::Devices::PointOfService::PosConnectionTypes const&);
            *value = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<Windows::Devices::PointOfService::PosConnectionTypes const*>(&connectionTypes)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IBarcodeScannerStatusUpdatedEventArgs> : produce_base<D, Windows::Devices::PointOfService::IBarcodeScannerStatusUpdatedEventArgs>
{
    int32_t WINRT_CALL get_Status(Windows::Devices::PointOfService::BarcodeScannerStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Devices::PointOfService::BarcodeScannerStatus));
            *value = detach_from<Windows::Devices::PointOfService::BarcodeScannerStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedStatus(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedStatus, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ExtendedStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics> : produce_base<D, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>
{
    int32_t WINRT_CALL get_Unknown(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Unknown, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Unknown());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Ean8(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Ean8, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Ean8());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Ean8Add2(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Ean8Add2, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Ean8Add2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Ean8Add5(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Ean8Add5, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Ean8Add5());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Eanv(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Eanv, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Eanv());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EanvAdd2(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EanvAdd2, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().EanvAdd2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EanvAdd5(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EanvAdd5, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().EanvAdd5());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Ean13(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Ean13, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Ean13());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Ean13Add2(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Ean13Add2, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Ean13Add2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Ean13Add5(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Ean13Add5, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Ean13Add5());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Isbn(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Isbn, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Isbn());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsbnAdd5(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsbnAdd5, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().IsbnAdd5());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Ismn(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Ismn, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Ismn());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsmnAdd2(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsmnAdd2, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().IsmnAdd2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsmnAdd5(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsmnAdd5, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().IsmnAdd5());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Issn(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Issn, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Issn());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IssnAdd2(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IssnAdd2, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().IssnAdd2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IssnAdd5(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IssnAdd5, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().IssnAdd5());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Ean99(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Ean99, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Ean99());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Ean99Add2(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Ean99Add2, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Ean99Add2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Ean99Add5(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Ean99Add5, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Ean99Add5());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Upca(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Upca, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Upca());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UpcaAdd2(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpcaAdd2, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().UpcaAdd2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UpcaAdd5(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpcaAdd5, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().UpcaAdd5());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Upce(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Upce, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Upce());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UpceAdd2(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpceAdd2, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().UpceAdd2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UpceAdd5(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpceAdd5, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().UpceAdd5());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UpcCoupon(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpcCoupon, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().UpcCoupon());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TfStd(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TfStd, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().TfStd());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TfDis(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TfDis, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().TfDis());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TfInt(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TfInt, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().TfInt());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TfInd(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TfInd, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().TfInd());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TfMat(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TfMat, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().TfMat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TfIata(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TfIata, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().TfIata());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Gs1DatabarType1(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Gs1DatabarType1, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Gs1DatabarType1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Gs1DatabarType2(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Gs1DatabarType2, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Gs1DatabarType2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Gs1DatabarType3(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Gs1DatabarType3, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Gs1DatabarType3());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Code39(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Code39, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Code39());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Code39Ex(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Code39Ex, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Code39Ex());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Trioptic39(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Trioptic39, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Trioptic39());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Code32(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Code32, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Code32());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Pzn(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pzn, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Pzn());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Code93(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Code93, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Code93());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Code93Ex(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Code93Ex, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Code93Ex());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Code128(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Code128, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Code128());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Gs1128(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Gs1128, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Gs1128());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Gs1128Coupon(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Gs1128Coupon, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Gs1128Coupon());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UccEan128(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UccEan128, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().UccEan128());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Sisac(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Sisac, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Sisac());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Isbt(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Isbt, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Isbt());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Codabar(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Codabar, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Codabar());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Code11(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Code11, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Code11());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Msi(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Msi, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Msi());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Plessey(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Plessey, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Plessey());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Telepen(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Telepen, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Telepen());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Code16k(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Code16k, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Code16k());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CodablockA(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CodablockA, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().CodablockA());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CodablockF(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CodablockF, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().CodablockF());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Codablock128(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Codablock128, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Codablock128());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Code49(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Code49, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Code49());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Aztec(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Aztec, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Aztec());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DataCode(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataCode, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().DataCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DataMatrix(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataMatrix, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().DataMatrix());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HanXin(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HanXin, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().HanXin());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Maxicode(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Maxicode, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Maxicode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MicroPdf417(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MicroPdf417, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MicroPdf417());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MicroQr(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MicroQr, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MicroQr());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Pdf417(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pdf417, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Pdf417());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Qr(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Qr, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Qr());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MsTag(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MsTag, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MsTag());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Ccab(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Ccab, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Ccab());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Ccc(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Ccc, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Ccc());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Tlc39(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tlc39, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Tlc39());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AusPost(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AusPost, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().AusPost());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanPost(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanPost, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().CanPost());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ChinaPost(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChinaPost, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ChinaPost());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DutchKix(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DutchKix, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().DutchKix());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InfoMail(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InfoMail, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().InfoMail());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ItalianPost25(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItalianPost25, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ItalianPost25());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ItalianPost39(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItalianPost39, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ItalianPost39());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_JapanPost(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(JapanPost, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().JapanPost());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KoreanPost(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KoreanPost, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().KoreanPost());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SwedenPost(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SwedenPost, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().SwedenPost());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UkPost(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UkPost, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().UkPost());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UsIntelligent(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UsIntelligent, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().UsIntelligent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UsIntelligentPkg(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UsIntelligentPkg, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().UsIntelligentPkg());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UsPlanet(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UsPlanet, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().UsPlanet());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UsPostNet(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UsPostNet, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().UsPostNet());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Us4StateFics(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Us4StateFics, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Us4StateFics());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OcrA(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OcrA, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().OcrA());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OcrB(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OcrB, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().OcrB());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Micr(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Micr, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Micr());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedBase(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedBase, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ExtendedBase());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetName(uint32_t scanDataType, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetName, WINRT_WRAP(hstring), uint32_t);
            *value = detach_from<hstring>(this->shim().GetName(scanDataType));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics2> : produce_base<D, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics2>
{
    int32_t WINRT_CALL get_Gs1DWCode(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Gs1DWCode, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Gs1DWCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IBarcodeSymbologyAttributes> : produce_base<D, Windows::Devices::PointOfService::IBarcodeSymbologyAttributes>
{
    int32_t WINRT_CALL get_IsCheckDigitValidationEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCheckDigitValidationEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCheckDigitValidationEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsCheckDigitValidationEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCheckDigitValidationEnabled, WINRT_WRAP(void), bool);
            this->shim().IsCheckDigitValidationEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsCheckDigitValidationSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCheckDigitValidationSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCheckDigitValidationSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsCheckDigitTransmissionEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCheckDigitTransmissionEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCheckDigitTransmissionEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsCheckDigitTransmissionEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCheckDigitTransmissionEnabled, WINRT_WRAP(void), bool);
            this->shim().IsCheckDigitTransmissionEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsCheckDigitTransmissionSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCheckDigitTransmissionSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCheckDigitTransmissionSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DecodeLength1(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DecodeLength1, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().DecodeLength1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DecodeLength1(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DecodeLength1, WINRT_WRAP(void), uint32_t);
            this->shim().DecodeLength1(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DecodeLength2(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DecodeLength2, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().DecodeLength2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DecodeLength2(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DecodeLength2, WINRT_WRAP(void), uint32_t);
            this->shim().DecodeLength2(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DecodeLengthKind(Windows::Devices::PointOfService::BarcodeSymbologyDecodeLengthKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DecodeLengthKind, WINRT_WRAP(Windows::Devices::PointOfService::BarcodeSymbologyDecodeLengthKind));
            *value = detach_from<Windows::Devices::PointOfService::BarcodeSymbologyDecodeLengthKind>(this->shim().DecodeLengthKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DecodeLengthKind(Windows::Devices::PointOfService::BarcodeSymbologyDecodeLengthKind value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DecodeLengthKind, WINRT_WRAP(void), Windows::Devices::PointOfService::BarcodeSymbologyDecodeLengthKind const&);
            this->shim().DecodeLengthKind(*reinterpret_cast<Windows::Devices::PointOfService::BarcodeSymbologyDecodeLengthKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDecodeLengthSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDecodeLengthSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDecodeLengthSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::ICashDrawer> : produce_base<D, Windows::Devices::PointOfService::ICashDrawer>
{
    int32_t WINRT_CALL get_DeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Capabilities(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Capabilities, WINRT_WRAP(Windows::Devices::PointOfService::CashDrawerCapabilities));
            *value = detach_from<Windows::Devices::PointOfService::CashDrawerCapabilities>(this->shim().Capabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Devices::PointOfService::CashDrawerStatus));
            *value = detach_from<Windows::Devices::PointOfService::CashDrawerStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDrawerOpen(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDrawerOpen, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDrawerOpen());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DrawerEventSource(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DrawerEventSource, WINRT_WRAP(Windows::Devices::PointOfService::CashDrawerEventSource));
            *value = detach_from<Windows::Devices::PointOfService::CashDrawerEventSource>(this->shim().DrawerEventSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClaimDrawerAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClaimDrawerAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::ClaimedCashDrawer>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::ClaimedCashDrawer>>(this->shim().ClaimDrawerAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CheckHealthAsync(Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel level, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckHealthAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>), Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().CheckHealthAsync(*reinterpret_cast<Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel const*>(&level)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStatisticsAsync(void* statisticsCategories, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStatisticsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>), Windows::Foundation::Collections::IIterable<hstring> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetStatisticsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&statisticsCategories)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_StatusUpdated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StatusUpdated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::CashDrawer, Windows::Devices::PointOfService::CashDrawerStatusUpdatedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().StatusUpdated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::CashDrawer, Windows::Devices::PointOfService::CashDrawerStatusUpdatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_StatusUpdated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(StatusUpdated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().StatusUpdated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::ICashDrawerCapabilities> : produce_base<D, Windows::Devices::PointOfService::ICashDrawerCapabilities>
{
    int32_t WINRT_CALL get_PowerReportingType(Windows::Devices::PointOfService::UnifiedPosPowerReportingType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PowerReportingType, WINRT_WRAP(Windows::Devices::PointOfService::UnifiedPosPowerReportingType));
            *value = detach_from<Windows::Devices::PointOfService::UnifiedPosPowerReportingType>(this->shim().PowerReportingType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsStatisticsReportingSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStatisticsReportingSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsStatisticsReportingSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsStatisticsUpdatingSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStatisticsUpdatingSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsStatisticsUpdatingSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsStatusReportingSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStatusReportingSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsStatusReportingSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsStatusMultiDrawerDetectSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStatusMultiDrawerDetectSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsStatusMultiDrawerDetectSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDrawerOpenSensorAvailable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDrawerOpenSensorAvailable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDrawerOpenSensorAvailable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::ICashDrawerCloseAlarm> : produce_base<D, Windows::Devices::PointOfService::ICashDrawerCloseAlarm>
{
    int32_t WINRT_CALL put_AlarmTimeout(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlarmTimeout, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().AlarmTimeout(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AlarmTimeout(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlarmTimeout, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().AlarmTimeout());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BeepFrequency(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BeepFrequency, WINRT_WRAP(void), uint32_t);
            this->shim().BeepFrequency(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BeepFrequency(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BeepFrequency, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().BeepFrequency());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BeepDuration(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BeepDuration, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().BeepDuration(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BeepDuration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BeepDuration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().BeepDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BeepDelay(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BeepDelay, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().BeepDelay(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BeepDelay(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BeepDelay, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().BeepDelay());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_AlarmTimeoutExpired(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlarmTimeoutExpired, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::CashDrawerCloseAlarm, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().AlarmTimeoutExpired(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::CashDrawerCloseAlarm, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AlarmTimeoutExpired(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AlarmTimeoutExpired, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AlarmTimeoutExpired(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL StartAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().StartAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::ICashDrawerEventSource> : produce_base<D, Windows::Devices::PointOfService::ICashDrawerEventSource>
{
    int32_t WINRT_CALL add_DrawerClosed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DrawerClosed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::CashDrawerEventSource, Windows::Devices::PointOfService::CashDrawerClosedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().DrawerClosed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::CashDrawerEventSource, Windows::Devices::PointOfService::CashDrawerClosedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DrawerClosed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DrawerClosed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DrawerClosed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_DrawerOpened(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DrawerOpened, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::CashDrawerEventSource, Windows::Devices::PointOfService::CashDrawerOpenedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().DrawerOpened(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::CashDrawerEventSource, Windows::Devices::PointOfService::CashDrawerOpenedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DrawerOpened(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DrawerOpened, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DrawerOpened(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::ICashDrawerEventSourceEventArgs> : produce_base<D, Windows::Devices::PointOfService::ICashDrawerEventSourceEventArgs>
{
    int32_t WINRT_CALL get_CashDrawer(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CashDrawer, WINRT_WRAP(Windows::Devices::PointOfService::CashDrawer));
            *value = detach_from<Windows::Devices::PointOfService::CashDrawer>(this->shim().CashDrawer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::ICashDrawerStatics> : produce_base<D, Windows::Devices::PointOfService::ICashDrawerStatics>
{
    int32_t WINRT_CALL GetDefaultAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefaultAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::CashDrawer>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::CashDrawer>>(this->shim().GetDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromIdAsync(void* deviceId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::CashDrawer>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::CashDrawer>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelector(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::ICashDrawerStatics2> : produce_base<D, Windows::Devices::PointOfService::ICashDrawerStatics2>
{
    int32_t WINRT_CALL GetDeviceSelectorWithConnectionTypes(Windows::Devices::PointOfService::PosConnectionTypes connectionTypes, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring), Windows::Devices::PointOfService::PosConnectionTypes const&);
            *value = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<Windows::Devices::PointOfService::PosConnectionTypes const*>(&connectionTypes)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::ICashDrawerStatus> : produce_base<D, Windows::Devices::PointOfService::ICashDrawerStatus>
{
    int32_t WINRT_CALL get_StatusKind(Windows::Devices::PointOfService::CashDrawerStatusKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StatusKind, WINRT_WRAP(Windows::Devices::PointOfService::CashDrawerStatusKind));
            *value = detach_from<Windows::Devices::PointOfService::CashDrawerStatusKind>(this->shim().StatusKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedStatus(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedStatus, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ExtendedStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::ICashDrawerStatusUpdatedEventArgs> : produce_base<D, Windows::Devices::PointOfService::ICashDrawerStatusUpdatedEventArgs>
{
    int32_t WINRT_CALL get_Status(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Devices::PointOfService::CashDrawerStatus));
            *value = detach_from<Windows::Devices::PointOfService::CashDrawerStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IClaimedBarcodeScanner> : produce_base<D, Windows::Devices::PointOfService::IClaimedBarcodeScanner>
{
    int32_t WINRT_CALL get_DeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsDisabledOnDataReceived(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDisabledOnDataReceived, WINRT_WRAP(void), bool);
            this->shim().IsDisabledOnDataReceived(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDisabledOnDataReceived(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDisabledOnDataReceived, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDisabledOnDataReceived());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsDecodeDataEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDecodeDataEnabled, WINRT_WRAP(void), bool);
            this->shim().IsDecodeDataEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDecodeDataEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDecodeDataEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDecodeDataEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EnableAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().EnableAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DisableAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisableAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DisableAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RetainDevice() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RetainDevice, WINRT_WRAP(void));
            this->shim().RetainDevice();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetActiveSymbologiesAsync(void* symbologies, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetActiveSymbologiesAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Foundation::Collections::IIterable<uint32_t> const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetActiveSymbologiesAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<uint32_t> const*>(&symbologies)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ResetStatisticsAsync(void* statisticsCategories, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResetStatisticsAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Foundation::Collections::IIterable<hstring> const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ResetStatisticsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&statisticsCategories)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateStatisticsAsync(void* statistics, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateStatisticsAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().UpdateStatisticsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const*>(&statistics)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetActiveProfileAsync(void* profile, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetActiveProfileAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetActiveProfileAsync(*reinterpret_cast<hstring const*>(&profile)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_DataReceived(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner, Windows::Devices::PointOfService::BarcodeScannerDataReceivedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().DataReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner, Windows::Devices::PointOfService::BarcodeScannerDataReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DataReceived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DataReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DataReceived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_TriggerPressed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TriggerPressed, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner> const&);
            *token = detach_from<winrt::event_token>(this->shim().TriggerPressed(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_TriggerPressed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(TriggerPressed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().TriggerPressed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_TriggerReleased(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TriggerReleased, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner> const&);
            *token = detach_from<winrt::event_token>(this->shim().TriggerReleased(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_TriggerReleased(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(TriggerReleased, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().TriggerReleased(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ReleaseDeviceRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReleaseDeviceRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner> const&);
            *token = detach_from<winrt::event_token>(this->shim().ReleaseDeviceRequested(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ReleaseDeviceRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ReleaseDeviceRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ReleaseDeviceRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ImagePreviewReceived(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImagePreviewReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner, Windows::Devices::PointOfService::BarcodeScannerImagePreviewReceivedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ImagePreviewReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner, Windows::Devices::PointOfService::BarcodeScannerImagePreviewReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ImagePreviewReceived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ImagePreviewReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ImagePreviewReceived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ErrorOccurred(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ErrorOccurred, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner, Windows::Devices::PointOfService::BarcodeScannerErrorOccurredEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ErrorOccurred(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner, Windows::Devices::PointOfService::BarcodeScannerErrorOccurredEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ErrorOccurred(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ErrorOccurred, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ErrorOccurred(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IClaimedBarcodeScanner1> : produce_base<D, Windows::Devices::PointOfService::IClaimedBarcodeScanner1>
{
    int32_t WINRT_CALL StartSoftwareTriggerAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartSoftwareTriggerAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().StartSoftwareTriggerAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopSoftwareTriggerAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopSoftwareTriggerAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().StopSoftwareTriggerAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IClaimedBarcodeScanner2> : produce_base<D, Windows::Devices::PointOfService::IClaimedBarcodeScanner2>
{
    int32_t WINRT_CALL GetSymbologyAttributesAsync(uint32_t barcodeSymbology, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSymbologyAttributesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::BarcodeSymbologyAttributes>), uint32_t);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::BarcodeSymbologyAttributes>>(this->shim().GetSymbologyAttributesAsync(barcodeSymbology));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetSymbologyAttributesAsync(uint32_t barcodeSymbology, void* attributes, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetSymbologyAttributesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), uint32_t, Windows::Devices::PointOfService::BarcodeSymbologyAttributes const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().SetSymbologyAttributesAsync(barcodeSymbology, *reinterpret_cast<Windows::Devices::PointOfService::BarcodeSymbologyAttributes const*>(&attributes)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IClaimedBarcodeScanner3> : produce_base<D, Windows::Devices::PointOfService::IClaimedBarcodeScanner3>
{
    int32_t WINRT_CALL ShowVideoPreviewAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowVideoPreviewAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().ShowVideoPreviewAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL HideVideoPreview() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HideVideoPreview, WINRT_WRAP(void));
            this->shim().HideVideoPreview();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsVideoPreviewShownOnEnable(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsVideoPreviewShownOnEnable, WINRT_WRAP(void), bool);
            this->shim().IsVideoPreviewShownOnEnable(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsVideoPreviewShownOnEnable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsVideoPreviewShownOnEnable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsVideoPreviewShownOnEnable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IClaimedBarcodeScanner4> : produce_base<D, Windows::Devices::PointOfService::IClaimedBarcodeScanner4>
{
    int32_t WINRT_CALL add_Closed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Closed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner, Windows::Devices::PointOfService::ClaimedBarcodeScannerClosedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedBarcodeScanner, Windows::Devices::PointOfService::ClaimedBarcodeScannerClosedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Closed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Closed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Closed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IClaimedBarcodeScannerClosedEventArgs> : produce_base<D, Windows::Devices::PointOfService::IClaimedBarcodeScannerClosedEventArgs>
{};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IClaimedCashDrawer> : produce_base<D, Windows::Devices::PointOfService::IClaimedCashDrawer>
{
    int32_t WINRT_CALL get_DeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDrawerOpen(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDrawerOpen, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDrawerOpen());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CloseAlarm(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CloseAlarm, WINRT_WRAP(Windows::Devices::PointOfService::CashDrawerCloseAlarm));
            *value = detach_from<Windows::Devices::PointOfService::CashDrawerCloseAlarm>(this->shim().CloseAlarm());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OpenDrawerAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenDrawerAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().OpenDrawerAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EnableAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().EnableAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DisableAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisableAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().DisableAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RetainDeviceAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RetainDeviceAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().RetainDeviceAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ResetStatisticsAsync(void* statisticsCategories, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResetStatisticsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Foundation::Collections::IIterable<hstring> const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().ResetStatisticsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&statisticsCategories)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateStatisticsAsync(void* statistics, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateStatisticsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().UpdateStatisticsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const*>(&statistics)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ReleaseDeviceRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReleaseDeviceRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedCashDrawer, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().ReleaseDeviceRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedCashDrawer, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ReleaseDeviceRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ReleaseDeviceRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ReleaseDeviceRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IClaimedCashDrawer2> : produce_base<D, Windows::Devices::PointOfService::IClaimedCashDrawer2>
{
    int32_t WINRT_CALL add_Closed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Closed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedCashDrawer, Windows::Devices::PointOfService::ClaimedCashDrawerClosedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedCashDrawer, Windows::Devices::PointOfService::ClaimedCashDrawerClosedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Closed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Closed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Closed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IClaimedCashDrawerClosedEventArgs> : produce_base<D, Windows::Devices::PointOfService::IClaimedCashDrawerClosedEventArgs>
{};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IClaimedJournalPrinter> : produce_base<D, Windows::Devices::PointOfService::IClaimedJournalPrinter>
{
    int32_t WINRT_CALL CreateJob(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateJob, WINRT_WRAP(Windows::Devices::PointOfService::JournalPrintJob));
            *value = detach_from<Windows::Devices::PointOfService::JournalPrintJob>(this->shim().CreateJob());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IClaimedLineDisplay> : produce_base<D, Windows::Devices::PointOfService::IClaimedLineDisplay>
{
    int32_t WINRT_CALL get_DeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Capabilities(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Capabilities, WINRT_WRAP(Windows::Devices::PointOfService::LineDisplayCapabilities));
            *value = detach_from<Windows::Devices::PointOfService::LineDisplayCapabilities>(this->shim().Capabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PhysicalDeviceName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhysicalDeviceName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PhysicalDeviceName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PhysicalDeviceDescription(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhysicalDeviceDescription, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PhysicalDeviceDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceControlDescription(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceControlDescription, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceControlDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceControlVersion(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceControlVersion, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceControlVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceServiceVersion(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceServiceVersion, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceServiceVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DefaultWindow(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultWindow, WINRT_WRAP(Windows::Devices::PointOfService::LineDisplayWindow));
            *value = detach_from<Windows::Devices::PointOfService::LineDisplayWindow>(this->shim().DefaultWindow());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RetainDevice() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RetainDevice, WINRT_WRAP(void));
            this->shim().RetainDevice();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ReleaseDeviceRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReleaseDeviceRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedLineDisplay, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().ReleaseDeviceRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedLineDisplay, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ReleaseDeviceRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ReleaseDeviceRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ReleaseDeviceRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IClaimedLineDisplay2> : produce_base<D, Windows::Devices::PointOfService::IClaimedLineDisplay2>
{
    int32_t WINRT_CALL GetStatisticsAsync(void* statisticsCategories, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStatisticsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>), Windows::Foundation::Collections::IIterable<hstring> const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetStatisticsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&statisticsCategories)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CheckHealthAsync(Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel level, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckHealthAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>), Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().CheckHealthAsync(*reinterpret_cast<Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel const*>(&level)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CheckPowerStatusAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckPowerStatusAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplayPowerStatus>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplayPowerStatus>>(this->shim().CheckPowerStatusAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_StatusUpdated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StatusUpdated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedLineDisplay, Windows::Devices::PointOfService::LineDisplayStatusUpdatedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().StatusUpdated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedLineDisplay, Windows::Devices::PointOfService::LineDisplayStatusUpdatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_StatusUpdated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(StatusUpdated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().StatusUpdated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_SupportedScreenSizesInCharacters(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedScreenSizesInCharacters, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Foundation::Size>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Foundation::Size>>(this->shim().SupportedScreenSizesInCharacters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxBitmapSizeInPixels(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxBitmapSizeInPixels, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().MaxBitmapSizeInPixels());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedCharacterSets(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedCharacterSets, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<int32_t>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<int32_t>>(this->shim().SupportedCharacterSets());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CustomGlyphs(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CustomGlyphs, WINRT_WRAP(Windows::Devices::PointOfService::LineDisplayCustomGlyphs));
            *value = detach_from<Windows::Devices::PointOfService::LineDisplayCustomGlyphs>(this->shim().CustomGlyphs());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAttributes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAttributes, WINRT_WRAP(Windows::Devices::PointOfService::LineDisplayAttributes));
            *value = detach_from<Windows::Devices::PointOfService::LineDisplayAttributes>(this->shim().GetAttributes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryUpdateAttributesAsync(void* attributes, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryUpdateAttributesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Devices::PointOfService::LineDisplayAttributes const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryUpdateAttributesAsync(*reinterpret_cast<Windows::Devices::PointOfService::LineDisplayAttributes const*>(&attributes)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySetDescriptorAsync(uint32_t descriptor, Windows::Devices::PointOfService::LineDisplayDescriptorState descriptorState, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySetDescriptorAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), uint32_t, Windows::Devices::PointOfService::LineDisplayDescriptorState const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TrySetDescriptorAsync(descriptor, *reinterpret_cast<Windows::Devices::PointOfService::LineDisplayDescriptorState const*>(&descriptorState)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryClearDescriptorsAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryClearDescriptorsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryClearDescriptorsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryCreateWindowAsync(Windows::Foundation::Rect viewport, Windows::Foundation::Size windowSize, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryCreateWindowAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplayWindow>), Windows::Foundation::Rect const, Windows::Foundation::Size const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplayWindow>>(this->shim().TryCreateWindowAsync(*reinterpret_cast<Windows::Foundation::Rect const*>(&viewport), *reinterpret_cast<Windows::Foundation::Size const*>(&windowSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryStoreStorageFileBitmapAsync(void* bitmap, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryStoreStorageFileBitmapAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplayStoredBitmap>), Windows::Storage::StorageFile const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplayStoredBitmap>>(this->shim().TryStoreStorageFileBitmapAsync(*reinterpret_cast<Windows::Storage::StorageFile const*>(&bitmap)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryStoreStorageFileBitmapWithAlignmentAsync(void* bitmap, Windows::Devices::PointOfService::LineDisplayHorizontalAlignment horizontalAlignment, Windows::Devices::PointOfService::LineDisplayVerticalAlignment verticalAlignment, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryStoreStorageFileBitmapAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplayStoredBitmap>), Windows::Storage::StorageFile const, Windows::Devices::PointOfService::LineDisplayHorizontalAlignment const, Windows::Devices::PointOfService::LineDisplayVerticalAlignment const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplayStoredBitmap>>(this->shim().TryStoreStorageFileBitmapAsync(*reinterpret_cast<Windows::Storage::StorageFile const*>(&bitmap), *reinterpret_cast<Windows::Devices::PointOfService::LineDisplayHorizontalAlignment const*>(&horizontalAlignment), *reinterpret_cast<Windows::Devices::PointOfService::LineDisplayVerticalAlignment const*>(&verticalAlignment)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryStoreStorageFileBitmapWithAlignmentAndWidthAsync(void* bitmap, Windows::Devices::PointOfService::LineDisplayHorizontalAlignment horizontalAlignment, Windows::Devices::PointOfService::LineDisplayVerticalAlignment verticalAlignment, int32_t widthInPixels, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryStoreStorageFileBitmapAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplayStoredBitmap>), Windows::Storage::StorageFile const, Windows::Devices::PointOfService::LineDisplayHorizontalAlignment const, Windows::Devices::PointOfService::LineDisplayVerticalAlignment const, int32_t);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplayStoredBitmap>>(this->shim().TryStoreStorageFileBitmapAsync(*reinterpret_cast<Windows::Storage::StorageFile const*>(&bitmap), *reinterpret_cast<Windows::Devices::PointOfService::LineDisplayHorizontalAlignment const*>(&horizontalAlignment), *reinterpret_cast<Windows::Devices::PointOfService::LineDisplayVerticalAlignment const*>(&verticalAlignment), widthInPixels));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IClaimedLineDisplay3> : produce_base<D, Windows::Devices::PointOfService::IClaimedLineDisplay3>
{
    int32_t WINRT_CALL add_Closed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Closed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedLineDisplay, Windows::Devices::PointOfService::ClaimedLineDisplayClosedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedLineDisplay, Windows::Devices::PointOfService::ClaimedLineDisplayClosedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Closed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Closed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Closed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IClaimedLineDisplayClosedEventArgs> : produce_base<D, Windows::Devices::PointOfService::IClaimedLineDisplayClosedEventArgs>
{};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IClaimedLineDisplayStatics> : produce_base<D, Windows::Devices::PointOfService::IClaimedLineDisplayStatics>
{
    int32_t WINRT_CALL FromIdAsync(void* deviceId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::ClaimedLineDisplay>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::ClaimedLineDisplay>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelector(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelectorWithConnectionTypes(Windows::Devices::PointOfService::PosConnectionTypes connectionTypes, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring), Windows::Devices::PointOfService::PosConnectionTypes const&);
            *value = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<Windows::Devices::PointOfService::PosConnectionTypes const*>(&connectionTypes)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IClaimedMagneticStripeReader> : produce_base<D, Windows::Devices::PointOfService::IClaimedMagneticStripeReader>
{
    int32_t WINRT_CALL get_DeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsDisabledOnDataReceived(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDisabledOnDataReceived, WINRT_WRAP(void), bool);
            this->shim().IsDisabledOnDataReceived(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDisabledOnDataReceived(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDisabledOnDataReceived, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDisabledOnDataReceived());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsDecodeDataEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDecodeDataEnabled, WINRT_WRAP(void), bool);
            this->shim().IsDecodeDataEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDecodeDataEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDecodeDataEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDecodeDataEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDeviceAuthenticated(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDeviceAuthenticated, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDeviceAuthenticated());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DataEncryptionAlgorithm(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataEncryptionAlgorithm, WINRT_WRAP(void), uint32_t);
            this->shim().DataEncryptionAlgorithm(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DataEncryptionAlgorithm(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataEncryptionAlgorithm, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().DataEncryptionAlgorithm());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TracksToRead(Windows::Devices::PointOfService::MagneticStripeReaderTrackIds value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TracksToRead, WINRT_WRAP(void), Windows::Devices::PointOfService::MagneticStripeReaderTrackIds const&);
            this->shim().TracksToRead(*reinterpret_cast<Windows::Devices::PointOfService::MagneticStripeReaderTrackIds const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TracksToRead(Windows::Devices::PointOfService::MagneticStripeReaderTrackIds* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TracksToRead, WINRT_WRAP(Windows::Devices::PointOfService::MagneticStripeReaderTrackIds));
            *value = detach_from<Windows::Devices::PointOfService::MagneticStripeReaderTrackIds>(this->shim().TracksToRead());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsTransmitSentinelsEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTransmitSentinelsEnabled, WINRT_WRAP(void), bool);
            this->shim().IsTransmitSentinelsEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsTransmitSentinelsEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTransmitSentinelsEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsTransmitSentinelsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EnableAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().EnableAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DisableAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisableAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DisableAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RetainDevice() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RetainDevice, WINRT_WRAP(void));
            this->shim().RetainDevice();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetErrorReportingType(Windows::Devices::PointOfService::MagneticStripeReaderErrorReportingType value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetErrorReportingType, WINRT_WRAP(void), Windows::Devices::PointOfService::MagneticStripeReaderErrorReportingType const&);
            this->shim().SetErrorReportingType(*reinterpret_cast<Windows::Devices::PointOfService::MagneticStripeReaderErrorReportingType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RetrieveDeviceAuthenticationDataAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RetrieveDeviceAuthenticationDataAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer>>(this->shim().RetrieveDeviceAuthenticationDataAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AuthenticateDeviceAsync(uint32_t __responseTokenSize, uint8_t* responseToken, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthenticateDeviceAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), array_view<uint8_t const>);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().AuthenticateDeviceAsync(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(responseToken), reinterpret_cast<uint8_t const *>(responseToken) + __responseTokenSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeAuthenticateDeviceAsync(uint32_t __responseTokenSize, uint8_t* responseToken, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeAuthenticateDeviceAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), array_view<uint8_t const>);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DeAuthenticateDeviceAsync(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(responseToken), reinterpret_cast<uint8_t const *>(responseToken) + __responseTokenSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateKeyAsync(void* key, void* keyName, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateKeyAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const, hstring const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().UpdateKeyAsync(*reinterpret_cast<hstring const*>(&key), *reinterpret_cast<hstring const*>(&keyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ResetStatisticsAsync(void* statisticsCategories, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResetStatisticsAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Foundation::Collections::IIterable<hstring> const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ResetStatisticsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&statisticsCategories)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateStatisticsAsync(void* statistics, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateStatisticsAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().UpdateStatisticsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const*>(&statistics)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_BankCardDataReceived(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BankCardDataReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader, Windows::Devices::PointOfService::MagneticStripeReaderBankCardDataReceivedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().BankCardDataReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader, Windows::Devices::PointOfService::MagneticStripeReaderBankCardDataReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_BankCardDataReceived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(BankCardDataReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().BankCardDataReceived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_AamvaCardDataReceived(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AamvaCardDataReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader, Windows::Devices::PointOfService::MagneticStripeReaderAamvaCardDataReceivedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().AamvaCardDataReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader, Windows::Devices::PointOfService::MagneticStripeReaderAamvaCardDataReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AamvaCardDataReceived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AamvaCardDataReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AamvaCardDataReceived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_VendorSpecificDataReceived(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VendorSpecificDataReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader, Windows::Devices::PointOfService::MagneticStripeReaderVendorSpecificCardDataReceivedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().VendorSpecificDataReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader, Windows::Devices::PointOfService::MagneticStripeReaderVendorSpecificCardDataReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_VendorSpecificDataReceived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(VendorSpecificDataReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().VendorSpecificDataReceived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ReleaseDeviceRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReleaseDeviceRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader> const&);
            *token = detach_from<winrt::event_token>(this->shim().ReleaseDeviceRequested(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ReleaseDeviceRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ReleaseDeviceRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ReleaseDeviceRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ErrorOccurred(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ErrorOccurred, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader, Windows::Devices::PointOfService::MagneticStripeReaderErrorOccurredEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ErrorOccurred(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader, Windows::Devices::PointOfService::MagneticStripeReaderErrorOccurredEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ErrorOccurred(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ErrorOccurred, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ErrorOccurred(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IClaimedMagneticStripeReader2> : produce_base<D, Windows::Devices::PointOfService::IClaimedMagneticStripeReader2>
{
    int32_t WINRT_CALL add_Closed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Closed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader, Windows::Devices::PointOfService::ClaimedMagneticStripeReaderClosedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedMagneticStripeReader, Windows::Devices::PointOfService::ClaimedMagneticStripeReaderClosedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Closed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Closed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Closed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IClaimedMagneticStripeReaderClosedEventArgs> : produce_base<D, Windows::Devices::PointOfService::IClaimedMagneticStripeReaderClosedEventArgs>
{};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IClaimedPosPrinter> : produce_base<D, Windows::Devices::PointOfService::IClaimedPosPrinter>
{
    int32_t WINRT_CALL get_DeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CharacterSet(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CharacterSet, WINRT_WRAP(void), uint32_t);
            this->shim().CharacterSet(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CharacterSet(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CharacterSet, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().CharacterSet());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsCoverOpen(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCoverOpen, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCoverOpen());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsCharacterSetMappingEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCharacterSetMappingEnabled, WINRT_WRAP(void), bool);
            this->shim().IsCharacterSetMappingEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsCharacterSetMappingEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCharacterSetMappingEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCharacterSetMappingEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MapMode(Windows::Devices::PointOfService::PosPrinterMapMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapMode, WINRT_WRAP(void), Windows::Devices::PointOfService::PosPrinterMapMode const&);
            this->shim().MapMode(*reinterpret_cast<Windows::Devices::PointOfService::PosPrinterMapMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MapMode(Windows::Devices::PointOfService::PosPrinterMapMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapMode, WINRT_WRAP(Windows::Devices::PointOfService::PosPrinterMapMode));
            *value = detach_from<Windows::Devices::PointOfService::PosPrinterMapMode>(this->shim().MapMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Receipt(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Receipt, WINRT_WRAP(Windows::Devices::PointOfService::ClaimedReceiptPrinter));
            *value = detach_from<Windows::Devices::PointOfService::ClaimedReceiptPrinter>(this->shim().Receipt());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Slip(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Slip, WINRT_WRAP(Windows::Devices::PointOfService::ClaimedSlipPrinter));
            *value = detach_from<Windows::Devices::PointOfService::ClaimedSlipPrinter>(this->shim().Slip());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Journal(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Journal, WINRT_WRAP(Windows::Devices::PointOfService::ClaimedJournalPrinter));
            *value = detach_from<Windows::Devices::PointOfService::ClaimedJournalPrinter>(this->shim().Journal());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EnableAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().EnableAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DisableAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisableAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().DisableAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RetainDeviceAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RetainDeviceAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().RetainDeviceAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ResetStatisticsAsync(void* statisticsCategories, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResetStatisticsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Foundation::Collections::IIterable<hstring> const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().ResetStatisticsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&statisticsCategories)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateStatisticsAsync(void* statistics, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateStatisticsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().UpdateStatisticsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const*>(&statistics)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ReleaseDeviceRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReleaseDeviceRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedPosPrinter, Windows::Devices::PointOfService::PosPrinterReleaseDeviceRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ReleaseDeviceRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedPosPrinter, Windows::Devices::PointOfService::PosPrinterReleaseDeviceRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ReleaseDeviceRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ReleaseDeviceRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ReleaseDeviceRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IClaimedPosPrinter2> : produce_base<D, Windows::Devices::PointOfService::IClaimedPosPrinter2>
{
    int32_t WINRT_CALL add_Closed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Closed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedPosPrinter, Windows::Devices::PointOfService::ClaimedPosPrinterClosedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::ClaimedPosPrinter, Windows::Devices::PointOfService::ClaimedPosPrinterClosedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Closed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Closed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Closed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IClaimedPosPrinterClosedEventArgs> : produce_base<D, Windows::Devices::PointOfService::IClaimedPosPrinterClosedEventArgs>
{};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IClaimedReceiptPrinter> : produce_base<D, Windows::Devices::PointOfService::IClaimedReceiptPrinter>
{
    int32_t WINRT_CALL get_SidewaysMaxLines(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SidewaysMaxLines, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().SidewaysMaxLines());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SidewaysMaxChars(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SidewaysMaxChars, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().SidewaysMaxChars());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LinesToPaperCut(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LinesToPaperCut, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().LinesToPaperCut());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PageSize(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PageSize, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().PageSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PrintArea(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrintArea, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().PrintArea());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateJob(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateJob, WINRT_WRAP(Windows::Devices::PointOfService::ReceiptPrintJob));
            *value = detach_from<Windows::Devices::PointOfService::ReceiptPrintJob>(this->shim().CreateJob());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IClaimedSlipPrinter> : produce_base<D, Windows::Devices::PointOfService::IClaimedSlipPrinter>
{
    int32_t WINRT_CALL get_SidewaysMaxLines(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SidewaysMaxLines, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().SidewaysMaxLines());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SidewaysMaxChars(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SidewaysMaxChars, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().SidewaysMaxChars());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxLines(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxLines, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaxLines());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LinesNearEndToEnd(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LinesNearEndToEnd, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().LinesNearEndToEnd());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PrintSide(Windows::Devices::PointOfService::PosPrinterPrintSide* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrintSide, WINRT_WRAP(Windows::Devices::PointOfService::PosPrinterPrintSide));
            *value = detach_from<Windows::Devices::PointOfService::PosPrinterPrintSide>(this->shim().PrintSide());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PageSize(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PageSize, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().PageSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PrintArea(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrintArea, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().PrintArea());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OpenJaws() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenJaws, WINRT_WRAP(void));
            this->shim().OpenJaws();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CloseJaws() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CloseJaws, WINRT_WRAP(void));
            this->shim().CloseJaws();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InsertSlipAsync(Windows::Foundation::TimeSpan timeout, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertSlipAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Foundation::TimeSpan const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().InsertSlipAsync(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&timeout)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveSlipAsync(Windows::Foundation::TimeSpan timeout, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveSlipAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Foundation::TimeSpan const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().RemoveSlipAsync(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&timeout)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ChangePrintSide(Windows::Devices::PointOfService::PosPrinterPrintSide printSide) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChangePrintSide, WINRT_WRAP(void), Windows::Devices::PointOfService::PosPrinterPrintSide const&);
            this->shim().ChangePrintSide(*reinterpret_cast<Windows::Devices::PointOfService::PosPrinterPrintSide const*>(&printSide));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateJob(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateJob, WINRT_WRAP(Windows::Devices::PointOfService::SlipPrintJob));
            *value = detach_from<Windows::Devices::PointOfService::SlipPrintJob>(this->shim().CreateJob());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation> : produce_base<D, Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation>
{
    int32_t WINRT_CALL put_CharactersPerLine(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CharactersPerLine, WINRT_WRAP(void), uint32_t);
            this->shim().CharactersPerLine(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CharactersPerLine(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CharactersPerLine, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().CharactersPerLine());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LineHeight(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineHeight, WINRT_WRAP(void), uint32_t);
            this->shim().LineHeight(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LineHeight(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineHeight, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().LineHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LineSpacing(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineSpacing, WINRT_WRAP(void), uint32_t);
            this->shim().LineSpacing(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LineSpacing(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineSpacing, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().LineSpacing());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LineWidth(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineWidth, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().LineWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsLetterQuality(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsLetterQuality, WINRT_WRAP(void), bool);
            this->shim().IsLetterQuality(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsLetterQuality(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsLetterQuality, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsLetterQuality());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsPaperNearEnd(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPaperNearEnd, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPaperNearEnd());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ColorCartridge(Windows::Devices::PointOfService::PosPrinterColorCartridge value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColorCartridge, WINRT_WRAP(void), Windows::Devices::PointOfService::PosPrinterColorCartridge const&);
            this->shim().ColorCartridge(*reinterpret_cast<Windows::Devices::PointOfService::PosPrinterColorCartridge const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ColorCartridge(Windows::Devices::PointOfService::PosPrinterColorCartridge* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColorCartridge, WINRT_WRAP(Windows::Devices::PointOfService::PosPrinterColorCartridge));
            *value = detach_from<Windows::Devices::PointOfService::PosPrinterColorCartridge>(this->shim().ColorCartridge());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsCoverOpen(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCoverOpen, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCoverOpen());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsCartridgeRemoved(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCartridgeRemoved, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCartridgeRemoved());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsCartridgeEmpty(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCartridgeEmpty, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCartridgeEmpty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsHeadCleaning(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsHeadCleaning, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsHeadCleaning());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsPaperEmpty(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPaperEmpty, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPaperEmpty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsReadyToPrint(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsReadyToPrint, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsReadyToPrint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ValidateData(void* data, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ValidateData, WINRT_WRAP(bool), hstring const&);
            *result = detach_from<bool>(this->shim().ValidateData(*reinterpret_cast<hstring const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities> : produce_base<D, Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities>
{
    int32_t WINRT_CALL get_IsPrinterPresent(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPrinterPresent, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPrinterPresent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDualColorSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDualColorSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDualColorSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ColorCartridgeCapabilities(Windows::Devices::PointOfService::PosPrinterColorCapabilities* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColorCartridgeCapabilities, WINRT_WRAP(Windows::Devices::PointOfService::PosPrinterColorCapabilities));
            *value = detach_from<Windows::Devices::PointOfService::PosPrinterColorCapabilities>(this->shim().ColorCartridgeCapabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CartridgeSensors(Windows::Devices::PointOfService::PosPrinterCartridgeSensors* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CartridgeSensors, WINRT_WRAP(Windows::Devices::PointOfService::PosPrinterCartridgeSensors));
            *value = detach_from<Windows::Devices::PointOfService::PosPrinterCartridgeSensors>(this->shim().CartridgeSensors());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsBoldSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsBoldSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsBoldSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsItalicSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsItalicSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsItalicSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsUnderlineSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsUnderlineSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsUnderlineSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDoubleHighPrintSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDoubleHighPrintSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDoubleHighPrintSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDoubleWidePrintSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDoubleWidePrintSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDoubleWidePrintSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDoubleHighDoubleWidePrintSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDoubleHighDoubleWidePrintSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDoubleHighDoubleWidePrintSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsPaperEmptySensorSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPaperEmptySensorSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPaperEmptySensorSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsPaperNearEndSensorSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPaperNearEndSensorSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPaperNearEndSensorSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedCharactersPerLine(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedCharactersPerLine, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<uint32_t>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<uint32_t>>(this->shim().SupportedCharactersPerLine());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::ICommonReceiptSlipCapabilities> : produce_base<D, Windows::Devices::PointOfService::ICommonReceiptSlipCapabilities>
{
    int32_t WINRT_CALL get_IsBarcodeSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsBarcodeSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsBarcodeSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsBitmapSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsBitmapSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsBitmapSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsLeft90RotationSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsLeft90RotationSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsLeft90RotationSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsRight90RotationSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRight90RotationSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsRight90RotationSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Is180RotationSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Is180RotationSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Is180RotationSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsPrintAreaSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPrintAreaSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPrintAreaSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RuledLineCapabilities(Windows::Devices::PointOfService::PosPrinterRuledLineCapabilities* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RuledLineCapabilities, WINRT_WRAP(Windows::Devices::PointOfService::PosPrinterRuledLineCapabilities));
            *value = detach_from<Windows::Devices::PointOfService::PosPrinterRuledLineCapabilities>(this->shim().RuledLineCapabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedBarcodeRotations(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedBarcodeRotations, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::PointOfService::PosPrinterRotation>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::PointOfService::PosPrinterRotation>>(this->shim().SupportedBarcodeRotations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedBitmapRotations(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedBitmapRotations, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::PointOfService::PosPrinterRotation>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::PointOfService::PosPrinterRotation>>(this->shim().SupportedBitmapRotations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IJournalPrintJob> : produce_base<D, Windows::Devices::PointOfService::IJournalPrintJob>
{
    int32_t WINRT_CALL Print(void* data, void* printOptions) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Print, WINRT_WRAP(void), hstring const&, Windows::Devices::PointOfService::PosPrinterPrintOptions const&);
            this->shim().Print(*reinterpret_cast<hstring const*>(&data), *reinterpret_cast<Windows::Devices::PointOfService::PosPrinterPrintOptions const*>(&printOptions));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FeedPaperByLine(int32_t lineCount) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FeedPaperByLine, WINRT_WRAP(void), int32_t);
            this->shim().FeedPaperByLine(lineCount);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FeedPaperByMapModeUnit(int32_t distance) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FeedPaperByMapModeUnit, WINRT_WRAP(void), int32_t);
            this->shim().FeedPaperByMapModeUnit(distance);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IJournalPrinterCapabilities> : produce_base<D, Windows::Devices::PointOfService::IJournalPrinterCapabilities>
{};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IJournalPrinterCapabilities2> : produce_base<D, Windows::Devices::PointOfService::IJournalPrinterCapabilities2>
{
    int32_t WINRT_CALL get_IsReverseVideoSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsReverseVideoSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsReverseVideoSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsStrikethroughSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStrikethroughSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsStrikethroughSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsSuperscriptSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSuperscriptSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSuperscriptSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsSubscriptSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSubscriptSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSubscriptSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsReversePaperFeedByLineSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsReversePaperFeedByLineSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsReversePaperFeedByLineSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsReversePaperFeedByMapModeUnitSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsReversePaperFeedByMapModeUnitSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsReversePaperFeedByMapModeUnitSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::ILineDisplay> : produce_base<D, Windows::Devices::PointOfService::ILineDisplay>
{
    int32_t WINRT_CALL get_DeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Capabilities(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Capabilities, WINRT_WRAP(Windows::Devices::PointOfService::LineDisplayCapabilities));
            *value = detach_from<Windows::Devices::PointOfService::LineDisplayCapabilities>(this->shim().Capabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PhysicalDeviceName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhysicalDeviceName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PhysicalDeviceName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PhysicalDeviceDescription(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhysicalDeviceDescription, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PhysicalDeviceDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceControlDescription(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceControlDescription, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceControlDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceControlVersion(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceControlVersion, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceControlVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceServiceVersion(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceServiceVersion, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceServiceVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClaimAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClaimAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::ClaimedLineDisplay>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::ClaimedLineDisplay>>(this->shim().ClaimAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::ILineDisplay2> : produce_base<D, Windows::Devices::PointOfService::ILineDisplay2>
{
    int32_t WINRT_CALL CheckPowerStatusAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckPowerStatusAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplayPowerStatus>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplayPowerStatus>>(this->shim().CheckPowerStatusAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::ILineDisplayAttributes> : produce_base<D, Windows::Devices::PointOfService::ILineDisplayAttributes>
{
    int32_t WINRT_CALL get_IsPowerNotifyEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPowerNotifyEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPowerNotifyEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsPowerNotifyEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPowerNotifyEnabled, WINRT_WRAP(void), bool);
            this->shim().IsPowerNotifyEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Brightness(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Brightness, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Brightness());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Brightness(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Brightness, WINRT_WRAP(void), int32_t);
            this->shim().Brightness(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BlinkRate(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BlinkRate, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().BlinkRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BlinkRate(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BlinkRate, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().BlinkRate(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScreenSizeInCharacters(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScreenSizeInCharacters, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().ScreenSizeInCharacters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ScreenSizeInCharacters(Windows::Foundation::Size value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScreenSizeInCharacters, WINRT_WRAP(void), Windows::Foundation::Size const&);
            this->shim().ScreenSizeInCharacters(*reinterpret_cast<Windows::Foundation::Size const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CharacterSet(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CharacterSet, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().CharacterSet());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CharacterSet(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CharacterSet, WINRT_WRAP(void), int32_t);
            this->shim().CharacterSet(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsCharacterSetMappingEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCharacterSetMappingEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCharacterSetMappingEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsCharacterSetMappingEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCharacterSetMappingEnabled, WINRT_WRAP(void), bool);
            this->shim().IsCharacterSetMappingEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CurrentWindow(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentWindow, WINRT_WRAP(Windows::Devices::PointOfService::LineDisplayWindow));
            *value = detach_from<Windows::Devices::PointOfService::LineDisplayWindow>(this->shim().CurrentWindow());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CurrentWindow(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentWindow, WINRT_WRAP(void), Windows::Devices::PointOfService::LineDisplayWindow const&);
            this->shim().CurrentWindow(*reinterpret_cast<Windows::Devices::PointOfService::LineDisplayWindow const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::ILineDisplayCapabilities> : produce_base<D, Windows::Devices::PointOfService::ILineDisplayCapabilities>
{
    int32_t WINRT_CALL get_IsStatisticsReportingSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStatisticsReportingSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsStatisticsReportingSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsStatisticsUpdatingSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStatisticsUpdatingSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsStatisticsUpdatingSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PowerReportingType(Windows::Devices::PointOfService::UnifiedPosPowerReportingType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PowerReportingType, WINRT_WRAP(Windows::Devices::PointOfService::UnifiedPosPowerReportingType));
            *value = detach_from<Windows::Devices::PointOfService::UnifiedPosPowerReportingType>(this->shim().PowerReportingType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanChangeScreenSize(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanChangeScreenSize, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanChangeScreenSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanDisplayBitmaps(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanDisplayBitmaps, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanDisplayBitmaps());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanReadCharacterAtCursor(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanReadCharacterAtCursor, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanReadCharacterAtCursor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanMapCharacterSets(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanMapCharacterSets, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanMapCharacterSets());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanDisplayCustomGlyphs(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanDisplayCustomGlyphs, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanDisplayCustomGlyphs());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanReverse(Windows::Devices::PointOfService::LineDisplayTextAttributeGranularity* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanReverse, WINRT_WRAP(Windows::Devices::PointOfService::LineDisplayTextAttributeGranularity));
            *value = detach_from<Windows::Devices::PointOfService::LineDisplayTextAttributeGranularity>(this->shim().CanReverse());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanBlink(Windows::Devices::PointOfService::LineDisplayTextAttributeGranularity* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanBlink, WINRT_WRAP(Windows::Devices::PointOfService::LineDisplayTextAttributeGranularity));
            *value = detach_from<Windows::Devices::PointOfService::LineDisplayTextAttributeGranularity>(this->shim().CanBlink());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanChangeBlinkRate(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanChangeBlinkRate, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanChangeBlinkRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsBrightnessSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsBrightnessSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsBrightnessSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsCursorSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCursorSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCursorSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsHorizontalMarqueeSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsHorizontalMarqueeSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsHorizontalMarqueeSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsVerticalMarqueeSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsVerticalMarqueeSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsVerticalMarqueeSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsInterCharacterWaitSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInterCharacterWaitSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsInterCharacterWaitSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedDescriptors(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedDescriptors, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().SupportedDescriptors());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedWindows(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedWindows, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().SupportedWindows());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::ILineDisplayCursor> : produce_base<D, Windows::Devices::PointOfService::ILineDisplayCursor>
{
    int32_t WINRT_CALL get_CanCustomize(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanCustomize, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanCustomize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsBlinkSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsBlinkSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsBlinkSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsBlockSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsBlockSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsBlockSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsHalfBlockSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsHalfBlockSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsHalfBlockSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsUnderlineSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsUnderlineSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsUnderlineSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsReverseSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsReverseSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsReverseSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsOtherSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOtherSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsOtherSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAttributes(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAttributes, WINRT_WRAP(Windows::Devices::PointOfService::LineDisplayCursorAttributes));
            *result = detach_from<Windows::Devices::PointOfService::LineDisplayCursorAttributes>(this->shim().GetAttributes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryUpdateAttributesAsync(void* attributes, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryUpdateAttributesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Devices::PointOfService::LineDisplayCursorAttributes const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryUpdateAttributesAsync(*reinterpret_cast<Windows::Devices::PointOfService::LineDisplayCursorAttributes const*>(&attributes)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::ILineDisplayCursorAttributes> : produce_base<D, Windows::Devices::PointOfService::ILineDisplayCursorAttributes>
{
    int32_t WINRT_CALL get_IsBlinkEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsBlinkEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsBlinkEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsBlinkEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsBlinkEnabled, WINRT_WRAP(void), bool);
            this->shim().IsBlinkEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CursorType(Windows::Devices::PointOfService::LineDisplayCursorType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CursorType, WINRT_WRAP(Windows::Devices::PointOfService::LineDisplayCursorType));
            *value = detach_from<Windows::Devices::PointOfService::LineDisplayCursorType>(this->shim().CursorType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CursorType(Windows::Devices::PointOfService::LineDisplayCursorType value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CursorType, WINRT_WRAP(void), Windows::Devices::PointOfService::LineDisplayCursorType const&);
            this->shim().CursorType(*reinterpret_cast<Windows::Devices::PointOfService::LineDisplayCursorType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsAutoAdvanceEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAutoAdvanceEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsAutoAdvanceEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsAutoAdvanceEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAutoAdvanceEnabled, WINRT_WRAP(void), bool);
            this->shim().IsAutoAdvanceEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Position(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Position(Windows::Foundation::Point value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(void), Windows::Foundation::Point const&);
            this->shim().Position(*reinterpret_cast<Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::ILineDisplayCustomGlyphs> : produce_base<D, Windows::Devices::PointOfService::ILineDisplayCustomGlyphs>
{
    int32_t WINRT_CALL get_SizeInPixels(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SizeInPixels, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().SizeInPixels());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedGlyphCodes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedGlyphCodes, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<uint32_t>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<uint32_t>>(this->shim().SupportedGlyphCodes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryRedefineAsync(uint32_t glyphCode, void* glyphData, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryRedefineAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), uint32_t, Windows::Storage::Streams::IBuffer const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryRedefineAsync(glyphCode, *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&glyphData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::ILineDisplayMarquee> : produce_base<D, Windows::Devices::PointOfService::ILineDisplayMarquee>
{
    int32_t WINRT_CALL get_Format(Windows::Devices::PointOfService::LineDisplayMarqueeFormat* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Format, WINRT_WRAP(Windows::Devices::PointOfService::LineDisplayMarqueeFormat));
            *value = detach_from<Windows::Devices::PointOfService::LineDisplayMarqueeFormat>(this->shim().Format());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Format(Windows::Devices::PointOfService::LineDisplayMarqueeFormat value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Format, WINRT_WRAP(void), Windows::Devices::PointOfService::LineDisplayMarqueeFormat const&);
            this->shim().Format(*reinterpret_cast<Windows::Devices::PointOfService::LineDisplayMarqueeFormat const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RepeatWaitInterval(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RepeatWaitInterval, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().RepeatWaitInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RepeatWaitInterval(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RepeatWaitInterval, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().RepeatWaitInterval(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScrollWaitInterval(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScrollWaitInterval, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().ScrollWaitInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ScrollWaitInterval(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScrollWaitInterval, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().ScrollWaitInterval(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryStartScrollingAsync(Windows::Devices::PointOfService::LineDisplayScrollDirection direction, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryStartScrollingAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Devices::PointOfService::LineDisplayScrollDirection const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryStartScrollingAsync(*reinterpret_cast<Windows::Devices::PointOfService::LineDisplayScrollDirection const*>(&direction)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryStopScrollingAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryStopScrollingAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryStopScrollingAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::ILineDisplayStatics> : produce_base<D, Windows::Devices::PointOfService::ILineDisplayStatics>
{
    int32_t WINRT_CALL FromIdAsync(void* deviceId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplay>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplay>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDefaultAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefaultAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplay>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplay>>(this->shim().GetDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelector(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelectorWithConnectionTypes(Windows::Devices::PointOfService::PosConnectionTypes connectionTypes, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring), Windows::Devices::PointOfService::PosConnectionTypes const&);
            *value = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<Windows::Devices::PointOfService::PosConnectionTypes const*>(&connectionTypes)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::ILineDisplayStatics2> : produce_base<D, Windows::Devices::PointOfService::ILineDisplayStatics2>
{
    int32_t WINRT_CALL get_StatisticsCategorySelector(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StatisticsCategorySelector, WINRT_WRAP(Windows::Devices::PointOfService::LineDisplayStatisticsCategorySelector));
            *value = detach_from<Windows::Devices::PointOfService::LineDisplayStatisticsCategorySelector>(this->shim().StatisticsCategorySelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::ILineDisplayStatisticsCategorySelector> : produce_base<D, Windows::Devices::PointOfService::ILineDisplayStatisticsCategorySelector>
{
    int32_t WINRT_CALL get_AllStatistics(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllStatistics, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AllStatistics());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UnifiedPosStatistics(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnifiedPosStatistics, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UnifiedPosStatistics());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ManufacturerStatistics(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ManufacturerStatistics, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ManufacturerStatistics());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::ILineDisplayStatusUpdatedEventArgs> : produce_base<D, Windows::Devices::PointOfService::ILineDisplayStatusUpdatedEventArgs>
{
    int32_t WINRT_CALL get_Status(Windows::Devices::PointOfService::LineDisplayPowerStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Devices::PointOfService::LineDisplayPowerStatus));
            *value = detach_from<Windows::Devices::PointOfService::LineDisplayPowerStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::ILineDisplayStoredBitmap> : produce_base<D, Windows::Devices::PointOfService::ILineDisplayStoredBitmap>
{
    int32_t WINRT_CALL get_EscapeSequence(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EscapeSequence, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EscapeSequence());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryDeleteAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryDeleteAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryDeleteAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::ILineDisplayWindow> : produce_base<D, Windows::Devices::PointOfService::ILineDisplayWindow>
{
    int32_t WINRT_CALL get_SizeInCharacters(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SizeInCharacters, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().SizeInCharacters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InterCharacterWaitInterval(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InterCharacterWaitInterval, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().InterCharacterWaitInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InterCharacterWaitInterval(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InterCharacterWaitInterval, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().InterCharacterWaitInterval(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryRefreshAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryRefreshAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryRefreshAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryDisplayTextAsync(void* text, Windows::Devices::PointOfService::LineDisplayTextAttribute displayAttribute, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryDisplayTextAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const, Windows::Devices::PointOfService::LineDisplayTextAttribute const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryDisplayTextAsync(*reinterpret_cast<hstring const*>(&text), *reinterpret_cast<Windows::Devices::PointOfService::LineDisplayTextAttribute const*>(&displayAttribute)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryDisplayTextAtPositionAsync(void* text, Windows::Devices::PointOfService::LineDisplayTextAttribute displayAttribute, Windows::Foundation::Point startPosition, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryDisplayTextAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const, Windows::Devices::PointOfService::LineDisplayTextAttribute const, Windows::Foundation::Point const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryDisplayTextAsync(*reinterpret_cast<hstring const*>(&text), *reinterpret_cast<Windows::Devices::PointOfService::LineDisplayTextAttribute const*>(&displayAttribute), *reinterpret_cast<Windows::Foundation::Point const*>(&startPosition)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryDisplayTextNormalAsync(void* text, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryDisplayTextAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryDisplayTextAsync(*reinterpret_cast<hstring const*>(&text)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryScrollTextAsync(Windows::Devices::PointOfService::LineDisplayScrollDirection direction, uint32_t numberOfColumnsOrRows, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryScrollTextAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Devices::PointOfService::LineDisplayScrollDirection const, uint32_t);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryScrollTextAsync(*reinterpret_cast<Windows::Devices::PointOfService::LineDisplayScrollDirection const*>(&direction), numberOfColumnsOrRows));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryClearTextAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryClearTextAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryClearTextAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::ILineDisplayWindow2> : produce_base<D, Windows::Devices::PointOfService::ILineDisplayWindow2>
{
    int32_t WINRT_CALL get_Cursor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cursor, WINRT_WRAP(Windows::Devices::PointOfService::LineDisplayCursor));
            *value = detach_from<Windows::Devices::PointOfService::LineDisplayCursor>(this->shim().Cursor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Marquee(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Marquee, WINRT_WRAP(Windows::Devices::PointOfService::LineDisplayMarquee));
            *value = detach_from<Windows::Devices::PointOfService::LineDisplayMarquee>(this->shim().Marquee());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadCharacterAtCursorAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadCharacterAtCursorAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<uint32_t>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<uint32_t>>(this->shim().ReadCharacterAtCursorAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryDisplayStoredBitmapAtCursorAsync(void* bitmap, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryDisplayStoredBitmapAtCursorAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Devices::PointOfService::LineDisplayStoredBitmap const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryDisplayStoredBitmapAtCursorAsync(*reinterpret_cast<Windows::Devices::PointOfService::LineDisplayStoredBitmap const*>(&bitmap)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryDisplayStorageFileBitmapAtCursorAsync(void* bitmap, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryDisplayStorageFileBitmapAtCursorAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Storage::StorageFile const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryDisplayStorageFileBitmapAtCursorAsync(*reinterpret_cast<Windows::Storage::StorageFile const*>(&bitmap)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryDisplayStorageFileBitmapAtCursorWithAlignmentAsync(void* bitmap, Windows::Devices::PointOfService::LineDisplayHorizontalAlignment horizontalAlignment, Windows::Devices::PointOfService::LineDisplayVerticalAlignment verticalAlignment, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryDisplayStorageFileBitmapAtCursorAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Storage::StorageFile const, Windows::Devices::PointOfService::LineDisplayHorizontalAlignment const, Windows::Devices::PointOfService::LineDisplayVerticalAlignment const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryDisplayStorageFileBitmapAtCursorAsync(*reinterpret_cast<Windows::Storage::StorageFile const*>(&bitmap), *reinterpret_cast<Windows::Devices::PointOfService::LineDisplayHorizontalAlignment const*>(&horizontalAlignment), *reinterpret_cast<Windows::Devices::PointOfService::LineDisplayVerticalAlignment const*>(&verticalAlignment)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryDisplayStorageFileBitmapAtCursorWithAlignmentAndWidthAsync(void* bitmap, Windows::Devices::PointOfService::LineDisplayHorizontalAlignment horizontalAlignment, Windows::Devices::PointOfService::LineDisplayVerticalAlignment verticalAlignment, int32_t widthInPixels, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryDisplayStorageFileBitmapAtCursorAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Storage::StorageFile const, Windows::Devices::PointOfService::LineDisplayHorizontalAlignment const, Windows::Devices::PointOfService::LineDisplayVerticalAlignment const, int32_t);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryDisplayStorageFileBitmapAtCursorAsync(*reinterpret_cast<Windows::Storage::StorageFile const*>(&bitmap), *reinterpret_cast<Windows::Devices::PointOfService::LineDisplayHorizontalAlignment const*>(&horizontalAlignment), *reinterpret_cast<Windows::Devices::PointOfService::LineDisplayVerticalAlignment const*>(&verticalAlignment), widthInPixels));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryDisplayStorageFileBitmapAtPointAsync(void* bitmap, Windows::Foundation::Point offsetInPixels, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryDisplayStorageFileBitmapAtPointAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Storage::StorageFile const, Windows::Foundation::Point const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryDisplayStorageFileBitmapAtPointAsync(*reinterpret_cast<Windows::Storage::StorageFile const*>(&bitmap), *reinterpret_cast<Windows::Foundation::Point const*>(&offsetInPixels)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryDisplayStorageFileBitmapAtPointWithWidthAsync(void* bitmap, Windows::Foundation::Point offsetInPixels, int32_t widthInPixels, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryDisplayStorageFileBitmapAtPointAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Storage::StorageFile const, Windows::Foundation::Point const, int32_t);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryDisplayStorageFileBitmapAtPointAsync(*reinterpret_cast<Windows::Storage::StorageFile const*>(&bitmap), *reinterpret_cast<Windows::Foundation::Point const*>(&offsetInPixels), widthInPixels));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IMagneticStripeReader> : produce_base<D, Windows::Devices::PointOfService::IMagneticStripeReader>
{
    int32_t WINRT_CALL get_DeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Capabilities(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Capabilities, WINRT_WRAP(Windows::Devices::PointOfService::MagneticStripeReaderCapabilities));
            *value = detach_from<Windows::Devices::PointOfService::MagneticStripeReaderCapabilities>(this->shim().Capabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedCardTypes(uint32_t* __valueSize, uint32_t** value) noexcept final
    {
        try
        {
            *__valueSize = 0;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedCardTypes, WINRT_WRAP(com_array<uint32_t>));
            std::tie(*__valueSize, *value) = detach_abi(this->shim().SupportedCardTypes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceAuthenticationProtocol(Windows::Devices::PointOfService::MagneticStripeReaderAuthenticationProtocol* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceAuthenticationProtocol, WINRT_WRAP(Windows::Devices::PointOfService::MagneticStripeReaderAuthenticationProtocol));
            *value = detach_from<Windows::Devices::PointOfService::MagneticStripeReaderAuthenticationProtocol>(this->shim().DeviceAuthenticationProtocol());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CheckHealthAsync(Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel level, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckHealthAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>), Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().CheckHealthAsync(*reinterpret_cast<Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel const*>(&level)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClaimReaderAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClaimReaderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::ClaimedMagneticStripeReader>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::ClaimedMagneticStripeReader>>(this->shim().ClaimReaderAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RetrieveStatisticsAsync(void* statisticsCategories, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RetrieveStatisticsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer>), Windows::Foundation::Collections::IIterable<hstring> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer>>(this->shim().RetrieveStatisticsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&statisticsCategories)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetErrorReportingType(Windows::Devices::PointOfService::MagneticStripeReaderErrorReportingType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetErrorReportingType, WINRT_WRAP(Windows::Devices::PointOfService::MagneticStripeReaderErrorReportingType));
            *value = detach_from<Windows::Devices::PointOfService::MagneticStripeReaderErrorReportingType>(this->shim().GetErrorReportingType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_StatusUpdated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StatusUpdated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::MagneticStripeReader, Windows::Devices::PointOfService::MagneticStripeReaderStatusUpdatedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().StatusUpdated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::MagneticStripeReader, Windows::Devices::PointOfService::MagneticStripeReaderStatusUpdatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_StatusUpdated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(StatusUpdated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().StatusUpdated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs> : produce_base<D, Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs>
{
    int32_t WINRT_CALL get_Report(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Report, WINRT_WRAP(Windows::Devices::PointOfService::MagneticStripeReaderReport));
            *value = detach_from<Windows::Devices::PointOfService::MagneticStripeReaderReport>(this->shim().Report());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LicenseNumber(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LicenseNumber, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().LicenseNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExpirationDate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpirationDate, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ExpirationDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Restrictions(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Restrictions, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Restrictions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Class(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Class, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Class());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Endorsements(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Endorsements, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Endorsements());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BirthDate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BirthDate, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BirthDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL get_Surname(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Surname, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Surname());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Suffix(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Suffix, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Suffix());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Gender(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Gender, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Gender());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HairColor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HairColor, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().HairColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EyeColor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EyeColor, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EyeColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Height(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Height, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Height());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Weight(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Weight, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Weight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL get_State(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().State());
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
struct produce<D, Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs> : produce_base<D, Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs>
{
    int32_t WINRT_CALL get_Report(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Report, WINRT_WRAP(Windows::Devices::PointOfService::MagneticStripeReaderReport));
            *value = detach_from<Windows::Devices::PointOfService::MagneticStripeReaderReport>(this->shim().Report());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AccountNumber(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccountNumber, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AccountNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExpirationDate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpirationDate, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ExpirationDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServiceCode(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceCode, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ServiceCode());
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

    int32_t WINRT_CALL get_MiddleInitial(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MiddleInitial, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MiddleInitial());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Surname(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Surname, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Surname());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Suffix(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Suffix, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Suffix());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities> : produce_base<D, Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities>
{
    int32_t WINRT_CALL get_CardAuthentication(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CardAuthentication, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CardAuthentication());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedEncryptionAlgorithms(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedEncryptionAlgorithms, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().SupportedEncryptionAlgorithms());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AuthenticationLevel(Windows::Devices::PointOfService::MagneticStripeReaderAuthenticationLevel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthenticationLevel, WINRT_WRAP(Windows::Devices::PointOfService::MagneticStripeReaderAuthenticationLevel));
            *value = detach_from<Windows::Devices::PointOfService::MagneticStripeReaderAuthenticationLevel>(this->shim().AuthenticationLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsIsoSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsIsoSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsIsoSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsJisOneSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsJisOneSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsJisOneSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsJisTwoSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsJisTwoSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsJisTwoSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PowerReportingType(Windows::Devices::PointOfService::UnifiedPosPowerReportingType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PowerReportingType, WINRT_WRAP(Windows::Devices::PointOfService::UnifiedPosPowerReportingType));
            *value = detach_from<Windows::Devices::PointOfService::UnifiedPosPowerReportingType>(this->shim().PowerReportingType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsStatisticsReportingSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStatisticsReportingSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsStatisticsReportingSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsStatisticsUpdatingSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStatisticsUpdatingSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsStatisticsUpdatingSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsTrackDataMaskingSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTrackDataMaskingSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsTrackDataMaskingSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsTransmitSentinelsSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTransmitSentinelsSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsTransmitSentinelsSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IMagneticStripeReaderCardTypesStatics> : produce_base<D, Windows::Devices::PointOfService::IMagneticStripeReaderCardTypesStatics>
{
    int32_t WINRT_CALL get_Unknown(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Unknown, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Unknown());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Bank(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bank, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Bank());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Aamva(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Aamva, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Aamva());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedBase(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedBase, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ExtendedBase());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IMagneticStripeReaderEncryptionAlgorithmsStatics> : produce_base<D, Windows::Devices::PointOfService::IMagneticStripeReaderEncryptionAlgorithmsStatics>
{
    int32_t WINRT_CALL get_None(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(None, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().None());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TripleDesDukpt(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TripleDesDukpt, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().TripleDesDukpt());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedBase(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedBase, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ExtendedBase());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IMagneticStripeReaderErrorOccurredEventArgs> : produce_base<D, Windows::Devices::PointOfService::IMagneticStripeReaderErrorOccurredEventArgs>
{
    int32_t WINRT_CALL get_Track1Status(Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Track1Status, WINRT_WRAP(Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType));
            *value = detach_from<Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType>(this->shim().Track1Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Track2Status(Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Track2Status, WINRT_WRAP(Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType));
            *value = detach_from<Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType>(this->shim().Track2Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Track3Status(Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Track3Status, WINRT_WRAP(Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType));
            *value = detach_from<Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType>(this->shim().Track3Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Track4Status(Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Track4Status, WINRT_WRAP(Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType));
            *value = detach_from<Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType>(this->shim().Track4Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ErrorData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ErrorData, WINRT_WRAP(Windows::Devices::PointOfService::UnifiedPosErrorData));
            *value = detach_from<Windows::Devices::PointOfService::UnifiedPosErrorData>(this->shim().ErrorData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PartialInputData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PartialInputData, WINRT_WRAP(Windows::Devices::PointOfService::MagneticStripeReaderReport));
            *value = detach_from<Windows::Devices::PointOfService::MagneticStripeReaderReport>(this->shim().PartialInputData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IMagneticStripeReaderReport> : produce_base<D, Windows::Devices::PointOfService::IMagneticStripeReaderReport>
{
    int32_t WINRT_CALL get_CardType(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CardType, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().CardType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Track1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Track1, WINRT_WRAP(Windows::Devices::PointOfService::MagneticStripeReaderTrackData));
            *value = detach_from<Windows::Devices::PointOfService::MagneticStripeReaderTrackData>(this->shim().Track1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Track2(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Track2, WINRT_WRAP(Windows::Devices::PointOfService::MagneticStripeReaderTrackData));
            *value = detach_from<Windows::Devices::PointOfService::MagneticStripeReaderTrackData>(this->shim().Track2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Track3(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Track3, WINRT_WRAP(Windows::Devices::PointOfService::MagneticStripeReaderTrackData));
            *value = detach_from<Windows::Devices::PointOfService::MagneticStripeReaderTrackData>(this->shim().Track3());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Track4(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Track4, WINRT_WRAP(Windows::Devices::PointOfService::MagneticStripeReaderTrackData));
            *value = detach_from<Windows::Devices::PointOfService::MagneticStripeReaderTrackData>(this->shim().Track4());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Properties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IMapView<hstring, hstring>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<hstring, hstring>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CardAuthenticationData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CardAuthenticationData, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().CardAuthenticationData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CardAuthenticationDataLength(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CardAuthenticationDataLength, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().CardAuthenticationDataLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AdditionalSecurityInformation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AdditionalSecurityInformation, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().AdditionalSecurityInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IMagneticStripeReaderStatics> : produce_base<D, Windows::Devices::PointOfService::IMagneticStripeReaderStatics>
{
    int32_t WINRT_CALL GetDefaultAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefaultAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::MagneticStripeReader>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::MagneticStripeReader>>(this->shim().GetDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromIdAsync(void* deviceId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::MagneticStripeReader>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::MagneticStripeReader>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelector(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IMagneticStripeReaderStatics2> : produce_base<D, Windows::Devices::PointOfService::IMagneticStripeReaderStatics2>
{
    int32_t WINRT_CALL GetDeviceSelectorWithConnectionTypes(Windows::Devices::PointOfService::PosConnectionTypes connectionTypes, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring), Windows::Devices::PointOfService::PosConnectionTypes const&);
            *value = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<Windows::Devices::PointOfService::PosConnectionTypes const*>(&connectionTypes)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IMagneticStripeReaderStatusUpdatedEventArgs> : produce_base<D, Windows::Devices::PointOfService::IMagneticStripeReaderStatusUpdatedEventArgs>
{
    int32_t WINRT_CALL get_Status(Windows::Devices::PointOfService::MagneticStripeReaderStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Devices::PointOfService::MagneticStripeReaderStatus));
            *value = detach_from<Windows::Devices::PointOfService::MagneticStripeReaderStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedStatus(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedStatus, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ExtendedStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IMagneticStripeReaderTrackData> : produce_base<D, Windows::Devices::PointOfService::IMagneticStripeReaderTrackData>
{
    int32_t WINRT_CALL get_Data(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Data, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().Data());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DiscretionaryData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DiscretionaryData, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().DiscretionaryData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EncryptedData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EncryptedData, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().EncryptedData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IMagneticStripeReaderVendorSpecificCardDataReceivedEventArgs> : produce_base<D, Windows::Devices::PointOfService::IMagneticStripeReaderVendorSpecificCardDataReceivedEventArgs>
{
    int32_t WINRT_CALL get_Report(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Report, WINRT_WRAP(Windows::Devices::PointOfService::MagneticStripeReaderReport));
            *value = detach_from<Windows::Devices::PointOfService::MagneticStripeReaderReport>(this->shim().Report());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IPosPrinter> : produce_base<D, Windows::Devices::PointOfService::IPosPrinter>
{
    int32_t WINRT_CALL get_DeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Capabilities(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Capabilities, WINRT_WRAP(Windows::Devices::PointOfService::PosPrinterCapabilities));
            *value = detach_from<Windows::Devices::PointOfService::PosPrinterCapabilities>(this->shim().Capabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedCharacterSets(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedCharacterSets, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<uint32_t>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<uint32_t>>(this->shim().SupportedCharacterSets());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedTypeFaces(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedTypeFaces, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().SupportedTypeFaces());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Devices::PointOfService::PosPrinterStatus));
            *value = detach_from<Windows::Devices::PointOfService::PosPrinterStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClaimPrinterAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClaimPrinterAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::ClaimedPosPrinter>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::ClaimedPosPrinter>>(this->shim().ClaimPrinterAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CheckHealthAsync(Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel level, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckHealthAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>), Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().CheckHealthAsync(*reinterpret_cast<Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel const*>(&level)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStatisticsAsync(void* statisticsCategories, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStatisticsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>), Windows::Foundation::Collections::IIterable<hstring> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetStatisticsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&statisticsCategories)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_StatusUpdated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StatusUpdated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::PosPrinter, Windows::Devices::PointOfService::PosPrinterStatusUpdatedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().StatusUpdated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::PosPrinter, Windows::Devices::PointOfService::PosPrinterStatusUpdatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_StatusUpdated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(StatusUpdated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().StatusUpdated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IPosPrinter2> : produce_base<D, Windows::Devices::PointOfService::IPosPrinter2>
{
    int32_t WINRT_CALL get_SupportedBarcodeSymbologies(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedBarcodeSymbologies, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<uint32_t>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<uint32_t>>(this->shim().SupportedBarcodeSymbologies());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFontProperty(void* typeface, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFontProperty, WINRT_WRAP(Windows::Devices::PointOfService::PosPrinterFontProperty), hstring const&);
            *result = detach_from<Windows::Devices::PointOfService::PosPrinterFontProperty>(this->shim().GetFontProperty(*reinterpret_cast<hstring const*>(&typeface)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IPosPrinterCapabilities> : produce_base<D, Windows::Devices::PointOfService::IPosPrinterCapabilities>
{
    int32_t WINRT_CALL get_PowerReportingType(Windows::Devices::PointOfService::UnifiedPosPowerReportingType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PowerReportingType, WINRT_WRAP(Windows::Devices::PointOfService::UnifiedPosPowerReportingType));
            *value = detach_from<Windows::Devices::PointOfService::UnifiedPosPowerReportingType>(this->shim().PowerReportingType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsStatisticsReportingSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStatisticsReportingSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsStatisticsReportingSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsStatisticsUpdatingSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStatisticsUpdatingSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsStatisticsUpdatingSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DefaultCharacterSet(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultCharacterSet, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().DefaultCharacterSet());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasCoverSensor(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasCoverSensor, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasCoverSensor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanMapCharacterSet(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanMapCharacterSet, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanMapCharacterSet());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsTransactionSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTransactionSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsTransactionSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Receipt(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Receipt, WINRT_WRAP(Windows::Devices::PointOfService::ReceiptPrinterCapabilities));
            *value = detach_from<Windows::Devices::PointOfService::ReceiptPrinterCapabilities>(this->shim().Receipt());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Slip(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Slip, WINRT_WRAP(Windows::Devices::PointOfService::SlipPrinterCapabilities));
            *value = detach_from<Windows::Devices::PointOfService::SlipPrinterCapabilities>(this->shim().Slip());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Journal(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Journal, WINRT_WRAP(Windows::Devices::PointOfService::JournalPrinterCapabilities));
            *value = detach_from<Windows::Devices::PointOfService::JournalPrinterCapabilities>(this->shim().Journal());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IPosPrinterCharacterSetIdsStatics> : produce_base<D, Windows::Devices::PointOfService::IPosPrinterCharacterSetIdsStatics>
{
    int32_t WINRT_CALL get_Utf16LE(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Utf16LE, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Utf16LE());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Ascii(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Ascii, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Ascii());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Ansi(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Ansi, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Ansi());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IPosPrinterFontProperty> : produce_base<D, Windows::Devices::PointOfService::IPosPrinterFontProperty>
{
    int32_t WINRT_CALL get_TypeFace(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TypeFace, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TypeFace());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsScalableToAnySize(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsScalableToAnySize, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsScalableToAnySize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CharacterSizes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CharacterSizes, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::PointOfService::SizeUInt32>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::PointOfService::SizeUInt32>>(this->shim().CharacterSizes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IPosPrinterJob> : produce_base<D, Windows::Devices::PointOfService::IPosPrinterJob>
{
    int32_t WINRT_CALL Print(void* data) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Print, WINRT_WRAP(void), hstring const&);
            this->shim().Print(*reinterpret_cast<hstring const*>(&data));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PrintLine(void* data) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrintLine, WINRT_WRAP(void), hstring const&);
            this->shim().PrintLine(*reinterpret_cast<hstring const*>(&data));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PrintNewline() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrintLine, WINRT_WRAP(void));
            this->shim().PrintLine();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ExecuteAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExecuteAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().ExecuteAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IPosPrinterPrintOptions> : produce_base<D, Windows::Devices::PointOfService::IPosPrinterPrintOptions>
{
    int32_t WINRT_CALL get_TypeFace(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TypeFace, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TypeFace());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TypeFace(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TypeFace, WINRT_WRAP(void), hstring const&);
            this->shim().TypeFace(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CharacterHeight(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CharacterHeight, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().CharacterHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CharacterHeight(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CharacterHeight, WINRT_WRAP(void), uint32_t);
            this->shim().CharacterHeight(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Bold(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bold, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Bold());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Bold(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bold, WINRT_WRAP(void), bool);
            this->shim().Bold(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Italic(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Italic, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Italic());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Italic(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Italic, WINRT_WRAP(void), bool);
            this->shim().Italic(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Underline(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Underline, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Underline());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Underline(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Underline, WINRT_WRAP(void), bool);
            this->shim().Underline(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReverseVideo(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReverseVideo, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ReverseVideo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ReverseVideo(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReverseVideo, WINRT_WRAP(void), bool);
            this->shim().ReverseVideo(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Strikethrough(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Strikethrough, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Strikethrough());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Strikethrough(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Strikethrough, WINRT_WRAP(void), bool);
            this->shim().Strikethrough(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Superscript(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Superscript, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Superscript());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Superscript(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Superscript, WINRT_WRAP(void), bool);
            this->shim().Superscript(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Subscript(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Subscript, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Subscript());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Subscript(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Subscript, WINRT_WRAP(void), bool);
            this->shim().Subscript(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DoubleWide(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DoubleWide, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().DoubleWide());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DoubleWide(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DoubleWide, WINRT_WRAP(void), bool);
            this->shim().DoubleWide(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DoubleHigh(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DoubleHigh, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().DoubleHigh());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DoubleHigh(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DoubleHigh, WINRT_WRAP(void), bool);
            this->shim().DoubleHigh(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Alignment(Windows::Devices::PointOfService::PosPrinterAlignment* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Alignment, WINRT_WRAP(Windows::Devices::PointOfService::PosPrinterAlignment));
            *value = detach_from<Windows::Devices::PointOfService::PosPrinterAlignment>(this->shim().Alignment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Alignment(Windows::Devices::PointOfService::PosPrinterAlignment value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Alignment, WINRT_WRAP(void), Windows::Devices::PointOfService::PosPrinterAlignment const&);
            this->shim().Alignment(*reinterpret_cast<Windows::Devices::PointOfService::PosPrinterAlignment const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CharacterSet(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CharacterSet, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().CharacterSet());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CharacterSet(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CharacterSet, WINRT_WRAP(void), uint32_t);
            this->shim().CharacterSet(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IPosPrinterReleaseDeviceRequestedEventArgs> : produce_base<D, Windows::Devices::PointOfService::IPosPrinterReleaseDeviceRequestedEventArgs>
{};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IPosPrinterStatics> : produce_base<D, Windows::Devices::PointOfService::IPosPrinterStatics>
{
    int32_t WINRT_CALL GetDefaultAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefaultAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::PosPrinter>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::PosPrinter>>(this->shim().GetDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromIdAsync(void* deviceId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::PosPrinter>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::PosPrinter>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelector(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IPosPrinterStatics2> : produce_base<D, Windows::Devices::PointOfService::IPosPrinterStatics2>
{
    int32_t WINRT_CALL GetDeviceSelectorWithConnectionTypes(Windows::Devices::PointOfService::PosConnectionTypes connectionTypes, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring), Windows::Devices::PointOfService::PosConnectionTypes const&);
            *value = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<Windows::Devices::PointOfService::PosConnectionTypes const*>(&connectionTypes)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IPosPrinterStatus> : produce_base<D, Windows::Devices::PointOfService::IPosPrinterStatus>
{
    int32_t WINRT_CALL get_StatusKind(Windows::Devices::PointOfService::PosPrinterStatusKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StatusKind, WINRT_WRAP(Windows::Devices::PointOfService::PosPrinterStatusKind));
            *value = detach_from<Windows::Devices::PointOfService::PosPrinterStatusKind>(this->shim().StatusKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedStatus(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedStatus, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ExtendedStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IPosPrinterStatusUpdatedEventArgs> : produce_base<D, Windows::Devices::PointOfService::IPosPrinterStatusUpdatedEventArgs>
{
    int32_t WINRT_CALL get_Status(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Devices::PointOfService::PosPrinterStatus));
            *value = detach_from<Windows::Devices::PointOfService::PosPrinterStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IReceiptOrSlipJob> : produce_base<D, Windows::Devices::PointOfService::IReceiptOrSlipJob>
{
    int32_t WINRT_CALL SetBarcodeRotation(Windows::Devices::PointOfService::PosPrinterRotation value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetBarcodeRotation, WINRT_WRAP(void), Windows::Devices::PointOfService::PosPrinterRotation const&);
            this->shim().SetBarcodeRotation(*reinterpret_cast<Windows::Devices::PointOfService::PosPrinterRotation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPrintRotation(Windows::Devices::PointOfService::PosPrinterRotation value, bool includeBitmaps) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPrintRotation, WINRT_WRAP(void), Windows::Devices::PointOfService::PosPrinterRotation const&, bool);
            this->shim().SetPrintRotation(*reinterpret_cast<Windows::Devices::PointOfService::PosPrinterRotation const*>(&value), includeBitmaps);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPrintArea(Windows::Foundation::Rect value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPrintArea, WINRT_WRAP(void), Windows::Foundation::Rect const&);
            this->shim().SetPrintArea(*reinterpret_cast<Windows::Foundation::Rect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetBitmap(uint32_t bitmapNumber, void* bitmap, Windows::Devices::PointOfService::PosPrinterAlignment alignment) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetBitmap, WINRT_WRAP(void), uint32_t, Windows::Graphics::Imaging::BitmapFrame const&, Windows::Devices::PointOfService::PosPrinterAlignment const&);
            this->shim().SetBitmap(bitmapNumber, *reinterpret_cast<Windows::Graphics::Imaging::BitmapFrame const*>(&bitmap), *reinterpret_cast<Windows::Devices::PointOfService::PosPrinterAlignment const*>(&alignment));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetBitmapCustomWidthStandardAlign(uint32_t bitmapNumber, void* bitmap, Windows::Devices::PointOfService::PosPrinterAlignment alignment, uint32_t width) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetBitmap, WINRT_WRAP(void), uint32_t, Windows::Graphics::Imaging::BitmapFrame const&, Windows::Devices::PointOfService::PosPrinterAlignment const&, uint32_t);
            this->shim().SetBitmap(bitmapNumber, *reinterpret_cast<Windows::Graphics::Imaging::BitmapFrame const*>(&bitmap), *reinterpret_cast<Windows::Devices::PointOfService::PosPrinterAlignment const*>(&alignment), width);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetCustomAlignedBitmap(uint32_t bitmapNumber, void* bitmap, uint32_t alignmentDistance) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetCustomAlignedBitmap, WINRT_WRAP(void), uint32_t, Windows::Graphics::Imaging::BitmapFrame const&, uint32_t);
            this->shim().SetCustomAlignedBitmap(bitmapNumber, *reinterpret_cast<Windows::Graphics::Imaging::BitmapFrame const*>(&bitmap), alignmentDistance);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetBitmapCustomWidthCustomAlign(uint32_t bitmapNumber, void* bitmap, uint32_t alignmentDistance, uint32_t width) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetCustomAlignedBitmap, WINRT_WRAP(void), uint32_t, Windows::Graphics::Imaging::BitmapFrame const&, uint32_t, uint32_t);
            this->shim().SetCustomAlignedBitmap(bitmapNumber, *reinterpret_cast<Windows::Graphics::Imaging::BitmapFrame const*>(&bitmap), alignmentDistance, width);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PrintSavedBitmap(uint32_t bitmapNumber) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrintSavedBitmap, WINRT_WRAP(void), uint32_t);
            this->shim().PrintSavedBitmap(bitmapNumber);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DrawRuledLine(void* positionList, Windows::Devices::PointOfService::PosPrinterLineDirection lineDirection, uint32_t lineWidth, Windows::Devices::PointOfService::PosPrinterLineStyle lineStyle, uint32_t lineColor) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DrawRuledLine, WINRT_WRAP(void), hstring const&, Windows::Devices::PointOfService::PosPrinterLineDirection const&, uint32_t, Windows::Devices::PointOfService::PosPrinterLineStyle const&, uint32_t);
            this->shim().DrawRuledLine(*reinterpret_cast<hstring const*>(&positionList), *reinterpret_cast<Windows::Devices::PointOfService::PosPrinterLineDirection const*>(&lineDirection), lineWidth, *reinterpret_cast<Windows::Devices::PointOfService::PosPrinterLineStyle const*>(&lineStyle), lineColor);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PrintBarcode(void* data, uint32_t symbology, uint32_t height, uint32_t width, Windows::Devices::PointOfService::PosPrinterBarcodeTextPosition textPosition, Windows::Devices::PointOfService::PosPrinterAlignment alignment) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrintBarcode, WINRT_WRAP(void), hstring const&, uint32_t, uint32_t, uint32_t, Windows::Devices::PointOfService::PosPrinterBarcodeTextPosition const&, Windows::Devices::PointOfService::PosPrinterAlignment const&);
            this->shim().PrintBarcode(*reinterpret_cast<hstring const*>(&data), symbology, height, width, *reinterpret_cast<Windows::Devices::PointOfService::PosPrinterBarcodeTextPosition const*>(&textPosition), *reinterpret_cast<Windows::Devices::PointOfService::PosPrinterAlignment const*>(&alignment));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PrintBarcodeCustomAlign(void* data, uint32_t symbology, uint32_t height, uint32_t width, Windows::Devices::PointOfService::PosPrinterBarcodeTextPosition textPosition, uint32_t alignmentDistance) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrintBarcodeCustomAlign, WINRT_WRAP(void), hstring const&, uint32_t, uint32_t, uint32_t, Windows::Devices::PointOfService::PosPrinterBarcodeTextPosition const&, uint32_t);
            this->shim().PrintBarcodeCustomAlign(*reinterpret_cast<hstring const*>(&data), symbology, height, width, *reinterpret_cast<Windows::Devices::PointOfService::PosPrinterBarcodeTextPosition const*>(&textPosition), alignmentDistance);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PrintBitmap(void* bitmap, Windows::Devices::PointOfService::PosPrinterAlignment alignment) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrintBitmap, WINRT_WRAP(void), Windows::Graphics::Imaging::BitmapFrame const&, Windows::Devices::PointOfService::PosPrinterAlignment const&);
            this->shim().PrintBitmap(*reinterpret_cast<Windows::Graphics::Imaging::BitmapFrame const*>(&bitmap), *reinterpret_cast<Windows::Devices::PointOfService::PosPrinterAlignment const*>(&alignment));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PrintBitmapCustomWidthStandardAlign(void* bitmap, Windows::Devices::PointOfService::PosPrinterAlignment alignment, uint32_t width) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrintBitmap, WINRT_WRAP(void), Windows::Graphics::Imaging::BitmapFrame const&, Windows::Devices::PointOfService::PosPrinterAlignment const&, uint32_t);
            this->shim().PrintBitmap(*reinterpret_cast<Windows::Graphics::Imaging::BitmapFrame const*>(&bitmap), *reinterpret_cast<Windows::Devices::PointOfService::PosPrinterAlignment const*>(&alignment), width);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PrintCustomAlignedBitmap(void* bitmap, uint32_t alignmentDistance) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrintCustomAlignedBitmap, WINRT_WRAP(void), Windows::Graphics::Imaging::BitmapFrame const&, uint32_t);
            this->shim().PrintCustomAlignedBitmap(*reinterpret_cast<Windows::Graphics::Imaging::BitmapFrame const*>(&bitmap), alignmentDistance);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PrintBitmapCustomWidthCustomAlign(void* bitmap, uint32_t alignmentDistance, uint32_t width) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrintCustomAlignedBitmap, WINRT_WRAP(void), Windows::Graphics::Imaging::BitmapFrame const&, uint32_t, uint32_t);
            this->shim().PrintCustomAlignedBitmap(*reinterpret_cast<Windows::Graphics::Imaging::BitmapFrame const*>(&bitmap), alignmentDistance, width);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IReceiptPrintJob> : produce_base<D, Windows::Devices::PointOfService::IReceiptPrintJob>
{
    int32_t WINRT_CALL MarkFeed(Windows::Devices::PointOfService::PosPrinterMarkFeedKind kind) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MarkFeed, WINRT_WRAP(void), Windows::Devices::PointOfService::PosPrinterMarkFeedKind const&);
            this->shim().MarkFeed(*reinterpret_cast<Windows::Devices::PointOfService::PosPrinterMarkFeedKind const*>(&kind));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CutPaper(double percentage) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CutPaper, WINRT_WRAP(void), double);
            this->shim().CutPaper(percentage);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CutPaperDefault() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CutPaper, WINRT_WRAP(void));
            this->shim().CutPaper();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IReceiptPrintJob2> : produce_base<D, Windows::Devices::PointOfService::IReceiptPrintJob2>
{
    int32_t WINRT_CALL StampPaper() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StampPaper, WINRT_WRAP(void));
            this->shim().StampPaper();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Print(void* data, void* printOptions) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Print, WINRT_WRAP(void), hstring const&, Windows::Devices::PointOfService::PosPrinterPrintOptions const&);
            this->shim().Print(*reinterpret_cast<hstring const*>(&data), *reinterpret_cast<Windows::Devices::PointOfService::PosPrinterPrintOptions const*>(&printOptions));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FeedPaperByLine(int32_t lineCount) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FeedPaperByLine, WINRT_WRAP(void), int32_t);
            this->shim().FeedPaperByLine(lineCount);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FeedPaperByMapModeUnit(int32_t distance) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FeedPaperByMapModeUnit, WINRT_WRAP(void), int32_t);
            this->shim().FeedPaperByMapModeUnit(distance);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IReceiptPrinterCapabilities> : produce_base<D, Windows::Devices::PointOfService::IReceiptPrinterCapabilities>
{
    int32_t WINRT_CALL get_CanCutPaper(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanCutPaper, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanCutPaper());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsStampSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStampSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsStampSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MarkFeedCapabilities(Windows::Devices::PointOfService::PosPrinterMarkFeedCapabilities* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MarkFeedCapabilities, WINRT_WRAP(Windows::Devices::PointOfService::PosPrinterMarkFeedCapabilities));
            *value = detach_from<Windows::Devices::PointOfService::PosPrinterMarkFeedCapabilities>(this->shim().MarkFeedCapabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IReceiptPrinterCapabilities2> : produce_base<D, Windows::Devices::PointOfService::IReceiptPrinterCapabilities2>
{
    int32_t WINRT_CALL get_IsReverseVideoSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsReverseVideoSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsReverseVideoSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsStrikethroughSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStrikethroughSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsStrikethroughSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsSuperscriptSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSuperscriptSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSuperscriptSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsSubscriptSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSubscriptSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSubscriptSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsReversePaperFeedByLineSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsReversePaperFeedByLineSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsReversePaperFeedByLineSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsReversePaperFeedByMapModeUnitSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsReversePaperFeedByMapModeUnitSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsReversePaperFeedByMapModeUnitSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::ISlipPrintJob> : produce_base<D, Windows::Devices::PointOfService::ISlipPrintJob>
{
    int32_t WINRT_CALL Print(void* data, void* printOptions) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Print, WINRT_WRAP(void), hstring const&, Windows::Devices::PointOfService::PosPrinterPrintOptions const&);
            this->shim().Print(*reinterpret_cast<hstring const*>(&data), *reinterpret_cast<Windows::Devices::PointOfService::PosPrinterPrintOptions const*>(&printOptions));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FeedPaperByLine(int32_t lineCount) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FeedPaperByLine, WINRT_WRAP(void), int32_t);
            this->shim().FeedPaperByLine(lineCount);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FeedPaperByMapModeUnit(int32_t distance) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FeedPaperByMapModeUnit, WINRT_WRAP(void), int32_t);
            this->shim().FeedPaperByMapModeUnit(distance);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::ISlipPrinterCapabilities> : produce_base<D, Windows::Devices::PointOfService::ISlipPrinterCapabilities>
{
    int32_t WINRT_CALL get_IsFullLengthSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsFullLengthSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsFullLengthSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsBothSidesPrintingSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsBothSidesPrintingSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsBothSidesPrintingSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::ISlipPrinterCapabilities2> : produce_base<D, Windows::Devices::PointOfService::ISlipPrinterCapabilities2>
{
    int32_t WINRT_CALL get_IsReverseVideoSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsReverseVideoSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsReverseVideoSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsStrikethroughSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStrikethroughSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsStrikethroughSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsSuperscriptSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSuperscriptSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSuperscriptSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsSubscriptSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSubscriptSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSubscriptSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsReversePaperFeedByLineSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsReversePaperFeedByLineSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsReversePaperFeedByLineSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsReversePaperFeedByMapModeUnitSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsReversePaperFeedByMapModeUnitSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsReversePaperFeedByMapModeUnitSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IUnifiedPosErrorData> : produce_base<D, Windows::Devices::PointOfService::IUnifiedPosErrorData>
{
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

    int32_t WINRT_CALL get_Severity(Windows::Devices::PointOfService::UnifiedPosErrorSeverity* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Severity, WINRT_WRAP(Windows::Devices::PointOfService::UnifiedPosErrorSeverity));
            *value = detach_from<Windows::Devices::PointOfService::UnifiedPosErrorSeverity>(this->shim().Severity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Reason(Windows::Devices::PointOfService::UnifiedPosErrorReason* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reason, WINRT_WRAP(Windows::Devices::PointOfService::UnifiedPosErrorReason));
            *value = detach_from<Windows::Devices::PointOfService::UnifiedPosErrorReason>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedReason(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedReason, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ExtendedReason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::IUnifiedPosErrorDataFactory> : produce_base<D, Windows::Devices::PointOfService::IUnifiedPosErrorDataFactory>
{
    int32_t WINRT_CALL CreateInstance(void* message, Windows::Devices::PointOfService::UnifiedPosErrorSeverity severity, Windows::Devices::PointOfService::UnifiedPosErrorReason reason, uint32_t extendedReason, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::Devices::PointOfService::UnifiedPosErrorData), hstring const&, Windows::Devices::PointOfService::UnifiedPosErrorSeverity const&, Windows::Devices::PointOfService::UnifiedPosErrorReason const&, uint32_t);
            *result = detach_from<Windows::Devices::PointOfService::UnifiedPosErrorData>(this->shim().CreateInstance(*reinterpret_cast<hstring const*>(&message), *reinterpret_cast<Windows::Devices::PointOfService::UnifiedPosErrorSeverity const*>(&severity), *reinterpret_cast<Windows::Devices::PointOfService::UnifiedPosErrorReason const*>(&reason), extendedReason));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::PointOfService {

inline Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::BarcodeScanner> BarcodeScanner::GetDefaultAsync()
{
    return impl::call_factory<BarcodeScanner, Windows::Devices::PointOfService::IBarcodeScannerStatics>([&](auto&& f) { return f.GetDefaultAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::BarcodeScanner> BarcodeScanner::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<BarcodeScanner, Windows::Devices::PointOfService::IBarcodeScannerStatics>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

inline hstring BarcodeScanner::GetDeviceSelector()
{
    return impl::call_factory<BarcodeScanner, Windows::Devices::PointOfService::IBarcodeScannerStatics>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline hstring BarcodeScanner::GetDeviceSelector(Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes)
{
    return impl::call_factory<BarcodeScanner, Windows::Devices::PointOfService::IBarcodeScannerStatics2>([&](auto&& f) { return f.GetDeviceSelector(connectionTypes); });
}

inline BarcodeScannerReport::BarcodeScannerReport(uint32_t scanDataType, Windows::Storage::Streams::IBuffer const& scanData, Windows::Storage::Streams::IBuffer const& scanDataLabel) :
    BarcodeScannerReport(impl::call_factory<BarcodeScannerReport, Windows::Devices::PointOfService::IBarcodeScannerReportFactory>([&](auto&& f) { return f.CreateInstance(scanDataType, scanData, scanDataLabel); }))
{}

inline uint32_t BarcodeSymbologies::Unknown()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Unknown(); });
}

inline uint32_t BarcodeSymbologies::Ean8()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Ean8(); });
}

inline uint32_t BarcodeSymbologies::Ean8Add2()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Ean8Add2(); });
}

inline uint32_t BarcodeSymbologies::Ean8Add5()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Ean8Add5(); });
}

inline uint32_t BarcodeSymbologies::Eanv()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Eanv(); });
}

inline uint32_t BarcodeSymbologies::EanvAdd2()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.EanvAdd2(); });
}

inline uint32_t BarcodeSymbologies::EanvAdd5()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.EanvAdd5(); });
}

inline uint32_t BarcodeSymbologies::Ean13()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Ean13(); });
}

inline uint32_t BarcodeSymbologies::Ean13Add2()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Ean13Add2(); });
}

inline uint32_t BarcodeSymbologies::Ean13Add5()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Ean13Add5(); });
}

inline uint32_t BarcodeSymbologies::Isbn()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Isbn(); });
}

inline uint32_t BarcodeSymbologies::IsbnAdd5()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.IsbnAdd5(); });
}

inline uint32_t BarcodeSymbologies::Ismn()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Ismn(); });
}

inline uint32_t BarcodeSymbologies::IsmnAdd2()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.IsmnAdd2(); });
}

inline uint32_t BarcodeSymbologies::IsmnAdd5()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.IsmnAdd5(); });
}

inline uint32_t BarcodeSymbologies::Issn()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Issn(); });
}

inline uint32_t BarcodeSymbologies::IssnAdd2()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.IssnAdd2(); });
}

inline uint32_t BarcodeSymbologies::IssnAdd5()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.IssnAdd5(); });
}

inline uint32_t BarcodeSymbologies::Ean99()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Ean99(); });
}

inline uint32_t BarcodeSymbologies::Ean99Add2()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Ean99Add2(); });
}

inline uint32_t BarcodeSymbologies::Ean99Add5()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Ean99Add5(); });
}

inline uint32_t BarcodeSymbologies::Upca()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Upca(); });
}

inline uint32_t BarcodeSymbologies::UpcaAdd2()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.UpcaAdd2(); });
}

inline uint32_t BarcodeSymbologies::UpcaAdd5()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.UpcaAdd5(); });
}

inline uint32_t BarcodeSymbologies::Upce()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Upce(); });
}

inline uint32_t BarcodeSymbologies::UpceAdd2()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.UpceAdd2(); });
}

inline uint32_t BarcodeSymbologies::UpceAdd5()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.UpceAdd5(); });
}

inline uint32_t BarcodeSymbologies::UpcCoupon()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.UpcCoupon(); });
}

inline uint32_t BarcodeSymbologies::TfStd()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.TfStd(); });
}

inline uint32_t BarcodeSymbologies::TfDis()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.TfDis(); });
}

inline uint32_t BarcodeSymbologies::TfInt()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.TfInt(); });
}

inline uint32_t BarcodeSymbologies::TfInd()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.TfInd(); });
}

inline uint32_t BarcodeSymbologies::TfMat()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.TfMat(); });
}

inline uint32_t BarcodeSymbologies::TfIata()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.TfIata(); });
}

inline uint32_t BarcodeSymbologies::Gs1DatabarType1()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Gs1DatabarType1(); });
}

inline uint32_t BarcodeSymbologies::Gs1DatabarType2()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Gs1DatabarType2(); });
}

inline uint32_t BarcodeSymbologies::Gs1DatabarType3()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Gs1DatabarType3(); });
}

inline uint32_t BarcodeSymbologies::Code39()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Code39(); });
}

inline uint32_t BarcodeSymbologies::Code39Ex()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Code39Ex(); });
}

inline uint32_t BarcodeSymbologies::Trioptic39()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Trioptic39(); });
}

inline uint32_t BarcodeSymbologies::Code32()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Code32(); });
}

inline uint32_t BarcodeSymbologies::Pzn()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Pzn(); });
}

inline uint32_t BarcodeSymbologies::Code93()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Code93(); });
}

inline uint32_t BarcodeSymbologies::Code93Ex()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Code93Ex(); });
}

inline uint32_t BarcodeSymbologies::Code128()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Code128(); });
}

inline uint32_t BarcodeSymbologies::Gs1128()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Gs1128(); });
}

inline uint32_t BarcodeSymbologies::Gs1128Coupon()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Gs1128Coupon(); });
}

inline uint32_t BarcodeSymbologies::UccEan128()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.UccEan128(); });
}

inline uint32_t BarcodeSymbologies::Sisac()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Sisac(); });
}

inline uint32_t BarcodeSymbologies::Isbt()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Isbt(); });
}

inline uint32_t BarcodeSymbologies::Codabar()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Codabar(); });
}

inline uint32_t BarcodeSymbologies::Code11()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Code11(); });
}

inline uint32_t BarcodeSymbologies::Msi()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Msi(); });
}

inline uint32_t BarcodeSymbologies::Plessey()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Plessey(); });
}

inline uint32_t BarcodeSymbologies::Telepen()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Telepen(); });
}

inline uint32_t BarcodeSymbologies::Code16k()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Code16k(); });
}

inline uint32_t BarcodeSymbologies::CodablockA()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.CodablockA(); });
}

inline uint32_t BarcodeSymbologies::CodablockF()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.CodablockF(); });
}

inline uint32_t BarcodeSymbologies::Codablock128()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Codablock128(); });
}

inline uint32_t BarcodeSymbologies::Code49()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Code49(); });
}

inline uint32_t BarcodeSymbologies::Aztec()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Aztec(); });
}

inline uint32_t BarcodeSymbologies::DataCode()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.DataCode(); });
}

inline uint32_t BarcodeSymbologies::DataMatrix()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.DataMatrix(); });
}

inline uint32_t BarcodeSymbologies::HanXin()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.HanXin(); });
}

inline uint32_t BarcodeSymbologies::Maxicode()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Maxicode(); });
}

inline uint32_t BarcodeSymbologies::MicroPdf417()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.MicroPdf417(); });
}

inline uint32_t BarcodeSymbologies::MicroQr()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.MicroQr(); });
}

inline uint32_t BarcodeSymbologies::Pdf417()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Pdf417(); });
}

inline uint32_t BarcodeSymbologies::Qr()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Qr(); });
}

inline uint32_t BarcodeSymbologies::MsTag()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.MsTag(); });
}

inline uint32_t BarcodeSymbologies::Ccab()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Ccab(); });
}

inline uint32_t BarcodeSymbologies::Ccc()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Ccc(); });
}

inline uint32_t BarcodeSymbologies::Tlc39()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Tlc39(); });
}

inline uint32_t BarcodeSymbologies::AusPost()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.AusPost(); });
}

inline uint32_t BarcodeSymbologies::CanPost()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.CanPost(); });
}

inline uint32_t BarcodeSymbologies::ChinaPost()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.ChinaPost(); });
}

inline uint32_t BarcodeSymbologies::DutchKix()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.DutchKix(); });
}

inline uint32_t BarcodeSymbologies::InfoMail()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.InfoMail(); });
}

inline uint32_t BarcodeSymbologies::ItalianPost25()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.ItalianPost25(); });
}

inline uint32_t BarcodeSymbologies::ItalianPost39()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.ItalianPost39(); });
}

inline uint32_t BarcodeSymbologies::JapanPost()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.JapanPost(); });
}

inline uint32_t BarcodeSymbologies::KoreanPost()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.KoreanPost(); });
}

inline uint32_t BarcodeSymbologies::SwedenPost()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.SwedenPost(); });
}

inline uint32_t BarcodeSymbologies::UkPost()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.UkPost(); });
}

inline uint32_t BarcodeSymbologies::UsIntelligent()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.UsIntelligent(); });
}

inline uint32_t BarcodeSymbologies::UsIntelligentPkg()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.UsIntelligentPkg(); });
}

inline uint32_t BarcodeSymbologies::UsPlanet()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.UsPlanet(); });
}

inline uint32_t BarcodeSymbologies::UsPostNet()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.UsPostNet(); });
}

inline uint32_t BarcodeSymbologies::Us4StateFics()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Us4StateFics(); });
}

inline uint32_t BarcodeSymbologies::OcrA()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.OcrA(); });
}

inline uint32_t BarcodeSymbologies::OcrB()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.OcrB(); });
}

inline uint32_t BarcodeSymbologies::Micr()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.Micr(); });
}

inline uint32_t BarcodeSymbologies::ExtendedBase()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.ExtendedBase(); });
}

inline hstring BarcodeSymbologies::GetName(uint32_t scanDataType)
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>([&](auto&& f) { return f.GetName(scanDataType); });
}

inline uint32_t BarcodeSymbologies::Gs1DWCode()
{
    return impl::call_factory<BarcodeSymbologies, Windows::Devices::PointOfService::IBarcodeSymbologiesStatics2>([&](auto&& f) { return f.Gs1DWCode(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::CashDrawer> CashDrawer::GetDefaultAsync()
{
    return impl::call_factory<CashDrawer, Windows::Devices::PointOfService::ICashDrawerStatics>([&](auto&& f) { return f.GetDefaultAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::CashDrawer> CashDrawer::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<CashDrawer, Windows::Devices::PointOfService::ICashDrawerStatics>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

inline hstring CashDrawer::GetDeviceSelector()
{
    return impl::call_factory<CashDrawer, Windows::Devices::PointOfService::ICashDrawerStatics>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline hstring CashDrawer::GetDeviceSelector(Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes)
{
    return impl::call_factory<CashDrawer, Windows::Devices::PointOfService::ICashDrawerStatics2>([&](auto&& f) { return f.GetDeviceSelector(connectionTypes); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::ClaimedLineDisplay> ClaimedLineDisplay::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<ClaimedLineDisplay, Windows::Devices::PointOfService::IClaimedLineDisplayStatics>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

inline hstring ClaimedLineDisplay::GetDeviceSelector()
{
    return impl::call_factory<ClaimedLineDisplay, Windows::Devices::PointOfService::IClaimedLineDisplayStatics>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline hstring ClaimedLineDisplay::GetDeviceSelector(Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes)
{
    return impl::call_factory<ClaimedLineDisplay, Windows::Devices::PointOfService::IClaimedLineDisplayStatics>([&](auto&& f) { return f.GetDeviceSelector(connectionTypes); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplay> LineDisplay::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<LineDisplay, Windows::Devices::PointOfService::ILineDisplayStatics>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::LineDisplay> LineDisplay::GetDefaultAsync()
{
    return impl::call_factory<LineDisplay, Windows::Devices::PointOfService::ILineDisplayStatics>([&](auto&& f) { return f.GetDefaultAsync(); });
}

inline hstring LineDisplay::GetDeviceSelector()
{
    return impl::call_factory<LineDisplay, Windows::Devices::PointOfService::ILineDisplayStatics>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline hstring LineDisplay::GetDeviceSelector(Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes)
{
    return impl::call_factory<LineDisplay, Windows::Devices::PointOfService::ILineDisplayStatics>([&](auto&& f) { return f.GetDeviceSelector(connectionTypes); });
}

inline Windows::Devices::PointOfService::LineDisplayStatisticsCategorySelector LineDisplay::StatisticsCategorySelector()
{
    return impl::call_factory<LineDisplay, Windows::Devices::PointOfService::ILineDisplayStatics2>([&](auto&& f) { return f.StatisticsCategorySelector(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::MagneticStripeReader> MagneticStripeReader::GetDefaultAsync()
{
    return impl::call_factory<MagneticStripeReader, Windows::Devices::PointOfService::IMagneticStripeReaderStatics>([&](auto&& f) { return f.GetDefaultAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::MagneticStripeReader> MagneticStripeReader::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<MagneticStripeReader, Windows::Devices::PointOfService::IMagneticStripeReaderStatics>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

inline hstring MagneticStripeReader::GetDeviceSelector()
{
    return impl::call_factory<MagneticStripeReader, Windows::Devices::PointOfService::IMagneticStripeReaderStatics>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline hstring MagneticStripeReader::GetDeviceSelector(Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes)
{
    return impl::call_factory<MagneticStripeReader, Windows::Devices::PointOfService::IMagneticStripeReaderStatics2>([&](auto&& f) { return f.GetDeviceSelector(connectionTypes); });
}

inline uint32_t MagneticStripeReaderCardTypes::Unknown()
{
    return impl::call_factory<MagneticStripeReaderCardTypes, Windows::Devices::PointOfService::IMagneticStripeReaderCardTypesStatics>([&](auto&& f) { return f.Unknown(); });
}

inline uint32_t MagneticStripeReaderCardTypes::Bank()
{
    return impl::call_factory<MagneticStripeReaderCardTypes, Windows::Devices::PointOfService::IMagneticStripeReaderCardTypesStatics>([&](auto&& f) { return f.Bank(); });
}

inline uint32_t MagneticStripeReaderCardTypes::Aamva()
{
    return impl::call_factory<MagneticStripeReaderCardTypes, Windows::Devices::PointOfService::IMagneticStripeReaderCardTypesStatics>([&](auto&& f) { return f.Aamva(); });
}

inline uint32_t MagneticStripeReaderCardTypes::ExtendedBase()
{
    return impl::call_factory<MagneticStripeReaderCardTypes, Windows::Devices::PointOfService::IMagneticStripeReaderCardTypesStatics>([&](auto&& f) { return f.ExtendedBase(); });
}

inline uint32_t MagneticStripeReaderEncryptionAlgorithms::None()
{
    return impl::call_factory<MagneticStripeReaderEncryptionAlgorithms, Windows::Devices::PointOfService::IMagneticStripeReaderEncryptionAlgorithmsStatics>([&](auto&& f) { return f.None(); });
}

inline uint32_t MagneticStripeReaderEncryptionAlgorithms::TripleDesDukpt()
{
    return impl::call_factory<MagneticStripeReaderEncryptionAlgorithms, Windows::Devices::PointOfService::IMagneticStripeReaderEncryptionAlgorithmsStatics>([&](auto&& f) { return f.TripleDesDukpt(); });
}

inline uint32_t MagneticStripeReaderEncryptionAlgorithms::ExtendedBase()
{
    return impl::call_factory<MagneticStripeReaderEncryptionAlgorithms, Windows::Devices::PointOfService::IMagneticStripeReaderEncryptionAlgorithmsStatics>([&](auto&& f) { return f.ExtendedBase(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::PosPrinter> PosPrinter::GetDefaultAsync()
{
    return impl::call_factory<PosPrinter, Windows::Devices::PointOfService::IPosPrinterStatics>([&](auto&& f) { return f.GetDefaultAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::PosPrinter> PosPrinter::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<PosPrinter, Windows::Devices::PointOfService::IPosPrinterStatics>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

inline hstring PosPrinter::GetDeviceSelector()
{
    return impl::call_factory<PosPrinter, Windows::Devices::PointOfService::IPosPrinterStatics>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline hstring PosPrinter::GetDeviceSelector(Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes)
{
    return impl::call_factory<PosPrinter, Windows::Devices::PointOfService::IPosPrinterStatics2>([&](auto&& f) { return f.GetDeviceSelector(connectionTypes); });
}

inline uint32_t PosPrinterCharacterSetIds::Utf16LE()
{
    return impl::call_factory<PosPrinterCharacterSetIds, Windows::Devices::PointOfService::IPosPrinterCharacterSetIdsStatics>([&](auto&& f) { return f.Utf16LE(); });
}

inline uint32_t PosPrinterCharacterSetIds::Ascii()
{
    return impl::call_factory<PosPrinterCharacterSetIds, Windows::Devices::PointOfService::IPosPrinterCharacterSetIdsStatics>([&](auto&& f) { return f.Ascii(); });
}

inline uint32_t PosPrinterCharacterSetIds::Ansi()
{
    return impl::call_factory<PosPrinterCharacterSetIds, Windows::Devices::PointOfService::IPosPrinterCharacterSetIdsStatics>([&](auto&& f) { return f.Ansi(); });
}

inline PosPrinterPrintOptions::PosPrinterPrintOptions() :
    PosPrinterPrintOptions(impl::call_factory<PosPrinterPrintOptions>([](auto&& f) { return f.template ActivateInstance<PosPrinterPrintOptions>(); }))
{}

inline UnifiedPosErrorData::UnifiedPosErrorData(param::hstring const& message, Windows::Devices::PointOfService::UnifiedPosErrorSeverity const& severity, Windows::Devices::PointOfService::UnifiedPosErrorReason const& reason, uint32_t extendedReason) :
    UnifiedPosErrorData(impl::call_factory<UnifiedPosErrorData, Windows::Devices::PointOfService::IUnifiedPosErrorDataFactory>([&](auto&& f) { return f.CreateInstance(message, severity, reason, extendedReason); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::PointOfService::IBarcodeScanner> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IBarcodeScanner> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IBarcodeScanner2> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IBarcodeScanner2> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities1> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities1> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities2> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities2> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IBarcodeScannerDataReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IBarcodeScannerDataReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IBarcodeScannerErrorOccurredEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IBarcodeScannerErrorOccurredEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IBarcodeScannerImagePreviewReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IBarcodeScannerImagePreviewReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IBarcodeScannerReport> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IBarcodeScannerReport> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IBarcodeScannerReportFactory> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IBarcodeScannerReportFactory> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IBarcodeScannerStatics> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IBarcodeScannerStatics> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IBarcodeScannerStatics2> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IBarcodeScannerStatics2> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IBarcodeScannerStatusUpdatedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IBarcodeScannerStatusUpdatedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics2> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics2> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IBarcodeSymbologyAttributes> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IBarcodeSymbologyAttributes> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ICashDrawer> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ICashDrawer> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ICashDrawerCapabilities> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ICashDrawerCapabilities> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ICashDrawerCloseAlarm> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ICashDrawerCloseAlarm> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ICashDrawerEventSource> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ICashDrawerEventSource> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ICashDrawerEventSourceEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ICashDrawerEventSourceEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ICashDrawerStatics> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ICashDrawerStatics> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ICashDrawerStatics2> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ICashDrawerStatics2> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ICashDrawerStatus> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ICashDrawerStatus> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ICashDrawerStatusUpdatedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ICashDrawerStatusUpdatedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner1> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner1> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner2> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner2> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner3> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner3> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner4> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner4> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScannerClosedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScannerClosedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedCashDrawer> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IClaimedCashDrawer> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedCashDrawer2> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IClaimedCashDrawer2> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedCashDrawerClosedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IClaimedCashDrawerClosedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedJournalPrinter> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IClaimedJournalPrinter> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedLineDisplay> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IClaimedLineDisplay> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedLineDisplay2> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IClaimedLineDisplay2> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedLineDisplay3> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IClaimedLineDisplay3> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedLineDisplayClosedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IClaimedLineDisplayClosedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedLineDisplayStatics> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IClaimedLineDisplayStatics> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader2> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader2> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReaderClosedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReaderClosedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedPosPrinter> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IClaimedPosPrinter> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedPosPrinter2> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IClaimedPosPrinter2> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedPosPrinterClosedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IClaimedPosPrinterClosedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedReceiptPrinter> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IClaimedReceiptPrinter> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedSlipPrinter> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IClaimedSlipPrinter> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ICommonReceiptSlipCapabilities> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ICommonReceiptSlipCapabilities> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IJournalPrintJob> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IJournalPrintJob> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IJournalPrinterCapabilities> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IJournalPrinterCapabilities> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IJournalPrinterCapabilities2> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IJournalPrinterCapabilities2> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ILineDisplay> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ILineDisplay> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ILineDisplay2> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ILineDisplay2> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ILineDisplayAttributes> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ILineDisplayAttributes> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ILineDisplayCapabilities> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ILineDisplayCapabilities> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ILineDisplayCursor> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ILineDisplayCursor> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ILineDisplayCursorAttributes> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ILineDisplayCursorAttributes> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ILineDisplayCustomGlyphs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ILineDisplayCustomGlyphs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ILineDisplayMarquee> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ILineDisplayMarquee> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ILineDisplayStatics> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ILineDisplayStatics> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ILineDisplayStatics2> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ILineDisplayStatics2> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ILineDisplayStatisticsCategorySelector> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ILineDisplayStatisticsCategorySelector> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ILineDisplayStatusUpdatedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ILineDisplayStatusUpdatedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ILineDisplayStoredBitmap> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ILineDisplayStoredBitmap> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ILineDisplayWindow> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ILineDisplayWindow> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ILineDisplayWindow2> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ILineDisplayWindow2> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IMagneticStripeReader> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IMagneticStripeReader> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCardTypesStatics> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCardTypesStatics> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderEncryptionAlgorithmsStatics> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderEncryptionAlgorithmsStatics> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderErrorOccurredEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderErrorOccurredEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderReport> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderReport> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatics> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatics> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatics2> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatics2> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatusUpdatedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatusUpdatedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderTrackData> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderTrackData> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderVendorSpecificCardDataReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderVendorSpecificCardDataReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IPosPrinter> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IPosPrinter> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IPosPrinter2> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IPosPrinter2> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IPosPrinterCapabilities> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IPosPrinterCapabilities> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IPosPrinterCharacterSetIdsStatics> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IPosPrinterCharacterSetIdsStatics> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IPosPrinterFontProperty> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IPosPrinterFontProperty> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IPosPrinterJob> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IPosPrinterJob> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IPosPrinterReleaseDeviceRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IPosPrinterReleaseDeviceRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IPosPrinterStatics> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IPosPrinterStatics> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IPosPrinterStatics2> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IPosPrinterStatics2> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IPosPrinterStatus> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IPosPrinterStatus> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IPosPrinterStatusUpdatedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IPosPrinterStatusUpdatedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IReceiptOrSlipJob> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IReceiptOrSlipJob> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IReceiptPrintJob> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IReceiptPrintJob> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IReceiptPrintJob2> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IReceiptPrintJob2> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IReceiptPrinterCapabilities> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IReceiptPrinterCapabilities> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IReceiptPrinterCapabilities2> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IReceiptPrinterCapabilities2> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ISlipPrintJob> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ISlipPrintJob> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ISlipPrinterCapabilities> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ISlipPrinterCapabilities> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ISlipPrinterCapabilities2> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ISlipPrinterCapabilities2> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IUnifiedPosErrorData> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IUnifiedPosErrorData> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::IUnifiedPosErrorDataFactory> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::IUnifiedPosErrorDataFactory> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::BarcodeScanner> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::BarcodeScanner> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::BarcodeScannerCapabilities> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::BarcodeScannerCapabilities> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::BarcodeScannerDataReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::BarcodeScannerDataReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::BarcodeScannerErrorOccurredEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::BarcodeScannerErrorOccurredEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::BarcodeScannerImagePreviewReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::BarcodeScannerImagePreviewReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::BarcodeScannerReport> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::BarcodeScannerReport> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::BarcodeScannerStatusUpdatedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::BarcodeScannerStatusUpdatedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::BarcodeSymbologies> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::BarcodeSymbologies> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::BarcodeSymbologyAttributes> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::BarcodeSymbologyAttributes> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::CashDrawer> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::CashDrawer> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::CashDrawerCapabilities> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::CashDrawerCapabilities> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::CashDrawerCloseAlarm> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::CashDrawerCloseAlarm> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::CashDrawerClosedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::CashDrawerClosedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::CashDrawerEventSource> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::CashDrawerEventSource> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::CashDrawerOpenedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::CashDrawerOpenedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::CashDrawerStatus> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::CashDrawerStatus> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::CashDrawerStatusUpdatedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::CashDrawerStatusUpdatedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScannerClosedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScannerClosedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ClaimedCashDrawer> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ClaimedCashDrawer> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ClaimedCashDrawerClosedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ClaimedCashDrawerClosedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ClaimedJournalPrinter> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ClaimedJournalPrinter> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ClaimedLineDisplay> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ClaimedLineDisplay> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ClaimedLineDisplayClosedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ClaimedLineDisplayClosedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReaderClosedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReaderClosedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ClaimedPosPrinter> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ClaimedPosPrinter> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ClaimedPosPrinterClosedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ClaimedPosPrinterClosedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ClaimedReceiptPrinter> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ClaimedReceiptPrinter> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ClaimedSlipPrinter> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ClaimedSlipPrinter> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::JournalPrintJob> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::JournalPrintJob> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::JournalPrinterCapabilities> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::JournalPrinterCapabilities> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::LineDisplay> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::LineDisplay> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::LineDisplayAttributes> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::LineDisplayAttributes> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::LineDisplayCapabilities> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::LineDisplayCapabilities> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::LineDisplayCursor> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::LineDisplayCursor> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::LineDisplayCursorAttributes> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::LineDisplayCursorAttributes> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::LineDisplayCustomGlyphs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::LineDisplayCustomGlyphs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::LineDisplayMarquee> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::LineDisplayMarquee> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::LineDisplayStatisticsCategorySelector> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::LineDisplayStatisticsCategorySelector> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::LineDisplayStatusUpdatedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::LineDisplayStatusUpdatedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::LineDisplayStoredBitmap> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::LineDisplayStoredBitmap> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::LineDisplayWindow> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::LineDisplayWindow> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::MagneticStripeReader> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::MagneticStripeReader> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::MagneticStripeReaderAamvaCardDataReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::MagneticStripeReaderAamvaCardDataReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::MagneticStripeReaderBankCardDataReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::MagneticStripeReaderBankCardDataReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::MagneticStripeReaderCapabilities> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::MagneticStripeReaderCapabilities> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::MagneticStripeReaderCardTypes> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::MagneticStripeReaderCardTypes> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::MagneticStripeReaderEncryptionAlgorithms> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::MagneticStripeReaderEncryptionAlgorithms> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::MagneticStripeReaderErrorOccurredEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::MagneticStripeReaderErrorOccurredEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::MagneticStripeReaderReport> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::MagneticStripeReaderReport> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::MagneticStripeReaderStatusUpdatedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::MagneticStripeReaderStatusUpdatedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackData> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackData> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::MagneticStripeReaderVendorSpecificCardDataReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::MagneticStripeReaderVendorSpecificCardDataReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::PosPrinter> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::PosPrinter> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::PosPrinterCapabilities> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::PosPrinterCapabilities> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::PosPrinterCharacterSetIds> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::PosPrinterCharacterSetIds> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::PosPrinterFontProperty> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::PosPrinterFontProperty> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::PosPrinterPrintOptions> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::PosPrinterPrintOptions> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::PosPrinterReleaseDeviceRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::PosPrinterReleaseDeviceRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::PosPrinterStatus> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::PosPrinterStatus> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::PosPrinterStatusUpdatedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::PosPrinterStatusUpdatedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ReceiptPrintJob> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ReceiptPrintJob> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::ReceiptPrinterCapabilities> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::ReceiptPrinterCapabilities> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::SlipPrintJob> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::SlipPrintJob> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::SlipPrinterCapabilities> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::SlipPrinterCapabilities> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::UnifiedPosErrorData> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::UnifiedPosErrorData> {};

}
