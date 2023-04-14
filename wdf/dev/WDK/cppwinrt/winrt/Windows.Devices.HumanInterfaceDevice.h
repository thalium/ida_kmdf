// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Devices.HumanInterfaceDevice.2.h"
#include "winrt/Windows.Devices.h"

namespace winrt::impl {

template <typename D> uint32_t consume_Windows_Devices_HumanInterfaceDevice_IHidBooleanControl<D>::Id() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidBooleanControl)->get_Id(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_HumanInterfaceDevice_IHidBooleanControl<D>::UsagePage() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidBooleanControl)->get_UsagePage(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_HumanInterfaceDevice_IHidBooleanControl<D>::UsageId() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidBooleanControl)->get_UsageId(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_HumanInterfaceDevice_IHidBooleanControl<D>::IsActive() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidBooleanControl)->get_IsActive(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_HumanInterfaceDevice_IHidBooleanControl<D>::IsActive(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidBooleanControl)->put_IsActive(value));
}

template <typename D> Windows::Devices::HumanInterfaceDevice::HidBooleanControlDescription consume_Windows_Devices_HumanInterfaceDevice_IHidBooleanControl<D>::ControlDescription() const
{
    Windows::Devices::HumanInterfaceDevice::HidBooleanControlDescription value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidBooleanControl)->get_ControlDescription(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_HumanInterfaceDevice_IHidBooleanControlDescription<D>::Id() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidBooleanControlDescription)->get_Id(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_HumanInterfaceDevice_IHidBooleanControlDescription<D>::ReportId() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidBooleanControlDescription)->get_ReportId(&value));
    return value;
}

template <typename D> Windows::Devices::HumanInterfaceDevice::HidReportType consume_Windows_Devices_HumanInterfaceDevice_IHidBooleanControlDescription<D>::ReportType() const
{
    Windows::Devices::HumanInterfaceDevice::HidReportType value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidBooleanControlDescription)->get_ReportType(put_abi(value)));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_HumanInterfaceDevice_IHidBooleanControlDescription<D>::UsagePage() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidBooleanControlDescription)->get_UsagePage(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_HumanInterfaceDevice_IHidBooleanControlDescription<D>::UsageId() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidBooleanControlDescription)->get_UsageId(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::HumanInterfaceDevice::HidCollection> consume_Windows_Devices_HumanInterfaceDevice_IHidBooleanControlDescription<D>::ParentCollections() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::HumanInterfaceDevice::HidCollection> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidBooleanControlDescription)->get_ParentCollections(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_HumanInterfaceDevice_IHidBooleanControlDescription2<D>::IsAbsolute() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidBooleanControlDescription2)->get_IsAbsolute(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_HumanInterfaceDevice_IHidCollection<D>::Id() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidCollection)->get_Id(&value));
    return value;
}

template <typename D> Windows::Devices::HumanInterfaceDevice::HidCollectionType consume_Windows_Devices_HumanInterfaceDevice_IHidCollection<D>::Type() const
{
    Windows::Devices::HumanInterfaceDevice::HidCollectionType value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidCollection)->get_Type(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_HumanInterfaceDevice_IHidCollection<D>::UsagePage() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidCollection)->get_UsagePage(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_HumanInterfaceDevice_IHidCollection<D>::UsageId() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidCollection)->get_UsageId(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_HumanInterfaceDevice_IHidDevice<D>::VendorId() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidDevice)->get_VendorId(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_HumanInterfaceDevice_IHidDevice<D>::ProductId() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidDevice)->get_ProductId(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_HumanInterfaceDevice_IHidDevice<D>::Version() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidDevice)->get_Version(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_HumanInterfaceDevice_IHidDevice<D>::UsagePage() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidDevice)->get_UsagePage(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_HumanInterfaceDevice_IHidDevice<D>::UsageId() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidDevice)->get_UsageId(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::HumanInterfaceDevice::HidInputReport> consume_Windows_Devices_HumanInterfaceDevice_IHidDevice<D>::GetInputReportAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::HumanInterfaceDevice::HidInputReport> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidDevice)->GetInputReportAsync(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::HumanInterfaceDevice::HidInputReport> consume_Windows_Devices_HumanInterfaceDevice_IHidDevice<D>::GetInputReportAsync(uint16_t reportId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::HumanInterfaceDevice::HidInputReport> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidDevice)->GetInputReportByIdAsync(reportId, put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::HumanInterfaceDevice::HidFeatureReport> consume_Windows_Devices_HumanInterfaceDevice_IHidDevice<D>::GetFeatureReportAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::HumanInterfaceDevice::HidFeatureReport> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidDevice)->GetFeatureReportAsync(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::HumanInterfaceDevice::HidFeatureReport> consume_Windows_Devices_HumanInterfaceDevice_IHidDevice<D>::GetFeatureReportAsync(uint16_t reportId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::HumanInterfaceDevice::HidFeatureReport> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidDevice)->GetFeatureReportByIdAsync(reportId, put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::HumanInterfaceDevice::HidOutputReport consume_Windows_Devices_HumanInterfaceDevice_IHidDevice<D>::CreateOutputReport() const
{
    Windows::Devices::HumanInterfaceDevice::HidOutputReport outputReport{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidDevice)->CreateOutputReport(put_abi(outputReport)));
    return outputReport;
}

template <typename D> Windows::Devices::HumanInterfaceDevice::HidOutputReport consume_Windows_Devices_HumanInterfaceDevice_IHidDevice<D>::CreateOutputReport(uint16_t reportId) const
{
    Windows::Devices::HumanInterfaceDevice::HidOutputReport outputReport{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidDevice)->CreateOutputReportById(reportId, put_abi(outputReport)));
    return outputReport;
}

template <typename D> Windows::Devices::HumanInterfaceDevice::HidFeatureReport consume_Windows_Devices_HumanInterfaceDevice_IHidDevice<D>::CreateFeatureReport() const
{
    Windows::Devices::HumanInterfaceDevice::HidFeatureReport featureReport{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidDevice)->CreateFeatureReport(put_abi(featureReport)));
    return featureReport;
}

template <typename D> Windows::Devices::HumanInterfaceDevice::HidFeatureReport consume_Windows_Devices_HumanInterfaceDevice_IHidDevice<D>::CreateFeatureReport(uint16_t reportId) const
{
    Windows::Devices::HumanInterfaceDevice::HidFeatureReport featureReport{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidDevice)->CreateFeatureReportById(reportId, put_abi(featureReport)));
    return featureReport;
}

template <typename D> Windows::Foundation::IAsyncOperation<uint32_t> consume_Windows_Devices_HumanInterfaceDevice_IHidDevice<D>::SendOutputReportAsync(Windows::Devices::HumanInterfaceDevice::HidOutputReport const& outputReport) const
{
    Windows::Foundation::IAsyncOperation<uint32_t> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidDevice)->SendOutputReportAsync(get_abi(outputReport), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<uint32_t> consume_Windows_Devices_HumanInterfaceDevice_IHidDevice<D>::SendFeatureReportAsync(Windows::Devices::HumanInterfaceDevice::HidFeatureReport const& featureReport) const
{
    Windows::Foundation::IAsyncOperation<uint32_t> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidDevice)->SendFeatureReportAsync(get_abi(featureReport), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::HumanInterfaceDevice::HidBooleanControlDescription> consume_Windows_Devices_HumanInterfaceDevice_IHidDevice<D>::GetBooleanControlDescriptions(Windows::Devices::HumanInterfaceDevice::HidReportType const& reportType, uint16_t usagePage, uint16_t usageId) const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::HumanInterfaceDevice::HidBooleanControlDescription> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidDevice)->GetBooleanControlDescriptions(get_abi(reportType), usagePage, usageId, put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::HumanInterfaceDevice::HidNumericControlDescription> consume_Windows_Devices_HumanInterfaceDevice_IHidDevice<D>::GetNumericControlDescriptions(Windows::Devices::HumanInterfaceDevice::HidReportType const& reportType, uint16_t usagePage, uint16_t usageId) const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::HumanInterfaceDevice::HidNumericControlDescription> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidDevice)->GetNumericControlDescriptions(get_abi(reportType), usagePage, usageId, put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_HumanInterfaceDevice_IHidDevice<D>::InputReportReceived(Windows::Foundation::TypedEventHandler<Windows::Devices::HumanInterfaceDevice::HidDevice, Windows::Devices::HumanInterfaceDevice::HidInputReportReceivedEventArgs> const& reportHandler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidDevice)->add_InputReportReceived(get_abi(reportHandler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_HumanInterfaceDevice_IHidDevice<D>::InputReportReceived_revoker consume_Windows_Devices_HumanInterfaceDevice_IHidDevice<D>::InputReportReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::HumanInterfaceDevice::HidDevice, Windows::Devices::HumanInterfaceDevice::HidInputReportReceivedEventArgs> const& reportHandler) const
{
    return impl::make_event_revoker<D, InputReportReceived_revoker>(this, InputReportReceived(reportHandler));
}

template <typename D> void consume_Windows_Devices_HumanInterfaceDevice_IHidDevice<D>::InputReportReceived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidDevice)->remove_InputReportReceived(get_abi(token)));
}

template <typename D> hstring consume_Windows_Devices_HumanInterfaceDevice_IHidDeviceStatics<D>::GetDeviceSelector(uint16_t usagePage, uint16_t usageId) const
{
    hstring selector{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidDeviceStatics)->GetDeviceSelector(usagePage, usageId, put_abi(selector)));
    return selector;
}

template <typename D> hstring consume_Windows_Devices_HumanInterfaceDevice_IHidDeviceStatics<D>::GetDeviceSelector(uint16_t usagePage, uint16_t usageId, uint16_t vendorId, uint16_t productId) const
{
    hstring selector{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidDeviceStatics)->GetDeviceSelectorVidPid(usagePage, usageId, vendorId, productId, put_abi(selector)));
    return selector;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::HumanInterfaceDevice::HidDevice> consume_Windows_Devices_HumanInterfaceDevice_IHidDeviceStatics<D>::FromIdAsync(param::hstring const& deviceId, Windows::Storage::FileAccessMode const& accessMode) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::HumanInterfaceDevice::HidDevice> hidDevice{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidDeviceStatics)->FromIdAsync(get_abi(deviceId), get_abi(accessMode), put_abi(hidDevice)));
    return hidDevice;
}

template <typename D> uint16_t consume_Windows_Devices_HumanInterfaceDevice_IHidFeatureReport<D>::Id() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidFeatureReport)->get_Id(&value));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_HumanInterfaceDevice_IHidFeatureReport<D>::Data() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidFeatureReport)->get_Data(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_HumanInterfaceDevice_IHidFeatureReport<D>::Data(Windows::Storage::Streams::IBuffer const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidFeatureReport)->put_Data(get_abi(value)));
}

template <typename D> Windows::Devices::HumanInterfaceDevice::HidBooleanControl consume_Windows_Devices_HumanInterfaceDevice_IHidFeatureReport<D>::GetBooleanControl(uint16_t usagePage, uint16_t usageId) const
{
    Windows::Devices::HumanInterfaceDevice::HidBooleanControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidFeatureReport)->GetBooleanControl(usagePage, usageId, put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::HumanInterfaceDevice::HidBooleanControl consume_Windows_Devices_HumanInterfaceDevice_IHidFeatureReport<D>::GetBooleanControlByDescription(Windows::Devices::HumanInterfaceDevice::HidBooleanControlDescription const& controlDescription) const
{
    Windows::Devices::HumanInterfaceDevice::HidBooleanControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidFeatureReport)->GetBooleanControlByDescription(get_abi(controlDescription), put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::HumanInterfaceDevice::HidNumericControl consume_Windows_Devices_HumanInterfaceDevice_IHidFeatureReport<D>::GetNumericControl(uint16_t usagePage, uint16_t usageId) const
{
    Windows::Devices::HumanInterfaceDevice::HidNumericControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidFeatureReport)->GetNumericControl(usagePage, usageId, put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::HumanInterfaceDevice::HidNumericControl consume_Windows_Devices_HumanInterfaceDevice_IHidFeatureReport<D>::GetNumericControlByDescription(Windows::Devices::HumanInterfaceDevice::HidNumericControlDescription const& controlDescription) const
{
    Windows::Devices::HumanInterfaceDevice::HidNumericControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidFeatureReport)->GetNumericControlByDescription(get_abi(controlDescription), put_abi(value)));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_HumanInterfaceDevice_IHidInputReport<D>::Id() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidInputReport)->get_Id(&value));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_HumanInterfaceDevice_IHidInputReport<D>::Data() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidInputReport)->get_Data(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::HumanInterfaceDevice::HidBooleanControl> consume_Windows_Devices_HumanInterfaceDevice_IHidInputReport<D>::ActivatedBooleanControls() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::HumanInterfaceDevice::HidBooleanControl> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidInputReport)->get_ActivatedBooleanControls(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::HumanInterfaceDevice::HidBooleanControl> consume_Windows_Devices_HumanInterfaceDevice_IHidInputReport<D>::TransitionedBooleanControls() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::HumanInterfaceDevice::HidBooleanControl> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidInputReport)->get_TransitionedBooleanControls(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::HumanInterfaceDevice::HidBooleanControl consume_Windows_Devices_HumanInterfaceDevice_IHidInputReport<D>::GetBooleanControl(uint16_t usagePage, uint16_t usageId) const
{
    Windows::Devices::HumanInterfaceDevice::HidBooleanControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidInputReport)->GetBooleanControl(usagePage, usageId, put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::HumanInterfaceDevice::HidBooleanControl consume_Windows_Devices_HumanInterfaceDevice_IHidInputReport<D>::GetBooleanControlByDescription(Windows::Devices::HumanInterfaceDevice::HidBooleanControlDescription const& controlDescription) const
{
    Windows::Devices::HumanInterfaceDevice::HidBooleanControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidInputReport)->GetBooleanControlByDescription(get_abi(controlDescription), put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::HumanInterfaceDevice::HidNumericControl consume_Windows_Devices_HumanInterfaceDevice_IHidInputReport<D>::GetNumericControl(uint16_t usagePage, uint16_t usageId) const
{
    Windows::Devices::HumanInterfaceDevice::HidNumericControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidInputReport)->GetNumericControl(usagePage, usageId, put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::HumanInterfaceDevice::HidNumericControl consume_Windows_Devices_HumanInterfaceDevice_IHidInputReport<D>::GetNumericControlByDescription(Windows::Devices::HumanInterfaceDevice::HidNumericControlDescription const& controlDescription) const
{
    Windows::Devices::HumanInterfaceDevice::HidNumericControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidInputReport)->GetNumericControlByDescription(get_abi(controlDescription), put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::HumanInterfaceDevice::HidInputReport consume_Windows_Devices_HumanInterfaceDevice_IHidInputReportReceivedEventArgs<D>::Report() const
{
    Windows::Devices::HumanInterfaceDevice::HidInputReport value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidInputReportReceivedEventArgs)->get_Report(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_HumanInterfaceDevice_IHidNumericControl<D>::Id() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidNumericControl)->get_Id(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_HumanInterfaceDevice_IHidNumericControl<D>::IsGrouped() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidNumericControl)->get_IsGrouped(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_HumanInterfaceDevice_IHidNumericControl<D>::UsagePage() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidNumericControl)->get_UsagePage(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_HumanInterfaceDevice_IHidNumericControl<D>::UsageId() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidNumericControl)->get_UsageId(&value));
    return value;
}

template <typename D> int64_t consume_Windows_Devices_HumanInterfaceDevice_IHidNumericControl<D>::Value() const
{
    int64_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidNumericControl)->get_Value(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_HumanInterfaceDevice_IHidNumericControl<D>::Value(int64_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidNumericControl)->put_Value(value));
}

template <typename D> int64_t consume_Windows_Devices_HumanInterfaceDevice_IHidNumericControl<D>::ScaledValue() const
{
    int64_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidNumericControl)->get_ScaledValue(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_HumanInterfaceDevice_IHidNumericControl<D>::ScaledValue(int64_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidNumericControl)->put_ScaledValue(value));
}

template <typename D> Windows::Devices::HumanInterfaceDevice::HidNumericControlDescription consume_Windows_Devices_HumanInterfaceDevice_IHidNumericControl<D>::ControlDescription() const
{
    Windows::Devices::HumanInterfaceDevice::HidNumericControlDescription value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidNumericControl)->get_ControlDescription(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_HumanInterfaceDevice_IHidNumericControlDescription<D>::Id() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidNumericControlDescription)->get_Id(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_HumanInterfaceDevice_IHidNumericControlDescription<D>::ReportId() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidNumericControlDescription)->get_ReportId(&value));
    return value;
}

template <typename D> Windows::Devices::HumanInterfaceDevice::HidReportType consume_Windows_Devices_HumanInterfaceDevice_IHidNumericControlDescription<D>::ReportType() const
{
    Windows::Devices::HumanInterfaceDevice::HidReportType value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidNumericControlDescription)->get_ReportType(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_HumanInterfaceDevice_IHidNumericControlDescription<D>::ReportSize() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidNumericControlDescription)->get_ReportSize(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_HumanInterfaceDevice_IHidNumericControlDescription<D>::ReportCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidNumericControlDescription)->get_ReportCount(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_HumanInterfaceDevice_IHidNumericControlDescription<D>::UsagePage() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidNumericControlDescription)->get_UsagePage(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_HumanInterfaceDevice_IHidNumericControlDescription<D>::UsageId() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidNumericControlDescription)->get_UsageId(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_HumanInterfaceDevice_IHidNumericControlDescription<D>::LogicalMinimum() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidNumericControlDescription)->get_LogicalMinimum(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_HumanInterfaceDevice_IHidNumericControlDescription<D>::LogicalMaximum() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidNumericControlDescription)->get_LogicalMaximum(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_HumanInterfaceDevice_IHidNumericControlDescription<D>::PhysicalMinimum() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidNumericControlDescription)->get_PhysicalMinimum(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_HumanInterfaceDevice_IHidNumericControlDescription<D>::PhysicalMaximum() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidNumericControlDescription)->get_PhysicalMaximum(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_HumanInterfaceDevice_IHidNumericControlDescription<D>::UnitExponent() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidNumericControlDescription)->get_UnitExponent(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_HumanInterfaceDevice_IHidNumericControlDescription<D>::Unit() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidNumericControlDescription)->get_Unit(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_HumanInterfaceDevice_IHidNumericControlDescription<D>::IsAbsolute() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidNumericControlDescription)->get_IsAbsolute(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_HumanInterfaceDevice_IHidNumericControlDescription<D>::HasNull() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidNumericControlDescription)->get_HasNull(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::HumanInterfaceDevice::HidCollection> consume_Windows_Devices_HumanInterfaceDevice_IHidNumericControlDescription<D>::ParentCollections() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::HumanInterfaceDevice::HidCollection> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidNumericControlDescription)->get_ParentCollections(put_abi(value)));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_HumanInterfaceDevice_IHidOutputReport<D>::Id() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidOutputReport)->get_Id(&value));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_HumanInterfaceDevice_IHidOutputReport<D>::Data() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidOutputReport)->get_Data(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_HumanInterfaceDevice_IHidOutputReport<D>::Data(Windows::Storage::Streams::IBuffer const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidOutputReport)->put_Data(get_abi(value)));
}

template <typename D> Windows::Devices::HumanInterfaceDevice::HidBooleanControl consume_Windows_Devices_HumanInterfaceDevice_IHidOutputReport<D>::GetBooleanControl(uint16_t usagePage, uint16_t usageId) const
{
    Windows::Devices::HumanInterfaceDevice::HidBooleanControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidOutputReport)->GetBooleanControl(usagePage, usageId, put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::HumanInterfaceDevice::HidBooleanControl consume_Windows_Devices_HumanInterfaceDevice_IHidOutputReport<D>::GetBooleanControlByDescription(Windows::Devices::HumanInterfaceDevice::HidBooleanControlDescription const& controlDescription) const
{
    Windows::Devices::HumanInterfaceDevice::HidBooleanControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidOutputReport)->GetBooleanControlByDescription(get_abi(controlDescription), put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::HumanInterfaceDevice::HidNumericControl consume_Windows_Devices_HumanInterfaceDevice_IHidOutputReport<D>::GetNumericControl(uint16_t usagePage, uint16_t usageId) const
{
    Windows::Devices::HumanInterfaceDevice::HidNumericControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidOutputReport)->GetNumericControl(usagePage, usageId, put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::HumanInterfaceDevice::HidNumericControl consume_Windows_Devices_HumanInterfaceDevice_IHidOutputReport<D>::GetNumericControlByDescription(Windows::Devices::HumanInterfaceDevice::HidNumericControlDescription const& controlDescription) const
{
    Windows::Devices::HumanInterfaceDevice::HidNumericControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::HumanInterfaceDevice::IHidOutputReport)->GetNumericControlByDescription(get_abi(controlDescription), put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Devices::HumanInterfaceDevice::IHidBooleanControl> : produce_base<D, Windows::Devices::HumanInterfaceDevice::IHidBooleanControl>
{
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

    int32_t WINRT_CALL get_UsagePage(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UsagePage, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().UsagePage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UsageId(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UsageId, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().UsageId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsActive(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsActive, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsActive());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsActive(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsActive, WINRT_WRAP(void), bool);
            this->shim().IsActive(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ControlDescription(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ControlDescription, WINRT_WRAP(Windows::Devices::HumanInterfaceDevice::HidBooleanControlDescription));
            *value = detach_from<Windows::Devices::HumanInterfaceDevice::HidBooleanControlDescription>(this->shim().ControlDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::HumanInterfaceDevice::IHidBooleanControlDescription> : produce_base<D, Windows::Devices::HumanInterfaceDevice::IHidBooleanControlDescription>
{
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

    int32_t WINRT_CALL get_ReportId(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportId, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().ReportId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReportType(Windows::Devices::HumanInterfaceDevice::HidReportType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportType, WINRT_WRAP(Windows::Devices::HumanInterfaceDevice::HidReportType));
            *value = detach_from<Windows::Devices::HumanInterfaceDevice::HidReportType>(this->shim().ReportType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UsagePage(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UsagePage, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().UsagePage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UsageId(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UsageId, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().UsageId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ParentCollections(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ParentCollections, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::HumanInterfaceDevice::HidCollection>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::HumanInterfaceDevice::HidCollection>>(this->shim().ParentCollections());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::HumanInterfaceDevice::IHidBooleanControlDescription2> : produce_base<D, Windows::Devices::HumanInterfaceDevice::IHidBooleanControlDescription2>
{
    int32_t WINRT_CALL get_IsAbsolute(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAbsolute, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsAbsolute());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::HumanInterfaceDevice::IHidCollection> : produce_base<D, Windows::Devices::HumanInterfaceDevice::IHidCollection>
{
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

    int32_t WINRT_CALL get_Type(Windows::Devices::HumanInterfaceDevice::HidCollectionType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(Windows::Devices::HumanInterfaceDevice::HidCollectionType));
            *value = detach_from<Windows::Devices::HumanInterfaceDevice::HidCollectionType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UsagePage(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UsagePage, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().UsagePage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UsageId(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UsageId, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().UsageId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::HumanInterfaceDevice::IHidDevice> : produce_base<D, Windows::Devices::HumanInterfaceDevice::IHidDevice>
{
    int32_t WINRT_CALL get_VendorId(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VendorId, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().VendorId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProductId(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProductId, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().ProductId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Version(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Version, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().Version());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UsagePage(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UsagePage, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().UsagePage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UsageId(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UsageId, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().UsageId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetInputReportAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetInputReportAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::HumanInterfaceDevice::HidInputReport>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::HumanInterfaceDevice::HidInputReport>>(this->shim().GetInputReportAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetInputReportByIdAsync(uint16_t reportId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetInputReportAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::HumanInterfaceDevice::HidInputReport>), uint16_t);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::HumanInterfaceDevice::HidInputReport>>(this->shim().GetInputReportAsync(reportId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFeatureReportAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFeatureReportAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::HumanInterfaceDevice::HidFeatureReport>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::HumanInterfaceDevice::HidFeatureReport>>(this->shim().GetFeatureReportAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFeatureReportByIdAsync(uint16_t reportId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFeatureReportAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::HumanInterfaceDevice::HidFeatureReport>), uint16_t);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::HumanInterfaceDevice::HidFeatureReport>>(this->shim().GetFeatureReportAsync(reportId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateOutputReport(void** outputReport) noexcept final
    {
        try
        {
            *outputReport = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateOutputReport, WINRT_WRAP(Windows::Devices::HumanInterfaceDevice::HidOutputReport));
            *outputReport = detach_from<Windows::Devices::HumanInterfaceDevice::HidOutputReport>(this->shim().CreateOutputReport());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateOutputReportById(uint16_t reportId, void** outputReport) noexcept final
    {
        try
        {
            *outputReport = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateOutputReport, WINRT_WRAP(Windows::Devices::HumanInterfaceDevice::HidOutputReport), uint16_t);
            *outputReport = detach_from<Windows::Devices::HumanInterfaceDevice::HidOutputReport>(this->shim().CreateOutputReport(reportId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFeatureReport(void** featureReport) noexcept final
    {
        try
        {
            *featureReport = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFeatureReport, WINRT_WRAP(Windows::Devices::HumanInterfaceDevice::HidFeatureReport));
            *featureReport = detach_from<Windows::Devices::HumanInterfaceDevice::HidFeatureReport>(this->shim().CreateFeatureReport());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFeatureReportById(uint16_t reportId, void** featureReport) noexcept final
    {
        try
        {
            *featureReport = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFeatureReport, WINRT_WRAP(Windows::Devices::HumanInterfaceDevice::HidFeatureReport), uint16_t);
            *featureReport = detach_from<Windows::Devices::HumanInterfaceDevice::HidFeatureReport>(this->shim().CreateFeatureReport(reportId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SendOutputReportAsync(void* outputReport, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendOutputReportAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<uint32_t>), Windows::Devices::HumanInterfaceDevice::HidOutputReport const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<uint32_t>>(this->shim().SendOutputReportAsync(*reinterpret_cast<Windows::Devices::HumanInterfaceDevice::HidOutputReport const*>(&outputReport)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SendFeatureReportAsync(void* featureReport, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendFeatureReportAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<uint32_t>), Windows::Devices::HumanInterfaceDevice::HidFeatureReport const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<uint32_t>>(this->shim().SendFeatureReportAsync(*reinterpret_cast<Windows::Devices::HumanInterfaceDevice::HidFeatureReport const*>(&featureReport)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetBooleanControlDescriptions(Windows::Devices::HumanInterfaceDevice::HidReportType reportType, uint16_t usagePage, uint16_t usageId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetBooleanControlDescriptions, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::HumanInterfaceDevice::HidBooleanControlDescription>), Windows::Devices::HumanInterfaceDevice::HidReportType const&, uint16_t, uint16_t);
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::HumanInterfaceDevice::HidBooleanControlDescription>>(this->shim().GetBooleanControlDescriptions(*reinterpret_cast<Windows::Devices::HumanInterfaceDevice::HidReportType const*>(&reportType), usagePage, usageId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNumericControlDescriptions(Windows::Devices::HumanInterfaceDevice::HidReportType reportType, uint16_t usagePage, uint16_t usageId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNumericControlDescriptions, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::HumanInterfaceDevice::HidNumericControlDescription>), Windows::Devices::HumanInterfaceDevice::HidReportType const&, uint16_t, uint16_t);
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::HumanInterfaceDevice::HidNumericControlDescription>>(this->shim().GetNumericControlDescriptions(*reinterpret_cast<Windows::Devices::HumanInterfaceDevice::HidReportType const*>(&reportType), usagePage, usageId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_InputReportReceived(void* reportHandler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InputReportReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::HumanInterfaceDevice::HidDevice, Windows::Devices::HumanInterfaceDevice::HidInputReportReceivedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().InputReportReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::HumanInterfaceDevice::HidDevice, Windows::Devices::HumanInterfaceDevice::HidInputReportReceivedEventArgs> const*>(&reportHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_InputReportReceived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(InputReportReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().InputReportReceived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::HumanInterfaceDevice::IHidDeviceStatics> : produce_base<D, Windows::Devices::HumanInterfaceDevice::IHidDeviceStatics>
{
    int32_t WINRT_CALL GetDeviceSelector(uint16_t usagePage, uint16_t usageId, void** selector) noexcept final
    {
        try
        {
            *selector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring), uint16_t, uint16_t);
            *selector = detach_from<hstring>(this->shim().GetDeviceSelector(usagePage, usageId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelectorVidPid(uint16_t usagePage, uint16_t usageId, uint16_t vendorId, uint16_t productId, void** selector) noexcept final
    {
        try
        {
            *selector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring), uint16_t, uint16_t, uint16_t, uint16_t);
            *selector = detach_from<hstring>(this->shim().GetDeviceSelector(usagePage, usageId, vendorId, productId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromIdAsync(void* deviceId, Windows::Storage::FileAccessMode accessMode, void** hidDevice) noexcept final
    {
        try
        {
            *hidDevice = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::HumanInterfaceDevice::HidDevice>), hstring const, Windows::Storage::FileAccessMode const);
            *hidDevice = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::HumanInterfaceDevice::HidDevice>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId), *reinterpret_cast<Windows::Storage::FileAccessMode const*>(&accessMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::HumanInterfaceDevice::IHidFeatureReport> : produce_base<D, Windows::Devices::HumanInterfaceDevice::IHidFeatureReport>
{
    int32_t WINRT_CALL get_Id(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL put_Data(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Data, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&);
            this->shim().Data(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetBooleanControl(uint16_t usagePage, uint16_t usageId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetBooleanControl, WINRT_WRAP(Windows::Devices::HumanInterfaceDevice::HidBooleanControl), uint16_t, uint16_t);
            *value = detach_from<Windows::Devices::HumanInterfaceDevice::HidBooleanControl>(this->shim().GetBooleanControl(usagePage, usageId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetBooleanControlByDescription(void* controlDescription, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetBooleanControlByDescription, WINRT_WRAP(Windows::Devices::HumanInterfaceDevice::HidBooleanControl), Windows::Devices::HumanInterfaceDevice::HidBooleanControlDescription const&);
            *value = detach_from<Windows::Devices::HumanInterfaceDevice::HidBooleanControl>(this->shim().GetBooleanControlByDescription(*reinterpret_cast<Windows::Devices::HumanInterfaceDevice::HidBooleanControlDescription const*>(&controlDescription)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNumericControl(uint16_t usagePage, uint16_t usageId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNumericControl, WINRT_WRAP(Windows::Devices::HumanInterfaceDevice::HidNumericControl), uint16_t, uint16_t);
            *value = detach_from<Windows::Devices::HumanInterfaceDevice::HidNumericControl>(this->shim().GetNumericControl(usagePage, usageId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNumericControlByDescription(void* controlDescription, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNumericControlByDescription, WINRT_WRAP(Windows::Devices::HumanInterfaceDevice::HidNumericControl), Windows::Devices::HumanInterfaceDevice::HidNumericControlDescription const&);
            *value = detach_from<Windows::Devices::HumanInterfaceDevice::HidNumericControl>(this->shim().GetNumericControlByDescription(*reinterpret_cast<Windows::Devices::HumanInterfaceDevice::HidNumericControlDescription const*>(&controlDescription)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::HumanInterfaceDevice::IHidInputReport> : produce_base<D, Windows::Devices::HumanInterfaceDevice::IHidInputReport>
{
    int32_t WINRT_CALL get_Id(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL get_ActivatedBooleanControls(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActivatedBooleanControls, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::HumanInterfaceDevice::HidBooleanControl>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::HumanInterfaceDevice::HidBooleanControl>>(this->shim().ActivatedBooleanControls());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransitionedBooleanControls(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransitionedBooleanControls, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::HumanInterfaceDevice::HidBooleanControl>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::HumanInterfaceDevice::HidBooleanControl>>(this->shim().TransitionedBooleanControls());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetBooleanControl(uint16_t usagePage, uint16_t usageId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetBooleanControl, WINRT_WRAP(Windows::Devices::HumanInterfaceDevice::HidBooleanControl), uint16_t, uint16_t);
            *value = detach_from<Windows::Devices::HumanInterfaceDevice::HidBooleanControl>(this->shim().GetBooleanControl(usagePage, usageId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetBooleanControlByDescription(void* controlDescription, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetBooleanControlByDescription, WINRT_WRAP(Windows::Devices::HumanInterfaceDevice::HidBooleanControl), Windows::Devices::HumanInterfaceDevice::HidBooleanControlDescription const&);
            *value = detach_from<Windows::Devices::HumanInterfaceDevice::HidBooleanControl>(this->shim().GetBooleanControlByDescription(*reinterpret_cast<Windows::Devices::HumanInterfaceDevice::HidBooleanControlDescription const*>(&controlDescription)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNumericControl(uint16_t usagePage, uint16_t usageId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNumericControl, WINRT_WRAP(Windows::Devices::HumanInterfaceDevice::HidNumericControl), uint16_t, uint16_t);
            *value = detach_from<Windows::Devices::HumanInterfaceDevice::HidNumericControl>(this->shim().GetNumericControl(usagePage, usageId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNumericControlByDescription(void* controlDescription, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNumericControlByDescription, WINRT_WRAP(Windows::Devices::HumanInterfaceDevice::HidNumericControl), Windows::Devices::HumanInterfaceDevice::HidNumericControlDescription const&);
            *value = detach_from<Windows::Devices::HumanInterfaceDevice::HidNumericControl>(this->shim().GetNumericControlByDescription(*reinterpret_cast<Windows::Devices::HumanInterfaceDevice::HidNumericControlDescription const*>(&controlDescription)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::HumanInterfaceDevice::IHidInputReportReceivedEventArgs> : produce_base<D, Windows::Devices::HumanInterfaceDevice::IHidInputReportReceivedEventArgs>
{
    int32_t WINRT_CALL get_Report(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Report, WINRT_WRAP(Windows::Devices::HumanInterfaceDevice::HidInputReport));
            *value = detach_from<Windows::Devices::HumanInterfaceDevice::HidInputReport>(this->shim().Report());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::HumanInterfaceDevice::IHidNumericControl> : produce_base<D, Windows::Devices::HumanInterfaceDevice::IHidNumericControl>
{
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

    int32_t WINRT_CALL get_IsGrouped(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsGrouped, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsGrouped());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UsagePage(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UsagePage, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().UsagePage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UsageId(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UsageId, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().UsageId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Value(int64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(int64_t));
            *value = detach_from<int64_t>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Value(int64_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(void), int64_t);
            this->shim().Value(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScaledValue(int64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScaledValue, WINRT_WRAP(int64_t));
            *value = detach_from<int64_t>(this->shim().ScaledValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ScaledValue(int64_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScaledValue, WINRT_WRAP(void), int64_t);
            this->shim().ScaledValue(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ControlDescription(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ControlDescription, WINRT_WRAP(Windows::Devices::HumanInterfaceDevice::HidNumericControlDescription));
            *value = detach_from<Windows::Devices::HumanInterfaceDevice::HidNumericControlDescription>(this->shim().ControlDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::HumanInterfaceDevice::IHidNumericControlDescription> : produce_base<D, Windows::Devices::HumanInterfaceDevice::IHidNumericControlDescription>
{
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

    int32_t WINRT_CALL get_ReportId(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportId, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().ReportId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReportType(Windows::Devices::HumanInterfaceDevice::HidReportType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportType, WINRT_WRAP(Windows::Devices::HumanInterfaceDevice::HidReportType));
            *value = detach_from<Windows::Devices::HumanInterfaceDevice::HidReportType>(this->shim().ReportType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReportSize(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportSize, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ReportSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReportCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ReportCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UsagePage(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UsagePage, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().UsagePage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UsageId(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UsageId, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().UsageId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LogicalMinimum(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LogicalMinimum, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().LogicalMinimum());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LogicalMaximum(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LogicalMaximum, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().LogicalMaximum());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PhysicalMinimum(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhysicalMinimum, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().PhysicalMinimum());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PhysicalMaximum(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhysicalMaximum, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().PhysicalMaximum());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UnitExponent(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnitExponent, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().UnitExponent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Unit(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Unit, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Unit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsAbsolute(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAbsolute, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsAbsolute());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasNull(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasNull, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasNull());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ParentCollections(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ParentCollections, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::HumanInterfaceDevice::HidCollection>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::HumanInterfaceDevice::HidCollection>>(this->shim().ParentCollections());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::HumanInterfaceDevice::IHidOutputReport> : produce_base<D, Windows::Devices::HumanInterfaceDevice::IHidOutputReport>
{
    int32_t WINRT_CALL get_Id(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL put_Data(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Data, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&);
            this->shim().Data(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetBooleanControl(uint16_t usagePage, uint16_t usageId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetBooleanControl, WINRT_WRAP(Windows::Devices::HumanInterfaceDevice::HidBooleanControl), uint16_t, uint16_t);
            *value = detach_from<Windows::Devices::HumanInterfaceDevice::HidBooleanControl>(this->shim().GetBooleanControl(usagePage, usageId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetBooleanControlByDescription(void* controlDescription, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetBooleanControlByDescription, WINRT_WRAP(Windows::Devices::HumanInterfaceDevice::HidBooleanControl), Windows::Devices::HumanInterfaceDevice::HidBooleanControlDescription const&);
            *value = detach_from<Windows::Devices::HumanInterfaceDevice::HidBooleanControl>(this->shim().GetBooleanControlByDescription(*reinterpret_cast<Windows::Devices::HumanInterfaceDevice::HidBooleanControlDescription const*>(&controlDescription)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNumericControl(uint16_t usagePage, uint16_t usageId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNumericControl, WINRT_WRAP(Windows::Devices::HumanInterfaceDevice::HidNumericControl), uint16_t, uint16_t);
            *value = detach_from<Windows::Devices::HumanInterfaceDevice::HidNumericControl>(this->shim().GetNumericControl(usagePage, usageId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNumericControlByDescription(void* controlDescription, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNumericControlByDescription, WINRT_WRAP(Windows::Devices::HumanInterfaceDevice::HidNumericControl), Windows::Devices::HumanInterfaceDevice::HidNumericControlDescription const&);
            *value = detach_from<Windows::Devices::HumanInterfaceDevice::HidNumericControl>(this->shim().GetNumericControlByDescription(*reinterpret_cast<Windows::Devices::HumanInterfaceDevice::HidNumericControlDescription const*>(&controlDescription)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::HumanInterfaceDevice {

inline hstring HidDevice::GetDeviceSelector(uint16_t usagePage, uint16_t usageId)
{
    return impl::call_factory<HidDevice, Windows::Devices::HumanInterfaceDevice::IHidDeviceStatics>([&](auto&& f) { return f.GetDeviceSelector(usagePage, usageId); });
}

inline hstring HidDevice::GetDeviceSelector(uint16_t usagePage, uint16_t usageId, uint16_t vendorId, uint16_t productId)
{
    return impl::call_factory<HidDevice, Windows::Devices::HumanInterfaceDevice::IHidDeviceStatics>([&](auto&& f) { return f.GetDeviceSelector(usagePage, usageId, vendorId, productId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::HumanInterfaceDevice::HidDevice> HidDevice::FromIdAsync(param::hstring const& deviceId, Windows::Storage::FileAccessMode const& accessMode)
{
    return impl::call_factory<HidDevice, Windows::Devices::HumanInterfaceDevice::IHidDeviceStatics>([&](auto&& f) { return f.FromIdAsync(deviceId, accessMode); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::HumanInterfaceDevice::IHidBooleanControl> : winrt::impl::hash_base<winrt::Windows::Devices::HumanInterfaceDevice::IHidBooleanControl> {};
template<> struct hash<winrt::Windows::Devices::HumanInterfaceDevice::IHidBooleanControlDescription> : winrt::impl::hash_base<winrt::Windows::Devices::HumanInterfaceDevice::IHidBooleanControlDescription> {};
template<> struct hash<winrt::Windows::Devices::HumanInterfaceDevice::IHidBooleanControlDescription2> : winrt::impl::hash_base<winrt::Windows::Devices::HumanInterfaceDevice::IHidBooleanControlDescription2> {};
template<> struct hash<winrt::Windows::Devices::HumanInterfaceDevice::IHidCollection> : winrt::impl::hash_base<winrt::Windows::Devices::HumanInterfaceDevice::IHidCollection> {};
template<> struct hash<winrt::Windows::Devices::HumanInterfaceDevice::IHidDevice> : winrt::impl::hash_base<winrt::Windows::Devices::HumanInterfaceDevice::IHidDevice> {};
template<> struct hash<winrt::Windows::Devices::HumanInterfaceDevice::IHidDeviceStatics> : winrt::impl::hash_base<winrt::Windows::Devices::HumanInterfaceDevice::IHidDeviceStatics> {};
template<> struct hash<winrt::Windows::Devices::HumanInterfaceDevice::IHidFeatureReport> : winrt::impl::hash_base<winrt::Windows::Devices::HumanInterfaceDevice::IHidFeatureReport> {};
template<> struct hash<winrt::Windows::Devices::HumanInterfaceDevice::IHidInputReport> : winrt::impl::hash_base<winrt::Windows::Devices::HumanInterfaceDevice::IHidInputReport> {};
template<> struct hash<winrt::Windows::Devices::HumanInterfaceDevice::IHidInputReportReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::HumanInterfaceDevice::IHidInputReportReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::HumanInterfaceDevice::IHidNumericControl> : winrt::impl::hash_base<winrt::Windows::Devices::HumanInterfaceDevice::IHidNumericControl> {};
template<> struct hash<winrt::Windows::Devices::HumanInterfaceDevice::IHidNumericControlDescription> : winrt::impl::hash_base<winrt::Windows::Devices::HumanInterfaceDevice::IHidNumericControlDescription> {};
template<> struct hash<winrt::Windows::Devices::HumanInterfaceDevice::IHidOutputReport> : winrt::impl::hash_base<winrt::Windows::Devices::HumanInterfaceDevice::IHidOutputReport> {};
template<> struct hash<winrt::Windows::Devices::HumanInterfaceDevice::HidBooleanControl> : winrt::impl::hash_base<winrt::Windows::Devices::HumanInterfaceDevice::HidBooleanControl> {};
template<> struct hash<winrt::Windows::Devices::HumanInterfaceDevice::HidBooleanControlDescription> : winrt::impl::hash_base<winrt::Windows::Devices::HumanInterfaceDevice::HidBooleanControlDescription> {};
template<> struct hash<winrt::Windows::Devices::HumanInterfaceDevice::HidCollection> : winrt::impl::hash_base<winrt::Windows::Devices::HumanInterfaceDevice::HidCollection> {};
template<> struct hash<winrt::Windows::Devices::HumanInterfaceDevice::HidDevice> : winrt::impl::hash_base<winrt::Windows::Devices::HumanInterfaceDevice::HidDevice> {};
template<> struct hash<winrt::Windows::Devices::HumanInterfaceDevice::HidFeatureReport> : winrt::impl::hash_base<winrt::Windows::Devices::HumanInterfaceDevice::HidFeatureReport> {};
template<> struct hash<winrt::Windows::Devices::HumanInterfaceDevice::HidInputReport> : winrt::impl::hash_base<winrt::Windows::Devices::HumanInterfaceDevice::HidInputReport> {};
template<> struct hash<winrt::Windows::Devices::HumanInterfaceDevice::HidInputReportReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::HumanInterfaceDevice::HidInputReportReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::HumanInterfaceDevice::HidNumericControl> : winrt::impl::hash_base<winrt::Windows::Devices::HumanInterfaceDevice::HidNumericControl> {};
template<> struct hash<winrt::Windows::Devices::HumanInterfaceDevice::HidNumericControlDescription> : winrt::impl::hash_base<winrt::Windows::Devices::HumanInterfaceDevice::HidNumericControlDescription> {};
template<> struct hash<winrt::Windows::Devices::HumanInterfaceDevice::HidOutputReport> : winrt::impl::hash_base<winrt::Windows::Devices::HumanInterfaceDevice::HidOutputReport> {};

}
