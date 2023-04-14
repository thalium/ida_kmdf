// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Networking.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Security.EnterpriseData.2.h"

namespace winrt::impl {

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Security_EnterpriseData_IBufferProtectUnprotectResult<D>::Buffer() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IBufferProtectUnprotectResult)->get_Buffer(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::EnterpriseData::DataProtectionInfo consume_Windows_Security_EnterpriseData_IBufferProtectUnprotectResult<D>::ProtectionInfo() const
{
    Windows::Security::EnterpriseData::DataProtectionInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IBufferProtectUnprotectResult)->get_ProtectionInfo(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::EnterpriseData::DataProtectionStatus consume_Windows_Security_EnterpriseData_IDataProtectionInfo<D>::Status() const
{
    Windows::Security::EnterpriseData::DataProtectionStatus value{};
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IDataProtectionInfo)->get_Status(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_EnterpriseData_IDataProtectionInfo<D>::Identity() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IDataProtectionInfo)->get_Identity(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::BufferProtectUnprotectResult> consume_Windows_Security_EnterpriseData_IDataProtectionManagerStatics<D>::ProtectAsync(Windows::Storage::Streams::IBuffer const& data, param::hstring const& identity) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::BufferProtectUnprotectResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IDataProtectionManagerStatics)->ProtectAsync(get_abi(data), get_abi(identity), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::BufferProtectUnprotectResult> consume_Windows_Security_EnterpriseData_IDataProtectionManagerStatics<D>::UnprotectAsync(Windows::Storage::Streams::IBuffer const& data) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::BufferProtectUnprotectResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IDataProtectionManagerStatics)->UnprotectAsync(get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::DataProtectionInfo> consume_Windows_Security_EnterpriseData_IDataProtectionManagerStatics<D>::ProtectStreamAsync(Windows::Storage::Streams::IInputStream const& unprotectedStream, param::hstring const& identity, Windows::Storage::Streams::IOutputStream const& protectedStream) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::DataProtectionInfo> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IDataProtectionManagerStatics)->ProtectStreamAsync(get_abi(unprotectedStream), get_abi(identity), get_abi(protectedStream), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::DataProtectionInfo> consume_Windows_Security_EnterpriseData_IDataProtectionManagerStatics<D>::UnprotectStreamAsync(Windows::Storage::Streams::IInputStream const& protectedStream, Windows::Storage::Streams::IOutputStream const& unprotectedStream) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::DataProtectionInfo> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IDataProtectionManagerStatics)->UnprotectStreamAsync(get_abi(protectedStream), get_abi(unprotectedStream), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::DataProtectionInfo> consume_Windows_Security_EnterpriseData_IDataProtectionManagerStatics<D>::GetProtectionInfoAsync(Windows::Storage::Streams::IBuffer const& protectedData) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::DataProtectionInfo> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IDataProtectionManagerStatics)->GetProtectionInfoAsync(get_abi(protectedData), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::DataProtectionInfo> consume_Windows_Security_EnterpriseData_IDataProtectionManagerStatics<D>::GetStreamProtectionInfoAsync(Windows::Storage::Streams::IInputStream const& protectedStream) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::DataProtectionInfo> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IDataProtectionManagerStatics)->GetStreamProtectionInfoAsync(get_abi(protectedStream), put_abi(result)));
    return result;
}

template <typename D> Windows::Security::EnterpriseData::FileProtectionStatus consume_Windows_Security_EnterpriseData_IFileProtectionInfo<D>::Status() const
{
    Windows::Security::EnterpriseData::FileProtectionStatus value{};
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IFileProtectionInfo)->get_Status(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Security_EnterpriseData_IFileProtectionInfo<D>::IsRoamable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IFileProtectionInfo)->get_IsRoamable(&value));
    return value;
}

template <typename D> hstring consume_Windows_Security_EnterpriseData_IFileProtectionInfo<D>::Identity() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IFileProtectionInfo)->get_Identity(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Security_EnterpriseData_IFileProtectionInfo2<D>::IsProtectWhileOpenSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IFileProtectionInfo2)->get_IsProtectWhileOpenSupported(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::FileProtectionInfo> consume_Windows_Security_EnterpriseData_IFileProtectionManagerStatics<D>::ProtectAsync(Windows::Storage::IStorageItem const& target, param::hstring const& identity) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::FileProtectionInfo> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IFileProtectionManagerStatics)->ProtectAsync(get_abi(target), get_abi(identity), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Security_EnterpriseData_IFileProtectionManagerStatics<D>::CopyProtectionAsync(Windows::Storage::IStorageItem const& source, Windows::Storage::IStorageItem const& target) const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IFileProtectionManagerStatics)->CopyProtectionAsync(get_abi(source), get_abi(target), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::FileProtectionInfo> consume_Windows_Security_EnterpriseData_IFileProtectionManagerStatics<D>::GetProtectionInfoAsync(Windows::Storage::IStorageItem const& source) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::FileProtectionInfo> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IFileProtectionManagerStatics)->GetProtectionInfoAsync(get_abi(source), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectedContainerExportResult> consume_Windows_Security_EnterpriseData_IFileProtectionManagerStatics<D>::SaveFileAsContainerAsync(Windows::Storage::IStorageFile const& protectedFile) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectedContainerExportResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IFileProtectionManagerStatics)->SaveFileAsContainerAsync(get_abi(protectedFile), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectedContainerImportResult> consume_Windows_Security_EnterpriseData_IFileProtectionManagerStatics<D>::LoadFileFromContainerAsync(Windows::Storage::IStorageFile const& containerFile) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectedContainerImportResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IFileProtectionManagerStatics)->LoadFileFromContainerAsync(get_abi(containerFile), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectedContainerImportResult> consume_Windows_Security_EnterpriseData_IFileProtectionManagerStatics<D>::LoadFileFromContainerAsync(Windows::Storage::IStorageFile const& containerFile, Windows::Storage::IStorageItem const& target) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectedContainerImportResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IFileProtectionManagerStatics)->LoadFileFromContainerWithTargetAsync(get_abi(containerFile), get_abi(target), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectedFileCreateResult> consume_Windows_Security_EnterpriseData_IFileProtectionManagerStatics<D>::CreateProtectedAndOpenAsync(Windows::Storage::IStorageFolder const& parentFolder, param::hstring const& desiredName, param::hstring const& identity, Windows::Storage::CreationCollisionOption const& collisionOption) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectedFileCreateResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IFileProtectionManagerStatics)->CreateProtectedAndOpenAsync(get_abi(parentFolder), get_abi(desiredName), get_abi(identity), get_abi(collisionOption), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Security_EnterpriseData_IFileProtectionManagerStatics2<D>::IsContainerAsync(Windows::Storage::IStorageFile const& file) const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IFileProtectionManagerStatics2)->IsContainerAsync(get_abi(file), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectedContainerImportResult> consume_Windows_Security_EnterpriseData_IFileProtectionManagerStatics2<D>::LoadFileFromContainerAsync(Windows::Storage::IStorageFile const& containerFile, Windows::Storage::IStorageItem const& target, Windows::Storage::NameCollisionOption const& collisionOption) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectedContainerImportResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IFileProtectionManagerStatics2)->LoadFileFromContainerWithTargetAndNameCollisionOptionAsync(get_abi(containerFile), get_abi(target), get_abi(collisionOption), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectedContainerExportResult> consume_Windows_Security_EnterpriseData_IFileProtectionManagerStatics2<D>::SaveFileAsContainerAsync(Windows::Storage::IStorageFile const& protectedFile, param::async_iterable<hstring> const& sharedWithIdentities) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectedContainerExportResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IFileProtectionManagerStatics2)->SaveFileAsContainerWithSharingAsync(get_abi(protectedFile), get_abi(sharedWithIdentities), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::FileProtectionInfo> consume_Windows_Security_EnterpriseData_IFileProtectionManagerStatics3<D>::UnprotectAsync(Windows::Storage::IStorageItem const& target) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::FileProtectionInfo> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IFileProtectionManagerStatics3)->UnprotectAsync(get_abi(target), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::FileProtectionInfo> consume_Windows_Security_EnterpriseData_IFileProtectionManagerStatics3<D>::UnprotectAsync(Windows::Storage::IStorageItem const& target, Windows::Security::EnterpriseData::FileUnprotectOptions const& options) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::FileProtectionInfo> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IFileProtectionManagerStatics3)->UnprotectWithOptionsAsync(get_abi(target), get_abi(options), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::FileProtectionStatus> consume_Windows_Security_EnterpriseData_IFileRevocationManagerStatics<D>::ProtectAsync(Windows::Storage::IStorageItem const& storageItem, param::hstring const& enterpriseIdentity) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::FileProtectionStatus> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IFileRevocationManagerStatics)->ProtectAsync(get_abi(storageItem), get_abi(enterpriseIdentity), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Security_EnterpriseData_IFileRevocationManagerStatics<D>::CopyProtectionAsync(Windows::Storage::IStorageItem const& sourceStorageItem, Windows::Storage::IStorageItem const& targetStorageItem) const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IFileRevocationManagerStatics)->CopyProtectionAsync(get_abi(sourceStorageItem), get_abi(targetStorageItem), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Security_EnterpriseData_IFileRevocationManagerStatics<D>::Revoke(param::hstring const& enterpriseIdentity) const
{
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IFileRevocationManagerStatics)->Revoke(get_abi(enterpriseIdentity)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::FileProtectionStatus> consume_Windows_Security_EnterpriseData_IFileRevocationManagerStatics<D>::GetStatusAsync(Windows::Storage::IStorageItem const& storageItem) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::FileProtectionStatus> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IFileRevocationManagerStatics)->GetStatusAsync(get_abi(storageItem), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Security_EnterpriseData_IFileUnprotectOptions<D>::Audit(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IFileUnprotectOptions)->put_Audit(value));
}

template <typename D> bool consume_Windows_Security_EnterpriseData_IFileUnprotectOptions<D>::Audit() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IFileUnprotectOptions)->get_Audit(&value));
    return value;
}

template <typename D> Windows::Security::EnterpriseData::FileUnprotectOptions consume_Windows_Security_EnterpriseData_IFileUnprotectOptionsFactory<D>::Create(bool audit) const
{
    Windows::Security::EnterpriseData::FileUnprotectOptions result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IFileUnprotectOptionsFactory)->Create(audit, put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_Security_EnterpriseData_IProtectedAccessResumedEventArgs<D>::Identities() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectedAccessResumedEventArgs)->get_Identities(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_Security_EnterpriseData_IProtectedAccessSuspendingEventArgs<D>::Identities() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectedAccessSuspendingEventArgs)->get_Identities(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Security_EnterpriseData_IProtectedAccessSuspendingEventArgs<D>::Deadline() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectedAccessSuspendingEventArgs)->get_Deadline(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Security_EnterpriseData_IProtectedAccessSuspendingEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectedAccessSuspendingEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> Windows::Security::EnterpriseData::ProtectedImportExportStatus consume_Windows_Security_EnterpriseData_IProtectedContainerExportResult<D>::Status() const
{
    Windows::Security::EnterpriseData::ProtectedImportExportStatus value{};
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectedContainerExportResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::StorageFile consume_Windows_Security_EnterpriseData_IProtectedContainerExportResult<D>::File() const
{
    Windows::Storage::StorageFile value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectedContainerExportResult)->get_File(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::EnterpriseData::ProtectedImportExportStatus consume_Windows_Security_EnterpriseData_IProtectedContainerImportResult<D>::Status() const
{
    Windows::Security::EnterpriseData::ProtectedImportExportStatus value{};
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectedContainerImportResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::StorageFile consume_Windows_Security_EnterpriseData_IProtectedContainerImportResult<D>::File() const
{
    Windows::Storage::StorageFile value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectedContainerImportResult)->get_File(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_Security_EnterpriseData_IProtectedContentRevokedEventArgs<D>::Identities() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectedContentRevokedEventArgs)->get_Identities(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::StorageFile consume_Windows_Security_EnterpriseData_IProtectedFileCreateResult<D>::File() const
{
    Windows::Storage::StorageFile value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectedFileCreateResult)->get_File(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IRandomAccessStream consume_Windows_Security_EnterpriseData_IProtectedFileCreateResult<D>::Stream() const
{
    Windows::Storage::Streams::IRandomAccessStream value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectedFileCreateResult)->get_Stream(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::EnterpriseData::FileProtectionInfo consume_Windows_Security_EnterpriseData_IProtectedFileCreateResult<D>::ProtectionInfo() const
{
    Windows::Security::EnterpriseData::FileProtectionInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectedFileCreateResult)->get_ProtectionInfo(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Security_EnterpriseData_IProtectionPolicyAuditInfo<D>::Action(Windows::Security::EnterpriseData::ProtectionPolicyAuditAction const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyAuditInfo)->put_Action(get_abi(value)));
}

template <typename D> Windows::Security::EnterpriseData::ProtectionPolicyAuditAction consume_Windows_Security_EnterpriseData_IProtectionPolicyAuditInfo<D>::Action() const
{
    Windows::Security::EnterpriseData::ProtectionPolicyAuditAction value{};
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyAuditInfo)->get_Action(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Security_EnterpriseData_IProtectionPolicyAuditInfo<D>::DataDescription(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyAuditInfo)->put_DataDescription(get_abi(value)));
}

template <typename D> hstring consume_Windows_Security_EnterpriseData_IProtectionPolicyAuditInfo<D>::DataDescription() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyAuditInfo)->get_DataDescription(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Security_EnterpriseData_IProtectionPolicyAuditInfo<D>::SourceDescription(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyAuditInfo)->put_SourceDescription(get_abi(value)));
}

template <typename D> hstring consume_Windows_Security_EnterpriseData_IProtectionPolicyAuditInfo<D>::SourceDescription() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyAuditInfo)->get_SourceDescription(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Security_EnterpriseData_IProtectionPolicyAuditInfo<D>::TargetDescription(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyAuditInfo)->put_TargetDescription(get_abi(value)));
}

template <typename D> hstring consume_Windows_Security_EnterpriseData_IProtectionPolicyAuditInfo<D>::TargetDescription() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyAuditInfo)->get_TargetDescription(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo consume_Windows_Security_EnterpriseData_IProtectionPolicyAuditInfoFactory<D>::Create(Windows::Security::EnterpriseData::ProtectionPolicyAuditAction const& action, param::hstring const& dataDescription, param::hstring const& sourceDescription, param::hstring const& targetDescription) const
{
    Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyAuditInfoFactory)->Create(get_abi(action), get_abi(dataDescription), get_abi(sourceDescription), get_abi(targetDescription), put_abi(result)));
    return result;
}

template <typename D> Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo consume_Windows_Security_EnterpriseData_IProtectionPolicyAuditInfoFactory<D>::CreateWithActionAndDataDescription(Windows::Security::EnterpriseData::ProtectionPolicyAuditAction const& action, param::hstring const& dataDescription) const
{
    Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyAuditInfoFactory)->CreateWithActionAndDataDescription(get_abi(action), get_abi(dataDescription), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Security_EnterpriseData_IProtectionPolicyManager<D>::Identity(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManager)->put_Identity(get_abi(value)));
}

template <typename D> hstring consume_Windows_Security_EnterpriseData_IProtectionPolicyManager<D>::Identity() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManager)->get_Identity(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Security_EnterpriseData_IProtectionPolicyManager2<D>::ShowEnterpriseIndicator(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManager2)->put_ShowEnterpriseIndicator(value));
}

template <typename D> bool consume_Windows_Security_EnterpriseData_IProtectionPolicyManager2<D>::ShowEnterpriseIndicator() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManager2)->get_ShowEnterpriseIndicator(&value));
    return value;
}

template <typename D> bool consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics<D>::IsIdentityManaged(param::hstring const& identity) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics)->IsIdentityManaged(get_abi(identity), &result));
    return result;
}

template <typename D> bool consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics<D>::TryApplyProcessUIPolicy(param::hstring const& identity) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics)->TryApplyProcessUIPolicy(get_abi(identity), &result));
    return result;
}

template <typename D> void consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics<D>::ClearProcessUIPolicy() const
{
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics)->ClearProcessUIPolicy());
}

template <typename D> Windows::Security::EnterpriseData::ThreadNetworkContext consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics<D>::CreateCurrentThreadNetworkContext(param::hstring const& identity) const
{
    Windows::Security::EnterpriseData::ThreadNetworkContext result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics)->CreateCurrentThreadNetworkContext(get_abi(identity), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics<D>::GetPrimaryManagedIdentityForNetworkEndpointAsync(Windows::Networking::HostName const& endpointHost) const
{
    Windows::Foundation::IAsyncOperation<hstring> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics)->GetPrimaryManagedIdentityForNetworkEndpointAsync(get_abi(endpointHost), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics<D>::RevokeContent(param::hstring const& identity) const
{
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics)->RevokeContent(get_abi(identity)));
}

template <typename D> Windows::Security::EnterpriseData::ProtectionPolicyManager consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics<D>::GetForCurrentView() const
{
    Windows::Security::EnterpriseData::ProtectionPolicyManager result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics)->GetForCurrentView(put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics<D>::ProtectedAccessSuspending(Windows::Foundation::EventHandler<Windows::Security::EnterpriseData::ProtectedAccessSuspendingEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics)->add_ProtectedAccessSuspending(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics<D>::ProtectedAccessSuspending_revoker consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics<D>::ProtectedAccessSuspending(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Security::EnterpriseData::ProtectedAccessSuspendingEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ProtectedAccessSuspending_revoker>(this, ProtectedAccessSuspending(handler));
}

template <typename D> void consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics<D>::ProtectedAccessSuspending(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics)->remove_ProtectedAccessSuspending(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics<D>::ProtectedAccessResumed(Windows::Foundation::EventHandler<Windows::Security::EnterpriseData::ProtectedAccessResumedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics)->add_ProtectedAccessResumed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics<D>::ProtectedAccessResumed_revoker consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics<D>::ProtectedAccessResumed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Security::EnterpriseData::ProtectedAccessResumedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ProtectedAccessResumed_revoker>(this, ProtectedAccessResumed(handler));
}

template <typename D> void consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics<D>::ProtectedAccessResumed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics)->remove_ProtectedAccessResumed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics<D>::ProtectedContentRevoked(Windows::Foundation::EventHandler<Windows::Security::EnterpriseData::ProtectedContentRevokedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics)->add_ProtectedContentRevoked(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics<D>::ProtectedContentRevoked_revoker consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics<D>::ProtectedContentRevoked(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Security::EnterpriseData::ProtectedContentRevokedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ProtectedContentRevoked_revoker>(this, ProtectedContentRevoked(handler));
}

template <typename D> void consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics<D>::ProtectedContentRevoked(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics)->remove_ProtectedContentRevoked(get_abi(token)));
}

template <typename D> Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics<D>::CheckAccess(param::hstring const& sourceIdentity, param::hstring const& targetIdentity) const
{
    Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult result{};
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics)->CheckAccess(get_abi(sourceIdentity), get_abi(targetIdentity), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics<D>::RequestAccessAsync(param::hstring const& sourceIdentity, param::hstring const& targetIdentity) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics)->RequestAccessAsync(get_abi(sourceIdentity), get_abi(targetIdentity), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics2<D>::HasContentBeenRevokedSince(param::hstring const& identity, Windows::Foundation::DateTime const& since) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics2)->HasContentBeenRevokedSince(get_abi(identity), get_abi(since), &result));
    return result;
}

template <typename D> Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics2<D>::CheckAccessForApp(param::hstring const& sourceIdentity, param::hstring const& appPackageFamilyName) const
{
    Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult result{};
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics2)->CheckAccessForApp(get_abi(sourceIdentity), get_abi(appPackageFamilyName), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics2<D>::RequestAccessForAppAsync(param::hstring const& sourceIdentity, param::hstring const& appPackageFamilyName) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics2)->RequestAccessForAppAsync(get_abi(sourceIdentity), get_abi(appPackageFamilyName), put_abi(result)));
    return result;
}

template <typename D> Windows::Security::EnterpriseData::EnforcementLevel consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics2<D>::GetEnforcementLevel(param::hstring const& identity) const
{
    Windows::Security::EnterpriseData::EnforcementLevel value{};
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics2)->GetEnforcementLevel(get_abi(identity), put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics2<D>::IsUserDecryptionAllowed(param::hstring const& identity) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics2)->IsUserDecryptionAllowed(get_abi(identity), &value));
    return value;
}

template <typename D> bool consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics2<D>::IsProtectionUnderLockRequired(param::hstring const& identity) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics2)->IsProtectionUnderLockRequired(get_abi(identity), &value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics2<D>::PolicyChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics2)->add_PolicyChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics2<D>::PolicyChanged_revoker consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics2<D>::PolicyChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, PolicyChanged_revoker>(this, PolicyChanged(handler));
}

template <typename D> void consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics2<D>::PolicyChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics2)->remove_PolicyChanged(get_abi(token)));
}

template <typename D> bool consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics2<D>::IsProtectionEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics2)->get_IsProtectionEnabled(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics3<D>::RequestAccessAsync(param::hstring const& sourceIdentity, param::hstring const& targetIdentity, Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const& auditInfo) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics3)->RequestAccessWithAuditingInfoAsync(get_abi(sourceIdentity), get_abi(targetIdentity), get_abi(auditInfo), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics3<D>::RequestAccessAsync(param::hstring const& sourceIdentity, param::hstring const& targetIdentity, Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const& auditInfo, param::hstring const& messageFromApp) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics3)->RequestAccessWithMessageAsync(get_abi(sourceIdentity), get_abi(targetIdentity), get_abi(auditInfo), get_abi(messageFromApp), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics3<D>::RequestAccessForAppAsync(param::hstring const& sourceIdentity, param::hstring const& appPackageFamilyName, Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const& auditInfo) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics3)->RequestAccessForAppWithAuditingInfoAsync(get_abi(sourceIdentity), get_abi(appPackageFamilyName), get_abi(auditInfo), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics3<D>::RequestAccessForAppAsync(param::hstring const& sourceIdentity, param::hstring const& appPackageFamilyName, Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const& auditInfo, param::hstring const& messageFromApp) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics3)->RequestAccessForAppWithMessageAsync(get_abi(sourceIdentity), get_abi(appPackageFamilyName), get_abi(auditInfo), get_abi(messageFromApp), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics3<D>::LogAuditEvent(param::hstring const& sourceIdentity, param::hstring const& targetIdentity, Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const& auditInfo) const
{
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics3)->LogAuditEvent(get_abi(sourceIdentity), get_abi(targetIdentity), get_abi(auditInfo)));
}

template <typename D> bool consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics4<D>::IsRoamableProtectionEnabled(param::hstring const& identity) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics4)->IsRoamableProtectionEnabled(get_abi(identity), &value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics4<D>::RequestAccessAsync(param::hstring const& sourceIdentity, param::hstring const& targetIdentity, Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const& auditInfo, param::hstring const& messageFromApp, Windows::Security::EnterpriseData::ProtectionPolicyRequestAccessBehavior const& behavior) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics4)->RequestAccessWithBehaviorAsync(get_abi(sourceIdentity), get_abi(targetIdentity), get_abi(auditInfo), get_abi(messageFromApp), get_abi(behavior), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics4<D>::RequestAccessForAppAsync(param::hstring const& sourceIdentity, param::hstring const& appPackageFamilyName, Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const& auditInfo, param::hstring const& messageFromApp, Windows::Security::EnterpriseData::ProtectionPolicyRequestAccessBehavior const& behavior) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics4)->RequestAccessForAppWithBehaviorAsync(get_abi(sourceIdentity), get_abi(appPackageFamilyName), get_abi(auditInfo), get_abi(messageFromApp), get_abi(behavior), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics4<D>::RequestAccessToFilesForAppAsync(param::async_iterable<Windows::Storage::IStorageItem> const& sourceItemList, param::hstring const& appPackageFamilyName, Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const& auditInfo) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics4)->RequestAccessToFilesForAppAsync(get_abi(sourceItemList), get_abi(appPackageFamilyName), get_abi(auditInfo), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics4<D>::RequestAccessToFilesForAppAsync(param::async_iterable<Windows::Storage::IStorageItem> const& sourceItemList, param::hstring const& appPackageFamilyName, Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const& auditInfo, param::hstring const& messageFromApp, Windows::Security::EnterpriseData::ProtectionPolicyRequestAccessBehavior const& behavior) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics4)->RequestAccessToFilesForAppWithMessageAndBehaviorAsync(get_abi(sourceItemList), get_abi(appPackageFamilyName), get_abi(auditInfo), get_abi(messageFromApp), get_abi(behavior), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics4<D>::RequestAccessToFilesForProcessAsync(param::async_iterable<Windows::Storage::IStorageItem> const& sourceItemList, uint32_t processId, Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const& auditInfo) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics4)->RequestAccessToFilesForProcessAsync(get_abi(sourceItemList), processId, get_abi(auditInfo), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics4<D>::RequestAccessToFilesForProcessAsync(param::async_iterable<Windows::Storage::IStorageItem> const& sourceItemList, uint32_t processId, Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const& auditInfo, param::hstring const& messageFromApp, Windows::Security::EnterpriseData::ProtectionPolicyRequestAccessBehavior const& behavior) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics4)->RequestAccessToFilesForProcessWithMessageAndBehaviorAsync(get_abi(sourceItemList), processId, get_abi(auditInfo), get_abi(messageFromApp), get_abi(behavior), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics4<D>::IsFileProtectionRequiredAsync(Windows::Storage::IStorageItem const& target, param::hstring const& identity) const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics4)->IsFileProtectionRequiredAsync(get_abi(target), get_abi(identity), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics4<D>::IsFileProtectionRequiredForNewFileAsync(Windows::Storage::IStorageFolder const& parentFolder, param::hstring const& identity, param::hstring const& desiredName) const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics4)->IsFileProtectionRequiredForNewFileAsync(get_abi(parentFolder), get_abi(identity), get_abi(desiredName), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics4<D>::PrimaryManagedIdentity() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics4)->get_PrimaryManagedIdentity(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics4<D>::GetPrimaryManagedIdentityForIdentity(param::hstring const& identity) const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics4)->GetPrimaryManagedIdentityForIdentity(get_abi(identity), put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Security::EnterpriseData::IBufferProtectUnprotectResult> : produce_base<D, Windows::Security::EnterpriseData::IBufferProtectUnprotectResult>
{
    int32_t WINRT_CALL get_Buffer(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Buffer, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().Buffer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProtectionInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtectionInfo, WINRT_WRAP(Windows::Security::EnterpriseData::DataProtectionInfo));
            *value = detach_from<Windows::Security::EnterpriseData::DataProtectionInfo>(this->shim().ProtectionInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::EnterpriseData::IDataProtectionInfo> : produce_base<D, Windows::Security::EnterpriseData::IDataProtectionInfo>
{
    int32_t WINRT_CALL get_Status(Windows::Security::EnterpriseData::DataProtectionStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Security::EnterpriseData::DataProtectionStatus));
            *value = detach_from<Windows::Security::EnterpriseData::DataProtectionStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Identity(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Identity, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Identity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::EnterpriseData::IDataProtectionManagerStatics> : produce_base<D, Windows::Security::EnterpriseData::IDataProtectionManagerStatics>
{
    int32_t WINRT_CALL ProtectAsync(void* data, void* identity, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtectAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::BufferProtectUnprotectResult>), Windows::Storage::Streams::IBuffer const, hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::BufferProtectUnprotectResult>>(this->shim().ProtectAsync(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&data), *reinterpret_cast<hstring const*>(&identity)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UnprotectAsync(void* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnprotectAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::BufferProtectUnprotectResult>), Windows::Storage::Streams::IBuffer const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::BufferProtectUnprotectResult>>(this->shim().UnprotectAsync(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ProtectStreamAsync(void* unprotectedStream, void* identity, void* protectedStream, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtectStreamAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::DataProtectionInfo>), Windows::Storage::Streams::IInputStream const, hstring const, Windows::Storage::Streams::IOutputStream const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::DataProtectionInfo>>(this->shim().ProtectStreamAsync(*reinterpret_cast<Windows::Storage::Streams::IInputStream const*>(&unprotectedStream), *reinterpret_cast<hstring const*>(&identity), *reinterpret_cast<Windows::Storage::Streams::IOutputStream const*>(&protectedStream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UnprotectStreamAsync(void* protectedStream, void* unprotectedStream, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnprotectStreamAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::DataProtectionInfo>), Windows::Storage::Streams::IInputStream const, Windows::Storage::Streams::IOutputStream const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::DataProtectionInfo>>(this->shim().UnprotectStreamAsync(*reinterpret_cast<Windows::Storage::Streams::IInputStream const*>(&protectedStream), *reinterpret_cast<Windows::Storage::Streams::IOutputStream const*>(&unprotectedStream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetProtectionInfoAsync(void* protectedData, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetProtectionInfoAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::DataProtectionInfo>), Windows::Storage::Streams::IBuffer const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::DataProtectionInfo>>(this->shim().GetProtectionInfoAsync(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&protectedData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStreamProtectionInfoAsync(void* protectedStream, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStreamProtectionInfoAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::DataProtectionInfo>), Windows::Storage::Streams::IInputStream const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::DataProtectionInfo>>(this->shim().GetStreamProtectionInfoAsync(*reinterpret_cast<Windows::Storage::Streams::IInputStream const*>(&protectedStream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::EnterpriseData::IFileProtectionInfo> : produce_base<D, Windows::Security::EnterpriseData::IFileProtectionInfo>
{
    int32_t WINRT_CALL get_Status(Windows::Security::EnterpriseData::FileProtectionStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Security::EnterpriseData::FileProtectionStatus));
            *value = detach_from<Windows::Security::EnterpriseData::FileProtectionStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsRoamable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRoamable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsRoamable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Identity(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Identity, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Identity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::EnterpriseData::IFileProtectionInfo2> : produce_base<D, Windows::Security::EnterpriseData::IFileProtectionInfo2>
{
    int32_t WINRT_CALL get_IsProtectWhileOpenSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsProtectWhileOpenSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsProtectWhileOpenSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::EnterpriseData::IFileProtectionManagerStatics> : produce_base<D, Windows::Security::EnterpriseData::IFileProtectionManagerStatics>
{
    int32_t WINRT_CALL ProtectAsync(void* target, void* identity, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtectAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::FileProtectionInfo>), Windows::Storage::IStorageItem const, hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::FileProtectionInfo>>(this->shim().ProtectAsync(*reinterpret_cast<Windows::Storage::IStorageItem const*>(&target), *reinterpret_cast<hstring const*>(&identity)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CopyProtectionAsync(void* source, void* target, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CopyProtectionAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Storage::IStorageItem const, Windows::Storage::IStorageItem const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().CopyProtectionAsync(*reinterpret_cast<Windows::Storage::IStorageItem const*>(&source), *reinterpret_cast<Windows::Storage::IStorageItem const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetProtectionInfoAsync(void* source, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetProtectionInfoAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::FileProtectionInfo>), Windows::Storage::IStorageItem const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::FileProtectionInfo>>(this->shim().GetProtectionInfoAsync(*reinterpret_cast<Windows::Storage::IStorageItem const*>(&source)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SaveFileAsContainerAsync(void* protectedFile, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveFileAsContainerAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectedContainerExportResult>), Windows::Storage::IStorageFile const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectedContainerExportResult>>(this->shim().SaveFileAsContainerAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&protectedFile)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LoadFileFromContainerAsync(void* containerFile, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadFileFromContainerAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectedContainerImportResult>), Windows::Storage::IStorageFile const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectedContainerImportResult>>(this->shim().LoadFileFromContainerAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&containerFile)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LoadFileFromContainerWithTargetAsync(void* containerFile, void* target, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadFileFromContainerAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectedContainerImportResult>), Windows::Storage::IStorageFile const, Windows::Storage::IStorageItem const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectedContainerImportResult>>(this->shim().LoadFileFromContainerAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&containerFile), *reinterpret_cast<Windows::Storage::IStorageItem const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateProtectedAndOpenAsync(void* parentFolder, void* desiredName, void* identity, Windows::Storage::CreationCollisionOption collisionOption, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateProtectedAndOpenAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectedFileCreateResult>), Windows::Storage::IStorageFolder const, hstring const, hstring const, Windows::Storage::CreationCollisionOption const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectedFileCreateResult>>(this->shim().CreateProtectedAndOpenAsync(*reinterpret_cast<Windows::Storage::IStorageFolder const*>(&parentFolder), *reinterpret_cast<hstring const*>(&desiredName), *reinterpret_cast<hstring const*>(&identity), *reinterpret_cast<Windows::Storage::CreationCollisionOption const*>(&collisionOption)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::EnterpriseData::IFileProtectionManagerStatics2> : produce_base<D, Windows::Security::EnterpriseData::IFileProtectionManagerStatics2>
{
    int32_t WINRT_CALL IsContainerAsync(void* file, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsContainerAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Storage::IStorageFile const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().IsContainerAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LoadFileFromContainerWithTargetAndNameCollisionOptionAsync(void* containerFile, void* target, Windows::Storage::NameCollisionOption collisionOption, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadFileFromContainerAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectedContainerImportResult>), Windows::Storage::IStorageFile const, Windows::Storage::IStorageItem const, Windows::Storage::NameCollisionOption const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectedContainerImportResult>>(this->shim().LoadFileFromContainerAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&containerFile), *reinterpret_cast<Windows::Storage::IStorageItem const*>(&target), *reinterpret_cast<Windows::Storage::NameCollisionOption const*>(&collisionOption)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SaveFileAsContainerWithSharingAsync(void* protectedFile, void* sharedWithIdentities, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveFileAsContainerAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectedContainerExportResult>), Windows::Storage::IStorageFile const, Windows::Foundation::Collections::IIterable<hstring> const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectedContainerExportResult>>(this->shim().SaveFileAsContainerAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&protectedFile), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&sharedWithIdentities)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::EnterpriseData::IFileProtectionManagerStatics3> : produce_base<D, Windows::Security::EnterpriseData::IFileProtectionManagerStatics3>
{
    int32_t WINRT_CALL UnprotectAsync(void* target, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnprotectAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::FileProtectionInfo>), Windows::Storage::IStorageItem const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::FileProtectionInfo>>(this->shim().UnprotectAsync(*reinterpret_cast<Windows::Storage::IStorageItem const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UnprotectWithOptionsAsync(void* target, void* options, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnprotectAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::FileProtectionInfo>), Windows::Storage::IStorageItem const, Windows::Security::EnterpriseData::FileUnprotectOptions const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::FileProtectionInfo>>(this->shim().UnprotectAsync(*reinterpret_cast<Windows::Storage::IStorageItem const*>(&target), *reinterpret_cast<Windows::Security::EnterpriseData::FileUnprotectOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::EnterpriseData::IFileRevocationManagerStatics> : produce_base<D, Windows::Security::EnterpriseData::IFileRevocationManagerStatics>
{
    int32_t WINRT_CALL ProtectAsync(void* storageItem, void* enterpriseIdentity, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtectAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::FileProtectionStatus>), Windows::Storage::IStorageItem const, hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::FileProtectionStatus>>(this->shim().ProtectAsync(*reinterpret_cast<Windows::Storage::IStorageItem const*>(&storageItem), *reinterpret_cast<hstring const*>(&enterpriseIdentity)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CopyProtectionAsync(void* sourceStorageItem, void* targetStorageItem, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CopyProtectionAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Storage::IStorageItem const, Windows::Storage::IStorageItem const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().CopyProtectionAsync(*reinterpret_cast<Windows::Storage::IStorageItem const*>(&sourceStorageItem), *reinterpret_cast<Windows::Storage::IStorageItem const*>(&targetStorageItem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Revoke(void* enterpriseIdentity) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Revoke, WINRT_WRAP(void), hstring const&);
            this->shim().Revoke(*reinterpret_cast<hstring const*>(&enterpriseIdentity));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStatusAsync(void* storageItem, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStatusAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::FileProtectionStatus>), Windows::Storage::IStorageItem const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::FileProtectionStatus>>(this->shim().GetStatusAsync(*reinterpret_cast<Windows::Storage::IStorageItem const*>(&storageItem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::EnterpriseData::IFileUnprotectOptions> : produce_base<D, Windows::Security::EnterpriseData::IFileUnprotectOptions>
{
    int32_t WINRT_CALL put_Audit(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Audit, WINRT_WRAP(void), bool);
            this->shim().Audit(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Audit(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Audit, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Audit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::EnterpriseData::IFileUnprotectOptionsFactory> : produce_base<D, Windows::Security::EnterpriseData::IFileUnprotectOptionsFactory>
{
    int32_t WINRT_CALL Create(bool audit, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Security::EnterpriseData::FileUnprotectOptions), bool);
            *result = detach_from<Windows::Security::EnterpriseData::FileUnprotectOptions>(this->shim().Create(audit));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::EnterpriseData::IProtectedAccessResumedEventArgs> : produce_base<D, Windows::Security::EnterpriseData::IProtectedAccessResumedEventArgs>
{
    int32_t WINRT_CALL get_Identities(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Identities, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().Identities());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::EnterpriseData::IProtectedAccessSuspendingEventArgs> : produce_base<D, Windows::Security::EnterpriseData::IProtectedAccessSuspendingEventArgs>
{
    int32_t WINRT_CALL get_Identities(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Identities, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().Identities());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Deadline(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Deadline, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().Deadline());
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
struct produce<D, Windows::Security::EnterpriseData::IProtectedContainerExportResult> : produce_base<D, Windows::Security::EnterpriseData::IProtectedContainerExportResult>
{
    int32_t WINRT_CALL get_Status(Windows::Security::EnterpriseData::ProtectedImportExportStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Security::EnterpriseData::ProtectedImportExportStatus));
            *value = detach_from<Windows::Security::EnterpriseData::ProtectedImportExportStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_File(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(File, WINRT_WRAP(Windows::Storage::StorageFile));
            *value = detach_from<Windows::Storage::StorageFile>(this->shim().File());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::EnterpriseData::IProtectedContainerImportResult> : produce_base<D, Windows::Security::EnterpriseData::IProtectedContainerImportResult>
{
    int32_t WINRT_CALL get_Status(Windows::Security::EnterpriseData::ProtectedImportExportStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Security::EnterpriseData::ProtectedImportExportStatus));
            *value = detach_from<Windows::Security::EnterpriseData::ProtectedImportExportStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_File(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(File, WINRT_WRAP(Windows::Storage::StorageFile));
            *value = detach_from<Windows::Storage::StorageFile>(this->shim().File());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::EnterpriseData::IProtectedContentRevokedEventArgs> : produce_base<D, Windows::Security::EnterpriseData::IProtectedContentRevokedEventArgs>
{
    int32_t WINRT_CALL get_Identities(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Identities, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().Identities());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::EnterpriseData::IProtectedFileCreateResult> : produce_base<D, Windows::Security::EnterpriseData::IProtectedFileCreateResult>
{
    int32_t WINRT_CALL get_File(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(File, WINRT_WRAP(Windows::Storage::StorageFile));
            *value = detach_from<Windows::Storage::StorageFile>(this->shim().File());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Stream(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stream, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStream));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStream>(this->shim().Stream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProtectionInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtectionInfo, WINRT_WRAP(Windows::Security::EnterpriseData::FileProtectionInfo));
            *value = detach_from<Windows::Security::EnterpriseData::FileProtectionInfo>(this->shim().ProtectionInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::EnterpriseData::IProtectionPolicyAuditInfo> : produce_base<D, Windows::Security::EnterpriseData::IProtectionPolicyAuditInfo>
{
    int32_t WINRT_CALL put_Action(Windows::Security::EnterpriseData::ProtectionPolicyAuditAction value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Action, WINRT_WRAP(void), Windows::Security::EnterpriseData::ProtectionPolicyAuditAction const&);
            this->shim().Action(*reinterpret_cast<Windows::Security::EnterpriseData::ProtectionPolicyAuditAction const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Action(Windows::Security::EnterpriseData::ProtectionPolicyAuditAction* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Action, WINRT_WRAP(Windows::Security::EnterpriseData::ProtectionPolicyAuditAction));
            *value = detach_from<Windows::Security::EnterpriseData::ProtectionPolicyAuditAction>(this->shim().Action());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DataDescription(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataDescription, WINRT_WRAP(void), hstring const&);
            this->shim().DataDescription(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DataDescription(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataDescription, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DataDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SourceDescription(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceDescription, WINRT_WRAP(void), hstring const&);
            this->shim().SourceDescription(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SourceDescription(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceDescription, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SourceDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TargetDescription(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetDescription, WINRT_WRAP(void), hstring const&);
            this->shim().TargetDescription(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TargetDescription(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetDescription, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TargetDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::EnterpriseData::IProtectionPolicyAuditInfoFactory> : produce_base<D, Windows::Security::EnterpriseData::IProtectionPolicyAuditInfoFactory>
{
    int32_t WINRT_CALL Create(Windows::Security::EnterpriseData::ProtectionPolicyAuditAction action, void* dataDescription, void* sourceDescription, void* targetDescription, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo), Windows::Security::EnterpriseData::ProtectionPolicyAuditAction const&, hstring const&, hstring const&, hstring const&);
            *result = detach_from<Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo>(this->shim().Create(*reinterpret_cast<Windows::Security::EnterpriseData::ProtectionPolicyAuditAction const*>(&action), *reinterpret_cast<hstring const*>(&dataDescription), *reinterpret_cast<hstring const*>(&sourceDescription), *reinterpret_cast<hstring const*>(&targetDescription)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithActionAndDataDescription(Windows::Security::EnterpriseData::ProtectionPolicyAuditAction action, void* dataDescription, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithActionAndDataDescription, WINRT_WRAP(Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo), Windows::Security::EnterpriseData::ProtectionPolicyAuditAction const&, hstring const&);
            *result = detach_from<Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo>(this->shim().CreateWithActionAndDataDescription(*reinterpret_cast<Windows::Security::EnterpriseData::ProtectionPolicyAuditAction const*>(&action), *reinterpret_cast<hstring const*>(&dataDescription)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::EnterpriseData::IProtectionPolicyManager> : produce_base<D, Windows::Security::EnterpriseData::IProtectionPolicyManager>
{
    int32_t WINRT_CALL put_Identity(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Identity, WINRT_WRAP(void), hstring const&);
            this->shim().Identity(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Identity(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Identity, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Identity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::EnterpriseData::IProtectionPolicyManager2> : produce_base<D, Windows::Security::EnterpriseData::IProtectionPolicyManager2>
{
    int32_t WINRT_CALL put_ShowEnterpriseIndicator(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowEnterpriseIndicator, WINRT_WRAP(void), bool);
            this->shim().ShowEnterpriseIndicator(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShowEnterpriseIndicator(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowEnterpriseIndicator, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ShowEnterpriseIndicator());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics> : produce_base<D, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics>
{
    int32_t WINRT_CALL IsIdentityManaged(void* identity, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsIdentityManaged, WINRT_WRAP(bool), hstring const&);
            *result = detach_from<bool>(this->shim().IsIdentityManaged(*reinterpret_cast<hstring const*>(&identity)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryApplyProcessUIPolicy(void* identity, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryApplyProcessUIPolicy, WINRT_WRAP(bool), hstring const&);
            *result = detach_from<bool>(this->shim().TryApplyProcessUIPolicy(*reinterpret_cast<hstring const*>(&identity)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClearProcessUIPolicy() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClearProcessUIPolicy, WINRT_WRAP(void));
            this->shim().ClearProcessUIPolicy();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateCurrentThreadNetworkContext(void* identity, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateCurrentThreadNetworkContext, WINRT_WRAP(Windows::Security::EnterpriseData::ThreadNetworkContext), hstring const&);
            *result = detach_from<Windows::Security::EnterpriseData::ThreadNetworkContext>(this->shim().CreateCurrentThreadNetworkContext(*reinterpret_cast<hstring const*>(&identity)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPrimaryManagedIdentityForNetworkEndpointAsync(void* endpointHost, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPrimaryManagedIdentityForNetworkEndpointAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>), Windows::Networking::HostName const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetPrimaryManagedIdentityForNetworkEndpointAsync(*reinterpret_cast<Windows::Networking::HostName const*>(&endpointHost)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RevokeContent(void* identity) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RevokeContent, WINRT_WRAP(void), hstring const&);
            this->shim().RevokeContent(*reinterpret_cast<hstring const*>(&identity));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetForCurrentView(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentView, WINRT_WRAP(Windows::Security::EnterpriseData::ProtectionPolicyManager));
            *result = detach_from<Windows::Security::EnterpriseData::ProtectionPolicyManager>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ProtectedAccessSuspending(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtectedAccessSuspending, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Security::EnterpriseData::ProtectedAccessSuspendingEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ProtectedAccessSuspending(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Security::EnterpriseData::ProtectedAccessSuspendingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ProtectedAccessSuspending(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ProtectedAccessSuspending, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ProtectedAccessSuspending(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ProtectedAccessResumed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtectedAccessResumed, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Security::EnterpriseData::ProtectedAccessResumedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ProtectedAccessResumed(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Security::EnterpriseData::ProtectedAccessResumedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ProtectedAccessResumed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ProtectedAccessResumed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ProtectedAccessResumed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ProtectedContentRevoked(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtectedContentRevoked, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Security::EnterpriseData::ProtectedContentRevokedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ProtectedContentRevoked(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Security::EnterpriseData::ProtectedContentRevokedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ProtectedContentRevoked(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ProtectedContentRevoked, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ProtectedContentRevoked(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL CheckAccess(void* sourceIdentity, void* targetIdentity, Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckAccess, WINRT_WRAP(Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult), hstring const&, hstring const&);
            *result = detach_from<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>(this->shim().CheckAccess(*reinterpret_cast<hstring const*>(&sourceIdentity), *reinterpret_cast<hstring const*>(&targetIdentity)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestAccessAsync(void* sourceIdentity, void* targetIdentity, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAccessAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>), hstring const, hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>>(this->shim().RequestAccessAsync(*reinterpret_cast<hstring const*>(&sourceIdentity), *reinterpret_cast<hstring const*>(&targetIdentity)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics2> : produce_base<D, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics2>
{
    int32_t WINRT_CALL HasContentBeenRevokedSince(void* identity, Windows::Foundation::DateTime since, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasContentBeenRevokedSince, WINRT_WRAP(bool), hstring const&, Windows::Foundation::DateTime const&);
            *result = detach_from<bool>(this->shim().HasContentBeenRevokedSince(*reinterpret_cast<hstring const*>(&identity), *reinterpret_cast<Windows::Foundation::DateTime const*>(&since)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CheckAccessForApp(void* sourceIdentity, void* appPackageFamilyName, Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckAccessForApp, WINRT_WRAP(Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult), hstring const&, hstring const&);
            *result = detach_from<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>(this->shim().CheckAccessForApp(*reinterpret_cast<hstring const*>(&sourceIdentity), *reinterpret_cast<hstring const*>(&appPackageFamilyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestAccessForAppAsync(void* sourceIdentity, void* appPackageFamilyName, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAccessForAppAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>), hstring const, hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>>(this->shim().RequestAccessForAppAsync(*reinterpret_cast<hstring const*>(&sourceIdentity), *reinterpret_cast<hstring const*>(&appPackageFamilyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetEnforcementLevel(void* identity, Windows::Security::EnterpriseData::EnforcementLevel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetEnforcementLevel, WINRT_WRAP(Windows::Security::EnterpriseData::EnforcementLevel), hstring const&);
            *value = detach_from<Windows::Security::EnterpriseData::EnforcementLevel>(this->shim().GetEnforcementLevel(*reinterpret_cast<hstring const*>(&identity)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsUserDecryptionAllowed(void* identity, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsUserDecryptionAllowed, WINRT_WRAP(bool), hstring const&);
            *value = detach_from<bool>(this->shim().IsUserDecryptionAllowed(*reinterpret_cast<hstring const*>(&identity)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsProtectionUnderLockRequired(void* identity, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsProtectionUnderLockRequired, WINRT_WRAP(bool), hstring const&);
            *value = detach_from<bool>(this->shim().IsProtectionUnderLockRequired(*reinterpret_cast<hstring const*>(&identity)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_PolicyChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PolicyChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().PolicyChanged(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PolicyChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PolicyChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PolicyChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_IsProtectionEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsProtectionEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsProtectionEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics3> : produce_base<D, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics3>
{
    int32_t WINRT_CALL RequestAccessWithAuditingInfoAsync(void* sourceIdentity, void* targetIdentity, void* auditInfo, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAccessAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>), hstring const, hstring const, Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>>(this->shim().RequestAccessAsync(*reinterpret_cast<hstring const*>(&sourceIdentity), *reinterpret_cast<hstring const*>(&targetIdentity), *reinterpret_cast<Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const*>(&auditInfo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestAccessWithMessageAsync(void* sourceIdentity, void* targetIdentity, void* auditInfo, void* messageFromApp, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAccessAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>), hstring const, hstring const, Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const, hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>>(this->shim().RequestAccessAsync(*reinterpret_cast<hstring const*>(&sourceIdentity), *reinterpret_cast<hstring const*>(&targetIdentity), *reinterpret_cast<Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const*>(&auditInfo), *reinterpret_cast<hstring const*>(&messageFromApp)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestAccessForAppWithAuditingInfoAsync(void* sourceIdentity, void* appPackageFamilyName, void* auditInfo, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAccessForAppAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>), hstring const, hstring const, Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>>(this->shim().RequestAccessForAppAsync(*reinterpret_cast<hstring const*>(&sourceIdentity), *reinterpret_cast<hstring const*>(&appPackageFamilyName), *reinterpret_cast<Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const*>(&auditInfo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestAccessForAppWithMessageAsync(void* sourceIdentity, void* appPackageFamilyName, void* auditInfo, void* messageFromApp, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAccessForAppAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>), hstring const, hstring const, Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const, hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>>(this->shim().RequestAccessForAppAsync(*reinterpret_cast<hstring const*>(&sourceIdentity), *reinterpret_cast<hstring const*>(&appPackageFamilyName), *reinterpret_cast<Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const*>(&auditInfo), *reinterpret_cast<hstring const*>(&messageFromApp)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LogAuditEvent(void* sourceIdentity, void* targetIdentity, void* auditInfo) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LogAuditEvent, WINRT_WRAP(void), hstring const&, hstring const&, Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const&);
            this->shim().LogAuditEvent(*reinterpret_cast<hstring const*>(&sourceIdentity), *reinterpret_cast<hstring const*>(&targetIdentity), *reinterpret_cast<Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const*>(&auditInfo));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics4> : produce_base<D, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics4>
{
    int32_t WINRT_CALL IsRoamableProtectionEnabled(void* identity, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRoamableProtectionEnabled, WINRT_WRAP(bool), hstring const&);
            *value = detach_from<bool>(this->shim().IsRoamableProtectionEnabled(*reinterpret_cast<hstring const*>(&identity)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestAccessWithBehaviorAsync(void* sourceIdentity, void* targetIdentity, void* auditInfo, void* messageFromApp, Windows::Security::EnterpriseData::ProtectionPolicyRequestAccessBehavior behavior, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAccessAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>), hstring const, hstring const, Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const, hstring const, Windows::Security::EnterpriseData::ProtectionPolicyRequestAccessBehavior const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>>(this->shim().RequestAccessAsync(*reinterpret_cast<hstring const*>(&sourceIdentity), *reinterpret_cast<hstring const*>(&targetIdentity), *reinterpret_cast<Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const*>(&auditInfo), *reinterpret_cast<hstring const*>(&messageFromApp), *reinterpret_cast<Windows::Security::EnterpriseData::ProtectionPolicyRequestAccessBehavior const*>(&behavior)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestAccessForAppWithBehaviorAsync(void* sourceIdentity, void* appPackageFamilyName, void* auditInfo, void* messageFromApp, Windows::Security::EnterpriseData::ProtectionPolicyRequestAccessBehavior behavior, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAccessForAppAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>), hstring const, hstring const, Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const, hstring const, Windows::Security::EnterpriseData::ProtectionPolicyRequestAccessBehavior const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>>(this->shim().RequestAccessForAppAsync(*reinterpret_cast<hstring const*>(&sourceIdentity), *reinterpret_cast<hstring const*>(&appPackageFamilyName), *reinterpret_cast<Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const*>(&auditInfo), *reinterpret_cast<hstring const*>(&messageFromApp), *reinterpret_cast<Windows::Security::EnterpriseData::ProtectionPolicyRequestAccessBehavior const*>(&behavior)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestAccessToFilesForAppAsync(void* sourceItemList, void* appPackageFamilyName, void* auditInfo, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAccessToFilesForAppAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>), Windows::Foundation::Collections::IIterable<Windows::Storage::IStorageItem> const, hstring const, Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>>(this->shim().RequestAccessToFilesForAppAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Storage::IStorageItem> const*>(&sourceItemList), *reinterpret_cast<hstring const*>(&appPackageFamilyName), *reinterpret_cast<Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const*>(&auditInfo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestAccessToFilesForAppWithMessageAndBehaviorAsync(void* sourceItemList, void* appPackageFamilyName, void* auditInfo, void* messageFromApp, Windows::Security::EnterpriseData::ProtectionPolicyRequestAccessBehavior behavior, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAccessToFilesForAppAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>), Windows::Foundation::Collections::IIterable<Windows::Storage::IStorageItem> const, hstring const, Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const, hstring const, Windows::Security::EnterpriseData::ProtectionPolicyRequestAccessBehavior const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>>(this->shim().RequestAccessToFilesForAppAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Storage::IStorageItem> const*>(&sourceItemList), *reinterpret_cast<hstring const*>(&appPackageFamilyName), *reinterpret_cast<Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const*>(&auditInfo), *reinterpret_cast<hstring const*>(&messageFromApp), *reinterpret_cast<Windows::Security::EnterpriseData::ProtectionPolicyRequestAccessBehavior const*>(&behavior)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestAccessToFilesForProcessAsync(void* sourceItemList, uint32_t processId, void* auditInfo, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAccessToFilesForProcessAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>), Windows::Foundation::Collections::IIterable<Windows::Storage::IStorageItem> const, uint32_t, Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>>(this->shim().RequestAccessToFilesForProcessAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Storage::IStorageItem> const*>(&sourceItemList), processId, *reinterpret_cast<Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const*>(&auditInfo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestAccessToFilesForProcessWithMessageAndBehaviorAsync(void* sourceItemList, uint32_t processId, void* auditInfo, void* messageFromApp, Windows::Security::EnterpriseData::ProtectionPolicyRequestAccessBehavior behavior, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAccessToFilesForProcessAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>), Windows::Foundation::Collections::IIterable<Windows::Storage::IStorageItem> const, uint32_t, Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const, hstring const, Windows::Security::EnterpriseData::ProtectionPolicyRequestAccessBehavior const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>>(this->shim().RequestAccessToFilesForProcessAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Storage::IStorageItem> const*>(&sourceItemList), processId, *reinterpret_cast<Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const*>(&auditInfo), *reinterpret_cast<hstring const*>(&messageFromApp), *reinterpret_cast<Windows::Security::EnterpriseData::ProtectionPolicyRequestAccessBehavior const*>(&behavior)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsFileProtectionRequiredAsync(void* target, void* identity, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsFileProtectionRequiredAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Storage::IStorageItem const, hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().IsFileProtectionRequiredAsync(*reinterpret_cast<Windows::Storage::IStorageItem const*>(&target), *reinterpret_cast<hstring const*>(&identity)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsFileProtectionRequiredForNewFileAsync(void* parentFolder, void* identity, void* desiredName, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsFileProtectionRequiredForNewFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Storage::IStorageFolder const, hstring const, hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().IsFileProtectionRequiredForNewFileAsync(*reinterpret_cast<Windows::Storage::IStorageFolder const*>(&parentFolder), *reinterpret_cast<hstring const*>(&identity), *reinterpret_cast<hstring const*>(&desiredName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PrimaryManagedIdentity(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrimaryManagedIdentity, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PrimaryManagedIdentity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPrimaryManagedIdentityForIdentity(void* identity, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPrimaryManagedIdentityForIdentity, WINRT_WRAP(hstring), hstring const&);
            *value = detach_from<hstring>(this->shim().GetPrimaryManagedIdentityForIdentity(*reinterpret_cast<hstring const*>(&identity)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::EnterpriseData::IThreadNetworkContext> : produce_base<D, Windows::Security::EnterpriseData::IThreadNetworkContext>
{};

}

WINRT_EXPORT namespace winrt::Windows::Security::EnterpriseData {

inline Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::BufferProtectUnprotectResult> DataProtectionManager::ProtectAsync(Windows::Storage::Streams::IBuffer const& data, param::hstring const& identity)
{
    return impl::call_factory<DataProtectionManager, Windows::Security::EnterpriseData::IDataProtectionManagerStatics>([&](auto&& f) { return f.ProtectAsync(data, identity); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::BufferProtectUnprotectResult> DataProtectionManager::UnprotectAsync(Windows::Storage::Streams::IBuffer const& data)
{
    return impl::call_factory<DataProtectionManager, Windows::Security::EnterpriseData::IDataProtectionManagerStatics>([&](auto&& f) { return f.UnprotectAsync(data); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::DataProtectionInfo> DataProtectionManager::ProtectStreamAsync(Windows::Storage::Streams::IInputStream const& unprotectedStream, param::hstring const& identity, Windows::Storage::Streams::IOutputStream const& protectedStream)
{
    return impl::call_factory<DataProtectionManager, Windows::Security::EnterpriseData::IDataProtectionManagerStatics>([&](auto&& f) { return f.ProtectStreamAsync(unprotectedStream, identity, protectedStream); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::DataProtectionInfo> DataProtectionManager::UnprotectStreamAsync(Windows::Storage::Streams::IInputStream const& protectedStream, Windows::Storage::Streams::IOutputStream const& unprotectedStream)
{
    return impl::call_factory<DataProtectionManager, Windows::Security::EnterpriseData::IDataProtectionManagerStatics>([&](auto&& f) { return f.UnprotectStreamAsync(protectedStream, unprotectedStream); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::DataProtectionInfo> DataProtectionManager::GetProtectionInfoAsync(Windows::Storage::Streams::IBuffer const& protectedData)
{
    return impl::call_factory<DataProtectionManager, Windows::Security::EnterpriseData::IDataProtectionManagerStatics>([&](auto&& f) { return f.GetProtectionInfoAsync(protectedData); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::DataProtectionInfo> DataProtectionManager::GetStreamProtectionInfoAsync(Windows::Storage::Streams::IInputStream const& protectedStream)
{
    return impl::call_factory<DataProtectionManager, Windows::Security::EnterpriseData::IDataProtectionManagerStatics>([&](auto&& f) { return f.GetStreamProtectionInfoAsync(protectedStream); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::FileProtectionInfo> FileProtectionManager::ProtectAsync(Windows::Storage::IStorageItem const& target, param::hstring const& identity)
{
    return impl::call_factory<FileProtectionManager, Windows::Security::EnterpriseData::IFileProtectionManagerStatics>([&](auto&& f) { return f.ProtectAsync(target, identity); });
}

inline Windows::Foundation::IAsyncOperation<bool> FileProtectionManager::CopyProtectionAsync(Windows::Storage::IStorageItem const& source, Windows::Storage::IStorageItem const& target)
{
    return impl::call_factory<FileProtectionManager, Windows::Security::EnterpriseData::IFileProtectionManagerStatics>([&](auto&& f) { return f.CopyProtectionAsync(source, target); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::FileProtectionInfo> FileProtectionManager::GetProtectionInfoAsync(Windows::Storage::IStorageItem const& source)
{
    return impl::call_factory<FileProtectionManager, Windows::Security::EnterpriseData::IFileProtectionManagerStatics>([&](auto&& f) { return f.GetProtectionInfoAsync(source); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectedContainerExportResult> FileProtectionManager::SaveFileAsContainerAsync(Windows::Storage::IStorageFile const& protectedFile)
{
    return impl::call_factory<FileProtectionManager, Windows::Security::EnterpriseData::IFileProtectionManagerStatics>([&](auto&& f) { return f.SaveFileAsContainerAsync(protectedFile); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectedContainerImportResult> FileProtectionManager::LoadFileFromContainerAsync(Windows::Storage::IStorageFile const& containerFile)
{
    return impl::call_factory<FileProtectionManager, Windows::Security::EnterpriseData::IFileProtectionManagerStatics>([&](auto&& f) { return f.LoadFileFromContainerAsync(containerFile); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectedContainerImportResult> FileProtectionManager::LoadFileFromContainerAsync(Windows::Storage::IStorageFile const& containerFile, Windows::Storage::IStorageItem const& target)
{
    return impl::call_factory<FileProtectionManager, Windows::Security::EnterpriseData::IFileProtectionManagerStatics>([&](auto&& f) { return f.LoadFileFromContainerAsync(containerFile, target); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectedFileCreateResult> FileProtectionManager::CreateProtectedAndOpenAsync(Windows::Storage::IStorageFolder const& parentFolder, param::hstring const& desiredName, param::hstring const& identity, Windows::Storage::CreationCollisionOption const& collisionOption)
{
    return impl::call_factory<FileProtectionManager, Windows::Security::EnterpriseData::IFileProtectionManagerStatics>([&](auto&& f) { return f.CreateProtectedAndOpenAsync(parentFolder, desiredName, identity, collisionOption); });
}

inline Windows::Foundation::IAsyncOperation<bool> FileProtectionManager::IsContainerAsync(Windows::Storage::IStorageFile const& file)
{
    return impl::call_factory<FileProtectionManager, Windows::Security::EnterpriseData::IFileProtectionManagerStatics2>([&](auto&& f) { return f.IsContainerAsync(file); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectedContainerImportResult> FileProtectionManager::LoadFileFromContainerAsync(Windows::Storage::IStorageFile const& containerFile, Windows::Storage::IStorageItem const& target, Windows::Storage::NameCollisionOption const& collisionOption)
{
    return impl::call_factory<FileProtectionManager, Windows::Security::EnterpriseData::IFileProtectionManagerStatics2>([&](auto&& f) { return f.LoadFileFromContainerAsync(containerFile, target, collisionOption); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectedContainerExportResult> FileProtectionManager::SaveFileAsContainerAsync(Windows::Storage::IStorageFile const& protectedFile, param::async_iterable<hstring> const& sharedWithIdentities)
{
    return impl::call_factory<FileProtectionManager, Windows::Security::EnterpriseData::IFileProtectionManagerStatics2>([&](auto&& f) { return f.SaveFileAsContainerAsync(protectedFile, sharedWithIdentities); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::FileProtectionInfo> FileProtectionManager::UnprotectAsync(Windows::Storage::IStorageItem const& target)
{
    return impl::call_factory<FileProtectionManager, Windows::Security::EnterpriseData::IFileProtectionManagerStatics3>([&](auto&& f) { return f.UnprotectAsync(target); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::FileProtectionInfo> FileProtectionManager::UnprotectAsync(Windows::Storage::IStorageItem const& target, Windows::Security::EnterpriseData::FileUnprotectOptions const& options)
{
    return impl::call_factory<FileProtectionManager, Windows::Security::EnterpriseData::IFileProtectionManagerStatics3>([&](auto&& f) { return f.UnprotectAsync(target, options); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::FileProtectionStatus> FileRevocationManager::ProtectAsync(Windows::Storage::IStorageItem const& storageItem, param::hstring const& enterpriseIdentity)
{
    return impl::call_factory<FileRevocationManager, Windows::Security::EnterpriseData::IFileRevocationManagerStatics>([&](auto&& f) { return f.ProtectAsync(storageItem, enterpriseIdentity); });
}

inline Windows::Foundation::IAsyncOperation<bool> FileRevocationManager::CopyProtectionAsync(Windows::Storage::IStorageItem const& sourceStorageItem, Windows::Storage::IStorageItem const& targetStorageItem)
{
    return impl::call_factory<FileRevocationManager, Windows::Security::EnterpriseData::IFileRevocationManagerStatics>([&](auto&& f) { return f.CopyProtectionAsync(sourceStorageItem, targetStorageItem); });
}

inline void FileRevocationManager::Revoke(param::hstring const& enterpriseIdentity)
{
    impl::call_factory<FileRevocationManager, Windows::Security::EnterpriseData::IFileRevocationManagerStatics>([&](auto&& f) { return f.Revoke(enterpriseIdentity); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::FileProtectionStatus> FileRevocationManager::GetStatusAsync(Windows::Storage::IStorageItem const& storageItem)
{
    return impl::call_factory<FileRevocationManager, Windows::Security::EnterpriseData::IFileRevocationManagerStatics>([&](auto&& f) { return f.GetStatusAsync(storageItem); });
}

inline FileUnprotectOptions::FileUnprotectOptions(bool audit) :
    FileUnprotectOptions(impl::call_factory<FileUnprotectOptions, Windows::Security::EnterpriseData::IFileUnprotectOptionsFactory>([&](auto&& f) { return f.Create(audit); }))
{}

inline ProtectionPolicyAuditInfo::ProtectionPolicyAuditInfo(Windows::Security::EnterpriseData::ProtectionPolicyAuditAction const& action, param::hstring const& dataDescription, param::hstring const& sourceDescription, param::hstring const& targetDescription) :
    ProtectionPolicyAuditInfo(impl::call_factory<ProtectionPolicyAuditInfo, Windows::Security::EnterpriseData::IProtectionPolicyAuditInfoFactory>([&](auto&& f) { return f.Create(action, dataDescription, sourceDescription, targetDescription); }))
{}

inline ProtectionPolicyAuditInfo::ProtectionPolicyAuditInfo(Windows::Security::EnterpriseData::ProtectionPolicyAuditAction const& action, param::hstring const& dataDescription) :
    ProtectionPolicyAuditInfo(impl::call_factory<ProtectionPolicyAuditInfo, Windows::Security::EnterpriseData::IProtectionPolicyAuditInfoFactory>([&](auto&& f) { return f.CreateWithActionAndDataDescription(action, dataDescription); }))
{}

inline bool ProtectionPolicyManager::IsIdentityManaged(param::hstring const& identity)
{
    return impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics>([&](auto&& f) { return f.IsIdentityManaged(identity); });
}

inline bool ProtectionPolicyManager::TryApplyProcessUIPolicy(param::hstring const& identity)
{
    return impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics>([&](auto&& f) { return f.TryApplyProcessUIPolicy(identity); });
}

inline void ProtectionPolicyManager::ClearProcessUIPolicy()
{
    impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics>([&](auto&& f) { return f.ClearProcessUIPolicy(); });
}

inline Windows::Security::EnterpriseData::ThreadNetworkContext ProtectionPolicyManager::CreateCurrentThreadNetworkContext(param::hstring const& identity)
{
    return impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics>([&](auto&& f) { return f.CreateCurrentThreadNetworkContext(identity); });
}

inline Windows::Foundation::IAsyncOperation<hstring> ProtectionPolicyManager::GetPrimaryManagedIdentityForNetworkEndpointAsync(Windows::Networking::HostName const& endpointHost)
{
    return impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics>([&](auto&& f) { return f.GetPrimaryManagedIdentityForNetworkEndpointAsync(endpointHost); });
}

inline void ProtectionPolicyManager::RevokeContent(param::hstring const& identity)
{
    impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics>([&](auto&& f) { return f.RevokeContent(identity); });
}

inline Windows::Security::EnterpriseData::ProtectionPolicyManager ProtectionPolicyManager::GetForCurrentView()
{
    return impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics>([&](auto&& f) { return f.GetForCurrentView(); });
}

inline winrt::event_token ProtectionPolicyManager::ProtectedAccessSuspending(Windows::Foundation::EventHandler<Windows::Security::EnterpriseData::ProtectedAccessSuspendingEventArgs> const& handler)
{
    return impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics>([&](auto&& f) { return f.ProtectedAccessSuspending(handler); });
}

inline ProtectionPolicyManager::ProtectedAccessSuspending_revoker ProtectionPolicyManager::ProtectedAccessSuspending(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Security::EnterpriseData::ProtectedAccessSuspendingEventArgs> const& handler)
{
    auto f = get_activation_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics>();
    return { f, f.ProtectedAccessSuspending(handler) };
}

inline void ProtectionPolicyManager::ProtectedAccessSuspending(winrt::event_token const& token)
{
    impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics>([&](auto&& f) { return f.ProtectedAccessSuspending(token); });
}

inline winrt::event_token ProtectionPolicyManager::ProtectedAccessResumed(Windows::Foundation::EventHandler<Windows::Security::EnterpriseData::ProtectedAccessResumedEventArgs> const& handler)
{
    return impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics>([&](auto&& f) { return f.ProtectedAccessResumed(handler); });
}

inline ProtectionPolicyManager::ProtectedAccessResumed_revoker ProtectionPolicyManager::ProtectedAccessResumed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Security::EnterpriseData::ProtectedAccessResumedEventArgs> const& handler)
{
    auto f = get_activation_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics>();
    return { f, f.ProtectedAccessResumed(handler) };
}

inline void ProtectionPolicyManager::ProtectedAccessResumed(winrt::event_token const& token)
{
    impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics>([&](auto&& f) { return f.ProtectedAccessResumed(token); });
}

inline winrt::event_token ProtectionPolicyManager::ProtectedContentRevoked(Windows::Foundation::EventHandler<Windows::Security::EnterpriseData::ProtectedContentRevokedEventArgs> const& handler)
{
    return impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics>([&](auto&& f) { return f.ProtectedContentRevoked(handler); });
}

inline ProtectionPolicyManager::ProtectedContentRevoked_revoker ProtectionPolicyManager::ProtectedContentRevoked(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Security::EnterpriseData::ProtectedContentRevokedEventArgs> const& handler)
{
    auto f = get_activation_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics>();
    return { f, f.ProtectedContentRevoked(handler) };
}

inline void ProtectionPolicyManager::ProtectedContentRevoked(winrt::event_token const& token)
{
    impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics>([&](auto&& f) { return f.ProtectedContentRevoked(token); });
}

inline Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult ProtectionPolicyManager::CheckAccess(param::hstring const& sourceIdentity, param::hstring const& targetIdentity)
{
    return impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics>([&](auto&& f) { return f.CheckAccess(sourceIdentity, targetIdentity); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> ProtectionPolicyManager::RequestAccessAsync(param::hstring const& sourceIdentity, param::hstring const& targetIdentity)
{
    return impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics>([&](auto&& f) { return f.RequestAccessAsync(sourceIdentity, targetIdentity); });
}

inline bool ProtectionPolicyManager::HasContentBeenRevokedSince(param::hstring const& identity, Windows::Foundation::DateTime const& since)
{
    return impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics2>([&](auto&& f) { return f.HasContentBeenRevokedSince(identity, since); });
}

inline Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult ProtectionPolicyManager::CheckAccessForApp(param::hstring const& sourceIdentity, param::hstring const& appPackageFamilyName)
{
    return impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics2>([&](auto&& f) { return f.CheckAccessForApp(sourceIdentity, appPackageFamilyName); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> ProtectionPolicyManager::RequestAccessForAppAsync(param::hstring const& sourceIdentity, param::hstring const& appPackageFamilyName)
{
    return impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics2>([&](auto&& f) { return f.RequestAccessForAppAsync(sourceIdentity, appPackageFamilyName); });
}

inline Windows::Security::EnterpriseData::EnforcementLevel ProtectionPolicyManager::GetEnforcementLevel(param::hstring const& identity)
{
    return impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics2>([&](auto&& f) { return f.GetEnforcementLevel(identity); });
}

inline bool ProtectionPolicyManager::IsUserDecryptionAllowed(param::hstring const& identity)
{
    return impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics2>([&](auto&& f) { return f.IsUserDecryptionAllowed(identity); });
}

inline bool ProtectionPolicyManager::IsProtectionUnderLockRequired(param::hstring const& identity)
{
    return impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics2>([&](auto&& f) { return f.IsProtectionUnderLockRequired(identity); });
}

inline winrt::event_token ProtectionPolicyManager::PolicyChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics2>([&](auto&& f) { return f.PolicyChanged(handler); });
}

inline ProtectionPolicyManager::PolicyChanged_revoker ProtectionPolicyManager::PolicyChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics2>();
    return { f, f.PolicyChanged(handler) };
}

inline void ProtectionPolicyManager::PolicyChanged(winrt::event_token const& token)
{
    impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics2>([&](auto&& f) { return f.PolicyChanged(token); });
}

inline bool ProtectionPolicyManager::IsProtectionEnabled()
{
    return impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics2>([&](auto&& f) { return f.IsProtectionEnabled(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> ProtectionPolicyManager::RequestAccessAsync(param::hstring const& sourceIdentity, param::hstring const& targetIdentity, Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const& auditInfo)
{
    return impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics3>([&](auto&& f) { return f.RequestAccessAsync(sourceIdentity, targetIdentity, auditInfo); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> ProtectionPolicyManager::RequestAccessAsync(param::hstring const& sourceIdentity, param::hstring const& targetIdentity, Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const& auditInfo, param::hstring const& messageFromApp)
{
    return impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics3>([&](auto&& f) { return f.RequestAccessAsync(sourceIdentity, targetIdentity, auditInfo, messageFromApp); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> ProtectionPolicyManager::RequestAccessForAppAsync(param::hstring const& sourceIdentity, param::hstring const& appPackageFamilyName, Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const& auditInfo)
{
    return impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics3>([&](auto&& f) { return f.RequestAccessForAppAsync(sourceIdentity, appPackageFamilyName, auditInfo); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> ProtectionPolicyManager::RequestAccessForAppAsync(param::hstring const& sourceIdentity, param::hstring const& appPackageFamilyName, Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const& auditInfo, param::hstring const& messageFromApp)
{
    return impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics3>([&](auto&& f) { return f.RequestAccessForAppAsync(sourceIdentity, appPackageFamilyName, auditInfo, messageFromApp); });
}

inline void ProtectionPolicyManager::LogAuditEvent(param::hstring const& sourceIdentity, param::hstring const& targetIdentity, Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const& auditInfo)
{
    impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics3>([&](auto&& f) { return f.LogAuditEvent(sourceIdentity, targetIdentity, auditInfo); });
}

inline bool ProtectionPolicyManager::IsRoamableProtectionEnabled(param::hstring const& identity)
{
    return impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics4>([&](auto&& f) { return f.IsRoamableProtectionEnabled(identity); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> ProtectionPolicyManager::RequestAccessAsync(param::hstring const& sourceIdentity, param::hstring const& targetIdentity, Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const& auditInfo, param::hstring const& messageFromApp, Windows::Security::EnterpriseData::ProtectionPolicyRequestAccessBehavior const& behavior)
{
    return impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics4>([&](auto&& f) { return f.RequestAccessAsync(sourceIdentity, targetIdentity, auditInfo, messageFromApp, behavior); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> ProtectionPolicyManager::RequestAccessForAppAsync(param::hstring const& sourceIdentity, param::hstring const& appPackageFamilyName, Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const& auditInfo, param::hstring const& messageFromApp, Windows::Security::EnterpriseData::ProtectionPolicyRequestAccessBehavior const& behavior)
{
    return impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics4>([&](auto&& f) { return f.RequestAccessForAppAsync(sourceIdentity, appPackageFamilyName, auditInfo, messageFromApp, behavior); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> ProtectionPolicyManager::RequestAccessToFilesForAppAsync(param::async_iterable<Windows::Storage::IStorageItem> const& sourceItemList, param::hstring const& appPackageFamilyName, Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const& auditInfo)
{
    return impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics4>([&](auto&& f) { return f.RequestAccessToFilesForAppAsync(sourceItemList, appPackageFamilyName, auditInfo); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> ProtectionPolicyManager::RequestAccessToFilesForAppAsync(param::async_iterable<Windows::Storage::IStorageItem> const& sourceItemList, param::hstring const& appPackageFamilyName, Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const& auditInfo, param::hstring const& messageFromApp, Windows::Security::EnterpriseData::ProtectionPolicyRequestAccessBehavior const& behavior)
{
    return impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics4>([&](auto&& f) { return f.RequestAccessToFilesForAppAsync(sourceItemList, appPackageFamilyName, auditInfo, messageFromApp, behavior); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> ProtectionPolicyManager::RequestAccessToFilesForProcessAsync(param::async_iterable<Windows::Storage::IStorageItem> const& sourceItemList, uint32_t processId, Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const& auditInfo)
{
    return impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics4>([&](auto&& f) { return f.RequestAccessToFilesForProcessAsync(sourceItemList, processId, auditInfo); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> ProtectionPolicyManager::RequestAccessToFilesForProcessAsync(param::async_iterable<Windows::Storage::IStorageItem> const& sourceItemList, uint32_t processId, Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const& auditInfo, param::hstring const& messageFromApp, Windows::Security::EnterpriseData::ProtectionPolicyRequestAccessBehavior const& behavior)
{
    return impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics4>([&](auto&& f) { return f.RequestAccessToFilesForProcessAsync(sourceItemList, processId, auditInfo, messageFromApp, behavior); });
}

inline Windows::Foundation::IAsyncOperation<bool> ProtectionPolicyManager::IsFileProtectionRequiredAsync(Windows::Storage::IStorageItem const& target, param::hstring const& identity)
{
    return impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics4>([&](auto&& f) { return f.IsFileProtectionRequiredAsync(target, identity); });
}

inline Windows::Foundation::IAsyncOperation<bool> ProtectionPolicyManager::IsFileProtectionRequiredForNewFileAsync(Windows::Storage::IStorageFolder const& parentFolder, param::hstring const& identity, param::hstring const& desiredName)
{
    return impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics4>([&](auto&& f) { return f.IsFileProtectionRequiredForNewFileAsync(parentFolder, identity, desiredName); });
}

inline hstring ProtectionPolicyManager::PrimaryManagedIdentity()
{
    return impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics4>([&](auto&& f) { return f.PrimaryManagedIdentity(); });
}

inline hstring ProtectionPolicyManager::GetPrimaryManagedIdentityForIdentity(param::hstring const& identity)
{
    return impl::call_factory<ProtectionPolicyManager, Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics4>([&](auto&& f) { return f.GetPrimaryManagedIdentityForIdentity(identity); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Security::EnterpriseData::IBufferProtectUnprotectResult> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::IBufferProtectUnprotectResult> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::IDataProtectionInfo> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::IDataProtectionInfo> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::IDataProtectionManagerStatics> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::IDataProtectionManagerStatics> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::IFileProtectionInfo> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::IFileProtectionInfo> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::IFileProtectionInfo2> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::IFileProtectionInfo2> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::IFileProtectionManagerStatics> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::IFileProtectionManagerStatics> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::IFileProtectionManagerStatics2> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::IFileProtectionManagerStatics2> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::IFileProtectionManagerStatics3> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::IFileProtectionManagerStatics3> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::IFileRevocationManagerStatics> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::IFileRevocationManagerStatics> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::IFileUnprotectOptions> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::IFileUnprotectOptions> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::IFileUnprotectOptionsFactory> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::IFileUnprotectOptionsFactory> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::IProtectedAccessResumedEventArgs> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::IProtectedAccessResumedEventArgs> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::IProtectedAccessSuspendingEventArgs> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::IProtectedAccessSuspendingEventArgs> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::IProtectedContainerExportResult> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::IProtectedContainerExportResult> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::IProtectedContainerImportResult> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::IProtectedContainerImportResult> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::IProtectedContentRevokedEventArgs> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::IProtectedContentRevokedEventArgs> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::IProtectedFileCreateResult> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::IProtectedFileCreateResult> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::IProtectionPolicyAuditInfo> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::IProtectionPolicyAuditInfo> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::IProtectionPolicyAuditInfoFactory> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::IProtectionPolicyAuditInfoFactory> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManager> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManager> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManager2> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManager2> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics2> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics2> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics3> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics3> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics4> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics4> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::IThreadNetworkContext> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::IThreadNetworkContext> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::BufferProtectUnprotectResult> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::BufferProtectUnprotectResult> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::DataProtectionInfo> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::DataProtectionInfo> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::DataProtectionManager> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::DataProtectionManager> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::FileProtectionInfo> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::FileProtectionInfo> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::FileProtectionManager> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::FileProtectionManager> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::FileRevocationManager> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::FileRevocationManager> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::FileUnprotectOptions> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::FileUnprotectOptions> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::ProtectedAccessResumedEventArgs> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::ProtectedAccessResumedEventArgs> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::ProtectedAccessSuspendingEventArgs> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::ProtectedAccessSuspendingEventArgs> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::ProtectedContainerExportResult> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::ProtectedContainerExportResult> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::ProtectedContainerImportResult> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::ProtectedContainerImportResult> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::ProtectedContentRevokedEventArgs> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::ProtectedContentRevokedEventArgs> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::ProtectedFileCreateResult> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::ProtectedFileCreateResult> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::ProtectionPolicyManager> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::ProtectionPolicyManager> {};
template<> struct hash<winrt::Windows::Security::EnterpriseData::ThreadNetworkContext> : winrt::impl::hash_base<winrt::Windows::Security::EnterpriseData::ThreadNetworkContext> {};

}
