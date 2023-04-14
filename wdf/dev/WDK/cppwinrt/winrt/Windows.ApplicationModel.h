// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.Activation.2.h"
#include "winrt/impl/Windows.ApplicationModel.Core.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.ApplicationModel.2.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_ApplicationModel_IAppDisplayInfo<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IAppDisplayInfo)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_IAppDisplayInfo<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IAppDisplayInfo)->get_Description(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::RandomAccessStreamReference consume_Windows_ApplicationModel_IAppDisplayInfo<D>::GetLogo(Windows::Foundation::Size const& size) const
{
    Windows::Storage::Streams::RandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IAppDisplayInfo)->GetLogo(get_abi(size), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_IAppInfo<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IAppInfo)->get_Id(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_IAppInfo<D>::AppUserModelId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IAppInfo)->get_AppUserModelId(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::AppDisplayInfo consume_Windows_ApplicationModel_IAppInfo<D>::DisplayInfo() const
{
    Windows::ApplicationModel::AppDisplayInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IAppInfo)->get_DisplayInfo(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_IAppInfo<D>::PackageFamilyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IAppInfo)->get_PackageFamilyName(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_ApplicationModel_IAppInstallerInfo<D>::Uri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IAppInstallerInfo)->get_Uri(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_IAppInstance<D>::Key() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IAppInstance)->get_Key(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_IAppInstance<D>::IsCurrentInstance() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IAppInstance)->get_IsCurrentInstance(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_IAppInstance<D>::RedirectActivationTo() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IAppInstance)->RedirectActivationTo());
}

template <typename D> Windows::ApplicationModel::AppInstance consume_Windows_ApplicationModel_IAppInstanceStatics<D>::RecommendedInstance() const
{
    Windows::ApplicationModel::AppInstance value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IAppInstanceStatics)->get_RecommendedInstance(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Activation::IActivatedEventArgs consume_Windows_ApplicationModel_IAppInstanceStatics<D>::GetActivatedEventArgs() const
{
    Windows::ApplicationModel::Activation::IActivatedEventArgs result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IAppInstanceStatics)->GetActivatedEventArgs(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::AppInstance consume_Windows_ApplicationModel_IAppInstanceStatics<D>::FindOrRegisterInstanceForKey(param::hstring const& key) const
{
    Windows::ApplicationModel::AppInstance result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IAppInstanceStatics)->FindOrRegisterInstanceForKey(get_abi(key), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_IAppInstanceStatics<D>::Unregister() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IAppInstanceStatics)->Unregister());
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::AppInstance> consume_Windows_ApplicationModel_IAppInstanceStatics<D>::GetInstances() const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::AppInstance> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IAppInstanceStatics)->GetInstances(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_IDesignModeStatics<D>::DesignModeEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IDesignModeStatics)->get_DesignModeEnabled(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_IDesignModeStatics2<D>::DesignMode2Enabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IDesignModeStatics2)->get_DesignMode2Enabled(&value));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_IEnteredBackgroundEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IEnteredBackgroundEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_IFullTrustProcessLauncherStatics<D>::LaunchFullTrustProcessForCurrentAppAsync() const
{
    Windows::Foundation::IAsyncAction asyncAction{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IFullTrustProcessLauncherStatics)->LaunchFullTrustProcessForCurrentAppAsync(put_abi(asyncAction)));
    return asyncAction;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_IFullTrustProcessLauncherStatics<D>::LaunchFullTrustProcessForCurrentAppAsync(param::hstring const& parameterGroupId) const
{
    Windows::Foundation::IAsyncAction asyncAction{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IFullTrustProcessLauncherStatics)->LaunchFullTrustProcessForCurrentAppWithParametersAsync(get_abi(parameterGroupId), put_abi(asyncAction)));
    return asyncAction;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_IFullTrustProcessLauncherStatics<D>::LaunchFullTrustProcessForAppAsync(param::hstring const& fullTrustPackageRelativeAppId) const
{
    Windows::Foundation::IAsyncAction asyncAction{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IFullTrustProcessLauncherStatics)->LaunchFullTrustProcessForAppAsync(get_abi(fullTrustPackageRelativeAppId), put_abi(asyncAction)));
    return asyncAction;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_IFullTrustProcessLauncherStatics<D>::LaunchFullTrustProcessForAppAsync(param::hstring const& fullTrustPackageRelativeAppId, param::hstring const& parameterGroupId) const
{
    Windows::Foundation::IAsyncAction asyncAction{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IFullTrustProcessLauncherStatics)->LaunchFullTrustProcessForAppWithParametersAsync(get_abi(fullTrustPackageRelativeAppId), get_abi(parameterGroupId), put_abi(asyncAction)));
    return asyncAction;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_ILeavingBackgroundEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ILeavingBackgroundEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_ILimitedAccessFeatureRequestResult<D>::FeatureId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ILimitedAccessFeatureRequestResult)->get_FeatureId(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::LimitedAccessFeatureStatus consume_Windows_ApplicationModel_ILimitedAccessFeatureRequestResult<D>::Status() const
{
    Windows::ApplicationModel::LimitedAccessFeatureStatus value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ILimitedAccessFeatureRequestResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_ApplicationModel_ILimitedAccessFeatureRequestResult<D>::EstimatedRemovalDate() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ILimitedAccessFeatureRequestResult)->get_EstimatedRemovalDate(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::LimitedAccessFeatureRequestResult consume_Windows_ApplicationModel_ILimitedAccessFeaturesStatics<D>::TryUnlockFeature(param::hstring const& featureId, param::hstring const& token, param::hstring const& attestation) const
{
    Windows::ApplicationModel::LimitedAccessFeatureRequestResult result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ILimitedAccessFeaturesStatics)->TryUnlockFeature(get_abi(featureId), get_abi(token), get_abi(attestation), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::PackageId consume_Windows_ApplicationModel_IPackage<D>::Id() const
{
    Windows::ApplicationModel::PackageId value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackage)->get_Id(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::StorageFolder consume_Windows_ApplicationModel_IPackage<D>::InstalledLocation() const
{
    Windows::Storage::StorageFolder value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackage)->get_InstalledLocation(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_IPackage<D>::IsFramework() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackage)->get_IsFramework(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Package> consume_Windows_ApplicationModel_IPackage<D>::Dependencies() const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Package> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackage)->get_Dependencies(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_IPackage2<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackage2)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_IPackage2<D>::PublisherDisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackage2)->get_PublisherDisplayName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_IPackage2<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackage2)->get_Description(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_ApplicationModel_IPackage2<D>::Logo() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackage2)->get_Logo(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_IPackage2<D>::IsResourcePackage() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackage2)->get_IsResourcePackage(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_IPackage2<D>::IsBundle() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackage2)->get_IsBundle(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_IPackage2<D>::IsDevelopmentMode() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackage2)->get_IsDevelopmentMode(&value));
    return value;
}

template <typename D> Windows::ApplicationModel::PackageStatus consume_Windows_ApplicationModel_IPackage3<D>::Status() const
{
    Windows::ApplicationModel::PackageStatus value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackage3)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_ApplicationModel_IPackage3<D>::InstalledDate() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackage3)->get_InstalledDate(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Core::AppListEntry>> consume_Windows_ApplicationModel_IPackage3<D>::GetAppListEntriesAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Core::AppListEntry>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackage3)->GetAppListEntriesAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::ApplicationModel::PackageSignatureKind consume_Windows_ApplicationModel_IPackage4<D>::SignatureKind() const
{
    Windows::ApplicationModel::PackageSignatureKind value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackage4)->get_SignatureKind(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_IPackage4<D>::IsOptional() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackage4)->get_IsOptional(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_IPackage4<D>::VerifyContentIntegrityAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackage4)->VerifyContentIntegrityAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::PackageContentGroup>> consume_Windows_ApplicationModel_IPackage5<D>::GetContentGroupsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::PackageContentGroup>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackage5)->GetContentGroupsAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::PackageContentGroup> consume_Windows_ApplicationModel_IPackage5<D>::GetContentGroupAsync(param::hstring const& name) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::PackageContentGroup> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackage5)->GetContentGroupAsync(get_abi(name), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::PackageContentGroup>> consume_Windows_ApplicationModel_IPackage5<D>::StageContentGroupsAsync(param::async_iterable<hstring> const& names) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::PackageContentGroup>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackage5)->StageContentGroupsAsync(get_abi(names), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::PackageContentGroup>> consume_Windows_ApplicationModel_IPackage5<D>::StageContentGroupsAsync(param::async_iterable<hstring> const& names, bool moveToHeadOfQueue) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::PackageContentGroup>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackage5)->StageContentGroupsWithPriorityAsync(get_abi(names), moveToHeadOfQueue, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_IPackage5<D>::SetInUseAsync(bool inUse) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackage5)->SetInUseAsync(inUse, put_abi(operation)));
    return operation;
}

template <typename D> Windows::ApplicationModel::AppInstallerInfo consume_Windows_ApplicationModel_IPackage6<D>::GetAppInstallerInfo() const
{
    Windows::ApplicationModel::AppInstallerInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackage6)->GetAppInstallerInfo(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::PackageUpdateAvailabilityResult> consume_Windows_ApplicationModel_IPackage6<D>::CheckUpdateAvailabilityAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::PackageUpdateAvailabilityResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackage6)->CheckUpdateAvailabilityAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Storage::StorageFolder consume_Windows_ApplicationModel_IPackage7<D>::MutableLocation() const
{
    Windows::Storage::StorageFolder value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackage7)->get_MutableLocation(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::StorageFolder consume_Windows_ApplicationModel_IPackage7<D>::EffectiveLocation() const
{
    Windows::Storage::StorageFolder value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackage7)->get_EffectiveLocation(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_IPackageCatalog<D>::PackageStaging(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageStagingEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageCatalog)->add_PackageStaging(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_IPackageCatalog<D>::PackageStaging_revoker consume_Windows_ApplicationModel_IPackageCatalog<D>::PackageStaging(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageStagingEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PackageStaging_revoker>(this, PackageStaging(handler));
}

template <typename D> void consume_Windows_ApplicationModel_IPackageCatalog<D>::PackageStaging(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::IPackageCatalog)->remove_PackageStaging(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_IPackageCatalog<D>::PackageInstalling(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageInstallingEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageCatalog)->add_PackageInstalling(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_IPackageCatalog<D>::PackageInstalling_revoker consume_Windows_ApplicationModel_IPackageCatalog<D>::PackageInstalling(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageInstallingEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PackageInstalling_revoker>(this, PackageInstalling(handler));
}

template <typename D> void consume_Windows_ApplicationModel_IPackageCatalog<D>::PackageInstalling(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::IPackageCatalog)->remove_PackageInstalling(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_IPackageCatalog<D>::PackageUpdating(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageUpdatingEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageCatalog)->add_PackageUpdating(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_IPackageCatalog<D>::PackageUpdating_revoker consume_Windows_ApplicationModel_IPackageCatalog<D>::PackageUpdating(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageUpdatingEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PackageUpdating_revoker>(this, PackageUpdating(handler));
}

template <typename D> void consume_Windows_ApplicationModel_IPackageCatalog<D>::PackageUpdating(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::IPackageCatalog)->remove_PackageUpdating(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_IPackageCatalog<D>::PackageUninstalling(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageUninstallingEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageCatalog)->add_PackageUninstalling(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_IPackageCatalog<D>::PackageUninstalling_revoker consume_Windows_ApplicationModel_IPackageCatalog<D>::PackageUninstalling(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageUninstallingEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PackageUninstalling_revoker>(this, PackageUninstalling(handler));
}

template <typename D> void consume_Windows_ApplicationModel_IPackageCatalog<D>::PackageUninstalling(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::IPackageCatalog)->remove_PackageUninstalling(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_IPackageCatalog<D>::PackageStatusChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageStatusChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageCatalog)->add_PackageStatusChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_IPackageCatalog<D>::PackageStatusChanged_revoker consume_Windows_ApplicationModel_IPackageCatalog<D>::PackageStatusChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageStatusChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PackageStatusChanged_revoker>(this, PackageStatusChanged(handler));
}

template <typename D> void consume_Windows_ApplicationModel_IPackageCatalog<D>::PackageStatusChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::IPackageCatalog)->remove_PackageStatusChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_IPackageCatalog2<D>::PackageContentGroupStaging(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageContentGroupStagingEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageCatalog2)->add_PackageContentGroupStaging(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_IPackageCatalog2<D>::PackageContentGroupStaging_revoker consume_Windows_ApplicationModel_IPackageCatalog2<D>::PackageContentGroupStaging(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageContentGroupStagingEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PackageContentGroupStaging_revoker>(this, PackageContentGroupStaging(handler));
}

template <typename D> void consume_Windows_ApplicationModel_IPackageCatalog2<D>::PackageContentGroupStaging(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::IPackageCatalog2)->remove_PackageContentGroupStaging(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::PackageCatalogAddOptionalPackageResult> consume_Windows_ApplicationModel_IPackageCatalog2<D>::AddOptionalPackageAsync(param::hstring const& optionalPackageFamilyName) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::PackageCatalogAddOptionalPackageResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageCatalog2)->AddOptionalPackageAsync(get_abi(optionalPackageFamilyName), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::PackageCatalogRemoveOptionalPackagesResult> consume_Windows_ApplicationModel_IPackageCatalog3<D>::RemoveOptionalPackagesAsync(param::async_iterable<hstring> const& optionalPackageFamilyNames) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::PackageCatalogRemoveOptionalPackagesResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageCatalog3)->RemoveOptionalPackagesAsync(get_abi(optionalPackageFamilyNames), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::ApplicationModel::PackageCatalogAddResourcePackageResult, Windows::ApplicationModel::PackageInstallProgress> consume_Windows_ApplicationModel_IPackageCatalog4<D>::AddResourcePackageAsync(param::hstring const& resourcePackageFamilyName, param::hstring const& resourceID, Windows::ApplicationModel::AddResourcePackageOptions const& options) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::ApplicationModel::PackageCatalogAddResourcePackageResult, Windows::ApplicationModel::PackageInstallProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageCatalog4)->AddResourcePackageAsync(get_abi(resourcePackageFamilyName), get_abi(resourceID), get_abi(options), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::PackageCatalogRemoveResourcePackagesResult> consume_Windows_ApplicationModel_IPackageCatalog4<D>::RemoveResourcePackagesAsync(param::async_iterable<Windows::ApplicationModel::Package> const& resourcePackages) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::PackageCatalogRemoveResourcePackagesResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageCatalog4)->RemoveResourcePackagesAsync(get_abi(resourcePackages), put_abi(operation)));
    return operation;
}

template <typename D> Windows::ApplicationModel::Package consume_Windows_ApplicationModel_IPackageCatalogAddOptionalPackageResult<D>::Package() const
{
    Windows::ApplicationModel::Package value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageCatalogAddOptionalPackageResult)->get_Package(put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_ApplicationModel_IPackageCatalogAddOptionalPackageResult<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageCatalogAddOptionalPackageResult)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Package consume_Windows_ApplicationModel_IPackageCatalogAddResourcePackageResult<D>::Package() const
{
    Windows::ApplicationModel::Package value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageCatalogAddResourcePackageResult)->get_Package(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_IPackageCatalogAddResourcePackageResult<D>::IsComplete() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageCatalogAddResourcePackageResult)->get_IsComplete(&value));
    return value;
}

template <typename D> winrt::hresult consume_Windows_ApplicationModel_IPackageCatalogAddResourcePackageResult<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageCatalogAddResourcePackageResult)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Package> consume_Windows_ApplicationModel_IPackageCatalogRemoveOptionalPackagesResult<D>::PackagesRemoved() const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Package> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageCatalogRemoveOptionalPackagesResult)->get_PackagesRemoved(put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_ApplicationModel_IPackageCatalogRemoveOptionalPackagesResult<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageCatalogRemoveOptionalPackagesResult)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Package> consume_Windows_ApplicationModel_IPackageCatalogRemoveResourcePackagesResult<D>::PackagesRemoved() const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Package> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageCatalogRemoveResourcePackagesResult)->get_PackagesRemoved(put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_ApplicationModel_IPackageCatalogRemoveResourcePackagesResult<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageCatalogRemoveResourcePackagesResult)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::PackageCatalog consume_Windows_ApplicationModel_IPackageCatalogStatics<D>::OpenForCurrentPackage() const
{
    Windows::ApplicationModel::PackageCatalog value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageCatalogStatics)->OpenForCurrentPackage(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::PackageCatalog consume_Windows_ApplicationModel_IPackageCatalogStatics<D>::OpenForCurrentUser() const
{
    Windows::ApplicationModel::PackageCatalog value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageCatalogStatics)->OpenForCurrentUser(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Package consume_Windows_ApplicationModel_IPackageContentGroup<D>::Package() const
{
    Windows::ApplicationModel::Package value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageContentGroup)->get_Package(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_IPackageContentGroup<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageContentGroup)->get_Name(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::PackageContentGroupState consume_Windows_ApplicationModel_IPackageContentGroup<D>::State() const
{
    Windows::ApplicationModel::PackageContentGroupState value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageContentGroup)->get_State(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_IPackageContentGroup<D>::IsRequired() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageContentGroup)->get_IsRequired(&value));
    return value;
}

template <typename D> winrt::guid consume_Windows_ApplicationModel_IPackageContentGroupStagingEventArgs<D>::ActivityId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageContentGroupStagingEventArgs)->get_ActivityId(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Package consume_Windows_ApplicationModel_IPackageContentGroupStagingEventArgs<D>::Package() const
{
    Windows::ApplicationModel::Package value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageContentGroupStagingEventArgs)->get_Package(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_ApplicationModel_IPackageContentGroupStagingEventArgs<D>::Progress() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageContentGroupStagingEventArgs)->get_Progress(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_IPackageContentGroupStagingEventArgs<D>::IsComplete() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageContentGroupStagingEventArgs)->get_IsComplete(&value));
    return value;
}

template <typename D> winrt::hresult consume_Windows_ApplicationModel_IPackageContentGroupStagingEventArgs<D>::ErrorCode() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageContentGroupStagingEventArgs)->get_ErrorCode(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_IPackageContentGroupStagingEventArgs<D>::ContentGroupName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageContentGroupStagingEventArgs)->get_ContentGroupName(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_IPackageContentGroupStagingEventArgs<D>::IsContentGroupRequired() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageContentGroupStagingEventArgs)->get_IsContentGroupRequired(&value));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_IPackageContentGroupStatics<D>::RequiredGroupName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageContentGroupStatics)->get_RequiredGroupName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_IPackageId<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageId)->get_Name(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::PackageVersion consume_Windows_ApplicationModel_IPackageId<D>::Version() const
{
    Windows::ApplicationModel::PackageVersion value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageId)->get_Version(put_abi(value)));
    return value;
}

template <typename D> Windows::System::ProcessorArchitecture consume_Windows_ApplicationModel_IPackageId<D>::Architecture() const
{
    Windows::System::ProcessorArchitecture value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageId)->get_Architecture(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_IPackageId<D>::ResourceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageId)->get_ResourceId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_IPackageId<D>::Publisher() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageId)->get_Publisher(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_IPackageId<D>::PublisherId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageId)->get_PublisherId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_IPackageId<D>::FullName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageId)->get_FullName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_IPackageId<D>::FamilyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageId)->get_FamilyName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_IPackageIdWithMetadata<D>::ProductId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageIdWithMetadata)->get_ProductId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_IPackageIdWithMetadata<D>::Author() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageIdWithMetadata)->get_Author(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_ApplicationModel_IPackageInstallingEventArgs<D>::ActivityId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageInstallingEventArgs)->get_ActivityId(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Package consume_Windows_ApplicationModel_IPackageInstallingEventArgs<D>::Package() const
{
    Windows::ApplicationModel::Package value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageInstallingEventArgs)->get_Package(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_ApplicationModel_IPackageInstallingEventArgs<D>::Progress() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageInstallingEventArgs)->get_Progress(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_IPackageInstallingEventArgs<D>::IsComplete() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageInstallingEventArgs)->get_IsComplete(&value));
    return value;
}

template <typename D> winrt::hresult consume_Windows_ApplicationModel_IPackageInstallingEventArgs<D>::ErrorCode() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageInstallingEventArgs)->get_ErrorCode(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_ApplicationModel_IPackageStagingEventArgs<D>::ActivityId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageStagingEventArgs)->get_ActivityId(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Package consume_Windows_ApplicationModel_IPackageStagingEventArgs<D>::Package() const
{
    Windows::ApplicationModel::Package value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageStagingEventArgs)->get_Package(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_ApplicationModel_IPackageStagingEventArgs<D>::Progress() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageStagingEventArgs)->get_Progress(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_IPackageStagingEventArgs<D>::IsComplete() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageStagingEventArgs)->get_IsComplete(&value));
    return value;
}

template <typename D> winrt::hresult consume_Windows_ApplicationModel_IPackageStagingEventArgs<D>::ErrorCode() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageStagingEventArgs)->get_ErrorCode(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Package consume_Windows_ApplicationModel_IPackageStatics<D>::Current() const
{
    Windows::ApplicationModel::Package value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageStatics)->get_Current(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_IPackageStatus<D>::VerifyIsOK() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageStatus)->VerifyIsOK(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_IPackageStatus<D>::NotAvailable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageStatus)->get_NotAvailable(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_IPackageStatus<D>::PackageOffline() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageStatus)->get_PackageOffline(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_IPackageStatus<D>::DataOffline() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageStatus)->get_DataOffline(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_IPackageStatus<D>::Disabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageStatus)->get_Disabled(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_IPackageStatus<D>::NeedsRemediation() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageStatus)->get_NeedsRemediation(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_IPackageStatus<D>::LicenseIssue() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageStatus)->get_LicenseIssue(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_IPackageStatus<D>::Modified() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageStatus)->get_Modified(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_IPackageStatus<D>::Tampered() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageStatus)->get_Tampered(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_IPackageStatus<D>::DependencyIssue() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageStatus)->get_DependencyIssue(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_IPackageStatus<D>::Servicing() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageStatus)->get_Servicing(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_IPackageStatus<D>::DeploymentInProgress() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageStatus)->get_DeploymentInProgress(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_IPackageStatus2<D>::IsPartiallyStaged() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageStatus2)->get_IsPartiallyStaged(&value));
    return value;
}

template <typename D> Windows::ApplicationModel::Package consume_Windows_ApplicationModel_IPackageStatusChangedEventArgs<D>::Package() const
{
    Windows::ApplicationModel::Package value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageStatusChangedEventArgs)->get_Package(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_ApplicationModel_IPackageUninstallingEventArgs<D>::ActivityId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageUninstallingEventArgs)->get_ActivityId(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Package consume_Windows_ApplicationModel_IPackageUninstallingEventArgs<D>::Package() const
{
    Windows::ApplicationModel::Package value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageUninstallingEventArgs)->get_Package(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_ApplicationModel_IPackageUninstallingEventArgs<D>::Progress() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageUninstallingEventArgs)->get_Progress(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_IPackageUninstallingEventArgs<D>::IsComplete() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageUninstallingEventArgs)->get_IsComplete(&value));
    return value;
}

template <typename D> winrt::hresult consume_Windows_ApplicationModel_IPackageUninstallingEventArgs<D>::ErrorCode() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageUninstallingEventArgs)->get_ErrorCode(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::PackageUpdateAvailability consume_Windows_ApplicationModel_IPackageUpdateAvailabilityResult<D>::Availability() const
{
    Windows::ApplicationModel::PackageUpdateAvailability value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageUpdateAvailabilityResult)->get_Availability(put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_ApplicationModel_IPackageUpdateAvailabilityResult<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageUpdateAvailabilityResult)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_ApplicationModel_IPackageUpdatingEventArgs<D>::ActivityId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageUpdatingEventArgs)->get_ActivityId(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Package consume_Windows_ApplicationModel_IPackageUpdatingEventArgs<D>::SourcePackage() const
{
    Windows::ApplicationModel::Package value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageUpdatingEventArgs)->get_SourcePackage(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Package consume_Windows_ApplicationModel_IPackageUpdatingEventArgs<D>::TargetPackage() const
{
    Windows::ApplicationModel::Package value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageUpdatingEventArgs)->get_TargetPackage(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_ApplicationModel_IPackageUpdatingEventArgs<D>::Progress() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageUpdatingEventArgs)->get_Progress(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_IPackageUpdatingEventArgs<D>::IsComplete() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageUpdatingEventArgs)->get_IsComplete(&value));
    return value;
}

template <typename D> winrt::hresult consume_Windows_ApplicationModel_IPackageUpdatingEventArgs<D>::ErrorCode() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageUpdatingEventArgs)->get_ErrorCode(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_ApplicationModel_IPackageWithMetadata<D>::InstallDate() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageWithMetadata)->get_InstallDate(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_IPackageWithMetadata<D>::GetThumbnailToken() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageWithMetadata)->GetThumbnailToken(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_IPackageWithMetadata<D>::Launch(param::hstring const& parameters) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IPackageWithMetadata)->Launch(get_abi(parameters)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::StartupTaskState> consume_Windows_ApplicationModel_IStartupTask<D>::RequestEnableAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::StartupTaskState> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IStartupTask)->RequestEnableAsync(put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_ApplicationModel_IStartupTask<D>::Disable() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IStartupTask)->Disable());
}

template <typename D> Windows::ApplicationModel::StartupTaskState consume_Windows_ApplicationModel_IStartupTask<D>::State() const
{
    Windows::ApplicationModel::StartupTaskState value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IStartupTask)->get_State(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_IStartupTask<D>::TaskId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IStartupTask)->get_TaskId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::StartupTask>> consume_Windows_ApplicationModel_IStartupTaskStatics<D>::GetForCurrentPackageAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::StartupTask>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IStartupTaskStatics)->GetForCurrentPackageAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::StartupTask> consume_Windows_ApplicationModel_IStartupTaskStatics<D>::GetAsync(param::hstring const& taskId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::StartupTask> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::IStartupTaskStatics)->GetAsync(get_abi(taskId), put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_ApplicationModel_ISuspendingDeferral<D>::Complete() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ISuspendingDeferral)->Complete());
}

template <typename D> Windows::ApplicationModel::SuspendingOperation consume_Windows_ApplicationModel_ISuspendingEventArgs<D>::SuspendingOperation() const
{
    Windows::ApplicationModel::SuspendingOperation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ISuspendingEventArgs)->get_SuspendingOperation(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::SuspendingDeferral consume_Windows_ApplicationModel_ISuspendingOperation<D>::GetDeferral() const
{
    Windows::ApplicationModel::SuspendingDeferral deferral{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ISuspendingOperation)->GetDeferral(put_abi(deferral)));
    return deferral;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_ApplicationModel_ISuspendingOperation<D>::Deadline() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ISuspendingOperation)->get_Deadline(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::ApplicationModel::IAppDisplayInfo> : produce_base<D, Windows::ApplicationModel::IAppDisplayInfo>
{
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

    int32_t WINRT_CALL GetLogo(Windows::Foundation::Size size, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLogo, WINRT_WRAP(Windows::Storage::Streams::RandomAccessStreamReference), Windows::Foundation::Size const&);
            *value = detach_from<Windows::Storage::Streams::RandomAccessStreamReference>(this->shim().GetLogo(*reinterpret_cast<Windows::Foundation::Size const*>(&size)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IAppInfo> : produce_base<D, Windows::ApplicationModel::IAppInfo>
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

    int32_t WINRT_CALL get_AppUserModelId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppUserModelId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AppUserModelId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayInfo, WINRT_WRAP(Windows::ApplicationModel::AppDisplayInfo));
            *value = detach_from<Windows::ApplicationModel::AppDisplayInfo>(this->shim().DisplayInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PackageFamilyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PackageFamilyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PackageFamilyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IAppInstallerInfo> : produce_base<D, Windows::ApplicationModel::IAppInstallerInfo>
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
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IAppInstance> : produce_base<D, Windows::ApplicationModel::IAppInstance>
{
    int32_t WINRT_CALL get_Key(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Key, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Key());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsCurrentInstance(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCurrentInstance, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCurrentInstance());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RedirectActivationTo() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RedirectActivationTo, WINRT_WRAP(void));
            this->shim().RedirectActivationTo();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IAppInstanceStatics> : produce_base<D, Windows::ApplicationModel::IAppInstanceStatics>
{
    int32_t WINRT_CALL get_RecommendedInstance(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecommendedInstance, WINRT_WRAP(Windows::ApplicationModel::AppInstance));
            *value = detach_from<Windows::ApplicationModel::AppInstance>(this->shim().RecommendedInstance());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetActivatedEventArgs(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetActivatedEventArgs, WINRT_WRAP(Windows::ApplicationModel::Activation::IActivatedEventArgs));
            *result = detach_from<Windows::ApplicationModel::Activation::IActivatedEventArgs>(this->shim().GetActivatedEventArgs());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindOrRegisterInstanceForKey(void* key, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindOrRegisterInstanceForKey, WINRT_WRAP(Windows::ApplicationModel::AppInstance), hstring const&);
            *result = detach_from<Windows::ApplicationModel::AppInstance>(this->shim().FindOrRegisterInstanceForKey(*reinterpret_cast<hstring const*>(&key)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Unregister() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Unregister, WINRT_WRAP(void));
            this->shim().Unregister();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetInstances(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetInstances, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::AppInstance>));
            *result = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::AppInstance>>(this->shim().GetInstances());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IDesignModeStatics> : produce_base<D, Windows::ApplicationModel::IDesignModeStatics>
{
    int32_t WINRT_CALL get_DesignModeEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesignModeEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().DesignModeEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IDesignModeStatics2> : produce_base<D, Windows::ApplicationModel::IDesignModeStatics2>
{
    int32_t WINRT_CALL get_DesignMode2Enabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesignMode2Enabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().DesignMode2Enabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IEnteredBackgroundEventArgs> : produce_base<D, Windows::ApplicationModel::IEnteredBackgroundEventArgs>
{
    int32_t WINRT_CALL GetDeferral(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Foundation::Deferral));
            *value = detach_from<Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IFullTrustProcessLauncherStatics> : produce_base<D, Windows::ApplicationModel::IFullTrustProcessLauncherStatics>
{
    int32_t WINRT_CALL LaunchFullTrustProcessForCurrentAppAsync(void** asyncAction) noexcept final
    {
        try
        {
            *asyncAction = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchFullTrustProcessForCurrentAppAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *asyncAction = detach_from<Windows::Foundation::IAsyncAction>(this->shim().LaunchFullTrustProcessForCurrentAppAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LaunchFullTrustProcessForCurrentAppWithParametersAsync(void* parameterGroupId, void** asyncAction) noexcept final
    {
        try
        {
            *asyncAction = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchFullTrustProcessForCurrentAppAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const);
            *asyncAction = detach_from<Windows::Foundation::IAsyncAction>(this->shim().LaunchFullTrustProcessForCurrentAppAsync(*reinterpret_cast<hstring const*>(&parameterGroupId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LaunchFullTrustProcessForAppAsync(void* fullTrustPackageRelativeAppId, void** asyncAction) noexcept final
    {
        try
        {
            *asyncAction = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchFullTrustProcessForAppAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const);
            *asyncAction = detach_from<Windows::Foundation::IAsyncAction>(this->shim().LaunchFullTrustProcessForAppAsync(*reinterpret_cast<hstring const*>(&fullTrustPackageRelativeAppId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LaunchFullTrustProcessForAppWithParametersAsync(void* fullTrustPackageRelativeAppId, void* parameterGroupId, void** asyncAction) noexcept final
    {
        try
        {
            *asyncAction = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchFullTrustProcessForAppAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const, hstring const);
            *asyncAction = detach_from<Windows::Foundation::IAsyncAction>(this->shim().LaunchFullTrustProcessForAppAsync(*reinterpret_cast<hstring const*>(&fullTrustPackageRelativeAppId), *reinterpret_cast<hstring const*>(&parameterGroupId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::ILeavingBackgroundEventArgs> : produce_base<D, Windows::ApplicationModel::ILeavingBackgroundEventArgs>
{
    int32_t WINRT_CALL GetDeferral(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Foundation::Deferral));
            *value = detach_from<Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::ILimitedAccessFeatureRequestResult> : produce_base<D, Windows::ApplicationModel::ILimitedAccessFeatureRequestResult>
{
    int32_t WINRT_CALL get_FeatureId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FeatureId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FeatureId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(Windows::ApplicationModel::LimitedAccessFeatureStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::ApplicationModel::LimitedAccessFeatureStatus));
            *value = detach_from<Windows::ApplicationModel::LimitedAccessFeatureStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EstimatedRemovalDate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EstimatedRemovalDate, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().EstimatedRemovalDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::ILimitedAccessFeaturesStatics> : produce_base<D, Windows::ApplicationModel::ILimitedAccessFeaturesStatics>
{
    int32_t WINRT_CALL TryUnlockFeature(void* featureId, void* token, void* attestation, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryUnlockFeature, WINRT_WRAP(Windows::ApplicationModel::LimitedAccessFeatureRequestResult), hstring const&, hstring const&, hstring const&);
            *result = detach_from<Windows::ApplicationModel::LimitedAccessFeatureRequestResult>(this->shim().TryUnlockFeature(*reinterpret_cast<hstring const*>(&featureId), *reinterpret_cast<hstring const*>(&token), *reinterpret_cast<hstring const*>(&attestation)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IPackage> : produce_base<D, Windows::ApplicationModel::IPackage>
{
    int32_t WINRT_CALL get_Id(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(Windows::ApplicationModel::PackageId));
            *value = detach_from<Windows::ApplicationModel::PackageId>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InstalledLocation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InstalledLocation, WINRT_WRAP(Windows::Storage::StorageFolder));
            *value = detach_from<Windows::Storage::StorageFolder>(this->shim().InstalledLocation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsFramework(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsFramework, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsFramework());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Dependencies(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Dependencies, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Package>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Package>>(this->shim().Dependencies());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IPackage2> : produce_base<D, Windows::ApplicationModel::IPackage2>
{
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

    int32_t WINRT_CALL get_PublisherDisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PublisherDisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PublisherDisplayName());
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

    int32_t WINRT_CALL get_Logo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Logo, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Logo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsResourcePackage(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsResourcePackage, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsResourcePackage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsBundle(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsBundle, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsBundle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDevelopmentMode(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDevelopmentMode, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDevelopmentMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IPackage3> : produce_base<D, Windows::ApplicationModel::IPackage3>
{
    int32_t WINRT_CALL get_Status(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::ApplicationModel::PackageStatus));
            *value = detach_from<Windows::ApplicationModel::PackageStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InstalledDate(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InstalledDate, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().InstalledDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAppListEntriesAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAppListEntriesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Core::AppListEntry>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Core::AppListEntry>>>(this->shim().GetAppListEntriesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IPackage4> : produce_base<D, Windows::ApplicationModel::IPackage4>
{
    int32_t WINRT_CALL get_SignatureKind(Windows::ApplicationModel::PackageSignatureKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SignatureKind, WINRT_WRAP(Windows::ApplicationModel::PackageSignatureKind));
            *value = detach_from<Windows::ApplicationModel::PackageSignatureKind>(this->shim().SignatureKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsOptional(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOptional, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsOptional());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL VerifyContentIntegrityAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerifyContentIntegrityAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().VerifyContentIntegrityAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IPackage5> : produce_base<D, Windows::ApplicationModel::IPackage5>
{
    int32_t WINRT_CALL GetContentGroupsAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetContentGroupsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::PackageContentGroup>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::PackageContentGroup>>>(this->shim().GetContentGroupsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetContentGroupAsync(void* name, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetContentGroupAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::PackageContentGroup>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::PackageContentGroup>>(this->shim().GetContentGroupAsync(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StageContentGroupsAsync(void* names, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StageContentGroupsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::PackageContentGroup>>), Windows::Foundation::Collections::IIterable<hstring> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::PackageContentGroup>>>(this->shim().StageContentGroupsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&names)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StageContentGroupsWithPriorityAsync(void* names, bool moveToHeadOfQueue, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StageContentGroupsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::PackageContentGroup>>), Windows::Foundation::Collections::IIterable<hstring> const, bool);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::PackageContentGroup>>>(this->shim().StageContentGroupsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&names), moveToHeadOfQueue));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetInUseAsync(bool inUse, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetInUseAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), bool);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().SetInUseAsync(inUse));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IPackage6> : produce_base<D, Windows::ApplicationModel::IPackage6>
{
    int32_t WINRT_CALL GetAppInstallerInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAppInstallerInfo, WINRT_WRAP(Windows::ApplicationModel::AppInstallerInfo));
            *value = detach_from<Windows::ApplicationModel::AppInstallerInfo>(this->shim().GetAppInstallerInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CheckUpdateAvailabilityAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckUpdateAvailabilityAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::PackageUpdateAvailabilityResult>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::PackageUpdateAvailabilityResult>>(this->shim().CheckUpdateAvailabilityAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IPackage7> : produce_base<D, Windows::ApplicationModel::IPackage7>
{
    int32_t WINRT_CALL get_MutableLocation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MutableLocation, WINRT_WRAP(Windows::Storage::StorageFolder));
            *value = detach_from<Windows::Storage::StorageFolder>(this->shim().MutableLocation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EffectiveLocation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EffectiveLocation, WINRT_WRAP(Windows::Storage::StorageFolder));
            *value = detach_from<Windows::Storage::StorageFolder>(this->shim().EffectiveLocation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IPackageCatalog> : produce_base<D, Windows::ApplicationModel::IPackageCatalog>
{
    int32_t WINRT_CALL add_PackageStaging(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PackageStaging, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageStagingEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().PackageStaging(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageStagingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PackageStaging(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PackageStaging, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PackageStaging(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PackageInstalling(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PackageInstalling, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageInstallingEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().PackageInstalling(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageInstallingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PackageInstalling(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PackageInstalling, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PackageInstalling(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PackageUpdating(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PackageUpdating, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageUpdatingEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().PackageUpdating(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageUpdatingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PackageUpdating(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PackageUpdating, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PackageUpdating(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PackageUninstalling(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PackageUninstalling, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageUninstallingEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().PackageUninstalling(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageUninstallingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PackageUninstalling(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PackageUninstalling, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PackageUninstalling(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PackageStatusChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PackageStatusChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageStatusChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().PackageStatusChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageStatusChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PackageStatusChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PackageStatusChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PackageStatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IPackageCatalog2> : produce_base<D, Windows::ApplicationModel::IPackageCatalog2>
{
    int32_t WINRT_CALL add_PackageContentGroupStaging(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PackageContentGroupStaging, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageContentGroupStagingEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().PackageContentGroupStaging(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageContentGroupStagingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PackageContentGroupStaging(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PackageContentGroupStaging, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PackageContentGroupStaging(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL AddOptionalPackageAsync(void* optionalPackageFamilyName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddOptionalPackageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::PackageCatalogAddOptionalPackageResult>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::PackageCatalogAddOptionalPackageResult>>(this->shim().AddOptionalPackageAsync(*reinterpret_cast<hstring const*>(&optionalPackageFamilyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IPackageCatalog3> : produce_base<D, Windows::ApplicationModel::IPackageCatalog3>
{
    int32_t WINRT_CALL RemoveOptionalPackagesAsync(void* optionalPackageFamilyNames, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveOptionalPackagesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::PackageCatalogRemoveOptionalPackagesResult>), Windows::Foundation::Collections::IIterable<hstring> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::PackageCatalogRemoveOptionalPackagesResult>>(this->shim().RemoveOptionalPackagesAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&optionalPackageFamilyNames)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IPackageCatalog4> : produce_base<D, Windows::ApplicationModel::IPackageCatalog4>
{
    int32_t WINRT_CALL AddResourcePackageAsync(void* resourcePackageFamilyName, void* resourceID, Windows::ApplicationModel::AddResourcePackageOptions options, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddResourcePackageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::ApplicationModel::PackageCatalogAddResourcePackageResult, Windows::ApplicationModel::PackageInstallProgress>), hstring const, hstring const, Windows::ApplicationModel::AddResourcePackageOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::ApplicationModel::PackageCatalogAddResourcePackageResult, Windows::ApplicationModel::PackageInstallProgress>>(this->shim().AddResourcePackageAsync(*reinterpret_cast<hstring const*>(&resourcePackageFamilyName), *reinterpret_cast<hstring const*>(&resourceID), *reinterpret_cast<Windows::ApplicationModel::AddResourcePackageOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveResourcePackagesAsync(void* resourcePackages, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveResourcePackagesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::PackageCatalogRemoveResourcePackagesResult>), Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::PackageCatalogRemoveResourcePackagesResult>>(this->shim().RemoveResourcePackagesAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> const*>(&resourcePackages)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IPackageCatalogAddOptionalPackageResult> : produce_base<D, Windows::ApplicationModel::IPackageCatalogAddOptionalPackageResult>
{
    int32_t WINRT_CALL get_Package(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Package, WINRT_WRAP(Windows::ApplicationModel::Package));
            *value = detach_from<Windows::ApplicationModel::Package>(this->shim().Package());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedError, WINRT_WRAP(winrt::hresult));
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IPackageCatalogAddResourcePackageResult> : produce_base<D, Windows::ApplicationModel::IPackageCatalogAddResourcePackageResult>
{
    int32_t WINRT_CALL get_Package(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Package, WINRT_WRAP(Windows::ApplicationModel::Package));
            *value = detach_from<Windows::ApplicationModel::Package>(this->shim().Package());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsComplete(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsComplete, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsComplete());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedError, WINRT_WRAP(winrt::hresult));
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IPackageCatalogRemoveOptionalPackagesResult> : produce_base<D, Windows::ApplicationModel::IPackageCatalogRemoveOptionalPackagesResult>
{
    int32_t WINRT_CALL get_PackagesRemoved(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PackagesRemoved, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Package>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Package>>(this->shim().PackagesRemoved());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedError, WINRT_WRAP(winrt::hresult));
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IPackageCatalogRemoveResourcePackagesResult> : produce_base<D, Windows::ApplicationModel::IPackageCatalogRemoveResourcePackagesResult>
{
    int32_t WINRT_CALL get_PackagesRemoved(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PackagesRemoved, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Package>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Package>>(this->shim().PackagesRemoved());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedError, WINRT_WRAP(winrt::hresult));
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IPackageCatalogStatics> : produce_base<D, Windows::ApplicationModel::IPackageCatalogStatics>
{
    int32_t WINRT_CALL OpenForCurrentPackage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenForCurrentPackage, WINRT_WRAP(Windows::ApplicationModel::PackageCatalog));
            *value = detach_from<Windows::ApplicationModel::PackageCatalog>(this->shim().OpenForCurrentPackage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OpenForCurrentUser(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenForCurrentUser, WINRT_WRAP(Windows::ApplicationModel::PackageCatalog));
            *value = detach_from<Windows::ApplicationModel::PackageCatalog>(this->shim().OpenForCurrentUser());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IPackageContentGroup> : produce_base<D, Windows::ApplicationModel::IPackageContentGroup>
{
    int32_t WINRT_CALL get_Package(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Package, WINRT_WRAP(Windows::ApplicationModel::Package));
            *value = detach_from<Windows::ApplicationModel::Package>(this->shim().Package());
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

    int32_t WINRT_CALL get_State(Windows::ApplicationModel::PackageContentGroupState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::ApplicationModel::PackageContentGroupState));
            *value = detach_from<Windows::ApplicationModel::PackageContentGroupState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsRequired(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRequired, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsRequired());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IPackageContentGroupStagingEventArgs> : produce_base<D, Windows::ApplicationModel::IPackageContentGroupStagingEventArgs>
{
    int32_t WINRT_CALL get_ActivityId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActivityId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().ActivityId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Package(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Package, WINRT_WRAP(Windows::ApplicationModel::Package));
            *value = detach_from<Windows::ApplicationModel::Package>(this->shim().Package());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Progress(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Progress, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Progress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsComplete(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsComplete, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsComplete());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL get_ContentGroupName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentGroupName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ContentGroupName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsContentGroupRequired(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsContentGroupRequired, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsContentGroupRequired());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IPackageContentGroupStatics> : produce_base<D, Windows::ApplicationModel::IPackageContentGroupStatics>
{
    int32_t WINRT_CALL get_RequiredGroupName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequiredGroupName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RequiredGroupName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IPackageId> : produce_base<D, Windows::ApplicationModel::IPackageId>
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

    int32_t WINRT_CALL get_Version(struct struct_Windows_ApplicationModel_PackageVersion* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Version, WINRT_WRAP(Windows::ApplicationModel::PackageVersion));
            *value = detach_from<Windows::ApplicationModel::PackageVersion>(this->shim().Version());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Architecture(Windows::System::ProcessorArchitecture* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Architecture, WINRT_WRAP(Windows::System::ProcessorArchitecture));
            *value = detach_from<Windows::System::ProcessorArchitecture>(this->shim().Architecture());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResourceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResourceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ResourceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Publisher(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Publisher, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Publisher());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PublisherId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PublisherId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PublisherId());
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

    int32_t WINRT_CALL get_FamilyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FamilyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FamilyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IPackageIdWithMetadata> : produce_base<D, Windows::ApplicationModel::IPackageIdWithMetadata>
{
    int32_t WINRT_CALL get_ProductId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProductId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ProductId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Author(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Author, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Author());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IPackageInstallingEventArgs> : produce_base<D, Windows::ApplicationModel::IPackageInstallingEventArgs>
{
    int32_t WINRT_CALL get_ActivityId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActivityId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().ActivityId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Package(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Package, WINRT_WRAP(Windows::ApplicationModel::Package));
            *value = detach_from<Windows::ApplicationModel::Package>(this->shim().Package());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Progress(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Progress, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Progress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsComplete(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsComplete, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsComplete());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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
struct produce<D, Windows::ApplicationModel::IPackageStagingEventArgs> : produce_base<D, Windows::ApplicationModel::IPackageStagingEventArgs>
{
    int32_t WINRT_CALL get_ActivityId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActivityId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().ActivityId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Package(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Package, WINRT_WRAP(Windows::ApplicationModel::Package));
            *value = detach_from<Windows::ApplicationModel::Package>(this->shim().Package());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Progress(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Progress, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Progress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsComplete(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsComplete, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsComplete());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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
struct produce<D, Windows::ApplicationModel::IPackageStatics> : produce_base<D, Windows::ApplicationModel::IPackageStatics>
{
    int32_t WINRT_CALL get_Current(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Current, WINRT_WRAP(Windows::ApplicationModel::Package));
            *value = detach_from<Windows::ApplicationModel::Package>(this->shim().Current());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IPackageStatus> : produce_base<D, Windows::ApplicationModel::IPackageStatus>
{
    int32_t WINRT_CALL VerifyIsOK(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerifyIsOK, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().VerifyIsOK());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NotAvailable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotAvailable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().NotAvailable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PackageOffline(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PackageOffline, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().PackageOffline());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DataOffline(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataOffline, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().DataOffline());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Disabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Disabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Disabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NeedsRemediation(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NeedsRemediation, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().NeedsRemediation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LicenseIssue(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LicenseIssue, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().LicenseIssue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Modified(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Modified, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Modified());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Tampered(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tampered, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Tampered());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DependencyIssue(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DependencyIssue, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().DependencyIssue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Servicing(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Servicing, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Servicing());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeploymentInProgress(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeploymentInProgress, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().DeploymentInProgress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IPackageStatus2> : produce_base<D, Windows::ApplicationModel::IPackageStatus2>
{
    int32_t WINRT_CALL get_IsPartiallyStaged(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPartiallyStaged, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPartiallyStaged());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IPackageStatusChangedEventArgs> : produce_base<D, Windows::ApplicationModel::IPackageStatusChangedEventArgs>
{
    int32_t WINRT_CALL get_Package(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Package, WINRT_WRAP(Windows::ApplicationModel::Package));
            *value = detach_from<Windows::ApplicationModel::Package>(this->shim().Package());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IPackageUninstallingEventArgs> : produce_base<D, Windows::ApplicationModel::IPackageUninstallingEventArgs>
{
    int32_t WINRT_CALL get_ActivityId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActivityId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().ActivityId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Package(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Package, WINRT_WRAP(Windows::ApplicationModel::Package));
            *value = detach_from<Windows::ApplicationModel::Package>(this->shim().Package());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Progress(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Progress, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Progress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsComplete(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsComplete, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsComplete());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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
struct produce<D, Windows::ApplicationModel::IPackageUpdateAvailabilityResult> : produce_base<D, Windows::ApplicationModel::IPackageUpdateAvailabilityResult>
{
    int32_t WINRT_CALL get_Availability(Windows::ApplicationModel::PackageUpdateAvailability* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Availability, WINRT_WRAP(Windows::ApplicationModel::PackageUpdateAvailability));
            *value = detach_from<Windows::ApplicationModel::PackageUpdateAvailability>(this->shim().Availability());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedError, WINRT_WRAP(winrt::hresult));
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IPackageUpdatingEventArgs> : produce_base<D, Windows::ApplicationModel::IPackageUpdatingEventArgs>
{
    int32_t WINRT_CALL get_ActivityId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActivityId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().ActivityId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SourcePackage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourcePackage, WINRT_WRAP(Windows::ApplicationModel::Package));
            *value = detach_from<Windows::ApplicationModel::Package>(this->shim().SourcePackage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TargetPackage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetPackage, WINRT_WRAP(Windows::ApplicationModel::Package));
            *value = detach_from<Windows::ApplicationModel::Package>(this->shim().TargetPackage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Progress(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Progress, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Progress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsComplete(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsComplete, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsComplete());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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
struct produce<D, Windows::ApplicationModel::IPackageWithMetadata> : produce_base<D, Windows::ApplicationModel::IPackageWithMetadata>
{
    int32_t WINRT_CALL get_InstallDate(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InstallDate, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().InstallDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetThumbnailToken(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetThumbnailToken, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GetThumbnailToken());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Launch(void* parameters) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Launch, WINRT_WRAP(void), hstring const&);
            this->shim().Launch(*reinterpret_cast<hstring const*>(&parameters));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IStartupTask> : produce_base<D, Windows::ApplicationModel::IStartupTask>
{
    int32_t WINRT_CALL RequestEnableAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestEnableAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::StartupTaskState>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::StartupTaskState>>(this->shim().RequestEnableAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Disable() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Disable, WINRT_WRAP(void));
            this->shim().Disable();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_State(Windows::ApplicationModel::StartupTaskState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::ApplicationModel::StartupTaskState));
            *value = detach_from<Windows::ApplicationModel::StartupTaskState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TaskId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TaskId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TaskId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::IStartupTaskStatics> : produce_base<D, Windows::ApplicationModel::IStartupTaskStatics>
{
    int32_t WINRT_CALL GetForCurrentPackageAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentPackageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::StartupTask>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::StartupTask>>>(this->shim().GetForCurrentPackageAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAsync(void* taskId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::StartupTask>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::StartupTask>>(this->shim().GetAsync(*reinterpret_cast<hstring const*>(&taskId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::ISuspendingDeferral> : produce_base<D, Windows::ApplicationModel::ISuspendingDeferral>
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
struct produce<D, Windows::ApplicationModel::ISuspendingEventArgs> : produce_base<D, Windows::ApplicationModel::ISuspendingEventArgs>
{
    int32_t WINRT_CALL get_SuspendingOperation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SuspendingOperation, WINRT_WRAP(Windows::ApplicationModel::SuspendingOperation));
            *value = detach_from<Windows::ApplicationModel::SuspendingOperation>(this->shim().SuspendingOperation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::ISuspendingOperation> : produce_base<D, Windows::ApplicationModel::ISuspendingOperation>
{
    int32_t WINRT_CALL GetDeferral(void** deferral) noexcept final
    {
        try
        {
            *deferral = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::ApplicationModel::SuspendingDeferral));
            *deferral = detach_from<Windows::ApplicationModel::SuspendingDeferral>(this->shim().GetDeferral());
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
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel {

inline Windows::ApplicationModel::AppInstance AppInstance::RecommendedInstance()
{
    return impl::call_factory<AppInstance, Windows::ApplicationModel::IAppInstanceStatics>([&](auto&& f) { return f.RecommendedInstance(); });
}

inline Windows::ApplicationModel::Activation::IActivatedEventArgs AppInstance::GetActivatedEventArgs()
{
    return impl::call_factory<AppInstance, Windows::ApplicationModel::IAppInstanceStatics>([&](auto&& f) { return f.GetActivatedEventArgs(); });
}

inline Windows::ApplicationModel::AppInstance AppInstance::FindOrRegisterInstanceForKey(param::hstring const& key)
{
    return impl::call_factory<AppInstance, Windows::ApplicationModel::IAppInstanceStatics>([&](auto&& f) { return f.FindOrRegisterInstanceForKey(key); });
}

inline void AppInstance::Unregister()
{
    impl::call_factory<AppInstance, Windows::ApplicationModel::IAppInstanceStatics>([&](auto&& f) { return f.Unregister(); });
}

inline Windows::Foundation::Collections::IVector<Windows::ApplicationModel::AppInstance> AppInstance::GetInstances()
{
    return impl::call_factory<AppInstance, Windows::ApplicationModel::IAppInstanceStatics>([&](auto&& f) { return f.GetInstances(); });
}

inline bool DesignMode::DesignModeEnabled()
{
    return impl::call_factory<DesignMode, Windows::ApplicationModel::IDesignModeStatics>([&](auto&& f) { return f.DesignModeEnabled(); });
}

inline bool DesignMode::DesignMode2Enabled()
{
    return impl::call_factory<DesignMode, Windows::ApplicationModel::IDesignModeStatics2>([&](auto&& f) { return f.DesignMode2Enabled(); });
}

inline Windows::Foundation::IAsyncAction FullTrustProcessLauncher::LaunchFullTrustProcessForCurrentAppAsync()
{
    return impl::call_factory<FullTrustProcessLauncher, Windows::ApplicationModel::IFullTrustProcessLauncherStatics>([&](auto&& f) { return f.LaunchFullTrustProcessForCurrentAppAsync(); });
}

inline Windows::Foundation::IAsyncAction FullTrustProcessLauncher::LaunchFullTrustProcessForCurrentAppAsync(param::hstring const& parameterGroupId)
{
    return impl::call_factory<FullTrustProcessLauncher, Windows::ApplicationModel::IFullTrustProcessLauncherStatics>([&](auto&& f) { return f.LaunchFullTrustProcessForCurrentAppAsync(parameterGroupId); });
}

inline Windows::Foundation::IAsyncAction FullTrustProcessLauncher::LaunchFullTrustProcessForAppAsync(param::hstring const& fullTrustPackageRelativeAppId)
{
    return impl::call_factory<FullTrustProcessLauncher, Windows::ApplicationModel::IFullTrustProcessLauncherStatics>([&](auto&& f) { return f.LaunchFullTrustProcessForAppAsync(fullTrustPackageRelativeAppId); });
}

inline Windows::Foundation::IAsyncAction FullTrustProcessLauncher::LaunchFullTrustProcessForAppAsync(param::hstring const& fullTrustPackageRelativeAppId, param::hstring const& parameterGroupId)
{
    return impl::call_factory<FullTrustProcessLauncher, Windows::ApplicationModel::IFullTrustProcessLauncherStatics>([&](auto&& f) { return f.LaunchFullTrustProcessForAppAsync(fullTrustPackageRelativeAppId, parameterGroupId); });
}

inline Windows::ApplicationModel::LimitedAccessFeatureRequestResult LimitedAccessFeatures::TryUnlockFeature(param::hstring const& featureId, param::hstring const& token, param::hstring const& attestation)
{
    return impl::call_factory<LimitedAccessFeatures, Windows::ApplicationModel::ILimitedAccessFeaturesStatics>([&](auto&& f) { return f.TryUnlockFeature(featureId, token, attestation); });
}

inline Windows::ApplicationModel::Package Package::Current()
{
    return impl::call_factory<Package, Windows::ApplicationModel::IPackageStatics>([&](auto&& f) { return f.Current(); });
}

inline Windows::ApplicationModel::PackageCatalog PackageCatalog::OpenForCurrentPackage()
{
    return impl::call_factory<PackageCatalog, Windows::ApplicationModel::IPackageCatalogStatics>([&](auto&& f) { return f.OpenForCurrentPackage(); });
}

inline Windows::ApplicationModel::PackageCatalog PackageCatalog::OpenForCurrentUser()
{
    return impl::call_factory<PackageCatalog, Windows::ApplicationModel::IPackageCatalogStatics>([&](auto&& f) { return f.OpenForCurrentUser(); });
}

inline hstring PackageContentGroup::RequiredGroupName()
{
    return impl::call_factory<PackageContentGroup, Windows::ApplicationModel::IPackageContentGroupStatics>([&](auto&& f) { return f.RequiredGroupName(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::StartupTask>> StartupTask::GetForCurrentPackageAsync()
{
    return impl::call_factory<StartupTask, Windows::ApplicationModel::IStartupTaskStatics>([&](auto&& f) { return f.GetForCurrentPackageAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::StartupTask> StartupTask::GetAsync(param::hstring const& taskId)
{
    return impl::call_factory<StartupTask, Windows::ApplicationModel::IStartupTaskStatics>([&](auto&& f) { return f.GetAsync(taskId); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::IAppDisplayInfo> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IAppDisplayInfo> {};
template<> struct hash<winrt::Windows::ApplicationModel::IAppInfo> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IAppInfo> {};
template<> struct hash<winrt::Windows::ApplicationModel::IAppInstallerInfo> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IAppInstallerInfo> {};
template<> struct hash<winrt::Windows::ApplicationModel::IAppInstance> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IAppInstance> {};
template<> struct hash<winrt::Windows::ApplicationModel::IAppInstanceStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IAppInstanceStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::IDesignModeStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IDesignModeStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::IDesignModeStatics2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IDesignModeStatics2> {};
template<> struct hash<winrt::Windows::ApplicationModel::IEnteredBackgroundEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IEnteredBackgroundEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::IFullTrustProcessLauncherStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IFullTrustProcessLauncherStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::ILeavingBackgroundEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::ILeavingBackgroundEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::ILimitedAccessFeatureRequestResult> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::ILimitedAccessFeatureRequestResult> {};
template<> struct hash<winrt::Windows::ApplicationModel::ILimitedAccessFeaturesStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::ILimitedAccessFeaturesStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::IPackage> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IPackage> {};
template<> struct hash<winrt::Windows::ApplicationModel::IPackage2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IPackage2> {};
template<> struct hash<winrt::Windows::ApplicationModel::IPackage3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IPackage3> {};
template<> struct hash<winrt::Windows::ApplicationModel::IPackage4> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IPackage4> {};
template<> struct hash<winrt::Windows::ApplicationModel::IPackage5> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IPackage5> {};
template<> struct hash<winrt::Windows::ApplicationModel::IPackage6> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IPackage6> {};
template<> struct hash<winrt::Windows::ApplicationModel::IPackage7> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IPackage7> {};
template<> struct hash<winrt::Windows::ApplicationModel::IPackageCatalog> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IPackageCatalog> {};
template<> struct hash<winrt::Windows::ApplicationModel::IPackageCatalog2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IPackageCatalog2> {};
template<> struct hash<winrt::Windows::ApplicationModel::IPackageCatalog3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IPackageCatalog3> {};
template<> struct hash<winrt::Windows::ApplicationModel::IPackageCatalog4> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IPackageCatalog4> {};
template<> struct hash<winrt::Windows::ApplicationModel::IPackageCatalogAddOptionalPackageResult> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IPackageCatalogAddOptionalPackageResult> {};
template<> struct hash<winrt::Windows::ApplicationModel::IPackageCatalogAddResourcePackageResult> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IPackageCatalogAddResourcePackageResult> {};
template<> struct hash<winrt::Windows::ApplicationModel::IPackageCatalogRemoveOptionalPackagesResult> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IPackageCatalogRemoveOptionalPackagesResult> {};
template<> struct hash<winrt::Windows::ApplicationModel::IPackageCatalogRemoveResourcePackagesResult> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IPackageCatalogRemoveResourcePackagesResult> {};
template<> struct hash<winrt::Windows::ApplicationModel::IPackageCatalogStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IPackageCatalogStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::IPackageContentGroup> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IPackageContentGroup> {};
template<> struct hash<winrt::Windows::ApplicationModel::IPackageContentGroupStagingEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IPackageContentGroupStagingEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::IPackageContentGroupStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IPackageContentGroupStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::IPackageId> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IPackageId> {};
template<> struct hash<winrt::Windows::ApplicationModel::IPackageIdWithMetadata> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IPackageIdWithMetadata> {};
template<> struct hash<winrt::Windows::ApplicationModel::IPackageInstallingEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IPackageInstallingEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::IPackageStagingEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IPackageStagingEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::IPackageStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IPackageStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::IPackageStatus> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IPackageStatus> {};
template<> struct hash<winrt::Windows::ApplicationModel::IPackageStatus2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IPackageStatus2> {};
template<> struct hash<winrt::Windows::ApplicationModel::IPackageStatusChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IPackageStatusChangedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::IPackageUninstallingEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IPackageUninstallingEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::IPackageUpdateAvailabilityResult> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IPackageUpdateAvailabilityResult> {};
template<> struct hash<winrt::Windows::ApplicationModel::IPackageUpdatingEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IPackageUpdatingEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::IPackageWithMetadata> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IPackageWithMetadata> {};
template<> struct hash<winrt::Windows::ApplicationModel::IStartupTask> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IStartupTask> {};
template<> struct hash<winrt::Windows::ApplicationModel::IStartupTaskStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::IStartupTaskStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::ISuspendingDeferral> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::ISuspendingDeferral> {};
template<> struct hash<winrt::Windows::ApplicationModel::ISuspendingEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::ISuspendingEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::ISuspendingOperation> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::ISuspendingOperation> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppDisplayInfo> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppDisplayInfo> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppInfo> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppInfo> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppInstallerInfo> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppInstallerInfo> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppInstance> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppInstance> {};
template<> struct hash<winrt::Windows::ApplicationModel::DesignMode> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DesignMode> {};
template<> struct hash<winrt::Windows::ApplicationModel::EnteredBackgroundEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::EnteredBackgroundEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::FullTrustProcessLauncher> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::FullTrustProcessLauncher> {};
template<> struct hash<winrt::Windows::ApplicationModel::LeavingBackgroundEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::LeavingBackgroundEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::LimitedAccessFeatureRequestResult> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::LimitedAccessFeatureRequestResult> {};
template<> struct hash<winrt::Windows::ApplicationModel::LimitedAccessFeatures> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::LimitedAccessFeatures> {};
template<> struct hash<winrt::Windows::ApplicationModel::Package> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Package> {};
template<> struct hash<winrt::Windows::ApplicationModel::PackageCatalog> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::PackageCatalog> {};
template<> struct hash<winrt::Windows::ApplicationModel::PackageCatalogAddOptionalPackageResult> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::PackageCatalogAddOptionalPackageResult> {};
template<> struct hash<winrt::Windows::ApplicationModel::PackageCatalogAddResourcePackageResult> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::PackageCatalogAddResourcePackageResult> {};
template<> struct hash<winrt::Windows::ApplicationModel::PackageCatalogRemoveOptionalPackagesResult> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::PackageCatalogRemoveOptionalPackagesResult> {};
template<> struct hash<winrt::Windows::ApplicationModel::PackageCatalogRemoveResourcePackagesResult> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::PackageCatalogRemoveResourcePackagesResult> {};
template<> struct hash<winrt::Windows::ApplicationModel::PackageContentGroup> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::PackageContentGroup> {};
template<> struct hash<winrt::Windows::ApplicationModel::PackageContentGroupStagingEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::PackageContentGroupStagingEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::PackageId> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::PackageId> {};
template<> struct hash<winrt::Windows::ApplicationModel::PackageInstallingEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::PackageInstallingEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::PackageStagingEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::PackageStagingEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::PackageStatus> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::PackageStatus> {};
template<> struct hash<winrt::Windows::ApplicationModel::PackageStatusChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::PackageStatusChangedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::PackageUninstallingEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::PackageUninstallingEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::PackageUpdateAvailabilityResult> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::PackageUpdateAvailabilityResult> {};
template<> struct hash<winrt::Windows::ApplicationModel::PackageUpdatingEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::PackageUpdatingEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::StartupTask> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::StartupTask> {};
template<> struct hash<winrt::Windows::ApplicationModel::SuspendingDeferral> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::SuspendingDeferral> {};
template<> struct hash<winrt::Windows::ApplicationModel::SuspendingEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::SuspendingEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::SuspendingOperation> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::SuspendingOperation> {};

}
