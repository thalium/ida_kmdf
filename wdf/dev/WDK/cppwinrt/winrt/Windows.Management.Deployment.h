// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Management.Deployment.2.h"
#include "winrt/Windows.Management.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_Management_Deployment_IDeploymentResult<D>::ErrorText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IDeploymentResult)->get_ErrorText(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Management_Deployment_IDeploymentResult<D>::ActivityId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IDeploymentResult)->get_ActivityId(put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_Management_Deployment_IDeploymentResult<D>::ExtendedErrorCode() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IDeploymentResult)->get_ExtendedErrorCode(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Management_Deployment_IDeploymentResult2<D>::IsRegistered() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IDeploymentResult2)->get_IsRegistered(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> consume_Windows_Management_Deployment_IPackageManager<D>::AddPackageAsync(Windows::Foundation::Uri const& packageUri, param::async_iterable<Windows::Foundation::Uri> const& dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions const& deploymentOptions) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> deploymentOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager)->AddPackageAsync(get_abi(packageUri), get_abi(dependencyPackageUris), get_abi(deploymentOptions), put_abi(deploymentOperation)));
    return deploymentOperation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> consume_Windows_Management_Deployment_IPackageManager<D>::UpdatePackageAsync(Windows::Foundation::Uri const& packageUri, param::async_iterable<Windows::Foundation::Uri> const& dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions const& deploymentOptions) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> deploymentOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager)->UpdatePackageAsync(get_abi(packageUri), get_abi(dependencyPackageUris), get_abi(deploymentOptions), put_abi(deploymentOperation)));
    return deploymentOperation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> consume_Windows_Management_Deployment_IPackageManager<D>::RemovePackageAsync(param::hstring const& packageFullName) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> deploymentOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager)->RemovePackageAsync(get_abi(packageFullName), put_abi(deploymentOperation)));
    return deploymentOperation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> consume_Windows_Management_Deployment_IPackageManager<D>::StagePackageAsync(Windows::Foundation::Uri const& packageUri, param::async_iterable<Windows::Foundation::Uri> const& dependencyPackageUris) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> deploymentOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager)->StagePackageAsync(get_abi(packageUri), get_abi(dependencyPackageUris), put_abi(deploymentOperation)));
    return deploymentOperation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> consume_Windows_Management_Deployment_IPackageManager<D>::RegisterPackageAsync(Windows::Foundation::Uri const& manifestUri, param::async_iterable<Windows::Foundation::Uri> const& dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions const& deploymentOptions) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> deploymentOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager)->RegisterPackageAsync(get_abi(manifestUri), get_abi(dependencyPackageUris), get_abi(deploymentOptions), put_abi(deploymentOperation)));
    return deploymentOperation;
}

template <typename D> Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> consume_Windows_Management_Deployment_IPackageManager<D>::FindPackages() const
{
    Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> packageCollection{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager)->FindPackages(put_abi(packageCollection)));
    return packageCollection;
}

template <typename D> Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> consume_Windows_Management_Deployment_IPackageManager<D>::FindPackagesForUser(param::hstring const& userSecurityId) const
{
    Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> packageCollection{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager)->FindPackagesByUserSecurityId(get_abi(userSecurityId), put_abi(packageCollection)));
    return packageCollection;
}

template <typename D> Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> consume_Windows_Management_Deployment_IPackageManager<D>::FindPackages(param::hstring const& packageName, param::hstring const& packagePublisher) const
{
    Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> packageCollection{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager)->FindPackagesByNamePublisher(get_abi(packageName), get_abi(packagePublisher), put_abi(packageCollection)));
    return packageCollection;
}

template <typename D> Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> consume_Windows_Management_Deployment_IPackageManager<D>::FindPackagesForUser(param::hstring const& userSecurityId, param::hstring const& packageName, param::hstring const& packagePublisher) const
{
    Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> packageCollection{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager)->FindPackagesByUserSecurityIdNamePublisher(get_abi(userSecurityId), get_abi(packageName), get_abi(packagePublisher), put_abi(packageCollection)));
    return packageCollection;
}

template <typename D> Windows::Foundation::Collections::IIterable<Windows::Management::Deployment::PackageUserInformation> consume_Windows_Management_Deployment_IPackageManager<D>::FindUsers(param::hstring const& packageFullName) const
{
    Windows::Foundation::Collections::IIterable<Windows::Management::Deployment::PackageUserInformation> users{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager)->FindUsers(get_abi(packageFullName), put_abi(users)));
    return users;
}

template <typename D> void consume_Windows_Management_Deployment_IPackageManager<D>::SetPackageState(param::hstring const& packageFullName, Windows::Management::Deployment::PackageState const& packageState) const
{
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager)->SetPackageState(get_abi(packageFullName), get_abi(packageState)));
}

template <typename D> Windows::ApplicationModel::Package consume_Windows_Management_Deployment_IPackageManager<D>::FindPackage(param::hstring const& packageFullName) const
{
    Windows::ApplicationModel::Package packageInformation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager)->FindPackageByPackageFullName(get_abi(packageFullName), put_abi(packageInformation)));
    return packageInformation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> consume_Windows_Management_Deployment_IPackageManager<D>::CleanupPackageForUserAsync(param::hstring const& packageName, param::hstring const& userSecurityId) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> deploymentOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager)->CleanupPackageForUserAsync(get_abi(packageName), get_abi(userSecurityId), put_abi(deploymentOperation)));
    return deploymentOperation;
}

template <typename D> Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> consume_Windows_Management_Deployment_IPackageManager<D>::FindPackages(param::hstring const& packageFamilyName) const
{
    Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> packageCollection{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager)->FindPackagesByPackageFamilyName(get_abi(packageFamilyName), put_abi(packageCollection)));
    return packageCollection;
}

template <typename D> Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> consume_Windows_Management_Deployment_IPackageManager<D>::FindPackagesForUser(param::hstring const& userSecurityId, param::hstring const& packageFamilyName) const
{
    Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> packageCollection{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager)->FindPackagesByUserSecurityIdPackageFamilyName(get_abi(userSecurityId), get_abi(packageFamilyName), put_abi(packageCollection)));
    return packageCollection;
}

template <typename D> Windows::ApplicationModel::Package consume_Windows_Management_Deployment_IPackageManager<D>::FindPackageForUser(param::hstring const& userSecurityId, param::hstring const& packageFullName) const
{
    Windows::ApplicationModel::Package packageInformation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager)->FindPackageByUserSecurityIdPackageFullName(get_abi(userSecurityId), get_abi(packageFullName), put_abi(packageInformation)));
    return packageInformation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> consume_Windows_Management_Deployment_IPackageManager2<D>::RemovePackageAsync(param::hstring const& packageFullName, Windows::Management::Deployment::RemovalOptions const& removalOptions) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> deploymentOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager2)->RemovePackageWithOptionsAsync(get_abi(packageFullName), get_abi(removalOptions), put_abi(deploymentOperation)));
    return deploymentOperation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> consume_Windows_Management_Deployment_IPackageManager2<D>::StagePackageAsync(Windows::Foundation::Uri const& packageUri, param::async_iterable<Windows::Foundation::Uri> const& dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions const& deploymentOptions) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> deploymentOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager2)->StagePackageWithOptionsAsync(get_abi(packageUri), get_abi(dependencyPackageUris), get_abi(deploymentOptions), put_abi(deploymentOperation)));
    return deploymentOperation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> consume_Windows_Management_Deployment_IPackageManager2<D>::RegisterPackageByFullNameAsync(param::hstring const& mainPackageFullName, param::async_iterable<hstring> const& dependencyPackageFullNames, Windows::Management::Deployment::DeploymentOptions const& deploymentOptions) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> deploymentOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager2)->RegisterPackageByFullNameAsync(get_abi(mainPackageFullName), get_abi(dependencyPackageFullNames), get_abi(deploymentOptions), put_abi(deploymentOperation)));
    return deploymentOperation;
}

template <typename D> Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> consume_Windows_Management_Deployment_IPackageManager2<D>::FindPackagesWithPackageTypes(Windows::Management::Deployment::PackageTypes const& packageTypes) const
{
    Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> packageCollection{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager2)->FindPackagesWithPackageTypes(get_abi(packageTypes), put_abi(packageCollection)));
    return packageCollection;
}

template <typename D> Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> consume_Windows_Management_Deployment_IPackageManager2<D>::FindPackagesForUserWithPackageTypes(param::hstring const& userSecurityId, Windows::Management::Deployment::PackageTypes const& packageTypes) const
{
    Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> packageCollection{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager2)->FindPackagesByUserSecurityIdWithPackageTypes(get_abi(userSecurityId), get_abi(packageTypes), put_abi(packageCollection)));
    return packageCollection;
}

template <typename D> Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> consume_Windows_Management_Deployment_IPackageManager2<D>::FindPackagesWithPackageTypes(param::hstring const& packageName, param::hstring const& packagePublisher, Windows::Management::Deployment::PackageTypes const& packageTypes) const
{
    Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> packageCollection{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager2)->FindPackagesByNamePublisherWithPackageTypes(get_abi(packageName), get_abi(packagePublisher), get_abi(packageTypes), put_abi(packageCollection)));
    return packageCollection;
}

template <typename D> Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> consume_Windows_Management_Deployment_IPackageManager2<D>::FindPackagesForUserWithPackageTypes(param::hstring const& userSecurityId, param::hstring const& packageName, param::hstring const& packagePublisher, Windows::Management::Deployment::PackageTypes const& packageTypes) const
{
    Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> packageCollection{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager2)->FindPackagesByUserSecurityIdNamePublisherWithPackageTypes(get_abi(userSecurityId), get_abi(packageName), get_abi(packagePublisher), get_abi(packageTypes), put_abi(packageCollection)));
    return packageCollection;
}

template <typename D> Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> consume_Windows_Management_Deployment_IPackageManager2<D>::FindPackagesWithPackageTypes(param::hstring const& packageFamilyName, Windows::Management::Deployment::PackageTypes const& packageTypes) const
{
    Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> packageCollection{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager2)->FindPackagesByPackageFamilyNameWithPackageTypes(get_abi(packageFamilyName), get_abi(packageTypes), put_abi(packageCollection)));
    return packageCollection;
}

template <typename D> Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> consume_Windows_Management_Deployment_IPackageManager2<D>::FindPackagesForUserWithPackageTypes(param::hstring const& userSecurityId, param::hstring const& packageFamilyName, Windows::Management::Deployment::PackageTypes const& packageTypes) const
{
    Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> packageCollection{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager2)->FindPackagesByUserSecurityIdPackageFamilyNameWithPackageTypes(get_abi(userSecurityId), get_abi(packageFamilyName), get_abi(packageTypes), put_abi(packageCollection)));
    return packageCollection;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> consume_Windows_Management_Deployment_IPackageManager2<D>::StageUserDataAsync(param::hstring const& packageFullName) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> deploymentOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager2)->StageUserDataAsync(get_abi(packageFullName), put_abi(deploymentOperation)));
    return deploymentOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Management::Deployment::PackageVolume> consume_Windows_Management_Deployment_IPackageManager3<D>::AddPackageVolumeAsync(param::hstring const& packageStorePath) const
{
    Windows::Foundation::IAsyncOperation<Windows::Management::Deployment::PackageVolume> packageVolume{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager3)->AddPackageVolumeAsync(get_abi(packageStorePath), put_abi(packageVolume)));
    return packageVolume;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> consume_Windows_Management_Deployment_IPackageManager3<D>::AddPackageAsync(Windows::Foundation::Uri const& packageUri, param::async_iterable<Windows::Foundation::Uri> const& dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions const& deploymentOptions, Windows::Management::Deployment::PackageVolume const& targetVolume) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> deploymentOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager3)->AddPackageToVolumeAsync(get_abi(packageUri), get_abi(dependencyPackageUris), get_abi(deploymentOptions), get_abi(targetVolume), put_abi(deploymentOperation)));
    return deploymentOperation;
}

template <typename D> void consume_Windows_Management_Deployment_IPackageManager3<D>::ClearPackageStatus(param::hstring const& packageFullName, Windows::Management::Deployment::PackageStatus const& status) const
{
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager3)->ClearPackageStatus(get_abi(packageFullName), get_abi(status)));
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> consume_Windows_Management_Deployment_IPackageManager3<D>::RegisterPackageAsync(Windows::Foundation::Uri const& manifestUri, param::async_iterable<Windows::Foundation::Uri> const& dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions const& deploymentOptions, Windows::Management::Deployment::PackageVolume const& appDataVolume) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> deploymentOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager3)->RegisterPackageWithAppDataVolumeAsync(get_abi(manifestUri), get_abi(dependencyPackageUris), get_abi(deploymentOptions), get_abi(appDataVolume), put_abi(deploymentOperation)));
    return deploymentOperation;
}

template <typename D> Windows::Management::Deployment::PackageVolume consume_Windows_Management_Deployment_IPackageManager3<D>::FindPackageVolume(param::hstring const& volumeName) const
{
    Windows::Management::Deployment::PackageVolume volume{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager3)->FindPackageVolumeByName(get_abi(volumeName), put_abi(volume)));
    return volume;
}

template <typename D> Windows::Foundation::Collections::IIterable<Windows::Management::Deployment::PackageVolume> consume_Windows_Management_Deployment_IPackageManager3<D>::FindPackageVolumes() const
{
    Windows::Foundation::Collections::IIterable<Windows::Management::Deployment::PackageVolume> volumeCollection{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager3)->FindPackageVolumes(put_abi(volumeCollection)));
    return volumeCollection;
}

template <typename D> Windows::Management::Deployment::PackageVolume consume_Windows_Management_Deployment_IPackageManager3<D>::GetDefaultPackageVolume() const
{
    Windows::Management::Deployment::PackageVolume volume{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager3)->GetDefaultPackageVolume(put_abi(volume)));
    return volume;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> consume_Windows_Management_Deployment_IPackageManager3<D>::MovePackageToVolumeAsync(param::hstring const& packageFullName, Windows::Management::Deployment::DeploymentOptions const& deploymentOptions, Windows::Management::Deployment::PackageVolume const& targetVolume) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> deploymentOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager3)->MovePackageToVolumeAsync(get_abi(packageFullName), get_abi(deploymentOptions), get_abi(targetVolume), put_abi(deploymentOperation)));
    return deploymentOperation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> consume_Windows_Management_Deployment_IPackageManager3<D>::RemovePackageVolumeAsync(Windows::Management::Deployment::PackageVolume const& volume) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> deploymentOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager3)->RemovePackageVolumeAsync(get_abi(volume), put_abi(deploymentOperation)));
    return deploymentOperation;
}

template <typename D> void consume_Windows_Management_Deployment_IPackageManager3<D>::SetDefaultPackageVolume(Windows::Management::Deployment::PackageVolume const& volume) const
{
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager3)->SetDefaultPackageVolume(get_abi(volume)));
}

template <typename D> void consume_Windows_Management_Deployment_IPackageManager3<D>::SetPackageStatus(param::hstring const& packageFullName, Windows::Management::Deployment::PackageStatus const& status) const
{
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager3)->SetPackageStatus(get_abi(packageFullName), get_abi(status)));
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> consume_Windows_Management_Deployment_IPackageManager3<D>::SetPackageVolumeOfflineAsync(Windows::Management::Deployment::PackageVolume const& packageVolume) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> deploymentOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager3)->SetPackageVolumeOfflineAsync(get_abi(packageVolume), put_abi(deploymentOperation)));
    return deploymentOperation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> consume_Windows_Management_Deployment_IPackageManager3<D>::SetPackageVolumeOnlineAsync(Windows::Management::Deployment::PackageVolume const& packageVolume) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> deploymentOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager3)->SetPackageVolumeOnlineAsync(get_abi(packageVolume), put_abi(deploymentOperation)));
    return deploymentOperation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> consume_Windows_Management_Deployment_IPackageManager3<D>::StagePackageAsync(Windows::Foundation::Uri const& packageUri, param::async_iterable<Windows::Foundation::Uri> const& dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions const& deploymentOptions, Windows::Management::Deployment::PackageVolume const& targetVolume) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> deploymentOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager3)->StagePackageToVolumeAsync(get_abi(packageUri), get_abi(dependencyPackageUris), get_abi(deploymentOptions), get_abi(targetVolume), put_abi(deploymentOperation)));
    return deploymentOperation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> consume_Windows_Management_Deployment_IPackageManager3<D>::StageUserDataAsync(param::hstring const& packageFullName, Windows::Management::Deployment::DeploymentOptions const& deploymentOptions) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> deploymentOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager3)->StageUserDataWithOptionsAsync(get_abi(packageFullName), get_abi(deploymentOptions), put_abi(deploymentOperation)));
    return deploymentOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Management::Deployment::PackageVolume>> consume_Windows_Management_Deployment_IPackageManager4<D>::GetPackageVolumesAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Management::Deployment::PackageVolume>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager4)->GetPackageVolumesAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> consume_Windows_Management_Deployment_IPackageManager5<D>::AddPackageAsync(Windows::Foundation::Uri const& packageUri, param::async_iterable<Windows::Foundation::Uri> const& dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions const& deploymentOptions, Windows::Management::Deployment::PackageVolume const& targetVolume, param::async_iterable<hstring> const& optionalPackageFamilyNames, param::async_iterable<Windows::Foundation::Uri> const& externalPackageUris) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> deploymentOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager5)->AddPackageToVolumeAndOptionalPackagesAsync(get_abi(packageUri), get_abi(dependencyPackageUris), get_abi(deploymentOptions), get_abi(targetVolume), get_abi(optionalPackageFamilyNames), get_abi(externalPackageUris), put_abi(deploymentOperation)));
    return deploymentOperation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> consume_Windows_Management_Deployment_IPackageManager5<D>::StagePackageAsync(Windows::Foundation::Uri const& packageUri, param::async_iterable<Windows::Foundation::Uri> const& dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions const& deploymentOptions, Windows::Management::Deployment::PackageVolume const& targetVolume, param::async_iterable<hstring> const& optionalPackageFamilyNames, param::async_iterable<Windows::Foundation::Uri> const& externalPackageUris) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> deploymentOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager5)->StagePackageToVolumeAndOptionalPackagesAsync(get_abi(packageUri), get_abi(dependencyPackageUris), get_abi(deploymentOptions), get_abi(targetVolume), get_abi(optionalPackageFamilyNames), get_abi(externalPackageUris), put_abi(deploymentOperation)));
    return deploymentOperation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> consume_Windows_Management_Deployment_IPackageManager5<D>::RegisterPackageByFamilyNameAsync(param::hstring const& mainPackageFamilyName, param::async_iterable<hstring> const& dependencyPackageFamilyNames, Windows::Management::Deployment::DeploymentOptions const& deploymentOptions, Windows::Management::Deployment::PackageVolume const& appDataVolume, param::async_iterable<hstring> const& optionalPackageFamilyNames) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> deploymentOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager5)->RegisterPackageByFamilyNameAndOptionalPackagesAsync(get_abi(mainPackageFamilyName), get_abi(dependencyPackageFamilyNames), get_abi(deploymentOptions), get_abi(appDataVolume), get_abi(optionalPackageFamilyNames), put_abi(deploymentOperation)));
    return deploymentOperation;
}

template <typename D> Windows::Management::Deployment::PackageManagerDebugSettings consume_Windows_Management_Deployment_IPackageManager5<D>::DebugSettings() const
{
    Windows::Management::Deployment::PackageManagerDebugSettings value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager5)->get_DebugSettings(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> consume_Windows_Management_Deployment_IPackageManager6<D>::ProvisionPackageForAllUsersAsync(param::hstring const& packageFamilyName) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager6)->ProvisionPackageForAllUsersAsync(get_abi(packageFamilyName), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> consume_Windows_Management_Deployment_IPackageManager6<D>::AddPackageByAppInstallerFileAsync(Windows::Foundation::Uri const& appInstallerFileUri, Windows::Management::Deployment::AddPackageByAppInstallerOptions const& options, Windows::Management::Deployment::PackageVolume const& targetVolume) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager6)->AddPackageByAppInstallerFileAsync(get_abi(appInstallerFileUri), get_abi(options), get_abi(targetVolume), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> consume_Windows_Management_Deployment_IPackageManager6<D>::RequestAddPackageByAppInstallerFileAsync(Windows::Foundation::Uri const& appInstallerFileUri, Windows::Management::Deployment::AddPackageByAppInstallerOptions const& options, Windows::Management::Deployment::PackageVolume const& targetVolume) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager6)->RequestAddPackageByAppInstallerFileAsync(get_abi(appInstallerFileUri), get_abi(options), get_abi(targetVolume), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> consume_Windows_Management_Deployment_IPackageManager6<D>::AddPackageAsync(Windows::Foundation::Uri const& packageUri, param::async_iterable<Windows::Foundation::Uri> const& dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions const& options, Windows::Management::Deployment::PackageVolume const& targetVolume, param::async_iterable<hstring> const& optionalPackageFamilyNames, param::async_iterable<Windows::Foundation::Uri> const& packageUrisToInstall, param::async_iterable<Windows::Foundation::Uri> const& relatedPackageUris) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager6)->AddPackageToVolumeAndRelatedSetAsync(get_abi(packageUri), get_abi(dependencyPackageUris), get_abi(options), get_abi(targetVolume), get_abi(optionalPackageFamilyNames), get_abi(packageUrisToInstall), get_abi(relatedPackageUris), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> consume_Windows_Management_Deployment_IPackageManager6<D>::StagePackageAsync(Windows::Foundation::Uri const& packageUri, param::async_iterable<Windows::Foundation::Uri> const& dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions const& options, Windows::Management::Deployment::PackageVolume const& targetVolume, param::async_iterable<hstring> const& optionalPackageFamilyNames, param::async_iterable<Windows::Foundation::Uri> const& packageUrisToInstall, param::async_iterable<Windows::Foundation::Uri> const& relatedPackageUris) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager6)->StagePackageToVolumeAndRelatedSetAsync(get_abi(packageUri), get_abi(dependencyPackageUris), get_abi(options), get_abi(targetVolume), get_abi(optionalPackageFamilyNames), get_abi(packageUrisToInstall), get_abi(relatedPackageUris), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> consume_Windows_Management_Deployment_IPackageManager6<D>::RequestAddPackageAsync(Windows::Foundation::Uri const& packageUri, param::async_iterable<Windows::Foundation::Uri> const& dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions const& deploymentOptions, Windows::Management::Deployment::PackageVolume const& targetVolume, param::async_iterable<hstring> const& optionalPackageFamilyNames, param::async_iterable<Windows::Foundation::Uri> const& relatedPackageUris) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager6)->RequestAddPackageAsync(get_abi(packageUri), get_abi(dependencyPackageUris), get_abi(deploymentOptions), get_abi(targetVolume), get_abi(optionalPackageFamilyNames), get_abi(relatedPackageUris), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> consume_Windows_Management_Deployment_IPackageManager7<D>::RequestAddPackageAsync(Windows::Foundation::Uri const& packageUri, param::async_iterable<Windows::Foundation::Uri> const& dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions const& deploymentOptions, Windows::Management::Deployment::PackageVolume const& targetVolume, param::async_iterable<hstring> const& optionalPackageFamilyNames, param::async_iterable<Windows::Foundation::Uri> const& relatedPackageUris, param::async_iterable<Windows::Foundation::Uri> const& packageUrisToInstall) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager7)->RequestAddPackageAndRelatedSetAsync(get_abi(packageUri), get_abi(dependencyPackageUris), get_abi(deploymentOptions), get_abi(targetVolume), get_abi(optionalPackageFamilyNames), get_abi(relatedPackageUris), get_abi(packageUrisToInstall), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> consume_Windows_Management_Deployment_IPackageManager8<D>::DeprovisionPackageForAllUsersAsync(param::hstring const& packageFamilyName) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManager8)->DeprovisionPackageForAllUsersAsync(get_abi(packageFamilyName), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Management_Deployment_IPackageManagerDebugSettings<D>::SetContentGroupStateAsync(Windows::ApplicationModel::Package const& package, param::hstring const& contentGroupName, Windows::ApplicationModel::PackageContentGroupState const& state) const
{
    Windows::Foundation::IAsyncAction action{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManagerDebugSettings)->SetContentGroupStateAsync(get_abi(package), get_abi(contentGroupName), get_abi(state), put_abi(action)));
    return action;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Management_Deployment_IPackageManagerDebugSettings<D>::SetContentGroupStateAsync(Windows::ApplicationModel::Package const& package, param::hstring const& contentGroupName, Windows::ApplicationModel::PackageContentGroupState const& state, double completionPercentage) const
{
    Windows::Foundation::IAsyncAction action{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageManagerDebugSettings)->SetContentGroupStateWithPercentageAsync(get_abi(package), get_abi(contentGroupName), get_abi(state), completionPercentage, put_abi(action)));
    return action;
}

template <typename D> hstring consume_Windows_Management_Deployment_IPackageUserInformation<D>::UserSecurityId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageUserInformation)->get_UserSecurityId(put_abi(value)));
    return value;
}

template <typename D> Windows::Management::Deployment::PackageInstallState consume_Windows_Management_Deployment_IPackageUserInformation<D>::InstallState() const
{
    Windows::Management::Deployment::PackageInstallState value{};
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageUserInformation)->get_InstallState(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Management_Deployment_IPackageVolume<D>::IsOffline() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageVolume)->get_IsOffline(&value));
    return value;
}

template <typename D> bool consume_Windows_Management_Deployment_IPackageVolume<D>::IsSystemVolume() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageVolume)->get_IsSystemVolume(&value));
    return value;
}

template <typename D> hstring consume_Windows_Management_Deployment_IPackageVolume<D>::MountPoint() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageVolume)->get_MountPoint(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Management_Deployment_IPackageVolume<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageVolume)->get_Name(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Management_Deployment_IPackageVolume<D>::PackageStorePath() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageVolume)->get_PackageStorePath(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Management_Deployment_IPackageVolume<D>::SupportsHardLinks() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageVolume)->get_SupportsHardLinks(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> consume_Windows_Management_Deployment_IPackageVolume<D>::FindPackages() const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> packageCollection{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageVolume)->FindPackages(put_abi(packageCollection)));
    return packageCollection;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> consume_Windows_Management_Deployment_IPackageVolume<D>::FindPackages(param::hstring const& packageName, param::hstring const& packagePublisher) const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> packageCollection{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageVolume)->FindPackagesByNamePublisher(get_abi(packageName), get_abi(packagePublisher), put_abi(packageCollection)));
    return packageCollection;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> consume_Windows_Management_Deployment_IPackageVolume<D>::FindPackages(param::hstring const& packageFamilyName) const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> packageCollection{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageVolume)->FindPackagesByPackageFamilyName(get_abi(packageFamilyName), put_abi(packageCollection)));
    return packageCollection;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> consume_Windows_Management_Deployment_IPackageVolume<D>::FindPackagesWithPackageTypes(Windows::Management::Deployment::PackageTypes const& packageTypes) const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> packageCollection{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageVolume)->FindPackagesWithPackageTypes(get_abi(packageTypes), put_abi(packageCollection)));
    return packageCollection;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> consume_Windows_Management_Deployment_IPackageVolume<D>::FindPackagesWithPackageTypes(Windows::Management::Deployment::PackageTypes const& packageTypes, param::hstring const& packageName, param::hstring const& packagePublisher) const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> packageCollection{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageVolume)->FindPackagesByNamePublisherWithPackagesTypes(get_abi(packageTypes), get_abi(packageName), get_abi(packagePublisher), put_abi(packageCollection)));
    return packageCollection;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> consume_Windows_Management_Deployment_IPackageVolume<D>::FindPackagesWithPackageTypes(Windows::Management::Deployment::PackageTypes const& packageTypes, param::hstring const& packageFamilyName) const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> packageCollection{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageVolume)->FindPackagesByPackageFamilyNameWithPackageTypes(get_abi(packageTypes), get_abi(packageFamilyName), put_abi(packageCollection)));
    return packageCollection;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> consume_Windows_Management_Deployment_IPackageVolume<D>::FindPackage(param::hstring const& packageFullName) const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> packageCollection{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageVolume)->FindPackageByPackageFullName(get_abi(packageFullName), put_abi(packageCollection)));
    return packageCollection;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> consume_Windows_Management_Deployment_IPackageVolume<D>::FindPackagesForUser(param::hstring const& userSecurityId) const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> packageCollection{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageVolume)->FindPackagesByUserSecurityId(get_abi(userSecurityId), put_abi(packageCollection)));
    return packageCollection;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> consume_Windows_Management_Deployment_IPackageVolume<D>::FindPackagesForUser(param::hstring const& userSecurityId, param::hstring const& packageName, param::hstring const& packagePublisher) const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> packageCollection{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageVolume)->FindPackagesByUserSecurityIdNamePublisher(get_abi(userSecurityId), get_abi(packageName), get_abi(packagePublisher), put_abi(packageCollection)));
    return packageCollection;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> consume_Windows_Management_Deployment_IPackageVolume<D>::FindPackagesForUser(param::hstring const& userSecurityId, param::hstring const& packageFamilyName) const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> packageCollection{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageVolume)->FindPackagesByUserSecurityIdPackageFamilyName(get_abi(userSecurityId), get_abi(packageFamilyName), put_abi(packageCollection)));
    return packageCollection;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> consume_Windows_Management_Deployment_IPackageVolume<D>::FindPackagesForUserWithPackageTypes(param::hstring const& userSecurityId, Windows::Management::Deployment::PackageTypes const& packageTypes) const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> packageCollection{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageVolume)->FindPackagesByUserSecurityIdWithPackageTypes(get_abi(userSecurityId), get_abi(packageTypes), put_abi(packageCollection)));
    return packageCollection;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> consume_Windows_Management_Deployment_IPackageVolume<D>::FindPackagesForUserWithPackageTypes(param::hstring const& userSecurityId, Windows::Management::Deployment::PackageTypes const& packageTypes, param::hstring const& packageName, param::hstring const& packagePublisher) const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> packageCollection{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageVolume)->FindPackagesByUserSecurityIdNamePublisherWithPackageTypes(get_abi(userSecurityId), get_abi(packageTypes), get_abi(packageName), get_abi(packagePublisher), put_abi(packageCollection)));
    return packageCollection;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> consume_Windows_Management_Deployment_IPackageVolume<D>::FindPackagesForUserWithPackageTypes(param::hstring const& userSecurityId, Windows::Management::Deployment::PackageTypes const& packageTypes, param::hstring const& packageFamilyName) const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> packageCollection{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageVolume)->FindPackagesByUserSecurityIdPackageFamilyNameWithPackagesTypes(get_abi(userSecurityId), get_abi(packageTypes), get_abi(packageFamilyName), put_abi(packageCollection)));
    return packageCollection;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> consume_Windows_Management_Deployment_IPackageVolume<D>::FindPackageForUser(param::hstring const& userSecurityId, param::hstring const& packageFullName) const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> packageCollection{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageVolume)->FindPackageByUserSecurityIdPackageFullName(get_abi(userSecurityId), get_abi(packageFullName), put_abi(packageCollection)));
    return packageCollection;
}

template <typename D> bool consume_Windows_Management_Deployment_IPackageVolume2<D>::IsFullTrustPackageSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageVolume2)->get_IsFullTrustPackageSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Management_Deployment_IPackageVolume2<D>::IsAppxInstallSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageVolume2)->get_IsAppxInstallSupported(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<uint64_t> consume_Windows_Management_Deployment_IPackageVolume2<D>::GetAvailableSpaceAsync() const
{
    Windows::Foundation::IAsyncOperation<uint64_t> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::IPackageVolume2)->GetAvailableSpaceAsync(put_abi(operation)));
    return operation;
}

template <typename D>
struct produce<D, Windows::Management::Deployment::IDeploymentResult> : produce_base<D, Windows::Management::Deployment::IDeploymentResult>
{
    int32_t WINRT_CALL get_ErrorText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ErrorText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ErrorText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL get_ExtendedErrorCode(winrt::hresult* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedErrorCode, WINRT_WRAP(winrt::hresult));
            *value = detach_from<winrt::hresult>(this->shim().ExtendedErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Management::Deployment::IDeploymentResult2> : produce_base<D, Windows::Management::Deployment::IDeploymentResult2>
{
    int32_t WINRT_CALL get_IsRegistered(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRegistered, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsRegistered());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Management::Deployment::IPackageManager> : produce_base<D, Windows::Management::Deployment::IPackageManager>
{
    int32_t WINRT_CALL AddPackageAsync(void* packageUri, void* dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions deploymentOptions, void** deploymentOperation) noexcept final
    {
        try
        {
            *deploymentOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddPackageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>), Windows::Foundation::Uri const, Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const, Windows::Management::Deployment::DeploymentOptions const);
            *deploymentOperation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>>(this->shim().AddPackageAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&packageUri), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const*>(&dependencyPackageUris), *reinterpret_cast<Windows::Management::Deployment::DeploymentOptions const*>(&deploymentOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdatePackageAsync(void* packageUri, void* dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions deploymentOptions, void** deploymentOperation) noexcept final
    {
        try
        {
            *deploymentOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdatePackageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>), Windows::Foundation::Uri const, Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const, Windows::Management::Deployment::DeploymentOptions const);
            *deploymentOperation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>>(this->shim().UpdatePackageAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&packageUri), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const*>(&dependencyPackageUris), *reinterpret_cast<Windows::Management::Deployment::DeploymentOptions const*>(&deploymentOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemovePackageAsync(void* packageFullName, void** deploymentOperation) noexcept final
    {
        try
        {
            *deploymentOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemovePackageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>), hstring const);
            *deploymentOperation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>>(this->shim().RemovePackageAsync(*reinterpret_cast<hstring const*>(&packageFullName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StagePackageAsync(void* packageUri, void* dependencyPackageUris, void** deploymentOperation) noexcept final
    {
        try
        {
            *deploymentOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StagePackageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>), Windows::Foundation::Uri const, Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const);
            *deploymentOperation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>>(this->shim().StagePackageAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&packageUri), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const*>(&dependencyPackageUris)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RegisterPackageAsync(void* manifestUri, void* dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions deploymentOptions, void** deploymentOperation) noexcept final
    {
        try
        {
            *deploymentOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterPackageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>), Windows::Foundation::Uri const, Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const, Windows::Management::Deployment::DeploymentOptions const);
            *deploymentOperation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>>(this->shim().RegisterPackageAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&manifestUri), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const*>(&dependencyPackageUris), *reinterpret_cast<Windows::Management::Deployment::DeploymentOptions const*>(&deploymentOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindPackages(void** packageCollection) noexcept final
    {
        try
        {
            *packageCollection = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindPackages, WINRT_WRAP(Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package>));
            *packageCollection = detach_from<Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package>>(this->shim().FindPackages());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindPackagesByUserSecurityId(void* userSecurityId, void** packageCollection) noexcept final
    {
        try
        {
            *packageCollection = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindPackagesForUser, WINRT_WRAP(Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package>), hstring const&);
            *packageCollection = detach_from<Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package>>(this->shim().FindPackagesForUser(*reinterpret_cast<hstring const*>(&userSecurityId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindPackagesByNamePublisher(void* packageName, void* packagePublisher, void** packageCollection) noexcept final
    {
        try
        {
            *packageCollection = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindPackages, WINRT_WRAP(Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package>), hstring const&, hstring const&);
            *packageCollection = detach_from<Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package>>(this->shim().FindPackages(*reinterpret_cast<hstring const*>(&packageName), *reinterpret_cast<hstring const*>(&packagePublisher)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindPackagesByUserSecurityIdNamePublisher(void* userSecurityId, void* packageName, void* packagePublisher, void** packageCollection) noexcept final
    {
        try
        {
            *packageCollection = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindPackagesForUser, WINRT_WRAP(Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package>), hstring const&, hstring const&, hstring const&);
            *packageCollection = detach_from<Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package>>(this->shim().FindPackagesForUser(*reinterpret_cast<hstring const*>(&userSecurityId), *reinterpret_cast<hstring const*>(&packageName), *reinterpret_cast<hstring const*>(&packagePublisher)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindUsers(void* packageFullName, void** users) noexcept final
    {
        try
        {
            *users = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindUsers, WINRT_WRAP(Windows::Foundation::Collections::IIterable<Windows::Management::Deployment::PackageUserInformation>), hstring const&);
            *users = detach_from<Windows::Foundation::Collections::IIterable<Windows::Management::Deployment::PackageUserInformation>>(this->shim().FindUsers(*reinterpret_cast<hstring const*>(&packageFullName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPackageState(void* packageFullName, Windows::Management::Deployment::PackageState packageState) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPackageState, WINRT_WRAP(void), hstring const&, Windows::Management::Deployment::PackageState const&);
            this->shim().SetPackageState(*reinterpret_cast<hstring const*>(&packageFullName), *reinterpret_cast<Windows::Management::Deployment::PackageState const*>(&packageState));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindPackageByPackageFullName(void* packageFullName, void** packageInformation) noexcept final
    {
        try
        {
            *packageInformation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindPackage, WINRT_WRAP(Windows::ApplicationModel::Package), hstring const&);
            *packageInformation = detach_from<Windows::ApplicationModel::Package>(this->shim().FindPackage(*reinterpret_cast<hstring const*>(&packageFullName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CleanupPackageForUserAsync(void* packageName, void* userSecurityId, void** deploymentOperation) noexcept final
    {
        try
        {
            *deploymentOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CleanupPackageForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>), hstring const, hstring const);
            *deploymentOperation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>>(this->shim().CleanupPackageForUserAsync(*reinterpret_cast<hstring const*>(&packageName), *reinterpret_cast<hstring const*>(&userSecurityId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindPackagesByPackageFamilyName(void* packageFamilyName, void** packageCollection) noexcept final
    {
        try
        {
            *packageCollection = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindPackages, WINRT_WRAP(Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package>), hstring const&);
            *packageCollection = detach_from<Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package>>(this->shim().FindPackages(*reinterpret_cast<hstring const*>(&packageFamilyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindPackagesByUserSecurityIdPackageFamilyName(void* userSecurityId, void* packageFamilyName, void** packageCollection) noexcept final
    {
        try
        {
            *packageCollection = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindPackagesForUser, WINRT_WRAP(Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package>), hstring const&, hstring const&);
            *packageCollection = detach_from<Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package>>(this->shim().FindPackagesForUser(*reinterpret_cast<hstring const*>(&userSecurityId), *reinterpret_cast<hstring const*>(&packageFamilyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindPackageByUserSecurityIdPackageFullName(void* userSecurityId, void* packageFullName, void** packageInformation) noexcept final
    {
        try
        {
            *packageInformation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindPackageForUser, WINRT_WRAP(Windows::ApplicationModel::Package), hstring const&, hstring const&);
            *packageInformation = detach_from<Windows::ApplicationModel::Package>(this->shim().FindPackageForUser(*reinterpret_cast<hstring const*>(&userSecurityId), *reinterpret_cast<hstring const*>(&packageFullName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Management::Deployment::IPackageManager2> : produce_base<D, Windows::Management::Deployment::IPackageManager2>
{
    int32_t WINRT_CALL RemovePackageWithOptionsAsync(void* packageFullName, Windows::Management::Deployment::RemovalOptions removalOptions, void** deploymentOperation) noexcept final
    {
        try
        {
            *deploymentOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemovePackageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>), hstring const, Windows::Management::Deployment::RemovalOptions const);
            *deploymentOperation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>>(this->shim().RemovePackageAsync(*reinterpret_cast<hstring const*>(&packageFullName), *reinterpret_cast<Windows::Management::Deployment::RemovalOptions const*>(&removalOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StagePackageWithOptionsAsync(void* packageUri, void* dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions deploymentOptions, void** deploymentOperation) noexcept final
    {
        try
        {
            *deploymentOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StagePackageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>), Windows::Foundation::Uri const, Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const, Windows::Management::Deployment::DeploymentOptions const);
            *deploymentOperation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>>(this->shim().StagePackageAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&packageUri), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const*>(&dependencyPackageUris), *reinterpret_cast<Windows::Management::Deployment::DeploymentOptions const*>(&deploymentOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RegisterPackageByFullNameAsync(void* mainPackageFullName, void* dependencyPackageFullNames, Windows::Management::Deployment::DeploymentOptions deploymentOptions, void** deploymentOperation) noexcept final
    {
        try
        {
            *deploymentOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterPackageByFullNameAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>), hstring const, Windows::Foundation::Collections::IIterable<hstring> const, Windows::Management::Deployment::DeploymentOptions const);
            *deploymentOperation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>>(this->shim().RegisterPackageByFullNameAsync(*reinterpret_cast<hstring const*>(&mainPackageFullName), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&dependencyPackageFullNames), *reinterpret_cast<Windows::Management::Deployment::DeploymentOptions const*>(&deploymentOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindPackagesWithPackageTypes(Windows::Management::Deployment::PackageTypes packageTypes, void** packageCollection) noexcept final
    {
        try
        {
            *packageCollection = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindPackagesWithPackageTypes, WINRT_WRAP(Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package>), Windows::Management::Deployment::PackageTypes const&);
            *packageCollection = detach_from<Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package>>(this->shim().FindPackagesWithPackageTypes(*reinterpret_cast<Windows::Management::Deployment::PackageTypes const*>(&packageTypes)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindPackagesByUserSecurityIdWithPackageTypes(void* userSecurityId, Windows::Management::Deployment::PackageTypes packageTypes, void** packageCollection) noexcept final
    {
        try
        {
            *packageCollection = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindPackagesForUserWithPackageTypes, WINRT_WRAP(Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package>), hstring const&, Windows::Management::Deployment::PackageTypes const&);
            *packageCollection = detach_from<Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package>>(this->shim().FindPackagesForUserWithPackageTypes(*reinterpret_cast<hstring const*>(&userSecurityId), *reinterpret_cast<Windows::Management::Deployment::PackageTypes const*>(&packageTypes)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindPackagesByNamePublisherWithPackageTypes(void* packageName, void* packagePublisher, Windows::Management::Deployment::PackageTypes packageTypes, void** packageCollection) noexcept final
    {
        try
        {
            *packageCollection = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindPackagesWithPackageTypes, WINRT_WRAP(Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package>), hstring const&, hstring const&, Windows::Management::Deployment::PackageTypes const&);
            *packageCollection = detach_from<Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package>>(this->shim().FindPackagesWithPackageTypes(*reinterpret_cast<hstring const*>(&packageName), *reinterpret_cast<hstring const*>(&packagePublisher), *reinterpret_cast<Windows::Management::Deployment::PackageTypes const*>(&packageTypes)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindPackagesByUserSecurityIdNamePublisherWithPackageTypes(void* userSecurityId, void* packageName, void* packagePublisher, Windows::Management::Deployment::PackageTypes packageTypes, void** packageCollection) noexcept final
    {
        try
        {
            *packageCollection = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindPackagesForUserWithPackageTypes, WINRT_WRAP(Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package>), hstring const&, hstring const&, hstring const&, Windows::Management::Deployment::PackageTypes const&);
            *packageCollection = detach_from<Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package>>(this->shim().FindPackagesForUserWithPackageTypes(*reinterpret_cast<hstring const*>(&userSecurityId), *reinterpret_cast<hstring const*>(&packageName), *reinterpret_cast<hstring const*>(&packagePublisher), *reinterpret_cast<Windows::Management::Deployment::PackageTypes const*>(&packageTypes)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindPackagesByPackageFamilyNameWithPackageTypes(void* packageFamilyName, Windows::Management::Deployment::PackageTypes packageTypes, void** packageCollection) noexcept final
    {
        try
        {
            *packageCollection = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindPackagesWithPackageTypes, WINRT_WRAP(Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package>), hstring const&, Windows::Management::Deployment::PackageTypes const&);
            *packageCollection = detach_from<Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package>>(this->shim().FindPackagesWithPackageTypes(*reinterpret_cast<hstring const*>(&packageFamilyName), *reinterpret_cast<Windows::Management::Deployment::PackageTypes const*>(&packageTypes)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindPackagesByUserSecurityIdPackageFamilyNameWithPackageTypes(void* userSecurityId, void* packageFamilyName, Windows::Management::Deployment::PackageTypes packageTypes, void** packageCollection) noexcept final
    {
        try
        {
            *packageCollection = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindPackagesForUserWithPackageTypes, WINRT_WRAP(Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package>), hstring const&, hstring const&, Windows::Management::Deployment::PackageTypes const&);
            *packageCollection = detach_from<Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package>>(this->shim().FindPackagesForUserWithPackageTypes(*reinterpret_cast<hstring const*>(&userSecurityId), *reinterpret_cast<hstring const*>(&packageFamilyName), *reinterpret_cast<Windows::Management::Deployment::PackageTypes const*>(&packageTypes)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StageUserDataAsync(void* packageFullName, void** deploymentOperation) noexcept final
    {
        try
        {
            *deploymentOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StageUserDataAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>), hstring const);
            *deploymentOperation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>>(this->shim().StageUserDataAsync(*reinterpret_cast<hstring const*>(&packageFullName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Management::Deployment::IPackageManager3> : produce_base<D, Windows::Management::Deployment::IPackageManager3>
{
    int32_t WINRT_CALL AddPackageVolumeAsync(void* packageStorePath, void** packageVolume) noexcept final
    {
        try
        {
            *packageVolume = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddPackageVolumeAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Management::Deployment::PackageVolume>), hstring const);
            *packageVolume = detach_from<Windows::Foundation::IAsyncOperation<Windows::Management::Deployment::PackageVolume>>(this->shim().AddPackageVolumeAsync(*reinterpret_cast<hstring const*>(&packageStorePath)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddPackageToVolumeAsync(void* packageUri, void* dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions deploymentOptions, void* targetVolume, void** deploymentOperation) noexcept final
    {
        try
        {
            *deploymentOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddPackageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>), Windows::Foundation::Uri const, Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const, Windows::Management::Deployment::DeploymentOptions const, Windows::Management::Deployment::PackageVolume const);
            *deploymentOperation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>>(this->shim().AddPackageAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&packageUri), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const*>(&dependencyPackageUris), *reinterpret_cast<Windows::Management::Deployment::DeploymentOptions const*>(&deploymentOptions), *reinterpret_cast<Windows::Management::Deployment::PackageVolume const*>(&targetVolume)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClearPackageStatus(void* packageFullName, Windows::Management::Deployment::PackageStatus status) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClearPackageStatus, WINRT_WRAP(void), hstring const&, Windows::Management::Deployment::PackageStatus const&);
            this->shim().ClearPackageStatus(*reinterpret_cast<hstring const*>(&packageFullName), *reinterpret_cast<Windows::Management::Deployment::PackageStatus const*>(&status));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RegisterPackageWithAppDataVolumeAsync(void* manifestUri, void* dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions deploymentOptions, void* appDataVolume, void** deploymentOperation) noexcept final
    {
        try
        {
            *deploymentOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterPackageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>), Windows::Foundation::Uri const, Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const, Windows::Management::Deployment::DeploymentOptions const, Windows::Management::Deployment::PackageVolume const);
            *deploymentOperation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>>(this->shim().RegisterPackageAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&manifestUri), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const*>(&dependencyPackageUris), *reinterpret_cast<Windows::Management::Deployment::DeploymentOptions const*>(&deploymentOptions), *reinterpret_cast<Windows::Management::Deployment::PackageVolume const*>(&appDataVolume)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindPackageVolumeByName(void* volumeName, void** volume) noexcept final
    {
        try
        {
            *volume = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindPackageVolume, WINRT_WRAP(Windows::Management::Deployment::PackageVolume), hstring const&);
            *volume = detach_from<Windows::Management::Deployment::PackageVolume>(this->shim().FindPackageVolume(*reinterpret_cast<hstring const*>(&volumeName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindPackageVolumes(void** volumeCollection) noexcept final
    {
        try
        {
            *volumeCollection = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindPackageVolumes, WINRT_WRAP(Windows::Foundation::Collections::IIterable<Windows::Management::Deployment::PackageVolume>));
            *volumeCollection = detach_from<Windows::Foundation::Collections::IIterable<Windows::Management::Deployment::PackageVolume>>(this->shim().FindPackageVolumes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDefaultPackageVolume(void** volume) noexcept final
    {
        try
        {
            *volume = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefaultPackageVolume, WINRT_WRAP(Windows::Management::Deployment::PackageVolume));
            *volume = detach_from<Windows::Management::Deployment::PackageVolume>(this->shim().GetDefaultPackageVolume());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MovePackageToVolumeAsync(void* packageFullName, Windows::Management::Deployment::DeploymentOptions deploymentOptions, void* targetVolume, void** deploymentOperation) noexcept final
    {
        try
        {
            *deploymentOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MovePackageToVolumeAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>), hstring const, Windows::Management::Deployment::DeploymentOptions const, Windows::Management::Deployment::PackageVolume const);
            *deploymentOperation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>>(this->shim().MovePackageToVolumeAsync(*reinterpret_cast<hstring const*>(&packageFullName), *reinterpret_cast<Windows::Management::Deployment::DeploymentOptions const*>(&deploymentOptions), *reinterpret_cast<Windows::Management::Deployment::PackageVolume const*>(&targetVolume)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemovePackageVolumeAsync(void* volume, void** deploymentOperation) noexcept final
    {
        try
        {
            *deploymentOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemovePackageVolumeAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>), Windows::Management::Deployment::PackageVolume const);
            *deploymentOperation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>>(this->shim().RemovePackageVolumeAsync(*reinterpret_cast<Windows::Management::Deployment::PackageVolume const*>(&volume)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetDefaultPackageVolume(void* volume) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetDefaultPackageVolume, WINRT_WRAP(void), Windows::Management::Deployment::PackageVolume const&);
            this->shim().SetDefaultPackageVolume(*reinterpret_cast<Windows::Management::Deployment::PackageVolume const*>(&volume));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPackageStatus(void* packageFullName, Windows::Management::Deployment::PackageStatus status) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPackageStatus, WINRT_WRAP(void), hstring const&, Windows::Management::Deployment::PackageStatus const&);
            this->shim().SetPackageStatus(*reinterpret_cast<hstring const*>(&packageFullName), *reinterpret_cast<Windows::Management::Deployment::PackageStatus const*>(&status));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPackageVolumeOfflineAsync(void* packageVolume, void** deploymentOperation) noexcept final
    {
        try
        {
            *deploymentOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPackageVolumeOfflineAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>), Windows::Management::Deployment::PackageVolume const);
            *deploymentOperation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>>(this->shim().SetPackageVolumeOfflineAsync(*reinterpret_cast<Windows::Management::Deployment::PackageVolume const*>(&packageVolume)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPackageVolumeOnlineAsync(void* packageVolume, void** deploymentOperation) noexcept final
    {
        try
        {
            *deploymentOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPackageVolumeOnlineAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>), Windows::Management::Deployment::PackageVolume const);
            *deploymentOperation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>>(this->shim().SetPackageVolumeOnlineAsync(*reinterpret_cast<Windows::Management::Deployment::PackageVolume const*>(&packageVolume)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StagePackageToVolumeAsync(void* packageUri, void* dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions deploymentOptions, void* targetVolume, void** deploymentOperation) noexcept final
    {
        try
        {
            *deploymentOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StagePackageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>), Windows::Foundation::Uri const, Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const, Windows::Management::Deployment::DeploymentOptions const, Windows::Management::Deployment::PackageVolume const);
            *deploymentOperation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>>(this->shim().StagePackageAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&packageUri), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const*>(&dependencyPackageUris), *reinterpret_cast<Windows::Management::Deployment::DeploymentOptions const*>(&deploymentOptions), *reinterpret_cast<Windows::Management::Deployment::PackageVolume const*>(&targetVolume)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StageUserDataWithOptionsAsync(void* packageFullName, Windows::Management::Deployment::DeploymentOptions deploymentOptions, void** deploymentOperation) noexcept final
    {
        try
        {
            *deploymentOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StageUserDataAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>), hstring const, Windows::Management::Deployment::DeploymentOptions const);
            *deploymentOperation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>>(this->shim().StageUserDataAsync(*reinterpret_cast<hstring const*>(&packageFullName), *reinterpret_cast<Windows::Management::Deployment::DeploymentOptions const*>(&deploymentOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Management::Deployment::IPackageManager4> : produce_base<D, Windows::Management::Deployment::IPackageManager4>
{
    int32_t WINRT_CALL GetPackageVolumesAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPackageVolumesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Management::Deployment::PackageVolume>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Management::Deployment::PackageVolume>>>(this->shim().GetPackageVolumesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Management::Deployment::IPackageManager5> : produce_base<D, Windows::Management::Deployment::IPackageManager5>
{
    int32_t WINRT_CALL AddPackageToVolumeAndOptionalPackagesAsync(void* packageUri, void* dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions deploymentOptions, void* targetVolume, void* optionalPackageFamilyNames, void* externalPackageUris, void** deploymentOperation) noexcept final
    {
        try
        {
            *deploymentOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddPackageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>), Windows::Foundation::Uri const, Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const, Windows::Management::Deployment::DeploymentOptions const, Windows::Management::Deployment::PackageVolume const, Windows::Foundation::Collections::IIterable<hstring> const, Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const);
            *deploymentOperation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>>(this->shim().AddPackageAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&packageUri), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const*>(&dependencyPackageUris), *reinterpret_cast<Windows::Management::Deployment::DeploymentOptions const*>(&deploymentOptions), *reinterpret_cast<Windows::Management::Deployment::PackageVolume const*>(&targetVolume), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&optionalPackageFamilyNames), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const*>(&externalPackageUris)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StagePackageToVolumeAndOptionalPackagesAsync(void* packageUri, void* dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions deploymentOptions, void* targetVolume, void* optionalPackageFamilyNames, void* externalPackageUris, void** deploymentOperation) noexcept final
    {
        try
        {
            *deploymentOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StagePackageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>), Windows::Foundation::Uri const, Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const, Windows::Management::Deployment::DeploymentOptions const, Windows::Management::Deployment::PackageVolume const, Windows::Foundation::Collections::IIterable<hstring> const, Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const);
            *deploymentOperation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>>(this->shim().StagePackageAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&packageUri), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const*>(&dependencyPackageUris), *reinterpret_cast<Windows::Management::Deployment::DeploymentOptions const*>(&deploymentOptions), *reinterpret_cast<Windows::Management::Deployment::PackageVolume const*>(&targetVolume), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&optionalPackageFamilyNames), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const*>(&externalPackageUris)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RegisterPackageByFamilyNameAndOptionalPackagesAsync(void* mainPackageFamilyName, void* dependencyPackageFamilyNames, Windows::Management::Deployment::DeploymentOptions deploymentOptions, void* appDataVolume, void* optionalPackageFamilyNames, void** deploymentOperation) noexcept final
    {
        try
        {
            *deploymentOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterPackageByFamilyNameAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>), hstring const, Windows::Foundation::Collections::IIterable<hstring> const, Windows::Management::Deployment::DeploymentOptions const, Windows::Management::Deployment::PackageVolume const, Windows::Foundation::Collections::IIterable<hstring> const);
            *deploymentOperation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>>(this->shim().RegisterPackageByFamilyNameAsync(*reinterpret_cast<hstring const*>(&mainPackageFamilyName), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&dependencyPackageFamilyNames), *reinterpret_cast<Windows::Management::Deployment::DeploymentOptions const*>(&deploymentOptions), *reinterpret_cast<Windows::Management::Deployment::PackageVolume const*>(&appDataVolume), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&optionalPackageFamilyNames)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DebugSettings(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DebugSettings, WINRT_WRAP(Windows::Management::Deployment::PackageManagerDebugSettings));
            *value = detach_from<Windows::Management::Deployment::PackageManagerDebugSettings>(this->shim().DebugSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Management::Deployment::IPackageManager6> : produce_base<D, Windows::Management::Deployment::IPackageManager6>
{
    int32_t WINRT_CALL ProvisionPackageForAllUsersAsync(void* packageFamilyName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProvisionPackageForAllUsersAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>>(this->shim().ProvisionPackageForAllUsersAsync(*reinterpret_cast<hstring const*>(&packageFamilyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddPackageByAppInstallerFileAsync(void* appInstallerFileUri, Windows::Management::Deployment::AddPackageByAppInstallerOptions options, void* targetVolume, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddPackageByAppInstallerFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>), Windows::Foundation::Uri const, Windows::Management::Deployment::AddPackageByAppInstallerOptions const, Windows::Management::Deployment::PackageVolume const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>>(this->shim().AddPackageByAppInstallerFileAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&appInstallerFileUri), *reinterpret_cast<Windows::Management::Deployment::AddPackageByAppInstallerOptions const*>(&options), *reinterpret_cast<Windows::Management::Deployment::PackageVolume const*>(&targetVolume)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestAddPackageByAppInstallerFileAsync(void* appInstallerFileUri, Windows::Management::Deployment::AddPackageByAppInstallerOptions options, void* targetVolume, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAddPackageByAppInstallerFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>), Windows::Foundation::Uri const, Windows::Management::Deployment::AddPackageByAppInstallerOptions const, Windows::Management::Deployment::PackageVolume const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>>(this->shim().RequestAddPackageByAppInstallerFileAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&appInstallerFileUri), *reinterpret_cast<Windows::Management::Deployment::AddPackageByAppInstallerOptions const*>(&options), *reinterpret_cast<Windows::Management::Deployment::PackageVolume const*>(&targetVolume)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddPackageToVolumeAndRelatedSetAsync(void* packageUri, void* dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions options, void* targetVolume, void* optionalPackageFamilyNames, void* packageUrisToInstall, void* relatedPackageUris, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddPackageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>), Windows::Foundation::Uri const, Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const, Windows::Management::Deployment::DeploymentOptions const, Windows::Management::Deployment::PackageVolume const, Windows::Foundation::Collections::IIterable<hstring> const, Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const, Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>>(this->shim().AddPackageAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&packageUri), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const*>(&dependencyPackageUris), *reinterpret_cast<Windows::Management::Deployment::DeploymentOptions const*>(&options), *reinterpret_cast<Windows::Management::Deployment::PackageVolume const*>(&targetVolume), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&optionalPackageFamilyNames), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const*>(&packageUrisToInstall), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const*>(&relatedPackageUris)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StagePackageToVolumeAndRelatedSetAsync(void* packageUri, void* dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions options, void* targetVolume, void* optionalPackageFamilyNames, void* packageUrisToInstall, void* relatedPackageUris, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StagePackageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>), Windows::Foundation::Uri const, Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const, Windows::Management::Deployment::DeploymentOptions const, Windows::Management::Deployment::PackageVolume const, Windows::Foundation::Collections::IIterable<hstring> const, Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const, Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>>(this->shim().StagePackageAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&packageUri), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const*>(&dependencyPackageUris), *reinterpret_cast<Windows::Management::Deployment::DeploymentOptions const*>(&options), *reinterpret_cast<Windows::Management::Deployment::PackageVolume const*>(&targetVolume), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&optionalPackageFamilyNames), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const*>(&packageUrisToInstall), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const*>(&relatedPackageUris)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestAddPackageAsync(void* packageUri, void* dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions deploymentOptions, void* targetVolume, void* optionalPackageFamilyNames, void* relatedPackageUris, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAddPackageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>), Windows::Foundation::Uri const, Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const, Windows::Management::Deployment::DeploymentOptions const, Windows::Management::Deployment::PackageVolume const, Windows::Foundation::Collections::IIterable<hstring> const, Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>>(this->shim().RequestAddPackageAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&packageUri), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const*>(&dependencyPackageUris), *reinterpret_cast<Windows::Management::Deployment::DeploymentOptions const*>(&deploymentOptions), *reinterpret_cast<Windows::Management::Deployment::PackageVolume const*>(&targetVolume), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&optionalPackageFamilyNames), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const*>(&relatedPackageUris)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Management::Deployment::IPackageManager7> : produce_base<D, Windows::Management::Deployment::IPackageManager7>
{
    int32_t WINRT_CALL RequestAddPackageAndRelatedSetAsync(void* packageUri, void* dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions deploymentOptions, void* targetVolume, void* optionalPackageFamilyNames, void* relatedPackageUris, void* packageUrisToInstall, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAddPackageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>), Windows::Foundation::Uri const, Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const, Windows::Management::Deployment::DeploymentOptions const, Windows::Management::Deployment::PackageVolume const, Windows::Foundation::Collections::IIterable<hstring> const, Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const, Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>>(this->shim().RequestAddPackageAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&packageUri), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const*>(&dependencyPackageUris), *reinterpret_cast<Windows::Management::Deployment::DeploymentOptions const*>(&deploymentOptions), *reinterpret_cast<Windows::Management::Deployment::PackageVolume const*>(&targetVolume), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&optionalPackageFamilyNames), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const*>(&relatedPackageUris), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Uri> const*>(&packageUrisToInstall)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Management::Deployment::IPackageManager8> : produce_base<D, Windows::Management::Deployment::IPackageManager8>
{
    int32_t WINRT_CALL DeprovisionPackageForAllUsersAsync(void* packageFamilyName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeprovisionPackageForAllUsersAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress>>(this->shim().DeprovisionPackageForAllUsersAsync(*reinterpret_cast<hstring const*>(&packageFamilyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Management::Deployment::IPackageManagerDebugSettings> : produce_base<D, Windows::Management::Deployment::IPackageManagerDebugSettings>
{
    int32_t WINRT_CALL SetContentGroupStateAsync(void* package, void* contentGroupName, Windows::ApplicationModel::PackageContentGroupState state, void** action) noexcept final
    {
        try
        {
            *action = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetContentGroupStateAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Package const, hstring const, Windows::ApplicationModel::PackageContentGroupState const);
            *action = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetContentGroupStateAsync(*reinterpret_cast<Windows::ApplicationModel::Package const*>(&package), *reinterpret_cast<hstring const*>(&contentGroupName), *reinterpret_cast<Windows::ApplicationModel::PackageContentGroupState const*>(&state)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetContentGroupStateWithPercentageAsync(void* package, void* contentGroupName, Windows::ApplicationModel::PackageContentGroupState state, double completionPercentage, void** action) noexcept final
    {
        try
        {
            *action = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetContentGroupStateAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Package const, hstring const, Windows::ApplicationModel::PackageContentGroupState const, double);
            *action = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetContentGroupStateAsync(*reinterpret_cast<Windows::ApplicationModel::Package const*>(&package), *reinterpret_cast<hstring const*>(&contentGroupName), *reinterpret_cast<Windows::ApplicationModel::PackageContentGroupState const*>(&state), completionPercentage));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Management::Deployment::IPackageUserInformation> : produce_base<D, Windows::Management::Deployment::IPackageUserInformation>
{
    int32_t WINRT_CALL get_UserSecurityId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserSecurityId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UserSecurityId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InstallState(Windows::Management::Deployment::PackageInstallState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InstallState, WINRT_WRAP(Windows::Management::Deployment::PackageInstallState));
            *value = detach_from<Windows::Management::Deployment::PackageInstallState>(this->shim().InstallState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Management::Deployment::IPackageVolume> : produce_base<D, Windows::Management::Deployment::IPackageVolume>
{
    int32_t WINRT_CALL get_IsOffline(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOffline, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsOffline());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsSystemVolume(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSystemVolume, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSystemVolume());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MountPoint(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MountPoint, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MountPoint());
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

    int32_t WINRT_CALL get_PackageStorePath(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PackageStorePath, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PackageStorePath());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportsHardLinks(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportsHardLinks, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().SupportsHardLinks());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindPackages(void** packageCollection) noexcept final
    {
        try
        {
            *packageCollection = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindPackages, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package>));
            *packageCollection = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package>>(this->shim().FindPackages());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindPackagesByNamePublisher(void* packageName, void* packagePublisher, void** packageCollection) noexcept final
    {
        try
        {
            *packageCollection = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindPackages, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package>), hstring const&, hstring const&);
            *packageCollection = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package>>(this->shim().FindPackages(*reinterpret_cast<hstring const*>(&packageName), *reinterpret_cast<hstring const*>(&packagePublisher)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindPackagesByPackageFamilyName(void* packageFamilyName, void** packageCollection) noexcept final
    {
        try
        {
            *packageCollection = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindPackages, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package>), hstring const&);
            *packageCollection = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package>>(this->shim().FindPackages(*reinterpret_cast<hstring const*>(&packageFamilyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindPackagesWithPackageTypes(Windows::Management::Deployment::PackageTypes packageTypes, void** packageCollection) noexcept final
    {
        try
        {
            *packageCollection = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindPackagesWithPackageTypes, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package>), Windows::Management::Deployment::PackageTypes const&);
            *packageCollection = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package>>(this->shim().FindPackagesWithPackageTypes(*reinterpret_cast<Windows::Management::Deployment::PackageTypes const*>(&packageTypes)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindPackagesByNamePublisherWithPackagesTypes(Windows::Management::Deployment::PackageTypes packageTypes, void* packageName, void* packagePublisher, void** packageCollection) noexcept final
    {
        try
        {
            *packageCollection = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindPackagesWithPackageTypes, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package>), Windows::Management::Deployment::PackageTypes const&, hstring const&, hstring const&);
            *packageCollection = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package>>(this->shim().FindPackagesWithPackageTypes(*reinterpret_cast<Windows::Management::Deployment::PackageTypes const*>(&packageTypes), *reinterpret_cast<hstring const*>(&packageName), *reinterpret_cast<hstring const*>(&packagePublisher)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindPackagesByPackageFamilyNameWithPackageTypes(Windows::Management::Deployment::PackageTypes packageTypes, void* packageFamilyName, void** packageCollection) noexcept final
    {
        try
        {
            *packageCollection = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindPackagesWithPackageTypes, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package>), Windows::Management::Deployment::PackageTypes const&, hstring const&);
            *packageCollection = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package>>(this->shim().FindPackagesWithPackageTypes(*reinterpret_cast<Windows::Management::Deployment::PackageTypes const*>(&packageTypes), *reinterpret_cast<hstring const*>(&packageFamilyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindPackageByPackageFullName(void* packageFullName, void** packageCollection) noexcept final
    {
        try
        {
            *packageCollection = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindPackage, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package>), hstring const&);
            *packageCollection = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package>>(this->shim().FindPackage(*reinterpret_cast<hstring const*>(&packageFullName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindPackagesByUserSecurityId(void* userSecurityId, void** packageCollection) noexcept final
    {
        try
        {
            *packageCollection = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindPackagesForUser, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package>), hstring const&);
            *packageCollection = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package>>(this->shim().FindPackagesForUser(*reinterpret_cast<hstring const*>(&userSecurityId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindPackagesByUserSecurityIdNamePublisher(void* userSecurityId, void* packageName, void* packagePublisher, void** packageCollection) noexcept final
    {
        try
        {
            *packageCollection = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindPackagesForUser, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package>), hstring const&, hstring const&, hstring const&);
            *packageCollection = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package>>(this->shim().FindPackagesForUser(*reinterpret_cast<hstring const*>(&userSecurityId), *reinterpret_cast<hstring const*>(&packageName), *reinterpret_cast<hstring const*>(&packagePublisher)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindPackagesByUserSecurityIdPackageFamilyName(void* userSecurityId, void* packageFamilyName, void** packageCollection) noexcept final
    {
        try
        {
            *packageCollection = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindPackagesForUser, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package>), hstring const&, hstring const&);
            *packageCollection = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package>>(this->shim().FindPackagesForUser(*reinterpret_cast<hstring const*>(&userSecurityId), *reinterpret_cast<hstring const*>(&packageFamilyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindPackagesByUserSecurityIdWithPackageTypes(void* userSecurityId, Windows::Management::Deployment::PackageTypes packageTypes, void** packageCollection) noexcept final
    {
        try
        {
            *packageCollection = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindPackagesForUserWithPackageTypes, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package>), hstring const&, Windows::Management::Deployment::PackageTypes const&);
            *packageCollection = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package>>(this->shim().FindPackagesForUserWithPackageTypes(*reinterpret_cast<hstring const*>(&userSecurityId), *reinterpret_cast<Windows::Management::Deployment::PackageTypes const*>(&packageTypes)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindPackagesByUserSecurityIdNamePublisherWithPackageTypes(void* userSecurityId, Windows::Management::Deployment::PackageTypes packageTypes, void* packageName, void* packagePublisher, void** packageCollection) noexcept final
    {
        try
        {
            *packageCollection = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindPackagesForUserWithPackageTypes, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package>), hstring const&, Windows::Management::Deployment::PackageTypes const&, hstring const&, hstring const&);
            *packageCollection = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package>>(this->shim().FindPackagesForUserWithPackageTypes(*reinterpret_cast<hstring const*>(&userSecurityId), *reinterpret_cast<Windows::Management::Deployment::PackageTypes const*>(&packageTypes), *reinterpret_cast<hstring const*>(&packageName), *reinterpret_cast<hstring const*>(&packagePublisher)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindPackagesByUserSecurityIdPackageFamilyNameWithPackagesTypes(void* userSecurityId, Windows::Management::Deployment::PackageTypes packageTypes, void* packageFamilyName, void** packageCollection) noexcept final
    {
        try
        {
            *packageCollection = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindPackagesForUserWithPackageTypes, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package>), hstring const&, Windows::Management::Deployment::PackageTypes const&, hstring const&);
            *packageCollection = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package>>(this->shim().FindPackagesForUserWithPackageTypes(*reinterpret_cast<hstring const*>(&userSecurityId), *reinterpret_cast<Windows::Management::Deployment::PackageTypes const*>(&packageTypes), *reinterpret_cast<hstring const*>(&packageFamilyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindPackageByUserSecurityIdPackageFullName(void* userSecurityId, void* packageFullName, void** packageCollection) noexcept final
    {
        try
        {
            *packageCollection = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindPackageForUser, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package>), hstring const&, hstring const&);
            *packageCollection = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package>>(this->shim().FindPackageForUser(*reinterpret_cast<hstring const*>(&userSecurityId), *reinterpret_cast<hstring const*>(&packageFullName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Management::Deployment::IPackageVolume2> : produce_base<D, Windows::Management::Deployment::IPackageVolume2>
{
    int32_t WINRT_CALL get_IsFullTrustPackageSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsFullTrustPackageSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsFullTrustPackageSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsAppxInstallSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAppxInstallSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsAppxInstallSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAvailableSpaceAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAvailableSpaceAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<uint64_t>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<uint64_t>>(this->shim().GetAvailableSpaceAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Management::Deployment {

inline PackageManager::PackageManager() :
    PackageManager(impl::call_factory<PackageManager>([](auto&& f) { return f.template ActivateInstance<PackageManager>(); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Management::Deployment::IDeploymentResult> : winrt::impl::hash_base<winrt::Windows::Management::Deployment::IDeploymentResult> {};
template<> struct hash<winrt::Windows::Management::Deployment::IDeploymentResult2> : winrt::impl::hash_base<winrt::Windows::Management::Deployment::IDeploymentResult2> {};
template<> struct hash<winrt::Windows::Management::Deployment::IPackageManager> : winrt::impl::hash_base<winrt::Windows::Management::Deployment::IPackageManager> {};
template<> struct hash<winrt::Windows::Management::Deployment::IPackageManager2> : winrt::impl::hash_base<winrt::Windows::Management::Deployment::IPackageManager2> {};
template<> struct hash<winrt::Windows::Management::Deployment::IPackageManager3> : winrt::impl::hash_base<winrt::Windows::Management::Deployment::IPackageManager3> {};
template<> struct hash<winrt::Windows::Management::Deployment::IPackageManager4> : winrt::impl::hash_base<winrt::Windows::Management::Deployment::IPackageManager4> {};
template<> struct hash<winrt::Windows::Management::Deployment::IPackageManager5> : winrt::impl::hash_base<winrt::Windows::Management::Deployment::IPackageManager5> {};
template<> struct hash<winrt::Windows::Management::Deployment::IPackageManager6> : winrt::impl::hash_base<winrt::Windows::Management::Deployment::IPackageManager6> {};
template<> struct hash<winrt::Windows::Management::Deployment::IPackageManager7> : winrt::impl::hash_base<winrt::Windows::Management::Deployment::IPackageManager7> {};
template<> struct hash<winrt::Windows::Management::Deployment::IPackageManager8> : winrt::impl::hash_base<winrt::Windows::Management::Deployment::IPackageManager8> {};
template<> struct hash<winrt::Windows::Management::Deployment::IPackageManagerDebugSettings> : winrt::impl::hash_base<winrt::Windows::Management::Deployment::IPackageManagerDebugSettings> {};
template<> struct hash<winrt::Windows::Management::Deployment::IPackageUserInformation> : winrt::impl::hash_base<winrt::Windows::Management::Deployment::IPackageUserInformation> {};
template<> struct hash<winrt::Windows::Management::Deployment::IPackageVolume> : winrt::impl::hash_base<winrt::Windows::Management::Deployment::IPackageVolume> {};
template<> struct hash<winrt::Windows::Management::Deployment::IPackageVolume2> : winrt::impl::hash_base<winrt::Windows::Management::Deployment::IPackageVolume2> {};
template<> struct hash<winrt::Windows::Management::Deployment::DeploymentResult> : winrt::impl::hash_base<winrt::Windows::Management::Deployment::DeploymentResult> {};
template<> struct hash<winrt::Windows::Management::Deployment::PackageManager> : winrt::impl::hash_base<winrt::Windows::Management::Deployment::PackageManager> {};
template<> struct hash<winrt::Windows::Management::Deployment::PackageManagerDebugSettings> : winrt::impl::hash_base<winrt::Windows::Management::Deployment::PackageManagerDebugSettings> {};
template<> struct hash<winrt::Windows::Management::Deployment::PackageUserInformation> : winrt::impl::hash_base<winrt::Windows::Management::Deployment::PackageUserInformation> {};
template<> struct hash<winrt::Windows::Management::Deployment::PackageVolume> : winrt::impl::hash_base<winrt::Windows::Management::Deployment::PackageVolume> {};

}
