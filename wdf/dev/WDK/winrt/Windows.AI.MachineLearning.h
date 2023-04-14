/* Header file automatically generated from windows.ai.machinelearning.idl */
/*
 * File built with Microsoft(R) MIDLRT Compiler Engine Version 10.00.0226 
 */

#pragma warning( disable: 4049 )  /* more than 64k source lines */

/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 500
#endif

/* verify that the <rpcsal.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCSAL_H_VERSION__
#define __REQUIRED_RPCSAL_H_VERSION__ 100
#endif

#include <rpc.h>
#include <rpcndr.h>

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif /* __RPCNDR_H_VERSION__ */

#ifndef COM_NO_WINDOWS_H
#include <windows.h>
#include <ole2.h>
#endif /*COM_NO_WINDOWS_H*/
#ifndef __windows2Eai2Emachinelearning_h__
#define __windows2Eai2Emachinelearning_h__
#ifndef __windows2Eai2Emachinelearning_p_h__
#define __windows2Eai2Emachinelearning_p_h__


#pragma once

//
// Deprecated attribute support
//

#pragma push_macro("DEPRECATED")
#undef DEPRECATED

#if !defined(DISABLE_WINRT_DEPRECATION)
#if defined(__cplusplus)
#if __cplusplus >= 201402
#define DEPRECATED(x) [[deprecated(x)]]
#define DEPRECATEDENUMERATOR(x) [[deprecated(x)]]
#elif defined(_MSC_VER)
#if _MSC_VER >= 1900
#define DEPRECATED(x) [[deprecated(x)]]
#define DEPRECATEDENUMERATOR(x) [[deprecated(x)]]
#else
#define DEPRECATED(x) __declspec(deprecated(x))
#define DEPRECATEDENUMERATOR(x)
#endif // _MSC_VER >= 1900
#else // Not Standard C++ or MSVC, ignore the construct.
#define DEPRECATED(x)
#define DEPRECATEDENUMERATOR(x)
#endif  // C++ deprecation
#else // C - disable deprecation
#define DEPRECATED(x)
#define DEPRECATEDENUMERATOR(x)
#endif
#else // Deprecation is disabled
#define DEPRECATED(x)
#define DEPRECATEDENUMERATOR(x)
#endif  /* DEPRECATED */

// Disable Deprecation for this header, MIDL verifies that cross-type access is acceptable
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#else
#pragma warning(push)
#pragma warning(disable: 4996)
#endif

// Ensure that the setting of the /ns_prefix command line switch is consistent for all headers.
// If you get an error from the compiler indicating "warning C4005: 'CHECK_NS_PREFIX_STATE': macro redefinition", this
// indicates that you have included two different headers with different settings for the /ns_prefix MIDL command line switch
#if !defined(DISABLE_NS_PREFIX_CHECKS)
#define CHECK_NS_PREFIX_STATE "always"
#endif // !defined(DISABLE_NS_PREFIX_CHECKS)


#pragma push_macro("MIDL_CONST_ID")
#undef MIDL_CONST_ID
#define MIDL_CONST_ID const __declspec(selectany)


//  API Contract Inclusion Definitions
#if !defined(SPECIFIC_API_CONTRACT_DEFINITIONS)
#if !defined(WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION)
#define WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION 0x20000
#endif // defined(WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION)

#if !defined(WINDOWS_APPLICATIONMODEL_ACTIVATION_ACTIVATEDEVENTSCONTRACT_VERSION)
#define WINDOWS_APPLICATIONMODEL_ACTIVATION_ACTIVATEDEVENTSCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_APPLICATIONMODEL_ACTIVATION_ACTIVATEDEVENTSCONTRACT_VERSION)

#if !defined(WINDOWS_APPLICATIONMODEL_ACTIVATION_ACTIVATIONCAMERASETTINGSCONTRACT_VERSION)
#define WINDOWS_APPLICATIONMODEL_ACTIVATION_ACTIVATIONCAMERASETTINGSCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_APPLICATIONMODEL_ACTIVATION_ACTIVATIONCAMERASETTINGSCONTRACT_VERSION)

#if !defined(WINDOWS_APPLICATIONMODEL_ACTIVATION_CONTACTACTIVATEDEVENTSCONTRACT_VERSION)
#define WINDOWS_APPLICATIONMODEL_ACTIVATION_CONTACTACTIVATEDEVENTSCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_APPLICATIONMODEL_ACTIVATION_CONTACTACTIVATEDEVENTSCONTRACT_VERSION)

#if !defined(WINDOWS_APPLICATIONMODEL_ACTIVATION_WEBUISEARCHACTIVATEDEVENTSCONTRACT_VERSION)
#define WINDOWS_APPLICATIONMODEL_ACTIVATION_WEBUISEARCHACTIVATEDEVENTSCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_APPLICATIONMODEL_ACTIVATION_WEBUISEARCHACTIVATEDEVENTSCONTRACT_VERSION)

#if !defined(WINDOWS_APPLICATIONMODEL_BACKGROUND_BACKGROUNDALARMAPPLICATIONCONTRACT_VERSION)
#define WINDOWS_APPLICATIONMODEL_BACKGROUND_BACKGROUNDALARMAPPLICATIONCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_APPLICATIONMODEL_BACKGROUND_BACKGROUNDALARMAPPLICATIONCONTRACT_VERSION)

#if !defined(WINDOWS_APPLICATIONMODEL_CALLS_BACKGROUND_CALLSBACKGROUNDCONTRACT_VERSION)
#define WINDOWS_APPLICATIONMODEL_CALLS_BACKGROUND_CALLSBACKGROUNDCONTRACT_VERSION 0x20000
#endif // defined(WINDOWS_APPLICATIONMODEL_CALLS_BACKGROUND_CALLSBACKGROUNDCONTRACT_VERSION)

#if !defined(WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION)
#define WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION 0x50000
#endif // defined(WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION)

#if !defined(WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION)
#define WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION 0x40000
#endif // defined(WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION)

#if !defined(WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION)
#define WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION)

#if !defined(WINDOWS_APPLICATIONMODEL_COMMUNICATIONBLOCKING_COMMUNICATIONBLOCKINGCONTRACT_VERSION)
#define WINDOWS_APPLICATIONMODEL_COMMUNICATIONBLOCKING_COMMUNICATIONBLOCKINGCONTRACT_VERSION 0x20000
#endif // defined(WINDOWS_APPLICATIONMODEL_COMMUNICATIONBLOCKING_COMMUNICATIONBLOCKINGCONTRACT_VERSION)

#if !defined(WINDOWS_APPLICATIONMODEL_FULLTRUSTAPPCONTRACT_VERSION)
#define WINDOWS_APPLICATIONMODEL_FULLTRUSTAPPCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_APPLICATIONMODEL_FULLTRUSTAPPCONTRACT_VERSION)

#if !defined(WINDOWS_APPLICATIONMODEL_SEARCH_SEARCHCONTRACT_VERSION)
#define WINDOWS_APPLICATIONMODEL_SEARCH_SEARCHCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_APPLICATIONMODEL_SEARCH_SEARCHCONTRACT_VERSION)

#if !defined(WINDOWS_APPLICATIONMODEL_STARTUPTASKCONTRACT_VERSION)
#define WINDOWS_APPLICATIONMODEL_STARTUPTASKCONTRACT_VERSION 0x30000
#endif // defined(WINDOWS_APPLICATIONMODEL_STARTUPTASKCONTRACT_VERSION)

#if !defined(WINDOWS_APPLICATIONMODEL_WALLET_WALLETCONTRACT_VERSION)
#define WINDOWS_APPLICATIONMODEL_WALLET_WALLETCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_APPLICATIONMODEL_WALLET_WALLETCONTRACT_VERSION)

#if !defined(WINDOWS_DEVICES_PRINTERS_EXTENSIONS_EXTENSIONSCONTRACT_VERSION)
#define WINDOWS_DEVICES_PRINTERS_EXTENSIONS_EXTENSIONSCONTRACT_VERSION 0x20000
#endif // defined(WINDOWS_DEVICES_PRINTERS_EXTENSIONS_EXTENSIONSCONTRACT_VERSION)

#if !defined(WINDOWS_DEVICES_SMARTCARDS_SMARTCARDBACKGROUNDTRIGGERCONTRACT_VERSION)
#define WINDOWS_DEVICES_SMARTCARDS_SMARTCARDBACKGROUNDTRIGGERCONTRACT_VERSION 0x30000
#endif // defined(WINDOWS_DEVICES_SMARTCARDS_SMARTCARDBACKGROUNDTRIGGERCONTRACT_VERSION)

#if !defined(WINDOWS_DEVICES_SMARTCARDS_SMARTCARDEMULATORCONTRACT_VERSION)
#define WINDOWS_DEVICES_SMARTCARDS_SMARTCARDEMULATORCONTRACT_VERSION 0x60000
#endif // defined(WINDOWS_DEVICES_SMARTCARDS_SMARTCARDEMULATORCONTRACT_VERSION)

#if !defined(WINDOWS_DEVICES_SMS_LEGACYSMSAPICONTRACT_VERSION)
#define WINDOWS_DEVICES_SMS_LEGACYSMSAPICONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_DEVICES_SMS_LEGACYSMSAPICONTRACT_VERSION)

#if !defined(WINDOWS_FOUNDATION_FOUNDATIONCONTRACT_VERSION)
#define WINDOWS_FOUNDATION_FOUNDATIONCONTRACT_VERSION 0x30000
#endif // defined(WINDOWS_FOUNDATION_FOUNDATIONCONTRACT_VERSION)

#if !defined(WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION)
#define WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION 0x80000
#endif // defined(WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION)

#if !defined(WINDOWS_GAMING_INPUT_GAMINGINPUTPREVIEWCONTRACT_VERSION)
#define WINDOWS_GAMING_INPUT_GAMINGINPUTPREVIEWCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_GAMING_INPUT_GAMINGINPUTPREVIEWCONTRACT_VERSION)

#if !defined(WINDOWS_GLOBALIZATION_GLOBALIZATIONJAPANESEPHONETICANALYZERCONTRACT_VERSION)
#define WINDOWS_GLOBALIZATION_GLOBALIZATIONJAPANESEPHONETICANALYZERCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_GLOBALIZATION_GLOBALIZATIONJAPANESEPHONETICANALYZERCONTRACT_VERSION)

#if !defined(WINDOWS_MEDIA_CAPTURE_APPBROADCASTCONTRACT_VERSION)
#define WINDOWS_MEDIA_CAPTURE_APPBROADCASTCONTRACT_VERSION 0x20000
#endif // defined(WINDOWS_MEDIA_CAPTURE_APPBROADCASTCONTRACT_VERSION)

#if !defined(WINDOWS_MEDIA_CAPTURE_APPCAPTURECONTRACT_VERSION)
#define WINDOWS_MEDIA_CAPTURE_APPCAPTURECONTRACT_VERSION 0x40000
#endif // defined(WINDOWS_MEDIA_CAPTURE_APPCAPTURECONTRACT_VERSION)

#if !defined(WINDOWS_MEDIA_CAPTURE_APPCAPTUREMETADATACONTRACT_VERSION)
#define WINDOWS_MEDIA_CAPTURE_APPCAPTUREMETADATACONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_MEDIA_CAPTURE_APPCAPTUREMETADATACONTRACT_VERSION)

#if !defined(WINDOWS_MEDIA_CAPTURE_CAMERACAPTUREUICONTRACT_VERSION)
#define WINDOWS_MEDIA_CAPTURE_CAMERACAPTUREUICONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_MEDIA_CAPTURE_CAMERACAPTUREUICONTRACT_VERSION)

#if !defined(WINDOWS_MEDIA_CAPTURE_GAMEBARCONTRACT_VERSION)
#define WINDOWS_MEDIA_CAPTURE_GAMEBARCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_MEDIA_CAPTURE_GAMEBARCONTRACT_VERSION)

#if !defined(WINDOWS_MEDIA_DEVICES_CALLCONTROLCONTRACT_VERSION)
#define WINDOWS_MEDIA_DEVICES_CALLCONTROLCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_MEDIA_DEVICES_CALLCONTROLCONTRACT_VERSION)

#if !defined(WINDOWS_MEDIA_MEDIACONTROLCONTRACT_VERSION)
#define WINDOWS_MEDIA_MEDIACONTROLCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_MEDIA_MEDIACONTROLCONTRACT_VERSION)

#if !defined(WINDOWS_MEDIA_PROTECTION_PROTECTIONRENEWALCONTRACT_VERSION)
#define WINDOWS_MEDIA_PROTECTION_PROTECTIONRENEWALCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_MEDIA_PROTECTION_PROTECTIONRENEWALCONTRACT_VERSION)

#if !defined(WINDOWS_NETWORKING_CONNECTIVITY_WWANCONTRACT_VERSION)
#define WINDOWS_NETWORKING_CONNECTIVITY_WWANCONTRACT_VERSION 0x20000
#endif // defined(WINDOWS_NETWORKING_CONNECTIVITY_WWANCONTRACT_VERSION)

#if !defined(WINDOWS_NETWORKING_SOCKETS_CONTROLCHANNELTRIGGERCONTRACT_VERSION)
#define WINDOWS_NETWORKING_SOCKETS_CONTROLCHANNELTRIGGERCONTRACT_VERSION 0x30000
#endif // defined(WINDOWS_NETWORKING_SOCKETS_CONTROLCHANNELTRIGGERCONTRACT_VERSION)

#if !defined(WINDOWS_PHONE_PHONECONTRACT_VERSION)
#define WINDOWS_PHONE_PHONECONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_PHONE_PHONECONTRACT_VERSION)

#if !defined(WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION)
#define WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION)

#if !defined(WINDOWS_SECURITY_ENTERPRISEDATA_ENTERPRISEDATACONTRACT_VERSION)
#define WINDOWS_SECURITY_ENTERPRISEDATA_ENTERPRISEDATACONTRACT_VERSION 0x50000
#endif // defined(WINDOWS_SECURITY_ENTERPRISEDATA_ENTERPRISEDATACONTRACT_VERSION)

#if !defined(WINDOWS_STORAGE_PROVIDER_CLOUDFILESCONTRACT_VERSION)
#define WINDOWS_STORAGE_PROVIDER_CLOUDFILESCONTRACT_VERSION 0x30000
#endif // defined(WINDOWS_STORAGE_PROVIDER_CLOUDFILESCONTRACT_VERSION)

#if !defined(WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION)
#define WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION 0x60000
#endif // defined(WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION)

#if !defined(WINDOWS_UI_CORE_COREWINDOWDIALOGSCONTRACT_VERSION)
#define WINDOWS_UI_CORE_COREWINDOWDIALOGSCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_UI_CORE_COREWINDOWDIALOGSCONTRACT_VERSION)

#if !defined(WINDOWS_UI_VIEWMANAGEMENT_VIEWMANAGEMENTVIEWSCALINGCONTRACT_VERSION)
#define WINDOWS_UI_VIEWMANAGEMENT_VIEWMANAGEMENTVIEWSCALINGCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_UI_VIEWMANAGEMENT_VIEWMANAGEMENTVIEWSCALINGCONTRACT_VERSION)

#if !defined(WINDOWS_UI_WEBUI_CORE_WEBUICOMMANDBARCONTRACT_VERSION)
#define WINDOWS_UI_WEBUI_CORE_WEBUICOMMANDBARCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_UI_WEBUI_CORE_WEBUICOMMANDBARCONTRACT_VERSION)

#endif // defined(SPECIFIC_API_CONTRACT_DEFINITIONS)


// Header files for imported files
#include "inspectable.h"
#include "AsyncInfo.h"
#include "EventToken.h"
#include "windowscontracts.h"
#include "Windows.Foundation.h"
#include "Windows.Graphics.h"
#include "Windows.Graphics.DirectX.Direct3D11.h"
#include "Windows.Graphics.Imaging.h"
#include "Windows.Media.h"
#include "Windows.Storage.h"
#include "Windows.Storage.Streams.h"
// Importing Collections header
#include <windows.foundation.collections.h>

#if defined(__cplusplus) && !defined(CINTERFACE)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface IImageFeatureDescriptor;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor ABI::Windows::AI::MachineLearning::IImageFeatureDescriptor

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValue_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValue_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface IImageFeatureValue;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValue ABI::Windows::AI::MachineLearning::IImageFeatureValue

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValue_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface IImageFeatureValueStatics;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueStatics ABI::Windows::AI::MachineLearning::IImageFeatureValueStatics

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModel_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModel_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ILearningModel;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel ABI::Windows::AI::MachineLearning::ILearningModel

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModel_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ILearningModelBinding;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding ABI::Windows::AI::MachineLearning::ILearningModelBinding

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingFactory_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ILearningModelBindingFactory;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingFactory ABI::Windows::AI::MachineLearning::ILearningModelBindingFactory

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ILearningModelDevice;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice ABI::Windows::AI::MachineLearning::ILearningModelDevice

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceFactory_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ILearningModelDeviceFactory;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceFactory ABI::Windows::AI::MachineLearning::ILearningModelDeviceFactory

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ILearningModelDeviceStatics;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceStatics ABI::Windows::AI::MachineLearning::ILearningModelDeviceStatics

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ILearningModelEvaluationResult;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult ABI::Windows::AI::MachineLearning::ILearningModelEvaluationResult

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ILearningModelFeatureDescriptor;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor ABI::Windows::AI::MachineLearning::ILearningModelFeatureDescriptor

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureValue_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureValue_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ILearningModelFeatureValue;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureValue ABI::Windows::AI::MachineLearning::ILearningModelFeatureValue

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureValue_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProvider_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProvider_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ILearningModelOperatorProvider;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProvider ABI::Windows::AI::MachineLearning::ILearningModelOperatorProvider

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProvider_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ILearningModelSession;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession ABI::Windows::AI::MachineLearning::ILearningModelSession

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ILearningModelSessionFactory;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory ABI::Windows::AI::MachineLearning::ILearningModelSessionFactory

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory2_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ILearningModelSessionFactory2;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory2 ABI::Windows::AI::MachineLearning::ILearningModelSessionFactory2

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptions_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptions_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ILearningModelSessionOptions;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptions ABI::Windows::AI::MachineLearning::ILearningModelSessionOptions

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptions_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ILearningModelStatics;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics ABI::Windows::AI::MachineLearning::ILearningModelStatics

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptor_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptor_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface IMapFeatureDescriptor;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptor ABI::Windows::AI::MachineLearning::IMapFeatureDescriptor

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptor_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CISequenceFeatureDescriptor_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CISequenceFeatureDescriptor_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ISequenceFeatureDescriptor;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CISequenceFeatureDescriptor ABI::Windows::AI::MachineLearning::ISequenceFeatureDescriptor

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CISequenceFeatureDescriptor_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensor_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensor_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensor;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensor ABI::Windows::AI::MachineLearning::ITensor

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensor_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorBoolean;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean ABI::Windows::AI::MachineLearning::ITensorBoolean

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorBooleanStatics;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics ABI::Windows::AI::MachineLearning::ITensorBooleanStatics

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorBooleanStatics2;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2 ABI::Windows::AI::MachineLearning::ITensorBooleanStatics2

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorDouble;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble ABI::Windows::AI::MachineLearning::ITensorDouble

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorDoubleStatics;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics ABI::Windows::AI::MachineLearning::ITensorDoubleStatics

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorDoubleStatics2;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2 ABI::Windows::AI::MachineLearning::ITensorDoubleStatics2

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptor_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptor_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorFeatureDescriptor;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptor ABI::Windows::AI::MachineLearning::ITensorFeatureDescriptor

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptor_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorFloat;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat ABI::Windows::AI::MachineLearning::ITensorFloat

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorFloat16Bit;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit ABI::Windows::AI::MachineLearning::ITensorFloat16Bit

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorFloat16BitStatics;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics ABI::Windows::AI::MachineLearning::ITensorFloat16BitStatics

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorFloat16BitStatics2;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2 ABI::Windows::AI::MachineLearning::ITensorFloat16BitStatics2

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorFloatStatics;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics ABI::Windows::AI::MachineLearning::ITensorFloatStatics

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorFloatStatics2;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2 ABI::Windows::AI::MachineLearning::ITensorFloatStatics2

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorInt16Bit;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit ABI::Windows::AI::MachineLearning::ITensorInt16Bit

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorInt16BitStatics;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics ABI::Windows::AI::MachineLearning::ITensorInt16BitStatics

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorInt16BitStatics2;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2 ABI::Windows::AI::MachineLearning::ITensorInt16BitStatics2

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorInt32Bit;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit ABI::Windows::AI::MachineLearning::ITensorInt32Bit

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorInt32BitStatics;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics ABI::Windows::AI::MachineLearning::ITensorInt32BitStatics

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorInt32BitStatics2;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2 ABI::Windows::AI::MachineLearning::ITensorInt32BitStatics2

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorInt64Bit;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit ABI::Windows::AI::MachineLearning::ITensorInt64Bit

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorInt64BitStatics;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics ABI::Windows::AI::MachineLearning::ITensorInt64BitStatics

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorInt64BitStatics2;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2 ABI::Windows::AI::MachineLearning::ITensorInt64BitStatics2

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorInt8Bit;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit ABI::Windows::AI::MachineLearning::ITensorInt8Bit

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorInt8BitStatics;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics ABI::Windows::AI::MachineLearning::ITensorInt8BitStatics

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorInt8BitStatics2;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2 ABI::Windows::AI::MachineLearning::ITensorInt8BitStatics2

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorString_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorString_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorString;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorString ABI::Windows::AI::MachineLearning::ITensorString

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorString_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorStringStatics;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics ABI::Windows::AI::MachineLearning::ITensorStringStatics

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorStringStatics2;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics2 ABI::Windows::AI::MachineLearning::ITensorStringStatics2

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorUInt16Bit;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit ABI::Windows::AI::MachineLearning::ITensorUInt16Bit

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorUInt16BitStatics;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics ABI::Windows::AI::MachineLearning::ITensorUInt16BitStatics

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorUInt16BitStatics2;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2 ABI::Windows::AI::MachineLearning::ITensorUInt16BitStatics2

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorUInt32Bit;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit ABI::Windows::AI::MachineLearning::ITensorUInt32Bit

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorUInt32BitStatics;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics ABI::Windows::AI::MachineLearning::ITensorUInt32BitStatics

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorUInt32BitStatics2;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2 ABI::Windows::AI::MachineLearning::ITensorUInt32BitStatics2

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorUInt64Bit;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit ABI::Windows::AI::MachineLearning::ITensorUInt64Bit

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorUInt64BitStatics;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics ABI::Windows::AI::MachineLearning::ITensorUInt64BitStatics

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorUInt64BitStatics2;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2 ABI::Windows::AI::MachineLearning::ITensorUInt64BitStatics2

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorUInt8Bit;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit ABI::Windows::AI::MachineLearning::ITensorUInt8Bit

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorUInt8BitStatics;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics ABI::Windows::AI::MachineLearning::ITensorUInt8BitStatics

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                interface ITensorUInt8BitStatics2;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2 ABI::Windows::AI::MachineLearning::ITensorUInt8BitStatics2

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2_FWD_DEFINED__

// Parameterized interface forward declarations (C++)

// Collection interface definitions

#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef DEF___FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_USE
#define DEF___FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("0ef412a8-a1e6-593a-97f2-0d699ca6a567"))
IIterator<ABI::Windows::AI::MachineLearning::ILearningModelFeatureDescriptor*> : IIterator_impl<ABI::Windows::AI::MachineLearning::ILearningModelFeatureDescriptor*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.AI.MachineLearning.ILearningModelFeatureDescriptor>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<ABI::Windows::AI::MachineLearning::ILearningModelFeatureDescriptor*> __FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_t;
#define __FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor ABI::Windows::Foundation::Collections::__FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::AI::MachineLearning::ILearningModelFeatureDescriptor*>
//#define __FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::AI::MachineLearning::ILearningModelFeatureDescriptor*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_USE */


#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef DEF___FIIterable_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_USE
#define DEF___FIIterable_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("0fa50877-6792-56b7-af46-430a8901894a"))
IIterable<ABI::Windows::AI::MachineLearning::ILearningModelFeatureDescriptor*> : IIterable_impl<ABI::Windows::AI::MachineLearning::ILearningModelFeatureDescriptor*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.AI.MachineLearning.ILearningModelFeatureDescriptor>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<ABI::Windows::AI::MachineLearning::ILearningModelFeatureDescriptor*> __FIIterable_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_t;
#define __FIIterable_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor ABI::Windows::Foundation::Collections::__FIIterable_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::AI::MachineLearning::ILearningModelFeatureDescriptor*>
//#define __FIIterable_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::AI::MachineLearning::ILearningModelFeatureDescriptor*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_USE */


#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef DEF___FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_USE
#define DEF___FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("53e53120-a6e1-527f-af8a-c812902e175e"))
IVectorView<ABI::Windows::AI::MachineLearning::ILearningModelFeatureDescriptor*> : IVectorView_impl<ABI::Windows::AI::MachineLearning::ILearningModelFeatureDescriptor*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Windows.AI.MachineLearning.ILearningModelFeatureDescriptor>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<ABI::Windows::AI::MachineLearning::ILearningModelFeatureDescriptor*> __FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_t;
#define __FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor ABI::Windows::Foundation::Collections::__FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::AI::MachineLearning::ILearningModelFeatureDescriptor*>
//#define __FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_t ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::AI::MachineLearning::ILearningModelFeatureDescriptor*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_USE */


#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                class LearningModel;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */


#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModel_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModel_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("755da6df-ed55-5aaa-b542-c665f010f50c"))
IAsyncOperationCompletedHandler<ABI::Windows::AI::MachineLearning::LearningModel*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::AI::MachineLearning::LearningModel*, ABI::Windows::AI::MachineLearning::ILearningModel*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.AI.MachineLearning.LearningModel>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::AI::MachineLearning::LearningModel*> __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModel_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModel ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModel_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModel ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::AI::MachineLearning::ILearningModel*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModel_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::AI::MachineLearning::ILearningModel*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModel_USE */


#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel_USE
#define DEF___FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("634ab3cb-406c-5ede-8a89-a7f9ca370326"))
IAsyncOperation<ABI::Windows::AI::MachineLearning::LearningModel*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::AI::MachineLearning::LearningModel*, ABI::Windows::AI::MachineLearning::ILearningModel*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.AI.MachineLearning.LearningModel>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::AI::MachineLearning::LearningModel*> __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel_t;
#define __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::AI::MachineLearning::ILearningModel*>
//#define __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::AI::MachineLearning::ILearningModel*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel_USE */


#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                class LearningModelEvaluationResult;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */


#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("b8776114-9adf-50e8-b67f-22e0f1372f45"))
IAsyncOperationCompletedHandler<ABI::Windows::AI::MachineLearning::LearningModelEvaluationResult*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::AI::MachineLearning::LearningModelEvaluationResult*, ABI::Windows::AI::MachineLearning::ILearningModelEvaluationResult*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.AI.MachineLearning.LearningModelEvaluationResult>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::AI::MachineLearning::LearningModelEvaluationResult*> __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::AI::MachineLearning::ILearningModelEvaluationResult*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::AI::MachineLearning::ILearningModelEvaluationResult*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult_USE */


#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult_USE
#define DEF___FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("28050590-1422-5a18-8c8b-847f2d2cf69a"))
IAsyncOperation<ABI::Windows::AI::MachineLearning::LearningModelEvaluationResult*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::AI::MachineLearning::LearningModelEvaluationResult*, ABI::Windows::AI::MachineLearning::ILearningModelEvaluationResult*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.AI.MachineLearning.LearningModelEvaluationResult>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::AI::MachineLearning::LearningModelEvaluationResult*> __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult_t;
#define __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::AI::MachineLearning::ILearningModelEvaluationResult*>
//#define __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::AI::MachineLearning::ILearningModelEvaluationResult*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult_USE */


#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


#ifndef DEF___FIKeyValuePair_2_HSTRING_HSTRING_USE
#define DEF___FIKeyValuePair_2_HSTRING_HSTRING_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("60310303-49c5-52e6-abc6-a9b36eccc716"))
IKeyValuePair<HSTRING,HSTRING> : IKeyValuePair_impl<HSTRING,HSTRING> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IKeyValuePair`2<String, String>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IKeyValuePair<HSTRING,HSTRING> __FIKeyValuePair_2_HSTRING_HSTRING_t;
#define __FIKeyValuePair_2_HSTRING_HSTRING ABI::Windows::Foundation::Collections::__FIKeyValuePair_2_HSTRING_HSTRING_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIKeyValuePair_2_HSTRING_HSTRING ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,HSTRING>
//#define __FIKeyValuePair_2_HSTRING_HSTRING_t ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,HSTRING>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIKeyValuePair_2_HSTRING_HSTRING_USE */





#ifndef DEF___FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING_USE
#define DEF___FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("05eb86f1-7140-5517-b88d-cbaebe57e6b1"))
IIterator<__FIKeyValuePair_2_HSTRING_HSTRING*> : IIterator_impl<__FIKeyValuePair_2_HSTRING_HSTRING*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.Foundation.Collections.IKeyValuePair`2<String, String>>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<__FIKeyValuePair_2_HSTRING_HSTRING*> __FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING_t;
#define __FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING ABI::Windows::Foundation::Collections::__FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,HSTRING>*>
//#define __FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,HSTRING>*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING_USE */





#ifndef DEF___FIIterable_1___FIKeyValuePair_2_HSTRING_HSTRING_USE
#define DEF___FIIterable_1___FIKeyValuePair_2_HSTRING_HSTRING_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("e9bdaaf0-cbf6-5c72-be90-29cbf3a1319b"))
IIterable<__FIKeyValuePair_2_HSTRING_HSTRING*> : IIterable_impl<__FIKeyValuePair_2_HSTRING_HSTRING*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.Foundation.Collections.IKeyValuePair`2<String, String>>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<__FIKeyValuePair_2_HSTRING_HSTRING*> __FIIterable_1___FIKeyValuePair_2_HSTRING_HSTRING_t;
#define __FIIterable_1___FIKeyValuePair_2_HSTRING_HSTRING ABI::Windows::Foundation::Collections::__FIIterable_1___FIKeyValuePair_2_HSTRING_HSTRING_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1___FIKeyValuePair_2_HSTRING_HSTRING ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,HSTRING>*>
//#define __FIIterable_1___FIKeyValuePair_2_HSTRING_HSTRING_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,HSTRING>*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1___FIKeyValuePair_2_HSTRING_HSTRING_USE */




#ifndef DEF___FIMapView_2_HSTRING_HSTRING_USE
#define DEF___FIMapView_2_HSTRING_HSTRING_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("ac7f26f2-feb7-5b2a-8ac4-345bc62caede"))
IMapView<HSTRING,HSTRING> : IMapView_impl<HSTRING,HSTRING> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IMapView`2<String, String>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IMapView<HSTRING,HSTRING> __FIMapView_2_HSTRING_HSTRING_t;
#define __FIMapView_2_HSTRING_HSTRING ABI::Windows::Foundation::Collections::__FIMapView_2_HSTRING_HSTRING_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIMapView_2_HSTRING_HSTRING ABI::Windows::Foundation::Collections::IMapView<HSTRING,HSTRING>
//#define __FIMapView_2_HSTRING_HSTRING_t ABI::Windows::Foundation::Collections::IMapView<HSTRING,HSTRING>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIMapView_2_HSTRING_HSTRING_USE */





#ifndef DEF___FIKeyValuePair_2_HSTRING_IInspectable_USE
#define DEF___FIKeyValuePair_2_HSTRING_IInspectable_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("09335560-6c6b-5a26-9348-97b781132b20"))
IKeyValuePair<HSTRING,IInspectable*> : IKeyValuePair_impl<HSTRING,IInspectable*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IKeyValuePair`2<String, Object>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IKeyValuePair<HSTRING,IInspectable*> __FIKeyValuePair_2_HSTRING_IInspectable_t;
#define __FIKeyValuePair_2_HSTRING_IInspectable ABI::Windows::Foundation::Collections::__FIKeyValuePair_2_HSTRING_IInspectable_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIKeyValuePair_2_HSTRING_IInspectable ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,IInspectable*>
//#define __FIKeyValuePair_2_HSTRING_IInspectable_t ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,IInspectable*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIKeyValuePair_2_HSTRING_IInspectable_USE */





#ifndef DEF___FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_USE
#define DEF___FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("5db5fa32-707c-5849-a06b-91c8eb9d10e8"))
IIterator<__FIKeyValuePair_2_HSTRING_IInspectable*> : IIterator_impl<__FIKeyValuePair_2_HSTRING_IInspectable*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.Foundation.Collections.IKeyValuePair`2<String, Object>>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<__FIKeyValuePair_2_HSTRING_IInspectable*> __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_t;
#define __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable ABI::Windows::Foundation::Collections::__FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,IInspectable*>*>
//#define __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,IInspectable*>*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_USE */





#ifndef DEF___FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable_USE
#define DEF___FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("fe2f3d47-5d47-5499-8374-430c7cda0204"))
IIterable<__FIKeyValuePair_2_HSTRING_IInspectable*> : IIterable_impl<__FIKeyValuePair_2_HSTRING_IInspectable*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.Foundation.Collections.IKeyValuePair`2<String, Object>>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<__FIKeyValuePair_2_HSTRING_IInspectable*> __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable_t;
#define __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable ABI::Windows::Foundation::Collections::__FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,IInspectable*>*>
//#define __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,IInspectable*>*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable_USE */





#ifndef DEF___FIMapView_2_HSTRING_IInspectable_USE
#define DEF___FIMapView_2_HSTRING_IInspectable_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("bb78502a-f79d-54fa-92c9-90c5039fdf7e"))
IMapView<HSTRING,IInspectable*> : IMapView_impl<HSTRING,IInspectable*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IMapView`2<String, Object>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IMapView<HSTRING,IInspectable*> __FIMapView_2_HSTRING_IInspectable_t;
#define __FIMapView_2_HSTRING_IInspectable ABI::Windows::Foundation::Collections::__FIMapView_2_HSTRING_IInspectable_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIMapView_2_HSTRING_IInspectable ABI::Windows::Foundation::Collections::IMapView<HSTRING,IInspectable*>
//#define __FIMapView_2_HSTRING_IInspectable_t ABI::Windows::Foundation::Collections::IMapView<HSTRING,IInspectable*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIMapView_2_HSTRING_IInspectable_USE */





#ifndef DEF___FIMap_2_HSTRING_IInspectable_USE
#define DEF___FIMap_2_HSTRING_IInspectable_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("1b0d3570-0877-5ec2-8a2c-3b9539506aca"))
IMap<HSTRING,IInspectable*> : IMap_impl<HSTRING,IInspectable*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IMap`2<String, Object>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IMap<HSTRING,IInspectable*> __FIMap_2_HSTRING_IInspectable_t;
#define __FIMap_2_HSTRING_IInspectable ABI::Windows::Foundation::Collections::__FIMap_2_HSTRING_IInspectable_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIMap_2_HSTRING_IInspectable ABI::Windows::Foundation::Collections::IMap<HSTRING,IInspectable*>
//#define __FIMap_2_HSTRING_IInspectable_t ABI::Windows::Foundation::Collections::IMap<HSTRING,IInspectable*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIMap_2_HSTRING_IInspectable_USE */




#ifndef DEF___FIIterator_1___z__zint64_USE
#define DEF___FIIterator_1___z__zint64_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("fb98034c-86b7-581f-8cd9-5ad0692201a9"))
IIterator<__int64> : IIterator_impl<__int64> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Int64>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<__int64> __FIIterator_1___z__zint64_t;
#define __FIIterator_1___z__zint64 ABI::Windows::Foundation::Collections::__FIIterator_1___z__zint64_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1___z__zint64 ABI::Windows::Foundation::Collections::IIterator<INT64>
//#define __FIIterator_1___z__zint64_t ABI::Windows::Foundation::Collections::IIterator<INT64>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1___z__zint64_USE */




#ifndef DEF___FIIterable_1___z__zint64_USE
#define DEF___FIIterable_1___z__zint64_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("7784427e-f9cc-518d-964b-e50d5ce727f1"))
IIterable<__int64> : IIterable_impl<__int64> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Int64>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<__int64> __FIIterable_1___z__zint64_t;
#define __FIIterable_1___z__zint64 ABI::Windows::Foundation::Collections::__FIIterable_1___z__zint64_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1___z__zint64 ABI::Windows::Foundation::Collections::IIterable<INT64>
//#define __FIIterable_1___z__zint64_t ABI::Windows::Foundation::Collections::IIterable<INT64>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1___z__zint64_USE */




#ifndef DEF___FIVectorView_1___z__zint64_USE
#define DEF___FIVectorView_1___z__zint64_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("8221aa0e-d1d2-5b22-a918-05672812d12f"))
IVectorView<__int64> : IVectorView_impl<__int64> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Int64>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<__int64> __FIVectorView_1___z__zint64_t;
#define __FIVectorView_1___z__zint64 ABI::Windows::Foundation::Collections::__FIVectorView_1___z__zint64_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1___z__zint64 ABI::Windows::Foundation::Collections::IVectorView<INT64>
//#define __FIVectorView_1___z__zint64_t ABI::Windows::Foundation::Collections::IVectorView<INT64>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1___z__zint64_USE */




#ifndef DEF___FIIterator_1_boolean_USE
#define DEF___FIIterator_1_boolean_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("740a0296-a535-572a-bf0b-17c18ff71fe6"))
IIterator<bool> : IIterator_impl<ABI::Windows::Foundation::Internal::AggregateType<bool, boolean>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Boolean>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<bool> __FIIterator_1_boolean_t;
#define __FIIterator_1_boolean ABI::Windows::Foundation::Collections::__FIIterator_1_boolean_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_boolean ABI::Windows::Foundation::Collections::IIterator<boolean>
//#define __FIIterator_1_boolean_t ABI::Windows::Foundation::Collections::IIterator<boolean>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_boolean_USE */




#ifndef DEF___FIIterable_1_boolean_USE
#define DEF___FIIterable_1_boolean_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("30160817-1d7d-54e9-99db-d7636266a476"))
IIterable<bool> : IIterable_impl<ABI::Windows::Foundation::Internal::AggregateType<bool, boolean>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Boolean>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<bool> __FIIterable_1_boolean_t;
#define __FIIterable_1_boolean ABI::Windows::Foundation::Collections::__FIIterable_1_boolean_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_boolean ABI::Windows::Foundation::Collections::IIterable<boolean>
//#define __FIIterable_1_boolean_t ABI::Windows::Foundation::Collections::IIterable<boolean>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_boolean_USE */




#ifndef DEF___FIVectorView_1_boolean_USE
#define DEF___FIVectorView_1_boolean_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("243a09cb-6f40-56af-a442-fe81431fbef5"))
IVectorView<bool> : IVectorView_impl<ABI::Windows::Foundation::Internal::AggregateType<bool, boolean>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Boolean>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<bool> __FIVectorView_1_boolean_t;
#define __FIVectorView_1_boolean ABI::Windows::Foundation::Collections::__FIVectorView_1_boolean_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_boolean ABI::Windows::Foundation::Collections::IVectorView<boolean>
//#define __FIVectorView_1_boolean_t ABI::Windows::Foundation::Collections::IVectorView<boolean>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_boolean_USE */




#ifndef DEF___FIIterator_1_double_USE
#define DEF___FIIterator_1_double_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("638a2cf4-f474-5318-9055-141cb909ac4b"))
IIterator<double> : IIterator_impl<double> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Double>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<double> __FIIterator_1_double_t;
#define __FIIterator_1_double ABI::Windows::Foundation::Collections::__FIIterator_1_double_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_double ABI::Windows::Foundation::Collections::IIterator<DOUBLE>
//#define __FIIterator_1_double_t ABI::Windows::Foundation::Collections::IIterator<DOUBLE>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_double_USE */




#ifndef DEF___FIIterable_1_double_USE
#define DEF___FIIterable_1_double_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("c738964e-9c64-5bce-b5ce-61e9a282ec4a"))
IIterable<double> : IIterable_impl<double> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Double>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<double> __FIIterable_1_double_t;
#define __FIIterable_1_double ABI::Windows::Foundation::Collections::__FIIterable_1_double_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_double ABI::Windows::Foundation::Collections::IIterable<DOUBLE>
//#define __FIIterable_1_double_t ABI::Windows::Foundation::Collections::IIterable<DOUBLE>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_double_USE */




#ifndef DEF___FIVectorView_1_double_USE
#define DEF___FIVectorView_1_double_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("af7586a8-6b21-5f61-bff1-1b682293ad96"))
IVectorView<double> : IVectorView_impl<double> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Double>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<double> __FIVectorView_1_double_t;
#define __FIVectorView_1_double ABI::Windows::Foundation::Collections::__FIVectorView_1_double_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_double ABI::Windows::Foundation::Collections::IVectorView<DOUBLE>
//#define __FIVectorView_1_double_t ABI::Windows::Foundation::Collections::IVectorView<DOUBLE>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_double_USE */




#ifndef DEF___FIIterator_1_float_USE
#define DEF___FIIterator_1_float_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("42614e61-b0aa-5e72-9354-2771db20b7a8"))
IIterator<float> : IIterator_impl<float> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Single>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<float> __FIIterator_1_float_t;
#define __FIIterator_1_float ABI::Windows::Foundation::Collections::__FIIterator_1_float_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_float ABI::Windows::Foundation::Collections::IIterator<FLOAT>
//#define __FIIterator_1_float_t ABI::Windows::Foundation::Collections::IIterator<FLOAT>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_float_USE */




#ifndef DEF___FIIterable_1_float_USE
#define DEF___FIIterable_1_float_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("b01bee51-063a-5fda-bd72-d76637bb8cb8"))
IIterable<float> : IIterable_impl<float> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Single>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<float> __FIIterable_1_float_t;
#define __FIIterable_1_float ABI::Windows::Foundation::Collections::__FIIterable_1_float_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_float ABI::Windows::Foundation::Collections::IIterable<FLOAT>
//#define __FIIterable_1_float_t ABI::Windows::Foundation::Collections::IIterable<FLOAT>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_float_USE */




#ifndef DEF___FIVectorView_1_float_USE
#define DEF___FIVectorView_1_float_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("7bca64fd-150c-5d50-b56b-9f4f474c5930"))
IVectorView<float> : IVectorView_impl<float> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Single>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<float> __FIVectorView_1_float_t;
#define __FIVectorView_1_float ABI::Windows::Foundation::Collections::__FIVectorView_1_float_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_float ABI::Windows::Foundation::Collections::IVectorView<FLOAT>
//#define __FIVectorView_1_float_t ABI::Windows::Foundation::Collections::IVectorView<FLOAT>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_float_USE */




#ifndef DEF___FIIterator_1_short_USE
#define DEF___FIIterator_1_short_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("5409069f-e7c1-5732-bb69-e5736f03f9a9"))
IIterator<short> : IIterator_impl<short> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Int16>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<short> __FIIterator_1_short_t;
#define __FIIterator_1_short ABI::Windows::Foundation::Collections::__FIIterator_1_short_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_short ABI::Windows::Foundation::Collections::IIterator<INT16>
//#define __FIIterator_1_short_t ABI::Windows::Foundation::Collections::IIterator<INT16>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_short_USE */




#ifndef DEF___FIIterable_1_short_USE
#define DEF___FIIterable_1_short_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("72ff2923-4b4e-53bb-8feb-41ec5f2bb734"))
IIterable<short> : IIterable_impl<short> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Int16>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<short> __FIIterable_1_short_t;
#define __FIIterable_1_short ABI::Windows::Foundation::Collections::__FIIterable_1_short_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_short ABI::Windows::Foundation::Collections::IIterable<INT16>
//#define __FIIterable_1_short_t ABI::Windows::Foundation::Collections::IIterable<INT16>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_short_USE */




#ifndef DEF___FIVectorView_1_short_USE
#define DEF___FIVectorView_1_short_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("e53056ad-8a0e-5c41-a62d-c92e3ac2de58"))
IVectorView<short> : IVectorView_impl<short> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Int16>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<short> __FIVectorView_1_short_t;
#define __FIVectorView_1_short ABI::Windows::Foundation::Collections::__FIVectorView_1_short_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_short ABI::Windows::Foundation::Collections::IVectorView<INT16>
//#define __FIVectorView_1_short_t ABI::Windows::Foundation::Collections::IVectorView<INT16>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_short_USE */




#ifndef DEF___FIIterator_1_int_USE
#define DEF___FIIterator_1_int_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("bfea7f78-50c2-5f1d-a6ea-9e978d2699ff"))
IIterator<int> : IIterator_impl<int> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Int32>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<int> __FIIterator_1_int_t;
#define __FIIterator_1_int ABI::Windows::Foundation::Collections::__FIIterator_1_int_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_int ABI::Windows::Foundation::Collections::IIterator<INT32>
//#define __FIIterator_1_int_t ABI::Windows::Foundation::Collections::IIterator<INT32>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_int_USE */




#ifndef DEF___FIIterable_1_int_USE
#define DEF___FIIterable_1_int_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("81a643fb-f51c-5565-83c4-f96425777b66"))
IIterable<int> : IIterable_impl<int> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Int32>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<int> __FIIterable_1_int_t;
#define __FIIterable_1_int ABI::Windows::Foundation::Collections::__FIIterable_1_int_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_int ABI::Windows::Foundation::Collections::IIterable<INT32>
//#define __FIIterable_1_int_t ABI::Windows::Foundation::Collections::IIterable<INT32>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_int_USE */




#ifndef DEF___FIVectorView_1_int_USE
#define DEF___FIVectorView_1_int_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("8d720cdf-3934-5d3f-9a55-40e8063b086a"))
IVectorView<int> : IVectorView_impl<int> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Int32>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<int> __FIVectorView_1_int_t;
#define __FIVectorView_1_int ABI::Windows::Foundation::Collections::__FIVectorView_1_int_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_int ABI::Windows::Foundation::Collections::IVectorView<INT32>
//#define __FIVectorView_1_int_t ABI::Windows::Foundation::Collections::IVectorView<INT32>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_int_USE */




#ifndef DEF___FIIterator_1_byte_USE
#define DEF___FIIterator_1_byte_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("40556131-a2a1-5fab-aaee-5f35268ca26b"))
IIterator<::byte> : IIterator_impl<::byte> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<UInt8>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<::byte> __FIIterator_1_byte_t;
#define __FIIterator_1_byte ABI::Windows::Foundation::Collections::__FIIterator_1_byte_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_byte ABI::Windows::Foundation::Collections::IIterator<BYTE>
//#define __FIIterator_1_byte_t ABI::Windows::Foundation::Collections::IIterator<BYTE>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_byte_USE */




#ifndef DEF___FIIterable_1_byte_USE
#define DEF___FIIterable_1_byte_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("88318266-f3fd-50fc-8f08-b823a41b60c1"))
IIterable<::byte> : IIterable_impl<::byte> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<UInt8>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<::byte> __FIIterable_1_byte_t;
#define __FIIterable_1_byte ABI::Windows::Foundation::Collections::__FIIterable_1_byte_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_byte ABI::Windows::Foundation::Collections::IIterable<BYTE>
//#define __FIIterable_1_byte_t ABI::Windows::Foundation::Collections::IIterable<BYTE>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_byte_USE */




#ifndef DEF___FIVectorView_1_byte_USE
#define DEF___FIVectorView_1_byte_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("6d05fb29-7885-544e-9382-a1ad391a3fa4"))
IVectorView<::byte> : IVectorView_impl<::byte> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<UInt8>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<::byte> __FIVectorView_1_byte_t;
#define __FIVectorView_1_byte ABI::Windows::Foundation::Collections::__FIVectorView_1_byte_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_byte ABI::Windows::Foundation::Collections::IVectorView<BYTE>
//#define __FIVectorView_1_byte_t ABI::Windows::Foundation::Collections::IVectorView<BYTE>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_byte_USE */




#ifndef DEF___FIIterator_1_HSTRING_USE
#define DEF___FIIterator_1_HSTRING_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("8c304ebb-6615-50a4-8829-879ecd443236"))
IIterator<HSTRING> : IIterator_impl<HSTRING> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<String>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<HSTRING> __FIIterator_1_HSTRING_t;
#define __FIIterator_1_HSTRING ABI::Windows::Foundation::Collections::__FIIterator_1_HSTRING_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_HSTRING ABI::Windows::Foundation::Collections::IIterator<HSTRING>
//#define __FIIterator_1_HSTRING_t ABI::Windows::Foundation::Collections::IIterator<HSTRING>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_HSTRING_USE */




#ifndef DEF___FIIterable_1_HSTRING_USE
#define DEF___FIIterable_1_HSTRING_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("e2fcc7c1-3bfc-5a0b-b2b0-72e769d1cb7e"))
IIterable<HSTRING> : IIterable_impl<HSTRING> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<String>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<HSTRING> __FIIterable_1_HSTRING_t;
#define __FIIterable_1_HSTRING ABI::Windows::Foundation::Collections::__FIIterable_1_HSTRING_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_HSTRING ABI::Windows::Foundation::Collections::IIterable<HSTRING>
//#define __FIIterable_1_HSTRING_t ABI::Windows::Foundation::Collections::IIterable<HSTRING>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_HSTRING_USE */




#ifndef DEF___FIVectorView_1_HSTRING_USE
#define DEF___FIVectorView_1_HSTRING_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("2f13c006-a03a-5f69-b090-75a43e33423e"))
IVectorView<HSTRING> : IVectorView_impl<HSTRING> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<String>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<HSTRING> __FIVectorView_1_HSTRING_t;
#define __FIVectorView_1_HSTRING ABI::Windows::Foundation::Collections::__FIVectorView_1_HSTRING_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_HSTRING ABI::Windows::Foundation::Collections::IVectorView<HSTRING>
//#define __FIVectorView_1_HSTRING_t ABI::Windows::Foundation::Collections::IVectorView<HSTRING>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_HSTRING_USE */




#ifndef DEF___FIIterator_1_UINT16_USE
#define DEF___FIIterator_1_UINT16_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("5738fc25-402b-5fc1-b1e4-0aa24ef652f1"))
IIterator<UINT16> : IIterator_impl<UINT16> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<UInt16>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<UINT16> __FIIterator_1_UINT16_t;
#define __FIIterator_1_UINT16 ABI::Windows::Foundation::Collections::__FIIterator_1_UINT16_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_UINT16 ABI::Windows::Foundation::Collections::IIterator<UINT16>
//#define __FIIterator_1_UINT16_t ABI::Windows::Foundation::Collections::IIterator<UINT16>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_UINT16_USE */




#ifndef DEF___FIIterable_1_UINT16_USE
#define DEF___FIIterable_1_UINT16_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("ecfa9a6f-fa2e-5345-b297-efb4e8c6be87"))
IIterable<UINT16> : IIterable_impl<UINT16> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<UInt16>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<UINT16> __FIIterable_1_UINT16_t;
#define __FIIterable_1_UINT16 ABI::Windows::Foundation::Collections::__FIIterable_1_UINT16_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_UINT16 ABI::Windows::Foundation::Collections::IIterable<UINT16>
//#define __FIIterable_1_UINT16_t ABI::Windows::Foundation::Collections::IIterable<UINT16>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_UINT16_USE */




#ifndef DEF___FIVectorView_1_UINT16_USE
#define DEF___FIVectorView_1_UINT16_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("9d0d0d9f-6a82-55a3-98c5-228499df38f9"))
IVectorView<UINT16> : IVectorView_impl<UINT16> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<UInt16>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<UINT16> __FIVectorView_1_UINT16_t;
#define __FIVectorView_1_UINT16 ABI::Windows::Foundation::Collections::__FIVectorView_1_UINT16_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_UINT16 ABI::Windows::Foundation::Collections::IVectorView<UINT16>
//#define __FIVectorView_1_UINT16_t ABI::Windows::Foundation::Collections::IVectorView<UINT16>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_UINT16_USE */




#ifndef DEF___FIIterator_1_UINT32_USE
#define DEF___FIIterator_1_UINT32_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("f06a2739-9443-5ef0-b284-dc5aff3e7d10"))
IIterator<UINT32> : IIterator_impl<UINT32> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<UInt32>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<UINT32> __FIIterator_1_UINT32_t;
#define __FIIterator_1_UINT32 ABI::Windows::Foundation::Collections::__FIIterator_1_UINT32_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_UINT32 ABI::Windows::Foundation::Collections::IIterator<UINT32>
//#define __FIIterator_1_UINT32_t ABI::Windows::Foundation::Collections::IIterator<UINT32>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_UINT32_USE */




#ifndef DEF___FIIterable_1_UINT32_USE
#define DEF___FIIterable_1_UINT32_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("421d4b91-b13b-5f37-ae54-b5249bd80539"))
IIterable<UINT32> : IIterable_impl<UINT32> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<UInt32>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<UINT32> __FIIterable_1_UINT32_t;
#define __FIIterable_1_UINT32 ABI::Windows::Foundation::Collections::__FIIterable_1_UINT32_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_UINT32 ABI::Windows::Foundation::Collections::IIterable<UINT32>
//#define __FIIterable_1_UINT32_t ABI::Windows::Foundation::Collections::IIterable<UINT32>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_UINT32_USE */




#ifndef DEF___FIVectorView_1_UINT32_USE
#define DEF___FIVectorView_1_UINT32_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("e5ce1a07-8d33-5007-ba64-7d2508ccf85c"))
IVectorView<UINT32> : IVectorView_impl<UINT32> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<UInt32>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<UINT32> __FIVectorView_1_UINT32_t;
#define __FIVectorView_1_UINT32 ABI::Windows::Foundation::Collections::__FIVectorView_1_UINT32_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_UINT32 ABI::Windows::Foundation::Collections::IVectorView<UINT32>
//#define __FIVectorView_1_UINT32_t ABI::Windows::Foundation::Collections::IVectorView<UINT32>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_UINT32_USE */




#ifndef DEF___FIIterator_1_UINT64_USE
#define DEF___FIIterator_1_UINT64_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("c473ed96-76e3-5ff2-9435-47feebfe9539"))
IIterator<UINT64> : IIterator_impl<UINT64> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<UInt64>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<UINT64> __FIIterator_1_UINT64_t;
#define __FIIterator_1_UINT64 ABI::Windows::Foundation::Collections::__FIIterator_1_UINT64_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_UINT64 ABI::Windows::Foundation::Collections::IIterator<UINT64>
//#define __FIIterator_1_UINT64_t ABI::Windows::Foundation::Collections::IIterator<UINT64>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_UINT64_USE */




#ifndef DEF___FIIterable_1_UINT64_USE
#define DEF___FIIterable_1_UINT64_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("4b3a3229-7995-5f3c-b248-6c1f7e664f01"))
IIterable<UINT64> : IIterable_impl<UINT64> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<UInt64>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<UINT64> __FIIterable_1_UINT64_t;
#define __FIIterable_1_UINT64 ABI::Windows::Foundation::Collections::__FIIterable_1_UINT64_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_UINT64 ABI::Windows::Foundation::Collections::IIterable<UINT64>
//#define __FIIterable_1_UINT64_t ABI::Windows::Foundation::Collections::IIterable<UINT64>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_UINT64_USE */




#ifndef DEF___FIVectorView_1_UINT64_USE
#define DEF___FIVectorView_1_UINT64_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("23d156c7-7ef9-5096-aaba-1e6c9ab5ceb4"))
IVectorView<UINT64> : IVectorView_impl<UINT64> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<UInt64>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<UINT64> __FIVectorView_1_UINT64_t;
#define __FIVectorView_1_UINT64 ABI::Windows::Foundation::Collections::__FIVectorView_1_UINT64_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_UINT64 ABI::Windows::Foundation::Collections::IVectorView<UINT64>
//#define __FIVectorView_1_UINT64_t ABI::Windows::Foundation::Collections::IVectorView<UINT64>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_UINT64_USE */





#ifndef ____x_ABI_CWindows_CFoundation_CCollections_CIPropertySet_FWD_DEFINED__
#define ____x_ABI_CWindows_CFoundation_CCollections_CIPropertySet_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Foundation {
            namespace Collections {
                interface IPropertySet;
            } /* Collections */
        } /* Foundation */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CFoundation_CCollections_CIPropertySet ABI::Windows::Foundation::Collections::IPropertySet

#endif // ____x_ABI_CWindows_CFoundation_CCollections_CIPropertySet_FWD_DEFINED__





#ifndef ____x_ABI_CWindows_CFoundation_CIClosable_FWD_DEFINED__
#define ____x_ABI_CWindows_CFoundation_CIClosable_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Foundation {
            interface IClosable;
        } /* Foundation */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CFoundation_CIClosable ABI::Windows::Foundation::IClosable

#endif // ____x_ABI_CWindows_CFoundation_CIClosable_FWD_DEFINED__


#ifndef ____x_ABI_CWindows_CFoundation_CIMemoryBuffer_FWD_DEFINED__
#define ____x_ABI_CWindows_CFoundation_CIMemoryBuffer_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Foundation {
            interface IMemoryBuffer;
        } /* Foundation */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CFoundation_CIMemoryBuffer ABI::Windows::Foundation::IMemoryBuffer

#endif // ____x_ABI_CWindows_CFoundation_CIMemoryBuffer_FWD_DEFINED__




#ifndef ____x_ABI_CWindows_CGraphics_CDirectX_CDirect3D11_CIDirect3DDevice_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDirectX_CDirect3D11_CIDirect3DDevice_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace DirectX {
                namespace Direct3D11 {
                    interface IDirect3DDevice;
                } /* Direct3D11 */
            } /* DirectX */
        } /* Graphics */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CGraphics_CDirectX_CDirect3D11_CIDirect3DDevice ABI::Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice

#endif // ____x_ABI_CWindows_CGraphics_CDirectX_CDirect3D11_CIDirect3DDevice_FWD_DEFINED__






namespace ABI {
    namespace Windows {
        namespace Graphics {
            
            typedef struct DisplayAdapterId DisplayAdapterId;
            
        } /* Graphics */
    } /* Windows */} /* ABI */



namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Imaging {
                
                typedef enum BitmapAlphaMode : int BitmapAlphaMode;
                
            } /* Imaging */
        } /* Graphics */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Imaging {
                
                typedef enum BitmapPixelFormat : int BitmapPixelFormat;
                
            } /* Imaging */
        } /* Graphics */
    } /* Windows */} /* ABI */




namespace ABI {
    namespace Windows {
        namespace Media {
            class VideoFrame;
        } /* Media */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CMedia_CIVideoFrame_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CIVideoFrame_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Media {
            interface IVideoFrame;
        } /* Media */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CMedia_CIVideoFrame ABI::Windows::Media::IVideoFrame

#endif // ____x_ABI_CWindows_CMedia_CIVideoFrame_FWD_DEFINED__




#ifndef ____x_ABI_CWindows_CStorage_CIStorageFile_FWD_DEFINED__
#define ____x_ABI_CWindows_CStorage_CIStorageFile_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Storage {
            interface IStorageFile;
        } /* Storage */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CStorage_CIStorageFile ABI::Windows::Storage::IStorageFile

#endif // ____x_ABI_CWindows_CStorage_CIStorageFile_FWD_DEFINED__




#ifndef ____x_ABI_CWindows_CStorage_CStreams_CIBuffer_FWD_DEFINED__
#define ____x_ABI_CWindows_CStorage_CStreams_CIBuffer_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Storage {
            namespace Streams {
                interface IBuffer;
            } /* Streams */
        } /* Storage */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CStorage_CStreams_CIBuffer ABI::Windows::Storage::Streams::IBuffer

#endif // ____x_ABI_CWindows_CStorage_CStreams_CIBuffer_FWD_DEFINED__


#ifndef ____x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStreamReference_FWD_DEFINED__
#define ____x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStreamReference_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Storage {
            namespace Streams {
                interface IRandomAccessStreamReference;
            } /* Streams */
        } /* Storage */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStreamReference ABI::Windows::Storage::Streams::IRandomAccessStreamReference

#endif // ____x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStreamReference_FWD_DEFINED__






namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                
                typedef enum LearningModelDeviceKind : int LearningModelDeviceKind;
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                
                typedef enum LearningModelFeatureKind : int LearningModelFeatureKind;
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                
                typedef enum TensorKind : int TensorKind;
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */






























































namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                class ImageFeatureDescriptor;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                class ImageFeatureValue;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */



namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                class LearningModelBinding;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                class LearningModelDevice;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */



namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                class LearningModelSession;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                class LearningModelSessionOptions;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                class MapFeatureDescriptor;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                class SequenceFeatureDescriptor;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                class TensorBoolean;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                class TensorDouble;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                class TensorFeatureDescriptor;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                class TensorFloat;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                class TensorFloat16Bit;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                class TensorInt16Bit;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                class TensorInt32Bit;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                class TensorInt64Bit;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                class TensorInt8Bit;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                class TensorString;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                class TensorUInt16Bit;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                class TensorUInt32Bit;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                class TensorUInt64Bit;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                class TensorUInt8Bit;
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */











/*
 *
 * Struct Windows.AI.MachineLearning.LearningModelDeviceKind
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 */

#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [v1_enum, contract] */
                enum LearningModelDeviceKind : int
                {
                    LearningModelDeviceKind_Default = 0,
                    LearningModelDeviceKind_Cpu = 1,
                    LearningModelDeviceKind_DirectX = 2,
                    LearningModelDeviceKind_DirectXHighPerformance = 3,
                    LearningModelDeviceKind_DirectXMinPower = 4,
                };
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.AI.MachineLearning.LearningModelFeatureKind
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 */

#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [v1_enum, contract] */
                enum LearningModelFeatureKind : int
                {
                    LearningModelFeatureKind_Tensor = 0,
                    LearningModelFeatureKind_Sequence = 1,
                    LearningModelFeatureKind_Map = 2,
                    LearningModelFeatureKind_Image = 3,
                };
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.AI.MachineLearning.TensorKind
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 */

#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [v1_enum, contract] */
                enum TensorKind : int
                {
                    TensorKind_Undefined = 0,
                    TensorKind_Float = 1,
                    TensorKind_UInt8 = 2,
                    TensorKind_Int8 = 3,
                    TensorKind_UInt16 = 4,
                    TensorKind_Int16 = 5,
                    TensorKind_Int32 = 6,
                    TensorKind_Int64 = 7,
                    TensorKind_String = 8,
                    TensorKind_Boolean = 9,
                    TensorKind_Float16 = 10,
                    TensorKind_Double = 11,
                    TensorKind_UInt32 = 12,
                    TensorKind_UInt64 = 13,
                    TensorKind_Complex64 = 14,
                    TensorKind_Complex128 = 15,
                };
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.IImageFeatureDescriptor
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.ImageFeatureDescriptor
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_IImageFeatureDescriptor[] = L"Windows.AI.MachineLearning.IImageFeatureDescriptor";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("365585A5-171A-4A2A-985F-265159D3895A"), exclusiveto, contract] */
                MIDL_INTERFACE("365585A5-171A-4A2A-985F-265159D3895A")
                IImageFeatureDescriptor : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_BitmapPixelFormat(
                        /* [retval, out] */__RPC__out ABI::Windows::Graphics::Imaging::BitmapPixelFormat * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_BitmapAlphaMode(
                        /* [retval, out] */__RPC__out ABI::Windows::Graphics::Imaging::BitmapAlphaMode * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Width(
                        /* [retval, out] */__RPC__out UINT32 * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Height(
                        /* [retval, out] */__RPC__out UINT32 * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IImageFeatureDescriptor=_uuidof(IImageFeatureDescriptor);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.IImageFeatureValue
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.ImageFeatureValue
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValue_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValue_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_IImageFeatureValue[] = L"Windows.AI.MachineLearning.IImageFeatureValue";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("F0414FD9-C9AA-4405-B7FB-94F87C8A3037"), exclusiveto, contract] */
                MIDL_INTERFACE("F0414FD9-C9AA-4405-B7FB-94F87C8A3037")
                IImageFeatureValue : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_VideoFrame(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Media::IVideoFrame * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IImageFeatureValue=_uuidof(IImageFeatureValue);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValue;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValue_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.IImageFeatureValueStatics
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.ImageFeatureValue
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_IImageFeatureValueStatics[] = L"Windows.AI.MachineLearning.IImageFeatureValueStatics";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("1BC317FD-23CB-4610-B085-C8E1C87EBAA0"), exclusiveto, contract] */
                MIDL_INTERFACE("1BC317FD-23CB-4610-B085-C8E1C87EBAA0")
                IImageFeatureValueStatics : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE CreateFromVideoFrame(
                        /* [in] */__RPC__in_opt ABI::Windows::Media::IVideoFrame * image,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::IImageFeatureValue * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IImageFeatureValueStatics=_uuidof(IImageFeatureValueStatics);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueStatics;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ILearningModel
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.LearningModel
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModel_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModel_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ILearningModel[] = L"Windows.AI.MachineLearning.ILearningModel";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("5B8E4920-489F-4E86-9128-265A327B78FA"), exclusiveto, contract] */
                MIDL_INTERFACE("5B8E4920-489F-4E86-9128-265A327B78FA")
                ILearningModel : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Author(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Name(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Domain(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Description(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Version(
                        /* [retval, out] */__RPC__out INT64 * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Metadata(
                        /* [retval, out] */__RPC__deref_out_opt __FIMapView_2_HSTRING_HSTRING * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_InputFeatures(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_OutputFeatures(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ILearningModel=_uuidof(ILearningModel);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CILearningModel;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModel_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ILearningModelBinding
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.LearningModelBinding
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ILearningModelBinding[] = L"Windows.AI.MachineLearning.ILearningModelBinding";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("EA312F20-168F-4F8C-94FE-2E7AC31B4AA8"), exclusiveto, contract] */
                MIDL_INTERFACE("EA312F20-168F-4F8C-94FE-2E7AC31B4AA8")
                ILearningModelBinding : public IInspectable
                {
                public:
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE Bind(
                        /* [in] */__RPC__in HSTRING name,
                        /* [in] */__RPC__in_opt IInspectable * value
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE BindWithProperties(
                        /* [in] */__RPC__in HSTRING name,
                        /* [in] */__RPC__in_opt IInspectable * value,
                        /* [in] */__RPC__in_opt ABI::Windows::Foundation::Collections::IPropertySet * props
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE Clear(void) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ILearningModelBinding=_uuidof(ILearningModelBinding);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ILearningModelBindingFactory
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.LearningModelBinding
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ILearningModelBindingFactory[] = L"Windows.AI.MachineLearning.ILearningModelBindingFactory";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("C95F7A7A-E788-475E-8917-23AA381FAF0B"), exclusiveto, contract] */
                MIDL_INTERFACE("C95F7A7A-E788-475E-8917-23AA381FAF0B")
                ILearningModelBindingFactory : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE CreateFromSession(
                        /* [in] */__RPC__in_opt ABI::Windows::AI::MachineLearning::ILearningModelSession * session,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ILearningModelBinding * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ILearningModelBindingFactory=_uuidof(ILearningModelBindingFactory);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingFactory;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ILearningModelDevice
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.LearningModelDevice
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ILearningModelDevice[] = L"Windows.AI.MachineLearning.ILearningModelDevice";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("F5C2C8FE-3F56-4A8C-AC5F-FDB92D8B8252"), exclusiveto, contract] */
                MIDL_INTERFACE("F5C2C8FE-3F56-4A8C-AC5F-FDB92D8B8252")
                ILearningModelDevice : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_AdapterId(
                        /* [retval, out] */__RPC__out ABI::Windows::Graphics::DisplayAdapterId * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Direct3D11Device(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ILearningModelDevice=_uuidof(ILearningModelDevice);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ILearningModelDeviceFactory
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.LearningModelDevice
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ILearningModelDeviceFactory[] = L"Windows.AI.MachineLearning.ILearningModelDeviceFactory";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("9CFFD74D-B1E5-4F20-80AD-0A56690DB06B"), exclusiveto, contract] */
                MIDL_INTERFACE("9CFFD74D-B1E5-4F20-80AD-0A56690DB06B")
                ILearningModelDeviceFactory : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE Create(
                        /* [in] */ABI::Windows::AI::MachineLearning::LearningModelDeviceKind deviceKind,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ILearningModelDevice * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ILearningModelDeviceFactory=_uuidof(ILearningModelDeviceFactory);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceFactory;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ILearningModelDeviceStatics
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.LearningModelDevice
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ILearningModelDeviceStatics[] = L"Windows.AI.MachineLearning.ILearningModelDeviceStatics";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("49F32107-A8BF-42BB-92C7-10B12DC5D21F"), exclusiveto, contract] */
                MIDL_INTERFACE("49F32107-A8BF-42BB-92C7-10B12DC5D21F")
                ILearningModelDeviceStatics : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE CreateFromDirect3D11Device(
                        /* [in] */__RPC__in_opt ABI::Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice * device,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ILearningModelDevice * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ILearningModelDeviceStatics=_uuidof(ILearningModelDeviceStatics);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceStatics;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ILearningModelEvaluationResult
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.LearningModelEvaluationResult
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ILearningModelEvaluationResult[] = L"Windows.AI.MachineLearning.ILearningModelEvaluationResult";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("B2F9BFCD-960E-49C0-8593-EB190AE3EEE2"), exclusiveto, contract] */
                MIDL_INTERFACE("B2F9BFCD-960E-49C0-8593-EB190AE3EEE2")
                ILearningModelEvaluationResult : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_CorrelationId(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ErrorStatus(
                        /* [retval, out] */__RPC__out INT32 * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Succeeded(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Outputs(
                        /* [retval, out] */__RPC__deref_out_opt __FIMapView_2_HSTRING_IInspectable * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ILearningModelEvaluationResult=_uuidof(ILearningModelEvaluationResult);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ILearningModelFeatureDescriptor
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ILearningModelFeatureDescriptor[] = L"Windows.AI.MachineLearning.ILearningModelFeatureDescriptor";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("BC08CF7C-6ED0-4004-97BA-B9A2EECD2B4F"), contract] */
                MIDL_INTERFACE("BC08CF7C-6ED0-4004-97BA-B9A2EECD2B4F")
                ILearningModelFeatureDescriptor : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Name(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Description(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Kind(
                        /* [retval, out] */__RPC__out ABI::Windows::AI::MachineLearning::LearningModelFeatureKind * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsRequired(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ILearningModelFeatureDescriptor=_uuidof(ILearningModelFeatureDescriptor);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ILearningModelFeatureValue
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureValue_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureValue_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ILearningModelFeatureValue[] = L"Windows.AI.MachineLearning.ILearningModelFeatureValue";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("F51005DB-4085-4DFE-9FED-95EB0C0CF75C"), contract] */
                MIDL_INTERFACE("F51005DB-4085-4DFE-9FED-95EB0C0CF75C")
                ILearningModelFeatureValue : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Kind(
                        /* [retval, out] */__RPC__out ABI::Windows::AI::MachineLearning::LearningModelFeatureKind * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ILearningModelFeatureValue=_uuidof(ILearningModelFeatureValue);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureValue;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureValue_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ILearningModelOperatorProvider
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProvider_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProvider_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ILearningModelOperatorProvider[] = L"Windows.AI.MachineLearning.ILearningModelOperatorProvider";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("2A222E5D-AFB1-47ED-BFAD-B5B3A459EC04"), contract] */
                MIDL_INTERFACE("2A222E5D-AFB1-47ED-BFAD-B5B3A459EC04")
                ILearningModelOperatorProvider : public IInspectable
                {
                public:
                    
                };

                extern MIDL_CONST_ID IID & IID_ILearningModelOperatorProvider=_uuidof(ILearningModelOperatorProvider);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProvider;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProvider_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ILearningModelSession
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.LearningModelSession
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ILearningModelSession[] = L"Windows.AI.MachineLearning.ILearningModelSession";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("8E58F8F6-B787-4C11-90F0-7129AECA74A9"), exclusiveto, contract] */
                MIDL_INTERFACE("8E58F8F6-B787-4C11-90F0-7129AECA74A9")
                ILearningModelSession : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Model(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ILearningModel * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Device(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ILearningModelDevice * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_EvaluationProperties(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::Collections::IPropertySet * * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE EvaluateAsync(
                        /* [in] */__RPC__in_opt ABI::Windows::AI::MachineLearning::ILearningModelBinding * bindings,
                        /* [in] */__RPC__in HSTRING correlationId,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE EvaluateFeaturesAsync(
                        /* [in] */__RPC__in_opt __FIMap_2_HSTRING_IInspectable * features,
                        /* [in] */__RPC__in HSTRING correlationId,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE Evaluate(
                        /* [in] */__RPC__in_opt ABI::Windows::AI::MachineLearning::ILearningModelBinding * bindings,
                        /* [in] */__RPC__in HSTRING correlationId,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ILearningModelEvaluationResult * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE EvaluateFeatures(
                        /* [in] */__RPC__in_opt __FIMap_2_HSTRING_IInspectable * features,
                        /* [in] */__RPC__in HSTRING correlationId,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ILearningModelEvaluationResult * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ILearningModelSession=_uuidof(ILearningModelSession);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ILearningModelSessionFactory
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.LearningModelSession
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ILearningModelSessionFactory[] = L"Windows.AI.MachineLearning.ILearningModelSessionFactory";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("0F6B881D-1C9B-47B6-BFE0-F1CF62A67579"), exclusiveto, contract] */
                MIDL_INTERFACE("0F6B881D-1C9B-47B6-BFE0-F1CF62A67579")
                ILearningModelSessionFactory : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE CreateFromModel(
                        /* [in] */__RPC__in_opt ABI::Windows::AI::MachineLearning::ILearningModel * model,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ILearningModelSession * * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromModelOnDevice(
                        /* [in] */__RPC__in_opt ABI::Windows::AI::MachineLearning::ILearningModel * model,
                        /* [in] */__RPC__in_opt ABI::Windows::AI::MachineLearning::ILearningModelDevice * deviceToRunOn,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ILearningModelSession * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ILearningModelSessionFactory=_uuidof(ILearningModelSessionFactory);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ILearningModelSessionFactory2
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.LearningModelSession
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ILearningModelSessionFactory2[] = L"Windows.AI.MachineLearning.ILearningModelSessionFactory2";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("4E5C88BF-0A1F-5FEC-ADE0-2FD91E4EF29B"), exclusiveto, contract] */
                MIDL_INTERFACE("4E5C88BF-0A1F-5FEC-ADE0-2FD91E4EF29B")
                ILearningModelSessionFactory2 : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE CreateFromModelOnDeviceWithSessionOptions(
                        /* [in] */__RPC__in_opt ABI::Windows::AI::MachineLearning::ILearningModel * model,
                        /* [in] */__RPC__in_opt ABI::Windows::AI::MachineLearning::ILearningModelDevice * deviceToRunOn,
                        /* [in] */__RPC__in_opt ABI::Windows::AI::MachineLearning::ILearningModelSessionOptions * learningModelSessionOptions,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ILearningModelSession * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ILearningModelSessionFactory2=_uuidof(ILearningModelSessionFactory2);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory2;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory2_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.AI.MachineLearning.ILearningModelSessionOptions
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.LearningModelSessionOptions
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptions_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptions_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ILearningModelSessionOptions[] = L"Windows.AI.MachineLearning.ILearningModelSessionOptions";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("B8F63FA1-134D-5133-8CFF-3A5C3C263BEB"), exclusiveto, contract] */
                MIDL_INTERFACE("B8F63FA1-134D-5133-8CFF-3A5C3C263BEB")
                ILearningModelSessionOptions : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_BatchSizeOverride(
                        /* [retval, out] */__RPC__out UINT32 * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_BatchSizeOverride(
                        /* [in] */UINT32 value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ILearningModelSessionOptions=_uuidof(ILearningModelSessionOptions);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptions;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptions_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.AI.MachineLearning.ILearningModelStatics
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.LearningModel
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ILearningModelStatics[] = L"Windows.AI.MachineLearning.ILearningModelStatics";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("E3B977E8-6952-4E47-8EF4-1F7F07897C6D"), exclusiveto, contract] */
                MIDL_INTERFACE("E3B977E8-6952-4E47-8EF4-1F7F07897C6D")
                ILearningModelStatics : public IInspectable
                {
                public:
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE LoadFromStorageFileAsync(
                        /* [in] */__RPC__in_opt ABI::Windows::Storage::IStorageFile * modelFile,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel * * operation
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE LoadFromStreamAsync(
                        /* [in] */__RPC__in_opt ABI::Windows::Storage::Streams::IRandomAccessStreamReference * modelStream,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel * * operation
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE LoadFromFilePath(
                        /* [in] */__RPC__in HSTRING filePath,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ILearningModel * * result
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE LoadFromStream(
                        /* [in] */__RPC__in_opt ABI::Windows::Storage::Streams::IRandomAccessStreamReference * modelStream,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ILearningModel * * result
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE LoadFromStorageFileWithOperatorProviderAsync(
                        /* [in] */__RPC__in_opt ABI::Windows::Storage::IStorageFile * modelFile,
                        /* [in] */__RPC__in_opt ABI::Windows::AI::MachineLearning::ILearningModelOperatorProvider * operatorProvider,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel * * operation
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE LoadFromStreamWithOperatorProviderAsync(
                        /* [in] */__RPC__in_opt ABI::Windows::Storage::Streams::IRandomAccessStreamReference * modelStream,
                        /* [in] */__RPC__in_opt ABI::Windows::AI::MachineLearning::ILearningModelOperatorProvider * operatorProvider,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel * * operation
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE LoadFromFilePathWithOperatorProvider(
                        /* [in] */__RPC__in HSTRING filePath,
                        /* [in] */__RPC__in_opt ABI::Windows::AI::MachineLearning::ILearningModelOperatorProvider * operatorProvider,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ILearningModel * * result
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE LoadFromStreamWithOperatorProvider(
                        /* [in] */__RPC__in_opt ABI::Windows::Storage::Streams::IRandomAccessStreamReference * modelStream,
                        /* [in] */__RPC__in_opt ABI::Windows::AI::MachineLearning::ILearningModelOperatorProvider * operatorProvider,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ILearningModel * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ILearningModelStatics=_uuidof(ILearningModelStatics);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.IMapFeatureDescriptor
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.MapFeatureDescriptor
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptor_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptor_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_IMapFeatureDescriptor[] = L"Windows.AI.MachineLearning.IMapFeatureDescriptor";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("530424BD-A257-436D-9E60-C2981F7CC5C4"), exclusiveto, contract] */
                MIDL_INTERFACE("530424BD-A257-436D-9E60-C2981F7CC5C4")
                IMapFeatureDescriptor : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_KeyKind(
                        /* [retval, out] */__RPC__out ABI::Windows::AI::MachineLearning::TensorKind * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ValueDescriptor(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ILearningModelFeatureDescriptor * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IMapFeatureDescriptor=_uuidof(IMapFeatureDescriptor);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptor;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptor_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ISequenceFeatureDescriptor
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.SequenceFeatureDescriptor
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CISequenceFeatureDescriptor_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CISequenceFeatureDescriptor_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ISequenceFeatureDescriptor[] = L"Windows.AI.MachineLearning.ISequenceFeatureDescriptor";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("84F6945A-562B-4D62-A851-739ACED96668"), exclusiveto, contract] */
                MIDL_INTERFACE("84F6945A-562B-4D62-A851-739ACED96668")
                ISequenceFeatureDescriptor : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ElementDescriptor(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ILearningModelFeatureDescriptor * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ISequenceFeatureDescriptor=_uuidof(ISequenceFeatureDescriptor);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CISequenceFeatureDescriptor;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CISequenceFeatureDescriptor_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensor
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Any object which implements this interface must also implement the following interfaces:
 *     Windows.AI.MachineLearning.ILearningModelFeatureValue
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensor_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensor_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensor[] = L"Windows.AI.MachineLearning.ITensor";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("05489593-A305-4A25-AD09-440119B4B7F6"), contract] */
                MIDL_INTERFACE("05489593-A305-4A25-AD09-440119B4B7F6")
                ITensor : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_TensorKind(
                        /* [retval, out] */__RPC__out ABI::Windows::AI::MachineLearning::TensorKind * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Shape(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1___z__zint64 * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensor=_uuidof(ITensor);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensor;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensor_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorBoolean
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorBoolean
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorBoolean[] = L"Windows.AI.MachineLearning.ITensorBoolean";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("50F311ED-29E9-4A5C-A44D-8FC512584EED"), exclusiveto, contract] */
                MIDL_INTERFACE("50F311ED-29E9-4A5C-A44D-8FC512584EED")
                ITensorBoolean : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetAsVectorView(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_boolean * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorBoolean=_uuidof(ITensorBoolean);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorBooleanStatics
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorBoolean
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorBooleanStatics[] = L"Windows.AI.MachineLearning.ITensorBooleanStatics";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("2796862C-2357-49A7-B476-D0AA3DFE6866"), exclusiveto, contract] */
                MIDL_INTERFACE("2796862C-2357-49A7-B476-D0AA3DFE6866")
                ITensorBooleanStatics : public IInspectable
                {
                public:
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE Create(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorBoolean * * result
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE Create2(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorBoolean * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromArray(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [in] */UINT32 __dataSize,
                        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) ::boolean * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorBoolean * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromIterable(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [in] */__RPC__in_opt __FIIterable_1_boolean * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorBoolean * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorBooleanStatics=_uuidof(ITensorBooleanStatics);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorBooleanStatics2
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorBoolean
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorBooleanStatics2[] = L"Windows.AI.MachineLearning.ITensorBooleanStatics2";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("A3A4A501-6A2D-52D7-B04B-C435BAEE0115"), exclusiveto, contract] */
                MIDL_INTERFACE("A3A4A501-6A2D-52D7-B04B-C435BAEE0115")
                ITensorBooleanStatics2 : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE CreateFromShapeArrayAndDataArray(
                        /* [in] */UINT32 __shapeSize,
                        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
                        /* [in] */UINT32 __dataSize,
                        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) ::boolean * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorBoolean * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromBuffer(
                        /* [in] */UINT32 __shapeSize,
                        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
                        /* [in] */__RPC__in_opt ABI::Windows::Storage::Streams::IBuffer * buffer,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorBoolean * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorBooleanStatics2=_uuidof(ITensorBooleanStatics2);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorDouble
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorDouble
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorDouble[] = L"Windows.AI.MachineLearning.ITensorDouble";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("91E41252-7A8F-4F0E-A28F-9637FFC8A3D0"), exclusiveto, contract] */
                MIDL_INTERFACE("91E41252-7A8F-4F0E-A28F-9637FFC8A3D0")
                ITensorDouble : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetAsVectorView(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_double * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorDouble=_uuidof(ITensorDouble);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorDoubleStatics
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorDouble
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorDoubleStatics[] = L"Windows.AI.MachineLearning.ITensorDoubleStatics";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("A86693C5-9538-44E7-A3CA-5DF374A5A70C"), exclusiveto, contract] */
                MIDL_INTERFACE("A86693C5-9538-44E7-A3CA-5DF374A5A70C")
                ITensorDoubleStatics : public IInspectable
                {
                public:
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE Create(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorDouble * * result
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE Create2(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorDouble * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromArray(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [in] */UINT32 __dataSize,
                        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) DOUBLE * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorDouble * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromIterable(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [in] */__RPC__in_opt __FIIterable_1_double * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorDouble * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorDoubleStatics=_uuidof(ITensorDoubleStatics);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorDoubleStatics2
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorDouble
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorDoubleStatics2[] = L"Windows.AI.MachineLearning.ITensorDoubleStatics2";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("93A570DE-5E9A-5094-85C8-592C655E68AC"), exclusiveto, contract] */
                MIDL_INTERFACE("93A570DE-5E9A-5094-85C8-592C655E68AC")
                ITensorDoubleStatics2 : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE CreateFromShapeArrayAndDataArray(
                        /* [in] */UINT32 __shapeSize,
                        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
                        /* [in] */UINT32 __dataSize,
                        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) DOUBLE * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorDouble * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromBuffer(
                        /* [in] */UINT32 __shapeSize,
                        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
                        /* [in] */__RPC__in_opt ABI::Windows::Storage::Streams::IBuffer * buffer,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorDouble * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorDoubleStatics2=_uuidof(ITensorDoubleStatics2);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorFeatureDescriptor
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorFeatureDescriptor
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptor_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptor_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorFeatureDescriptor[] = L"Windows.AI.MachineLearning.ITensorFeatureDescriptor";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("74455C80-946A-4310-A19C-EE0AF028FCE4"), exclusiveto, contract] */
                MIDL_INTERFACE("74455C80-946A-4310-A19C-EE0AF028FCE4")
                ITensorFeatureDescriptor : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_TensorKind(
                        /* [retval, out] */__RPC__out ABI::Windows::AI::MachineLearning::TensorKind * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Shape(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1___z__zint64 * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorFeatureDescriptor=_uuidof(ITensorFeatureDescriptor);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptor;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptor_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorFloat
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorFloat
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorFloat[] = L"Windows.AI.MachineLearning.ITensorFloat";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("F2282D82-AA02-42C8-A0C8-DF1EFC9676E1"), exclusiveto, contract] */
                MIDL_INTERFACE("F2282D82-AA02-42C8-A0C8-DF1EFC9676E1")
                ITensorFloat : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetAsVectorView(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_float * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorFloat=_uuidof(ITensorFloat);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorFloat16Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorFloat16Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorFloat16Bit[] = L"Windows.AI.MachineLearning.ITensorFloat16Bit";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("0AB994FC-5B89-4C3C-B5E4-5282A5316C0A"), exclusiveto, contract] */
                MIDL_INTERFACE("0AB994FC-5B89-4C3C-B5E4-5282A5316C0A")
                ITensorFloat16Bit : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetAsVectorView(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_float * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorFloat16Bit=_uuidof(ITensorFloat16Bit);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorFloat16BitStatics
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorFloat16Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorFloat16BitStatics[] = L"Windows.AI.MachineLearning.ITensorFloat16BitStatics";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("A52DB6F5-318A-44D4-820B-0CDC7054A84A"), exclusiveto, contract] */
                MIDL_INTERFACE("A52DB6F5-318A-44D4-820B-0CDC7054A84A")
                ITensorFloat16BitStatics : public IInspectable
                {
                public:
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE Create(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorFloat16Bit * * result
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE Create2(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorFloat16Bit * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromArray(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [in] */UINT32 __dataSize,
                        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) FLOAT * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorFloat16Bit * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromIterable(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [in] */__RPC__in_opt __FIIterable_1_float * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorFloat16Bit * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorFloat16BitStatics=_uuidof(ITensorFloat16BitStatics);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorFloat16BitStatics2
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorFloat16Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorFloat16BitStatics2[] = L"Windows.AI.MachineLearning.ITensorFloat16BitStatics2";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("68545726-2DC7-51BF-B470-0B344CC2A1BC"), exclusiveto, contract] */
                MIDL_INTERFACE("68545726-2DC7-51BF-B470-0B344CC2A1BC")
                ITensorFloat16BitStatics2 : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE CreateFromShapeArrayAndDataArray(
                        /* [in] */UINT32 __shapeSize,
                        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
                        /* [in] */UINT32 __dataSize,
                        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) FLOAT * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorFloat16Bit * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromBuffer(
                        /* [in] */UINT32 __shapeSize,
                        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
                        /* [in] */__RPC__in_opt ABI::Windows::Storage::Streams::IBuffer * buffer,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorFloat16Bit * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorFloat16BitStatics2=_uuidof(ITensorFloat16BitStatics2);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorFloatStatics
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorFloat
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorFloatStatics[] = L"Windows.AI.MachineLearning.ITensorFloatStatics";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("DBCD395B-3BA3-452F-B10D-3C135E573FA9"), exclusiveto, contract] */
                MIDL_INTERFACE("DBCD395B-3BA3-452F-B10D-3C135E573FA9")
                ITensorFloatStatics : public IInspectable
                {
                public:
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE Create(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorFloat * * result
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE Create2(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorFloat * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromArray(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [in] */UINT32 __dataSize,
                        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) FLOAT * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorFloat * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromIterable(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [in] */__RPC__in_opt __FIIterable_1_float * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorFloat * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorFloatStatics=_uuidof(ITensorFloatStatics);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorFloatStatics2
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorFloat
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorFloatStatics2[] = L"Windows.AI.MachineLearning.ITensorFloatStatics2";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("24610BC1-5E44-5713-B281-8F4AD4D555E8"), exclusiveto, contract] */
                MIDL_INTERFACE("24610BC1-5E44-5713-B281-8F4AD4D555E8")
                ITensorFloatStatics2 : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE CreateFromShapeArrayAndDataArray(
                        /* [in] */UINT32 __shapeSize,
                        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
                        /* [in] */UINT32 __dataSize,
                        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) FLOAT * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorFloat * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromBuffer(
                        /* [in] */UINT32 __shapeSize,
                        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
                        /* [in] */__RPC__in_opt ABI::Windows::Storage::Streams::IBuffer * buffer,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorFloat * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorFloatStatics2=_uuidof(ITensorFloatStatics2);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorInt16Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorInt16Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorInt16Bit[] = L"Windows.AI.MachineLearning.ITensorInt16Bit";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("98A32D39-E6D6-44AF-8AFA-BAEBC44DC020"), exclusiveto, contract] */
                MIDL_INTERFACE("98A32D39-E6D6-44AF-8AFA-BAEBC44DC020")
                ITensorInt16Bit : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetAsVectorView(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_short * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorInt16Bit=_uuidof(ITensorInt16Bit);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorInt16BitStatics
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorInt16Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorInt16BitStatics[] = L"Windows.AI.MachineLearning.ITensorInt16BitStatics";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("98646293-266E-4B1A-821F-E60D70898B91"), exclusiveto, contract] */
                MIDL_INTERFACE("98646293-266E-4B1A-821F-E60D70898B91")
                ITensorInt16BitStatics : public IInspectable
                {
                public:
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE Create(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorInt16Bit * * result
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE Create2(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorInt16Bit * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromArray(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [in] */UINT32 __dataSize,
                        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) INT16 * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorInt16Bit * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromIterable(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [in] */__RPC__in_opt __FIIterable_1_short * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorInt16Bit * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorInt16BitStatics=_uuidof(ITensorInt16BitStatics);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorInt16BitStatics2
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorInt16Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorInt16BitStatics2[] = L"Windows.AI.MachineLearning.ITensorInt16BitStatics2";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("0CD70CF4-696C-5E5F-95D8-5EBF9670148B"), exclusiveto, contract] */
                MIDL_INTERFACE("0CD70CF4-696C-5E5F-95D8-5EBF9670148B")
                ITensorInt16BitStatics2 : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE CreateFromShapeArrayAndDataArray(
                        /* [in] */UINT32 __shapeSize,
                        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
                        /* [in] */UINT32 __dataSize,
                        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) INT16 * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorInt16Bit * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromBuffer(
                        /* [in] */UINT32 __shapeSize,
                        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
                        /* [in] */__RPC__in_opt ABI::Windows::Storage::Streams::IBuffer * buffer,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorInt16Bit * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorInt16BitStatics2=_uuidof(ITensorInt16BitStatics2);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorInt32Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorInt32Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorInt32Bit[] = L"Windows.AI.MachineLearning.ITensorInt32Bit";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("2C0C28D3-207C-4486-A7D2-884522C5E589"), exclusiveto, contract] */
                MIDL_INTERFACE("2C0C28D3-207C-4486-A7D2-884522C5E589")
                ITensorInt32Bit : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetAsVectorView(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_int * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorInt32Bit=_uuidof(ITensorInt32Bit);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorInt32BitStatics
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorInt32Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorInt32BitStatics[] = L"Windows.AI.MachineLearning.ITensorInt32BitStatics";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("6539864B-52FA-4E35-907C-834CAC417B50"), exclusiveto, contract] */
                MIDL_INTERFACE("6539864B-52FA-4E35-907C-834CAC417B50")
                ITensorInt32BitStatics : public IInspectable
                {
                public:
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE Create(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorInt32Bit * * result
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE Create2(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorInt32Bit * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromArray(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [in] */UINT32 __dataSize,
                        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) INT32 * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorInt32Bit * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromIterable(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [in] */__RPC__in_opt __FIIterable_1_int * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorInt32Bit * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorInt32BitStatics=_uuidof(ITensorInt32BitStatics);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorInt32BitStatics2
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorInt32Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorInt32BitStatics2[] = L"Windows.AI.MachineLearning.ITensorInt32BitStatics2";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("7C4B079A-E956-5CE0-A3BD-157D9D79B5EC"), exclusiveto, contract] */
                MIDL_INTERFACE("7C4B079A-E956-5CE0-A3BD-157D9D79B5EC")
                ITensorInt32BitStatics2 : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE CreateFromShapeArrayAndDataArray(
                        /* [in] */UINT32 __shapeSize,
                        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
                        /* [in] */UINT32 __dataSize,
                        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) INT32 * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorInt32Bit * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromBuffer(
                        /* [in] */UINT32 __shapeSize,
                        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
                        /* [in] */__RPC__in_opt ABI::Windows::Storage::Streams::IBuffer * buffer,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorInt32Bit * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorInt32BitStatics2=_uuidof(ITensorInt32BitStatics2);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorInt64Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorInt64Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorInt64Bit[] = L"Windows.AI.MachineLearning.ITensorInt64Bit";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("499665BA-1FA2-45AD-AF25-A0BD9BDA4C87"), exclusiveto, contract] */
                MIDL_INTERFACE("499665BA-1FA2-45AD-AF25-A0BD9BDA4C87")
                ITensorInt64Bit : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetAsVectorView(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1___z__zint64 * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorInt64Bit=_uuidof(ITensorInt64Bit);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorInt64BitStatics
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorInt64Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorInt64BitStatics[] = L"Windows.AI.MachineLearning.ITensorInt64BitStatics";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("9648AD9D-1198-4D74-9517-783AB62B9CC2"), exclusiveto, contract] */
                MIDL_INTERFACE("9648AD9D-1198-4D74-9517-783AB62B9CC2")
                ITensorInt64BitStatics : public IInspectable
                {
                public:
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE Create(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorInt64Bit * * result
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE Create2(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorInt64Bit * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromArray(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [in] */UINT32 __dataSize,
                        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) INT64 * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorInt64Bit * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromIterable(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorInt64Bit * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorInt64BitStatics=_uuidof(ITensorInt64BitStatics);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorInt64BitStatics2
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorInt64Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorInt64BitStatics2[] = L"Windows.AI.MachineLearning.ITensorInt64BitStatics2";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("6D3D9DCB-FF40-5EC2-89FE-084E2B6BC6DB"), exclusiveto, contract] */
                MIDL_INTERFACE("6D3D9DCB-FF40-5EC2-89FE-084E2B6BC6DB")
                ITensorInt64BitStatics2 : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE CreateFromShapeArrayAndDataArray(
                        /* [in] */UINT32 __shapeSize,
                        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
                        /* [in] */UINT32 __dataSize,
                        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) INT64 * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorInt64Bit * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromBuffer(
                        /* [in] */UINT32 __shapeSize,
                        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
                        /* [in] */__RPC__in_opt ABI::Windows::Storage::Streams::IBuffer * buffer,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorInt64Bit * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorInt64BitStatics2=_uuidof(ITensorInt64BitStatics2);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorInt8Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorInt8Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorInt8Bit[] = L"Windows.AI.MachineLearning.ITensorInt8Bit";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("CDDD97C5-FFD8-4FEF-AEFB-30E1A485B2EE"), exclusiveto, contract] */
                MIDL_INTERFACE("CDDD97C5-FFD8-4FEF-AEFB-30E1A485B2EE")
                ITensorInt8Bit : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetAsVectorView(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_byte * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorInt8Bit=_uuidof(ITensorInt8Bit);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorInt8BitStatics
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorInt8Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorInt8BitStatics[] = L"Windows.AI.MachineLearning.ITensorInt8BitStatics";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("B1A12284-095C-4C76-A661-AC4CEE1F3E8B"), exclusiveto, contract] */
                MIDL_INTERFACE("B1A12284-095C-4C76-A661-AC4CEE1F3E8B")
                ITensorInt8BitStatics : public IInspectable
                {
                public:
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE Create(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorInt8Bit * * result
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE Create2(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorInt8Bit * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromArray(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [in] */UINT32 __dataSize,
                        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) BYTE * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorInt8Bit * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromIterable(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [in] */__RPC__in_opt __FIIterable_1_byte * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorInt8Bit * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorInt8BitStatics=_uuidof(ITensorInt8BitStatics);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorInt8BitStatics2
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorInt8Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorInt8BitStatics2[] = L"Windows.AI.MachineLearning.ITensorInt8BitStatics2";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("C0D59637-C468-56FB-9535-C052BDB93DC0"), exclusiveto, contract] */
                MIDL_INTERFACE("C0D59637-C468-56FB-9535-C052BDB93DC0")
                ITensorInt8BitStatics2 : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE CreateFromShapeArrayAndDataArray(
                        /* [in] */UINT32 __shapeSize,
                        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
                        /* [in] */UINT32 __dataSize,
                        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) BYTE * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorInt8Bit * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromBuffer(
                        /* [in] */UINT32 __shapeSize,
                        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
                        /* [in] */__RPC__in_opt ABI::Windows::Storage::Streams::IBuffer * buffer,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorInt8Bit * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorInt8BitStatics2=_uuidof(ITensorInt8BitStatics2);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorString
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorString
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorString_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorString_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorString[] = L"Windows.AI.MachineLearning.ITensorString";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("582335C8-BDB1-4610-BC75-35E9CBF009B7"), exclusiveto, contract] */
                MIDL_INTERFACE("582335C8-BDB1-4610-BC75-35E9CBF009B7")
                ITensorString : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetAsVectorView(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_HSTRING * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorString=_uuidof(ITensorString);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorString;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorString_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorStringStatics
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorString
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorStringStatics[] = L"Windows.AI.MachineLearning.ITensorStringStatics";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("83623324-CF26-4F17-A2D4-20EF8D097D53"), exclusiveto, contract] */
                MIDL_INTERFACE("83623324-CF26-4F17-A2D4-20EF8D097D53")
                ITensorStringStatics : public IInspectable
                {
                public:
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE Create(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorString * * result
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE Create2(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorString * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromArray(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [in] */UINT32 __dataSize,
                        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) HSTRING * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorString * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromIterable(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorString * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorStringStatics=_uuidof(ITensorStringStatics);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorStringStatics2
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorString
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorStringStatics2[] = L"Windows.AI.MachineLearning.ITensorStringStatics2";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("9E355ED0-C8E2-5254-9137-0193A3668FD8"), exclusiveto, contract] */
                MIDL_INTERFACE("9E355ED0-C8E2-5254-9137-0193A3668FD8")
                ITensorStringStatics2 : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE CreateFromShapeArrayAndDataArray(
                        /* [in] */UINT32 __shapeSize,
                        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
                        /* [in] */UINT32 __dataSize,
                        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) HSTRING * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorString * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorStringStatics2=_uuidof(ITensorStringStatics2);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics2;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorUInt16Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorUInt16Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorUInt16Bit[] = L"Windows.AI.MachineLearning.ITensorUInt16Bit";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("68140F4B-23C0-42F3-81F6-A891C011BC3F"), exclusiveto, contract] */
                MIDL_INTERFACE("68140F4B-23C0-42F3-81F6-A891C011BC3F")
                ITensorUInt16Bit : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetAsVectorView(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_UINT16 * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorUInt16Bit=_uuidof(ITensorUInt16Bit);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorUInt16BitStatics
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorUInt16Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorUInt16BitStatics[] = L"Windows.AI.MachineLearning.ITensorUInt16BitStatics";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("5DF745DD-028A-481A-A27C-C7E6435E52DD"), exclusiveto, contract] */
                MIDL_INTERFACE("5DF745DD-028A-481A-A27C-C7E6435E52DD")
                ITensorUInt16BitStatics : public IInspectable
                {
                public:
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE Create(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorUInt16Bit * * result
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE Create2(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorUInt16Bit * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromArray(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [in] */UINT32 __dataSize,
                        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) UINT16 * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorUInt16Bit * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromIterable(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [in] */__RPC__in_opt __FIIterable_1_UINT16 * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorUInt16Bit * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorUInt16BitStatics=_uuidof(ITensorUInt16BitStatics);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorUInt16BitStatics2
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorUInt16Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorUInt16BitStatics2[] = L"Windows.AI.MachineLearning.ITensorUInt16BitStatics2";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("8AF40C64-D69F-5315-9348-490877BBD642"), exclusiveto, contract] */
                MIDL_INTERFACE("8AF40C64-D69F-5315-9348-490877BBD642")
                ITensorUInt16BitStatics2 : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE CreateFromShapeArrayAndDataArray(
                        /* [in] */UINT32 __shapeSize,
                        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
                        /* [in] */UINT32 __dataSize,
                        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) UINT16 * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorUInt16Bit * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromBuffer(
                        /* [in] */UINT32 __shapeSize,
                        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
                        /* [in] */__RPC__in_opt ABI::Windows::Storage::Streams::IBuffer * buffer,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorUInt16Bit * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorUInt16BitStatics2=_uuidof(ITensorUInt16BitStatics2);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorUInt32Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorUInt32Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorUInt32Bit[] = L"Windows.AI.MachineLearning.ITensorUInt32Bit";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("D8C9C2FF-7511-45A3-BFAC-C38F370D2237"), exclusiveto, contract] */
                MIDL_INTERFACE("D8C9C2FF-7511-45A3-BFAC-C38F370D2237")
                ITensorUInt32Bit : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetAsVectorView(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_UINT32 * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorUInt32Bit=_uuidof(ITensorUInt32Bit);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorUInt32BitStatics
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorUInt32Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorUInt32BitStatics[] = L"Windows.AI.MachineLearning.ITensorUInt32BitStatics";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("417C3837-E773-4378-8E7F-0CC33DBEA697"), exclusiveto, contract] */
                MIDL_INTERFACE("417C3837-E773-4378-8E7F-0CC33DBEA697")
                ITensorUInt32BitStatics : public IInspectable
                {
                public:
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE Create(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorUInt32Bit * * result
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE Create2(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorUInt32Bit * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromArray(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [in] */UINT32 __dataSize,
                        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) UINT32 * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorUInt32Bit * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromIterable(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [in] */__RPC__in_opt __FIIterable_1_UINT32 * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorUInt32Bit * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorUInt32BitStatics=_uuidof(ITensorUInt32BitStatics);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorUInt32BitStatics2
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorUInt32Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorUInt32BitStatics2[] = L"Windows.AI.MachineLearning.ITensorUInt32BitStatics2";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("EF1A1F1C-314E-569D-B496-5C8447D20CD2"), exclusiveto, contract] */
                MIDL_INTERFACE("EF1A1F1C-314E-569D-B496-5C8447D20CD2")
                ITensorUInt32BitStatics2 : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE CreateFromShapeArrayAndDataArray(
                        /* [in] */UINT32 __shapeSize,
                        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
                        /* [in] */UINT32 __dataSize,
                        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) UINT32 * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorUInt32Bit * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromBuffer(
                        /* [in] */UINT32 __shapeSize,
                        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
                        /* [in] */__RPC__in_opt ABI::Windows::Storage::Streams::IBuffer * buffer,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorUInt32Bit * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorUInt32BitStatics2=_uuidof(ITensorUInt32BitStatics2);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorUInt64Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorUInt64Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorUInt64Bit[] = L"Windows.AI.MachineLearning.ITensorUInt64Bit";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("2E70FFAD-04BF-4825-839A-82BAEF8C7886"), exclusiveto, contract] */
                MIDL_INTERFACE("2E70FFAD-04BF-4825-839A-82BAEF8C7886")
                ITensorUInt64Bit : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetAsVectorView(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_UINT64 * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorUInt64Bit=_uuidof(ITensorUInt64Bit);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorUInt64BitStatics
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorUInt64Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorUInt64BitStatics[] = L"Windows.AI.MachineLearning.ITensorUInt64BitStatics";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("7A7E20EB-242F-47CB-A9C6-F602ECFBFEE4"), exclusiveto, contract] */
                MIDL_INTERFACE("7A7E20EB-242F-47CB-A9C6-F602ECFBFEE4")
                ITensorUInt64BitStatics : public IInspectable
                {
                public:
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE Create(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorUInt64Bit * * result
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE Create2(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorUInt64Bit * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromArray(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [in] */UINT32 __dataSize,
                        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) UINT64 * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorUInt64Bit * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromIterable(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [in] */__RPC__in_opt __FIIterable_1_UINT64 * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorUInt64Bit * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorUInt64BitStatics=_uuidof(ITensorUInt64BitStatics);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorUInt64BitStatics2
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorUInt64Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorUInt64BitStatics2[] = L"Windows.AI.MachineLearning.ITensorUInt64BitStatics2";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("085A687D-67E1-5B1E-B232-4FABE9CA20B3"), exclusiveto, contract] */
                MIDL_INTERFACE("085A687D-67E1-5B1E-B232-4FABE9CA20B3")
                ITensorUInt64BitStatics2 : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE CreateFromShapeArrayAndDataArray(
                        /* [in] */UINT32 __shapeSize,
                        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
                        /* [in] */UINT32 __dataSize,
                        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) UINT64 * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorUInt64Bit * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromBuffer(
                        /* [in] */UINT32 __shapeSize,
                        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
                        /* [in] */__RPC__in_opt ABI::Windows::Storage::Streams::IBuffer * buffer,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorUInt64Bit * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorUInt64BitStatics2=_uuidof(ITensorUInt64BitStatics2);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorUInt8Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorUInt8Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorUInt8Bit[] = L"Windows.AI.MachineLearning.ITensorUInt8Bit";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("58E1AE27-622B-48E3-BE22-D867AED1DAAC"), exclusiveto, contract] */
                MIDL_INTERFACE("58E1AE27-622B-48E3-BE22-D867AED1DAAC")
                ITensorUInt8Bit : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetAsVectorView(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_byte * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorUInt8Bit=_uuidof(ITensorUInt8Bit);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorUInt8BitStatics
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorUInt8Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorUInt8BitStatics[] = L"Windows.AI.MachineLearning.ITensorUInt8BitStatics";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("05F67583-BC24-4220-8A41-2DCD8C5ED33C"), exclusiveto, contract] */
                MIDL_INTERFACE("05F67583-BC24-4220-8A41-2DCD8C5ED33C")
                ITensorUInt8BitStatics : public IInspectable
                {
                public:
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE Create(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorUInt8Bit * * result
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE Create2(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorUInt8Bit * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromArray(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [in] */UINT32 __dataSize,
                        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) BYTE * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorUInt8Bit * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromIterable(
                        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
                        /* [in] */__RPC__in_opt __FIIterable_1_byte * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorUInt8Bit * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorUInt8BitStatics=_uuidof(ITensorUInt8BitStatics);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorUInt8BitStatics2
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorUInt8Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorUInt8BitStatics2[] = L"Windows.AI.MachineLearning.ITensorUInt8BitStatics2";
namespace ABI {
    namespace Windows {
        namespace AI {
            namespace MachineLearning {
                /* [object, uuid("2BA042D6-373E-5A3A-A2FC-A6C41BD52789"), exclusiveto, contract] */
                MIDL_INTERFACE("2BA042D6-373E-5A3A-A2FC-A6C41BD52789")
                ITensorUInt8BitStatics2 : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE CreateFromShapeArrayAndDataArray(
                        /* [in] */UINT32 __shapeSize,
                        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
                        /* [in] */UINT32 __dataSize,
                        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) BYTE * data,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorUInt8Bit * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromBuffer(
                        /* [in] */UINT32 __shapeSize,
                        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
                        /* [in] */__RPC__in_opt ABI::Windows::Storage::Streams::IBuffer * buffer,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::AI::MachineLearning::ITensorUInt8Bit * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ITensorUInt8BitStatics2=_uuidof(ITensorUInt8BitStatics2);
                
            } /* MachineLearning */
        } /* AI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000


/*
 *
 * Class Windows.AI.MachineLearning.ImageFeatureDescriptor
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.IImageFeatureDescriptor ** Default Interface **
 *    Windows.AI.MachineLearning.ILearningModelFeatureDescriptor
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_ImageFeatureDescriptor_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_ImageFeatureDescriptor_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_ImageFeatureDescriptor[] = L"Windows.AI.MachineLearning.ImageFeatureDescriptor";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.ImageFeatureValue
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.AI.MachineLearning.IImageFeatureValueStatics interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.IImageFeatureValue ** Default Interface **
 *    Windows.AI.MachineLearning.ILearningModelFeatureValue
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_ImageFeatureValue_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_ImageFeatureValue_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_ImageFeatureValue[] = L"Windows.AI.MachineLearning.ImageFeatureValue";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.LearningModel
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.AI.MachineLearning.ILearningModelStatics interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ILearningModel ** Default Interface **
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_LearningModel_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_LearningModel_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_LearningModel[] = L"Windows.AI.MachineLearning.LearningModel";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.LearningModelBinding
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via the Windows.AI.MachineLearning.ILearningModelBindingFactory interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ILearningModelBinding ** Default Interface **
 *    Windows.Foundation.Collections.IMapView_2_HSTRING,IInspectable
 *    Windows.Foundation.Collections.IIterable_1___FIKeyValuePair_2_HSTRING_IInspectable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_LearningModelBinding_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_LearningModelBinding_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_LearningModelBinding[] = L"Windows.AI.MachineLearning.LearningModelBinding";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.LearningModelDevice
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via the Windows.AI.MachineLearning.ILearningModelDeviceFactory interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.AI.MachineLearning.ILearningModelDeviceStatics interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ILearningModelDevice ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_LearningModelDevice_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_LearningModelDevice_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_LearningModelDevice[] = L"Windows.AI.MachineLearning.LearningModelDevice";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.LearningModelEvaluationResult
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ILearningModelEvaluationResult ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_LearningModelEvaluationResult_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_LearningModelEvaluationResult_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_LearningModelEvaluationResult[] = L"Windows.AI.MachineLearning.LearningModelEvaluationResult";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.LearningModelSession
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via the Windows.AI.MachineLearning.ILearningModelSessionFactory2 interface starting with version 2.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *   Type can be activated via the Windows.AI.MachineLearning.ILearningModelSessionFactory interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ILearningModelSession ** Default Interface **
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_LearningModelSession_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_LearningModelSession_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_LearningModelSession[] = L"Windows.AI.MachineLearning.LearningModelSession";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.LearningModelSessionOptions
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 2.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 2.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ILearningModelSessionOptions ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_LearningModelSessionOptions_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_LearningModelSessionOptions_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_LearningModelSessionOptions[] = L"Windows.AI.MachineLearning.LearningModelSessionOptions";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000


/*
 *
 * Class Windows.AI.MachineLearning.MapFeatureDescriptor
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.IMapFeatureDescriptor ** Default Interface **
 *    Windows.AI.MachineLearning.ILearningModelFeatureDescriptor
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_MapFeatureDescriptor_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_MapFeatureDescriptor_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_MapFeatureDescriptor[] = L"Windows.AI.MachineLearning.MapFeatureDescriptor";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.SequenceFeatureDescriptor
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ISequenceFeatureDescriptor ** Default Interface **
 *    Windows.AI.MachineLearning.ILearningModelFeatureDescriptor
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_SequenceFeatureDescriptor_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_SequenceFeatureDescriptor_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_SequenceFeatureDescriptor[] = L"Windows.AI.MachineLearning.SequenceFeatureDescriptor";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.TensorBoolean
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorBooleanStatics2 interface starting with version 2.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorBooleanStatics interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ITensorBoolean ** Default Interface **
 *    Windows.AI.MachineLearning.ITensor
 *    Windows.AI.MachineLearning.ILearningModelFeatureValue
 *    Windows.Foundation.IMemoryBuffer
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_TensorBoolean_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_TensorBoolean_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_TensorBoolean[] = L"Windows.AI.MachineLearning.TensorBoolean";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.TensorDouble
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorDoubleStatics2 interface starting with version 2.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorDoubleStatics interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ITensorDouble ** Default Interface **
 *    Windows.AI.MachineLearning.ITensor
 *    Windows.AI.MachineLearning.ILearningModelFeatureValue
 *    Windows.Foundation.IMemoryBuffer
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_TensorDouble_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_TensorDouble_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_TensorDouble[] = L"Windows.AI.MachineLearning.TensorDouble";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.TensorFeatureDescriptor
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ITensorFeatureDescriptor ** Default Interface **
 *    Windows.AI.MachineLearning.ILearningModelFeatureDescriptor
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_TensorFeatureDescriptor_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_TensorFeatureDescriptor_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_TensorFeatureDescriptor[] = L"Windows.AI.MachineLearning.TensorFeatureDescriptor";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.TensorFloat
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorFloatStatics2 interface starting with version 2.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorFloatStatics interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ITensorFloat ** Default Interface **
 *    Windows.AI.MachineLearning.ITensor
 *    Windows.AI.MachineLearning.ILearningModelFeatureValue
 *    Windows.Foundation.IMemoryBuffer
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_TensorFloat_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_TensorFloat_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_TensorFloat[] = L"Windows.AI.MachineLearning.TensorFloat";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.TensorFloat16Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorFloat16BitStatics2 interface starting with version 2.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorFloat16BitStatics interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ITensorFloat16Bit ** Default Interface **
 *    Windows.AI.MachineLearning.ITensor
 *    Windows.AI.MachineLearning.ILearningModelFeatureValue
 *    Windows.Foundation.IMemoryBuffer
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_TensorFloat16Bit_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_TensorFloat16Bit_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_TensorFloat16Bit[] = L"Windows.AI.MachineLearning.TensorFloat16Bit";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.TensorInt16Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorInt16BitStatics2 interface starting with version 2.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorInt16BitStatics interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ITensorInt16Bit ** Default Interface **
 *    Windows.AI.MachineLearning.ITensor
 *    Windows.AI.MachineLearning.ILearningModelFeatureValue
 *    Windows.Foundation.IMemoryBuffer
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_TensorInt16Bit_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_TensorInt16Bit_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_TensorInt16Bit[] = L"Windows.AI.MachineLearning.TensorInt16Bit";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.TensorInt32Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorInt32BitStatics2 interface starting with version 2.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorInt32BitStatics interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ITensorInt32Bit ** Default Interface **
 *    Windows.AI.MachineLearning.ITensor
 *    Windows.AI.MachineLearning.ILearningModelFeatureValue
 *    Windows.Foundation.IMemoryBuffer
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_TensorInt32Bit_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_TensorInt32Bit_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_TensorInt32Bit[] = L"Windows.AI.MachineLearning.TensorInt32Bit";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.TensorInt64Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorInt64BitStatics2 interface starting with version 2.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorInt64BitStatics interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ITensorInt64Bit ** Default Interface **
 *    Windows.AI.MachineLearning.ITensor
 *    Windows.AI.MachineLearning.ILearningModelFeatureValue
 *    Windows.Foundation.IMemoryBuffer
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_TensorInt64Bit_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_TensorInt64Bit_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_TensorInt64Bit[] = L"Windows.AI.MachineLearning.TensorInt64Bit";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.TensorInt8Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorInt8BitStatics2 interface starting with version 2.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorInt8BitStatics interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ITensorInt8Bit ** Default Interface **
 *    Windows.AI.MachineLearning.ITensor
 *    Windows.AI.MachineLearning.ILearningModelFeatureValue
 *    Windows.Foundation.IMemoryBuffer
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_TensorInt8Bit_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_TensorInt8Bit_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_TensorInt8Bit[] = L"Windows.AI.MachineLearning.TensorInt8Bit";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.TensorString
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorStringStatics2 interface starting with version 2.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorStringStatics interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ITensorString ** Default Interface **
 *    Windows.AI.MachineLearning.ITensor
 *    Windows.AI.MachineLearning.ILearningModelFeatureValue
 *    Windows.Foundation.IMemoryBuffer
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_TensorString_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_TensorString_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_TensorString[] = L"Windows.AI.MachineLearning.TensorString";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.TensorUInt16Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorUInt16BitStatics2 interface starting with version 2.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorUInt16BitStatics interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ITensorUInt16Bit ** Default Interface **
 *    Windows.AI.MachineLearning.ITensor
 *    Windows.AI.MachineLearning.ILearningModelFeatureValue
 *    Windows.Foundation.IMemoryBuffer
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_TensorUInt16Bit_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_TensorUInt16Bit_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_TensorUInt16Bit[] = L"Windows.AI.MachineLearning.TensorUInt16Bit";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.TensorUInt32Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorUInt32BitStatics2 interface starting with version 2.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorUInt32BitStatics interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ITensorUInt32Bit ** Default Interface **
 *    Windows.AI.MachineLearning.ITensor
 *    Windows.AI.MachineLearning.ILearningModelFeatureValue
 *    Windows.Foundation.IMemoryBuffer
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_TensorUInt32Bit_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_TensorUInt32Bit_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_TensorUInt32Bit[] = L"Windows.AI.MachineLearning.TensorUInt32Bit";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.TensorUInt64Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorUInt64BitStatics2 interface starting with version 2.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorUInt64BitStatics interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ITensorUInt64Bit ** Default Interface **
 *    Windows.AI.MachineLearning.ITensor
 *    Windows.AI.MachineLearning.ILearningModelFeatureValue
 *    Windows.Foundation.IMemoryBuffer
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_TensorUInt64Bit_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_TensorUInt64Bit_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_TensorUInt64Bit[] = L"Windows.AI.MachineLearning.TensorUInt64Bit";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.TensorUInt8Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorUInt8BitStatics2 interface starting with version 2.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorUInt8BitStatics interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ITensorUInt8Bit ** Default Interface **
 *    Windows.AI.MachineLearning.ITensor
 *    Windows.AI.MachineLearning.ILearningModelFeatureValue
 *    Windows.Foundation.IMemoryBuffer
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_TensorUInt8Bit_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_TensorUInt8Bit_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_TensorUInt8Bit[] = L"Windows.AI.MachineLearning.TensorUInt8Bit";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000




#else // !defined(__cplusplus)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValue_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValue_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValue __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValue;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValue_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueStatics __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueStatics;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModel_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModel_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModel_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingFactory_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingFactory __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingFactory;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceFactory_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceFactory __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceFactory;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceStatics __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceStatics;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureValue_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureValue_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureValue __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureValue;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureValue_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProvider_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProvider_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProvider __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProvider;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProvider_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory2_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory2 __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory2;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptions_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptions_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptions __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptions;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptions_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptor_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptor_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptor __x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptor;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptor_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CISequenceFeatureDescriptor_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CISequenceFeatureDescriptor_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CISequenceFeatureDescriptor __x_ABI_CWindows_CAI_CMachineLearning_CISequenceFeatureDescriptor;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CISequenceFeatureDescriptor_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensor_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensor_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensor __x_ABI_CWindows_CAI_CMachineLearning_CITensor;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensor_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean __x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2 __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble __x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2 __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptor_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptor_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptor __x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptor;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptor_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2 __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2 __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2 __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2 __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2 __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2 __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorString_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorString_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorString __x_ABI_CWindows_CAI_CMachineLearning_CITensorString;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorString_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics2 __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics2;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2 __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2 __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2 __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2 __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2;

#endif // ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2_FWD_DEFINED__

// Parameterized interface forward declarations (C)

// Collection interface definitions

#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_INTERFACE_DEFINED__)
#define ____FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_INTERFACE_DEFINED__

typedef interface __FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor __FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor;

typedef struct __FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptorVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptorVtbl;

interface __FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor
{
    CONST_VTBL struct __FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptorVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_INTERFACE_DEFINED__

#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____FIIterable_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_INTERFACE_DEFINED__)
#define ____FIIterable_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_INTERFACE_DEFINED__

typedef interface __FIIterable_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor __FIIterable_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor;

typedef  struct __FIIterable_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptorVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor **first);

    END_INTERFACE
} __FIIterable_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptorVtbl;

interface __FIIterable_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor
{
    CONST_VTBL struct __FIIterable_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptorVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_INTERFACE_DEFINED__

#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_INTERFACE_DEFINED__)
#define ____FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor __FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor;

typedef struct __FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptorVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor * *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor * This,
            /* [in] */ __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor * item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor * *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptorVtbl;

interface __FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor
{
    CONST_VTBL struct __FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptorVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor_INTERFACE_DEFINED__

#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModel_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModel_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModel __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModel;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModel;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModelVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModel * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModel * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModel * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModel * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModelVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModel
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModelVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModel_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModel_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModel_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModel_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModel_INTERFACE_DEFINED__

#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel;

typedef struct __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModel *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModel **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelVtbl;

interface __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel_INTERFACE_DEFINED__

#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResultVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResultVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult_INTERFACE_DEFINED__

#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult;

typedef struct __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResultVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResultVtbl;

interface __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult_INTERFACE_DEFINED__

#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#if !defined(____FIKeyValuePair_2_HSTRING_HSTRING_INTERFACE_DEFINED__)
#define ____FIKeyValuePair_2_HSTRING_HSTRING_INTERFACE_DEFINED__

typedef interface __FIKeyValuePair_2_HSTRING_HSTRING __FIKeyValuePair_2_HSTRING_HSTRING;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIKeyValuePair_2_HSTRING_HSTRING;

typedef struct __FIKeyValuePair_2_HSTRING_HSTRINGVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIKeyValuePair_2_HSTRING_HSTRING * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIKeyValuePair_2_HSTRING_HSTRING * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIKeyValuePair_2_HSTRING_HSTRING * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIKeyValuePair_2_HSTRING_HSTRING * This,
            /* [out] */ __RPC__out ULONG *iidCount,
            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIKeyValuePair_2_HSTRING_HSTRING * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIKeyValuePair_2_HSTRING_HSTRING * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Key )(__RPC__in __FIKeyValuePair_2_HSTRING_HSTRING * This, /* [retval][out] */ __RPC__out HSTRING *key);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Value )(__RPC__in __FIKeyValuePair_2_HSTRING_HSTRING * This, /* [retval][out] */ __RPC__deref_out_opt HSTRING *value);
    END_INTERFACE
} __FIKeyValuePair_2_HSTRING_HSTRINGVtbl;

interface __FIKeyValuePair_2_HSTRING_HSTRING
{
    CONST_VTBL struct __FIKeyValuePair_2_HSTRING_HSTRINGVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIKeyValuePair_2_HSTRING_HSTRING_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIKeyValuePair_2_HSTRING_HSTRING_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIKeyValuePair_2_HSTRING_HSTRING_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIKeyValuePair_2_HSTRING_HSTRING_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIKeyValuePair_2_HSTRING_HSTRING_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIKeyValuePair_2_HSTRING_HSTRING_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIKeyValuePair_2_HSTRING_HSTRING_get_Key(This,key)	\
    ( (This)->lpVtbl -> get_Key(This,key) ) 

#define __FIKeyValuePair_2_HSTRING_HSTRING_get_Value(This,value)	\
    ( (This)->lpVtbl -> get_Value(This,value) ) 
#endif /* COBJMACROS */


#endif // ____FIKeyValuePair_2_HSTRING_HSTRING_INTERFACE_DEFINED__



#if !defined(____FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING_INTERFACE_DEFINED__)
#define ____FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING_INTERFACE_DEFINED__

typedef interface __FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING __FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING;

typedef struct __FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRINGVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING * This, /* [retval][out] */ __RPC__out __FIKeyValuePair_2_HSTRING_HSTRING * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __FIKeyValuePair_2_HSTRING_HSTRING * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRINGVtbl;

interface __FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING
{
    CONST_VTBL struct __FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRINGVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING_INTERFACE_DEFINED__



#if !defined(____FIIterable_1___FIKeyValuePair_2_HSTRING_HSTRING_INTERFACE_DEFINED__)
#define ____FIIterable_1___FIKeyValuePair_2_HSTRING_HSTRING_INTERFACE_DEFINED__

typedef interface __FIIterable_1___FIKeyValuePair_2_HSTRING_HSTRING __FIIterable_1___FIKeyValuePair_2_HSTRING_HSTRING;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1___FIKeyValuePair_2_HSTRING_HSTRING;

typedef  struct __FIIterable_1___FIKeyValuePair_2_HSTRING_HSTRINGVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_HSTRING * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_HSTRING * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_HSTRING * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_HSTRING * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_HSTRING * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_HSTRING * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_HSTRING * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1___FIKeyValuePair_2_HSTRING_HSTRING **first);

    END_INTERFACE
} __FIIterable_1___FIKeyValuePair_2_HSTRING_HSTRINGVtbl;

interface __FIIterable_1___FIKeyValuePair_2_HSTRING_HSTRING
{
    CONST_VTBL struct __FIIterable_1___FIKeyValuePair_2_HSTRING_HSTRINGVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1___FIKeyValuePair_2_HSTRING_HSTRING_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1___FIKeyValuePair_2_HSTRING_HSTRING_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1___FIKeyValuePair_2_HSTRING_HSTRING_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1___FIKeyValuePair_2_HSTRING_HSTRING_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1___FIKeyValuePair_2_HSTRING_HSTRING_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1___FIKeyValuePair_2_HSTRING_HSTRING_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1___FIKeyValuePair_2_HSTRING_HSTRING_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1___FIKeyValuePair_2_HSTRING_HSTRING_INTERFACE_DEFINED__


#if !defined(____FIMapView_2_HSTRING_HSTRING_INTERFACE_DEFINED__)
#define ____FIMapView_2_HSTRING_HSTRING_INTERFACE_DEFINED__

typedef interface __FIMapView_2_HSTRING_HSTRING __FIMapView_2_HSTRING_HSTRING;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIMapView_2_HSTRING_HSTRING;

typedef struct __FIMapView_2_HSTRING_HSTRINGVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIMapView_2_HSTRING_HSTRING * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIMapView_2_HSTRING_HSTRING * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIMapView_2_HSTRING_HSTRING * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIMapView_2_HSTRING_HSTRING * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIMapView_2_HSTRING_HSTRING * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIMapView_2_HSTRING_HSTRING * This,/* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *Lookup )(__RPC__in __FIMapView_2_HSTRING_HSTRING * This,
        /* [in] */ __RPC__in HSTRING key,
        /* [retval][out] */ __RPC__deref_out_opt HSTRING *value);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )(__RPC__in __FIMapView_2_HSTRING_HSTRING * This, /* [retval][out] */ __RPC__out unsigned int *size);
    HRESULT ( STDMETHODCALLTYPE *HasKey )(__RPC__in __FIMapView_2_HSTRING_HSTRING * This, /* [in] */ __RPC__in HSTRING key, /* [retval][out] */ __RPC__out boolean *found);
    HRESULT ( STDMETHODCALLTYPE *Split )(__RPC__in __FIMapView_2_HSTRING_HSTRING * This,/* [out] */ __RPC__deref_out_opt __FIMapView_2_HSTRING_HSTRING **firstPartition,
        /* [out] */ __RPC__deref_out_opt __FIMapView_2_HSTRING_HSTRING **secondPartition);
    END_INTERFACE
} __FIMapView_2_HSTRING_HSTRINGVtbl;

interface __FIMapView_2_HSTRING_HSTRING
{
    CONST_VTBL struct __FIMapView_2_HSTRING_HSTRINGVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIMapView_2_HSTRING_HSTRING_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIMapView_2_HSTRING_HSTRING_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIMapView_2_HSTRING_HSTRING_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIMapView_2_HSTRING_HSTRING_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIMapView_2_HSTRING_HSTRING_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIMapView_2_HSTRING_HSTRING_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIMapView_2_HSTRING_HSTRING_Lookup(This,key,value)	\
    ( (This)->lpVtbl -> Lookup(This,key,value) ) 
#define __FIMapView_2_HSTRING_HSTRING_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 
#define __FIMapView_2_HSTRING_HSTRING_HasKey(This,key,found)	\
    ( (This)->lpVtbl -> HasKey(This,key,found) ) 
#define __FIMapView_2_HSTRING_HSTRING_Split(This,firstPartition,secondPartition)	\
    ( (This)->lpVtbl -> Split(This,firstPartition,secondPartition) ) 
#endif /* COBJMACROS */


#endif // ____FIMapView_2_HSTRING_HSTRING_INTERFACE_DEFINED__



#if !defined(____FIKeyValuePair_2_HSTRING_IInspectable_INTERFACE_DEFINED__)
#define ____FIKeyValuePair_2_HSTRING_IInspectable_INTERFACE_DEFINED__

typedef interface __FIKeyValuePair_2_HSTRING_IInspectable __FIKeyValuePair_2_HSTRING_IInspectable;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIKeyValuePair_2_HSTRING_IInspectable;

typedef struct __FIKeyValuePair_2_HSTRING_IInspectableVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIKeyValuePair_2_HSTRING_IInspectable * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIKeyValuePair_2_HSTRING_IInspectable * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIKeyValuePair_2_HSTRING_IInspectable * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIKeyValuePair_2_HSTRING_IInspectable * This,
            /* [out] */ __RPC__out ULONG *iidCount,
            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIKeyValuePair_2_HSTRING_IInspectable * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIKeyValuePair_2_HSTRING_IInspectable * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Key )(__RPC__in __FIKeyValuePair_2_HSTRING_IInspectable * This, /* [retval][out] */ __RPC__out HSTRING *key);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Value )(__RPC__in __FIKeyValuePair_2_HSTRING_IInspectable * This, /* [retval][out] */ __RPC__deref_out_opt IInspectable * *value);
    END_INTERFACE
} __FIKeyValuePair_2_HSTRING_IInspectableVtbl;

interface __FIKeyValuePair_2_HSTRING_IInspectable
{
    CONST_VTBL struct __FIKeyValuePair_2_HSTRING_IInspectableVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIKeyValuePair_2_HSTRING_IInspectable_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIKeyValuePair_2_HSTRING_IInspectable_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIKeyValuePair_2_HSTRING_IInspectable_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIKeyValuePair_2_HSTRING_IInspectable_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIKeyValuePair_2_HSTRING_IInspectable_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIKeyValuePair_2_HSTRING_IInspectable_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIKeyValuePair_2_HSTRING_IInspectable_get_Key(This,key)	\
    ( (This)->lpVtbl -> get_Key(This,key) ) 

#define __FIKeyValuePair_2_HSTRING_IInspectable_get_Value(This,value)	\
    ( (This)->lpVtbl -> get_Value(This,value) ) 
#endif /* COBJMACROS */


#endif // ____FIKeyValuePair_2_HSTRING_IInspectable_INTERFACE_DEFINED__



#if !defined(____FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_INTERFACE_DEFINED__)
#define ____FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_INTERFACE_DEFINED__

typedef interface __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable;

typedef struct __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectableVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable * This, /* [retval][out] */ __RPC__out __FIKeyValuePair_2_HSTRING_IInspectable * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __FIKeyValuePair_2_HSTRING_IInspectable * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectableVtbl;

interface __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable
{
    CONST_VTBL struct __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectableVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_INTERFACE_DEFINED__



#if !defined(____FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable_INTERFACE_DEFINED__)
#define ____FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable_INTERFACE_DEFINED__

typedef interface __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable;

typedef  struct __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectableVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable **first);

    END_INTERFACE
} __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectableVtbl;

interface __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable
{
    CONST_VTBL struct __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectableVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable_INTERFACE_DEFINED__



#if !defined(____FIMapView_2_HSTRING_IInspectable_INTERFACE_DEFINED__)
#define ____FIMapView_2_HSTRING_IInspectable_INTERFACE_DEFINED__

typedef interface __FIMapView_2_HSTRING_IInspectable __FIMapView_2_HSTRING_IInspectable;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIMapView_2_HSTRING_IInspectable;

typedef struct __FIMapView_2_HSTRING_IInspectableVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIMapView_2_HSTRING_IInspectable * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIMapView_2_HSTRING_IInspectable * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIMapView_2_HSTRING_IInspectable * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIMapView_2_HSTRING_IInspectable * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIMapView_2_HSTRING_IInspectable * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIMapView_2_HSTRING_IInspectable * This,/* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *Lookup )(__RPC__in __FIMapView_2_HSTRING_IInspectable * This,
        /* [in] */ __RPC__in HSTRING key,
        /* [retval][out] */ __RPC__deref_out_opt IInspectable * *value);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )(__RPC__in __FIMapView_2_HSTRING_IInspectable * This, /* [retval][out] */ __RPC__out unsigned int *size);
    HRESULT ( STDMETHODCALLTYPE *HasKey )(__RPC__in __FIMapView_2_HSTRING_IInspectable * This, /* [in] */ __RPC__in HSTRING key, /* [retval][out] */ __RPC__out boolean *found);
    HRESULT ( STDMETHODCALLTYPE *Split )(__RPC__in __FIMapView_2_HSTRING_IInspectable * This,/* [out] */ __RPC__deref_out_opt __FIMapView_2_HSTRING_IInspectable **firstPartition,
        /* [out] */ __RPC__deref_out_opt __FIMapView_2_HSTRING_IInspectable **secondPartition);
    END_INTERFACE
} __FIMapView_2_HSTRING_IInspectableVtbl;

interface __FIMapView_2_HSTRING_IInspectable
{
    CONST_VTBL struct __FIMapView_2_HSTRING_IInspectableVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIMapView_2_HSTRING_IInspectable_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIMapView_2_HSTRING_IInspectable_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIMapView_2_HSTRING_IInspectable_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIMapView_2_HSTRING_IInspectable_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIMapView_2_HSTRING_IInspectable_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIMapView_2_HSTRING_IInspectable_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIMapView_2_HSTRING_IInspectable_Lookup(This,key,value)	\
    ( (This)->lpVtbl -> Lookup(This,key,value) ) 
#define __FIMapView_2_HSTRING_IInspectable_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 
#define __FIMapView_2_HSTRING_IInspectable_HasKey(This,key,found)	\
    ( (This)->lpVtbl -> HasKey(This,key,found) ) 
#define __FIMapView_2_HSTRING_IInspectable_Split(This,firstPartition,secondPartition)	\
    ( (This)->lpVtbl -> Split(This,firstPartition,secondPartition) ) 
#endif /* COBJMACROS */


#endif // ____FIMapView_2_HSTRING_IInspectable_INTERFACE_DEFINED__



#if !defined(____FIMap_2_HSTRING_IInspectable_INTERFACE_DEFINED__)
#define ____FIMap_2_HSTRING_IInspectable_INTERFACE_DEFINED__

typedef interface __FIMap_2_HSTRING_IInspectable __FIMap_2_HSTRING_IInspectable;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIMap_2_HSTRING_IInspectable;

typedef struct __FIMap_2_HSTRING_IInspectableVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIMap_2_HSTRING_IInspectable * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIMap_2_HSTRING_IInspectable * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIMap_2_HSTRING_IInspectable * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIMap_2_HSTRING_IInspectable * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIMap_2_HSTRING_IInspectable * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIMap_2_HSTRING_IInspectable * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *Lookup )(__RPC__in __FIMap_2_HSTRING_IInspectable * This,
        /* [in] */ HSTRING key,
        /* [retval][out] */ __RPC__deref_out_opt IInspectable * **value);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )(__RPC__in __FIMap_2_HSTRING_IInspectable * This, /* [retval][out] */ __RPC__out unsigned int *size);
    HRESULT ( STDMETHODCALLTYPE *HasKey )(__RPC__in __FIMap_2_HSTRING_IInspectable * This, /* [in] */ HSTRING key, /* [retval][out] */ __RPC__out boolean *found);
    HRESULT ( STDMETHODCALLTYPE *GetView )(__RPC__in __FIMap_2_HSTRING_IInspectable * This, /* [retval][out] */ __RPC__deref_out_opt __FIMapView_2_HSTRING_IInspectable **view);
    HRESULT ( STDMETHODCALLTYPE *Insert )(__RPC__in __FIMap_2_HSTRING_IInspectable * This,
        /* [in] */ HSTRING key,
        /* [in] */ __RPC__in_opt IInspectable * *value,
        /* [retval][out] */ __RPC__out boolean *replaced);
    HRESULT ( STDMETHODCALLTYPE *Remove )(__RPC__in __FIMap_2_HSTRING_IInspectable * This,/* [in] */ HSTRING key);
    HRESULT ( STDMETHODCALLTYPE *Clear )(__RPC__in __FIMap_2_HSTRING_IInspectable * This);
    END_INTERFACE
} __FIMap_2_HSTRING_IInspectableVtbl;

interface __FIMap_2_HSTRING_IInspectable
{
    CONST_VTBL struct __FIMap_2_HSTRING_IInspectableVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIMap_2_HSTRING_IInspectable_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIMap_2_HSTRING_IInspectable_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIMap_2_HSTRING_IInspectable_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIMap_2_HSTRING_IInspectable_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIMap_2_HSTRING_IInspectable_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIMap_2_HSTRING_IInspectable_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIMap_2_HSTRING_IInspectable_Lookup(This,key,value)	\
    ( (This)->lpVtbl -> Lookup(This,key,value) ) 

#define __FIMap_2_HSTRING_IInspectable_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIMap_2_HSTRING_IInspectable_HasKey(This,key,found)	\
    ( (This)->lpVtbl -> HasKey(This,key,found) ) 

#define __FIMap_2_HSTRING_IInspectable_GetView(This,view)	\
    ( (This)->lpVtbl -> GetView(This,view) ) 

#define __FIMap_2_HSTRING_IInspectable_Insert(This,key,value,replaced)	\
    ( (This)->lpVtbl -> Insert(This,key,value,replaced) ) 

#define __FIMap_2_HSTRING_IInspectable_Remove(This,key)	\
    ( (This)->lpVtbl -> Remove(This,key) ) 

#define __FIMap_2_HSTRING_IInspectable_Clear(This)	\
    ( (This)->lpVtbl -> Clear(This) ) 
#endif /* COBJMACROS */



#endif // ____FIMap_2_HSTRING_IInspectable_INTERFACE_DEFINED__


#if !defined(____FIIterator_1___z__zint64_INTERFACE_DEFINED__)
#define ____FIIterator_1___z__zint64_INTERFACE_DEFINED__

typedef interface __FIIterator_1___z__zint64 __FIIterator_1___z__zint64;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1___z__zint64;

typedef struct __FIIterator_1___z__zint64Vtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1___z__zint64 * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1___z__zint64 * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1___z__zint64 * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1___z__zint64 * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1___z__zint64 * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1___z__zint64 * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1___z__zint64 * This, /* [retval][out] */ __RPC__out __int64 *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1___z__zint64 * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1___z__zint64 * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1___z__zint64 * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __int64 *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1___z__zint64Vtbl;

interface __FIIterator_1___z__zint64
{
    CONST_VTBL struct __FIIterator_1___z__zint64Vtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1___z__zint64_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1___z__zint64_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1___z__zint64_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1___z__zint64_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1___z__zint64_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1___z__zint64_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1___z__zint64_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1___z__zint64_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1___z__zint64_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1___z__zint64_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1___z__zint64_INTERFACE_DEFINED__


#if !defined(____FIIterable_1___z__zint64_INTERFACE_DEFINED__)
#define ____FIIterable_1___z__zint64_INTERFACE_DEFINED__

typedef interface __FIIterable_1___z__zint64 __FIIterable_1___z__zint64;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1___z__zint64;

typedef  struct __FIIterable_1___z__zint64Vtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1___z__zint64 * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1___z__zint64 * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1___z__zint64 * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1___z__zint64 * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1___z__zint64 * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1___z__zint64 * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1___z__zint64 * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1___z__zint64 **first);

    END_INTERFACE
} __FIIterable_1___z__zint64Vtbl;

interface __FIIterable_1___z__zint64
{
    CONST_VTBL struct __FIIterable_1___z__zint64Vtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1___z__zint64_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1___z__zint64_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1___z__zint64_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1___z__zint64_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1___z__zint64_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1___z__zint64_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1___z__zint64_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1___z__zint64_INTERFACE_DEFINED__


#if !defined(____FIVectorView_1___z__zint64_INTERFACE_DEFINED__)
#define ____FIVectorView_1___z__zint64_INTERFACE_DEFINED__

typedef interface __FIVectorView_1___z__zint64 __FIVectorView_1___z__zint64;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1___z__zint64;

typedef struct __FIVectorView_1___z__zint64Vtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1___z__zint64 * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1___z__zint64 * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1___z__zint64 * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1___z__zint64 * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1___z__zint64 * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1___z__zint64 * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1___z__zint64 * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out __int64 *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1___z__zint64 * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1___z__zint64 * This,
            /* [in] */ __int64 item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1___z__zint64 * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __int64 *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1___z__zint64Vtbl;

interface __FIVectorView_1___z__zint64
{
    CONST_VTBL struct __FIVectorView_1___z__zint64Vtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1___z__zint64_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1___z__zint64_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1___z__zint64_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1___z__zint64_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1___z__zint64_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1___z__zint64_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1___z__zint64_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1___z__zint64_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1___z__zint64_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1___z__zint64_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1___z__zint64_INTERFACE_DEFINED__


#if !defined(____FIIterator_1_boolean_INTERFACE_DEFINED__)
#define ____FIIterator_1_boolean_INTERFACE_DEFINED__

typedef interface __FIIterator_1_boolean __FIIterator_1_boolean;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_boolean;

typedef struct __FIIterator_1_booleanVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_boolean * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_boolean * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_boolean * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_boolean * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_boolean * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_boolean * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_boolean * This, /* [retval][out] */ __RPC__out boolean *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_boolean * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_boolean * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_boolean * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) boolean *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_booleanVtbl;

interface __FIIterator_1_boolean
{
    CONST_VTBL struct __FIIterator_1_booleanVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_boolean_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_boolean_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_boolean_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_boolean_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_boolean_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_boolean_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_boolean_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_boolean_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_boolean_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_boolean_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_boolean_INTERFACE_DEFINED__


#if !defined(____FIIterable_1_boolean_INTERFACE_DEFINED__)
#define ____FIIterable_1_boolean_INTERFACE_DEFINED__

typedef interface __FIIterable_1_boolean __FIIterable_1_boolean;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_boolean;

typedef  struct __FIIterable_1_booleanVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_boolean * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_boolean * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_boolean * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_boolean * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_boolean * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_boolean * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_boolean * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_boolean **first);

    END_INTERFACE
} __FIIterable_1_booleanVtbl;

interface __FIIterable_1_boolean
{
    CONST_VTBL struct __FIIterable_1_booleanVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_boolean_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_boolean_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_boolean_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_boolean_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_boolean_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_boolean_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_boolean_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_boolean_INTERFACE_DEFINED__


#if !defined(____FIVectorView_1_boolean_INTERFACE_DEFINED__)
#define ____FIVectorView_1_boolean_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_boolean __FIVectorView_1_boolean;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_boolean;

typedef struct __FIVectorView_1_booleanVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_boolean * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_boolean * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_boolean * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_boolean * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_boolean * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_boolean * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_boolean * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out boolean *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_boolean * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_boolean * This,
            /* [in] */ boolean item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_boolean * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) boolean *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_booleanVtbl;

interface __FIVectorView_1_boolean
{
    CONST_VTBL struct __FIVectorView_1_booleanVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_boolean_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_boolean_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_boolean_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_boolean_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_boolean_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_boolean_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_boolean_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_boolean_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_boolean_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_boolean_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_boolean_INTERFACE_DEFINED__


#if !defined(____FIIterator_1_double_INTERFACE_DEFINED__)
#define ____FIIterator_1_double_INTERFACE_DEFINED__

typedef interface __FIIterator_1_double __FIIterator_1_double;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_double;

typedef struct __FIIterator_1_doubleVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_double * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_double * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_double * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_double * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_double * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_double * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_double * This, /* [retval][out] */ __RPC__out double *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_double * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_double * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_double * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) double *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_doubleVtbl;

interface __FIIterator_1_double
{
    CONST_VTBL struct __FIIterator_1_doubleVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_double_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_double_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_double_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_double_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_double_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_double_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_double_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_double_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_double_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_double_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_double_INTERFACE_DEFINED__


#if !defined(____FIIterable_1_double_INTERFACE_DEFINED__)
#define ____FIIterable_1_double_INTERFACE_DEFINED__

typedef interface __FIIterable_1_double __FIIterable_1_double;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_double;

typedef  struct __FIIterable_1_doubleVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_double * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_double * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_double * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_double * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_double * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_double * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_double * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_double **first);

    END_INTERFACE
} __FIIterable_1_doubleVtbl;

interface __FIIterable_1_double
{
    CONST_VTBL struct __FIIterable_1_doubleVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_double_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_double_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_double_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_double_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_double_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_double_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_double_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_double_INTERFACE_DEFINED__


#if !defined(____FIVectorView_1_double_INTERFACE_DEFINED__)
#define ____FIVectorView_1_double_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_double __FIVectorView_1_double;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_double;

typedef struct __FIVectorView_1_doubleVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_double * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_double * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_double * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_double * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_double * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_double * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_double * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out double *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_double * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_double * This,
            /* [in] */ double item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_double * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) double *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_doubleVtbl;

interface __FIVectorView_1_double
{
    CONST_VTBL struct __FIVectorView_1_doubleVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_double_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_double_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_double_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_double_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_double_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_double_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_double_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_double_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_double_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_double_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_double_INTERFACE_DEFINED__


#if !defined(____FIIterator_1_float_INTERFACE_DEFINED__)
#define ____FIIterator_1_float_INTERFACE_DEFINED__

typedef interface __FIIterator_1_float __FIIterator_1_float;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_float;

typedef struct __FIIterator_1_floatVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_float * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_float * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_float * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_float * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_float * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_float * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_float * This, /* [retval][out] */ __RPC__out float *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_float * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_float * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_float * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) float *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_floatVtbl;

interface __FIIterator_1_float
{
    CONST_VTBL struct __FIIterator_1_floatVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_float_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_float_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_float_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_float_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_float_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_float_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_float_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_float_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_float_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_float_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_float_INTERFACE_DEFINED__


#if !defined(____FIIterable_1_float_INTERFACE_DEFINED__)
#define ____FIIterable_1_float_INTERFACE_DEFINED__

typedef interface __FIIterable_1_float __FIIterable_1_float;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_float;

typedef  struct __FIIterable_1_floatVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_float * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_float * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_float * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_float * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_float * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_float * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_float * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_float **first);

    END_INTERFACE
} __FIIterable_1_floatVtbl;

interface __FIIterable_1_float
{
    CONST_VTBL struct __FIIterable_1_floatVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_float_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_float_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_float_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_float_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_float_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_float_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_float_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_float_INTERFACE_DEFINED__


#if !defined(____FIVectorView_1_float_INTERFACE_DEFINED__)
#define ____FIVectorView_1_float_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_float __FIVectorView_1_float;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_float;

typedef struct __FIVectorView_1_floatVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_float * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_float * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_float * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_float * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_float * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_float * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_float * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out float *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_float * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_float * This,
            /* [in] */ float item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_float * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) float *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_floatVtbl;

interface __FIVectorView_1_float
{
    CONST_VTBL struct __FIVectorView_1_floatVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_float_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_float_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_float_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_float_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_float_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_float_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_float_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_float_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_float_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_float_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_float_INTERFACE_DEFINED__


#if !defined(____FIIterator_1_short_INTERFACE_DEFINED__)
#define ____FIIterator_1_short_INTERFACE_DEFINED__

typedef interface __FIIterator_1_short __FIIterator_1_short;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_short;

typedef struct __FIIterator_1_shortVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_short * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_short * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_short * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_short * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_short * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_short * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_short * This, /* [retval][out] */ __RPC__out short *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_short * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_short * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_short * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) short *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_shortVtbl;

interface __FIIterator_1_short
{
    CONST_VTBL struct __FIIterator_1_shortVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_short_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_short_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_short_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_short_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_short_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_short_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_short_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_short_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_short_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_short_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_short_INTERFACE_DEFINED__


#if !defined(____FIIterable_1_short_INTERFACE_DEFINED__)
#define ____FIIterable_1_short_INTERFACE_DEFINED__

typedef interface __FIIterable_1_short __FIIterable_1_short;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_short;

typedef  struct __FIIterable_1_shortVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_short * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_short * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_short * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_short * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_short * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_short * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_short * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_short **first);

    END_INTERFACE
} __FIIterable_1_shortVtbl;

interface __FIIterable_1_short
{
    CONST_VTBL struct __FIIterable_1_shortVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_short_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_short_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_short_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_short_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_short_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_short_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_short_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_short_INTERFACE_DEFINED__


#if !defined(____FIVectorView_1_short_INTERFACE_DEFINED__)
#define ____FIVectorView_1_short_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_short __FIVectorView_1_short;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_short;

typedef struct __FIVectorView_1_shortVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_short * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_short * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_short * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_short * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_short * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_short * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_short * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out short *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_short * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_short * This,
            /* [in] */ short item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_short * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) short *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_shortVtbl;

interface __FIVectorView_1_short
{
    CONST_VTBL struct __FIVectorView_1_shortVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_short_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_short_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_short_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_short_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_short_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_short_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_short_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_short_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_short_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_short_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_short_INTERFACE_DEFINED__


#if !defined(____FIIterator_1_int_INTERFACE_DEFINED__)
#define ____FIIterator_1_int_INTERFACE_DEFINED__

typedef interface __FIIterator_1_int __FIIterator_1_int;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_int;

typedef struct __FIIterator_1_intVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_int * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_int * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_int * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_int * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_int * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_int * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_int * This, /* [retval][out] */ __RPC__out int *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_int * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_int * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_int * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) int *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_intVtbl;

interface __FIIterator_1_int
{
    CONST_VTBL struct __FIIterator_1_intVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_int_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_int_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_int_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_int_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_int_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_int_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_int_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_int_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_int_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_int_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_int_INTERFACE_DEFINED__


#if !defined(____FIIterable_1_int_INTERFACE_DEFINED__)
#define ____FIIterable_1_int_INTERFACE_DEFINED__

typedef interface __FIIterable_1_int __FIIterable_1_int;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_int;

typedef  struct __FIIterable_1_intVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_int * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_int * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_int * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_int * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_int * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_int * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_int * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_int **first);

    END_INTERFACE
} __FIIterable_1_intVtbl;

interface __FIIterable_1_int
{
    CONST_VTBL struct __FIIterable_1_intVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_int_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_int_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_int_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_int_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_int_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_int_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_int_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_int_INTERFACE_DEFINED__


#if !defined(____FIVectorView_1_int_INTERFACE_DEFINED__)
#define ____FIVectorView_1_int_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_int __FIVectorView_1_int;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_int;

typedef struct __FIVectorView_1_intVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_int * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_int * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_int * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_int * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_int * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_int * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_int * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out int *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_int * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_int * This,
            /* [in] */ int item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_int * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) int *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_intVtbl;

interface __FIVectorView_1_int
{
    CONST_VTBL struct __FIVectorView_1_intVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_int_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_int_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_int_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_int_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_int_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_int_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_int_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_int_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_int_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_int_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_int_INTERFACE_DEFINED__


#if !defined(____FIIterator_1_byte_INTERFACE_DEFINED__)
#define ____FIIterator_1_byte_INTERFACE_DEFINED__

typedef interface __FIIterator_1_byte __FIIterator_1_byte;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_byte;

typedef struct __FIIterator_1_byteVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_byte * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_byte * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_byte * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_byte * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_byte * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_byte * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_byte * This, /* [retval][out] */ __RPC__out byte *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_byte * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_byte * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_byte * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) byte *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_byteVtbl;

interface __FIIterator_1_byte
{
    CONST_VTBL struct __FIIterator_1_byteVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_byte_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_byte_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_byte_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_byte_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_byte_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_byte_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_byte_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_byte_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_byte_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_byte_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_byte_INTERFACE_DEFINED__


#if !defined(____FIIterable_1_byte_INTERFACE_DEFINED__)
#define ____FIIterable_1_byte_INTERFACE_DEFINED__

typedef interface __FIIterable_1_byte __FIIterable_1_byte;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_byte;

typedef  struct __FIIterable_1_byteVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_byte * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_byte * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_byte * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_byte * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_byte * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_byte * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_byte * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_byte **first);

    END_INTERFACE
} __FIIterable_1_byteVtbl;

interface __FIIterable_1_byte
{
    CONST_VTBL struct __FIIterable_1_byteVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_byte_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_byte_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_byte_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_byte_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_byte_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_byte_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_byte_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_byte_INTERFACE_DEFINED__


#if !defined(____FIVectorView_1_byte_INTERFACE_DEFINED__)
#define ____FIVectorView_1_byte_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_byte __FIVectorView_1_byte;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_byte;

typedef struct __FIVectorView_1_byteVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_byte * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_byte * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_byte * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_byte * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_byte * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_byte * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_byte * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out byte *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_byte * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_byte * This,
            /* [in] */ byte item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_byte * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) byte *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_byteVtbl;

interface __FIVectorView_1_byte
{
    CONST_VTBL struct __FIVectorView_1_byteVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_byte_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_byte_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_byte_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_byte_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_byte_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_byte_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_byte_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_byte_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_byte_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_byte_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_byte_INTERFACE_DEFINED__


#if !defined(____FIIterator_1_HSTRING_INTERFACE_DEFINED__)
#define ____FIIterator_1_HSTRING_INTERFACE_DEFINED__

typedef interface __FIIterator_1_HSTRING __FIIterator_1_HSTRING;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_HSTRING;

typedef struct __FIIterator_1_HSTRINGVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_HSTRING * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_HSTRING * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_HSTRING * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_HSTRING * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_HSTRING * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_HSTRING * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_HSTRING * This, /* [retval][out] */ __RPC__out HSTRING *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_HSTRING * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_HSTRING * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_HSTRING * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) HSTRING *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_HSTRINGVtbl;

interface __FIIterator_1_HSTRING
{
    CONST_VTBL struct __FIIterator_1_HSTRINGVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_HSTRING_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_HSTRING_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_HSTRING_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_HSTRING_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_HSTRING_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_HSTRING_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_HSTRING_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_HSTRING_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_HSTRING_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_HSTRING_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_HSTRING_INTERFACE_DEFINED__


#if !defined(____FIIterable_1_HSTRING_INTERFACE_DEFINED__)
#define ____FIIterable_1_HSTRING_INTERFACE_DEFINED__

typedef interface __FIIterable_1_HSTRING __FIIterable_1_HSTRING;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_HSTRING;

typedef  struct __FIIterable_1_HSTRINGVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_HSTRING * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_HSTRING * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_HSTRING * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_HSTRING * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_HSTRING * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_HSTRING * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_HSTRING * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_HSTRING **first);

    END_INTERFACE
} __FIIterable_1_HSTRINGVtbl;

interface __FIIterable_1_HSTRING
{
    CONST_VTBL struct __FIIterable_1_HSTRINGVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_HSTRING_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_HSTRING_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_HSTRING_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_HSTRING_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_HSTRING_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_HSTRING_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_HSTRING_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_HSTRING_INTERFACE_DEFINED__


#if !defined(____FIVectorView_1_HSTRING_INTERFACE_DEFINED__)
#define ____FIVectorView_1_HSTRING_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_HSTRING __FIVectorView_1_HSTRING;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_HSTRING;

typedef struct __FIVectorView_1_HSTRINGVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_HSTRING * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_HSTRING * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_HSTRING * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_HSTRING * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_HSTRING * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_HSTRING * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_HSTRING * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out HSTRING *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_HSTRING * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_HSTRING * This,
            /* [in] */ HSTRING item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_HSTRING * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) HSTRING *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_HSTRINGVtbl;

interface __FIVectorView_1_HSTRING
{
    CONST_VTBL struct __FIVectorView_1_HSTRINGVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_HSTRING_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_HSTRING_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_HSTRING_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_HSTRING_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_HSTRING_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_HSTRING_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_HSTRING_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_HSTRING_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_HSTRING_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_HSTRING_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_HSTRING_INTERFACE_DEFINED__


#if !defined(____FIIterator_1_UINT16_INTERFACE_DEFINED__)
#define ____FIIterator_1_UINT16_INTERFACE_DEFINED__

typedef interface __FIIterator_1_UINT16 __FIIterator_1_UINT16;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_UINT16;

typedef struct __FIIterator_1_UINT16Vtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_UINT16 * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_UINT16 * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_UINT16 * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_UINT16 * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_UINT16 * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_UINT16 * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_UINT16 * This, /* [retval][out] */ __RPC__out unsigned short *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_UINT16 * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_UINT16 * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_UINT16 * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) unsigned short *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_UINT16Vtbl;

interface __FIIterator_1_UINT16
{
    CONST_VTBL struct __FIIterator_1_UINT16Vtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_UINT16_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_UINT16_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_UINT16_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_UINT16_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_UINT16_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_UINT16_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_UINT16_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_UINT16_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_UINT16_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_UINT16_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_UINT16_INTERFACE_DEFINED__


#if !defined(____FIIterable_1_UINT16_INTERFACE_DEFINED__)
#define ____FIIterable_1_UINT16_INTERFACE_DEFINED__

typedef interface __FIIterable_1_UINT16 __FIIterable_1_UINT16;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_UINT16;

typedef  struct __FIIterable_1_UINT16Vtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_UINT16 * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_UINT16 * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_UINT16 * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_UINT16 * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_UINT16 * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_UINT16 * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_UINT16 * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_UINT16 **first);

    END_INTERFACE
} __FIIterable_1_UINT16Vtbl;

interface __FIIterable_1_UINT16
{
    CONST_VTBL struct __FIIterable_1_UINT16Vtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_UINT16_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_UINT16_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_UINT16_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_UINT16_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_UINT16_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_UINT16_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_UINT16_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_UINT16_INTERFACE_DEFINED__


#if !defined(____FIVectorView_1_UINT16_INTERFACE_DEFINED__)
#define ____FIVectorView_1_UINT16_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_UINT16 __FIVectorView_1_UINT16;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_UINT16;

typedef struct __FIVectorView_1_UINT16Vtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_UINT16 * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_UINT16 * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_UINT16 * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_UINT16 * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_UINT16 * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_UINT16 * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_UINT16 * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out unsigned short *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_UINT16 * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_UINT16 * This,
            /* [in] */ unsigned short item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_UINT16 * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) unsigned short *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_UINT16Vtbl;

interface __FIVectorView_1_UINT16
{
    CONST_VTBL struct __FIVectorView_1_UINT16Vtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_UINT16_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_UINT16_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_UINT16_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_UINT16_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_UINT16_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_UINT16_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_UINT16_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_UINT16_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_UINT16_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_UINT16_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_UINT16_INTERFACE_DEFINED__


#if !defined(____FIIterator_1_UINT32_INTERFACE_DEFINED__)
#define ____FIIterator_1_UINT32_INTERFACE_DEFINED__

typedef interface __FIIterator_1_UINT32 __FIIterator_1_UINT32;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_UINT32;

typedef struct __FIIterator_1_UINT32Vtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_UINT32 * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_UINT32 * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_UINT32 * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_UINT32 * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_UINT32 * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_UINT32 * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_UINT32 * This, /* [retval][out] */ __RPC__out unsigned int *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_UINT32 * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_UINT32 * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_UINT32 * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) unsigned int *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_UINT32Vtbl;

interface __FIIterator_1_UINT32
{
    CONST_VTBL struct __FIIterator_1_UINT32Vtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_UINT32_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_UINT32_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_UINT32_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_UINT32_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_UINT32_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_UINT32_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_UINT32_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_UINT32_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_UINT32_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_UINT32_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_UINT32_INTERFACE_DEFINED__


#if !defined(____FIIterable_1_UINT32_INTERFACE_DEFINED__)
#define ____FIIterable_1_UINT32_INTERFACE_DEFINED__

typedef interface __FIIterable_1_UINT32 __FIIterable_1_UINT32;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_UINT32;

typedef  struct __FIIterable_1_UINT32Vtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_UINT32 * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_UINT32 * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_UINT32 * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_UINT32 * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_UINT32 * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_UINT32 * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_UINT32 * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_UINT32 **first);

    END_INTERFACE
} __FIIterable_1_UINT32Vtbl;

interface __FIIterable_1_UINT32
{
    CONST_VTBL struct __FIIterable_1_UINT32Vtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_UINT32_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_UINT32_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_UINT32_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_UINT32_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_UINT32_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_UINT32_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_UINT32_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_UINT32_INTERFACE_DEFINED__


#if !defined(____FIVectorView_1_UINT32_INTERFACE_DEFINED__)
#define ____FIVectorView_1_UINT32_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_UINT32 __FIVectorView_1_UINT32;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_UINT32;

typedef struct __FIVectorView_1_UINT32Vtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_UINT32 * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_UINT32 * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_UINT32 * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_UINT32 * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_UINT32 * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_UINT32 * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_UINT32 * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out unsigned int *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_UINT32 * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_UINT32 * This,
            /* [in] */ unsigned int item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_UINT32 * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) unsigned int *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_UINT32Vtbl;

interface __FIVectorView_1_UINT32
{
    CONST_VTBL struct __FIVectorView_1_UINT32Vtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_UINT32_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_UINT32_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_UINT32_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_UINT32_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_UINT32_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_UINT32_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_UINT32_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_UINT32_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_UINT32_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_UINT32_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_UINT32_INTERFACE_DEFINED__


#if !defined(____FIIterator_1_UINT64_INTERFACE_DEFINED__)
#define ____FIIterator_1_UINT64_INTERFACE_DEFINED__

typedef interface __FIIterator_1_UINT64 __FIIterator_1_UINT64;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_UINT64;

typedef struct __FIIterator_1_UINT64Vtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_UINT64 * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_UINT64 * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_UINT64 * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_UINT64 * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_UINT64 * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_UINT64 * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_UINT64 * This, /* [retval][out] */ __RPC__out unsigned __int64 *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_UINT64 * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_UINT64 * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_UINT64 * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) unsigned __int64 *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_UINT64Vtbl;

interface __FIIterator_1_UINT64
{
    CONST_VTBL struct __FIIterator_1_UINT64Vtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_UINT64_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_UINT64_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_UINT64_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_UINT64_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_UINT64_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_UINT64_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_UINT64_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_UINT64_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_UINT64_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_UINT64_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_UINT64_INTERFACE_DEFINED__


#if !defined(____FIIterable_1_UINT64_INTERFACE_DEFINED__)
#define ____FIIterable_1_UINT64_INTERFACE_DEFINED__

typedef interface __FIIterable_1_UINT64 __FIIterable_1_UINT64;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_UINT64;

typedef  struct __FIIterable_1_UINT64Vtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_UINT64 * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_UINT64 * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_UINT64 * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_UINT64 * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_UINT64 * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_UINT64 * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_UINT64 * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_UINT64 **first);

    END_INTERFACE
} __FIIterable_1_UINT64Vtbl;

interface __FIIterable_1_UINT64
{
    CONST_VTBL struct __FIIterable_1_UINT64Vtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_UINT64_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_UINT64_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_UINT64_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_UINT64_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_UINT64_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_UINT64_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_UINT64_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_UINT64_INTERFACE_DEFINED__


#if !defined(____FIVectorView_1_UINT64_INTERFACE_DEFINED__)
#define ____FIVectorView_1_UINT64_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_UINT64 __FIVectorView_1_UINT64;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_UINT64;

typedef struct __FIVectorView_1_UINT64Vtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_UINT64 * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_UINT64 * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_UINT64 * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_UINT64 * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_UINT64 * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_UINT64 * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_UINT64 * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out unsigned __int64 *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_UINT64 * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_UINT64 * This,
            /* [in] */ unsigned __int64 item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_UINT64 * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) unsigned __int64 *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_UINT64Vtbl;

interface __FIVectorView_1_UINT64
{
    CONST_VTBL struct __FIVectorView_1_UINT64Vtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_UINT64_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_UINT64_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_UINT64_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_UINT64_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_UINT64_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_UINT64_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_UINT64_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_UINT64_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_UINT64_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_UINT64_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_UINT64_INTERFACE_DEFINED__



#ifndef ____x_ABI_CWindows_CFoundation_CCollections_CIPropertySet_FWD_DEFINED__
#define ____x_ABI_CWindows_CFoundation_CCollections_CIPropertySet_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CFoundation_CCollections_CIPropertySet __x_ABI_CWindows_CFoundation_CCollections_CIPropertySet;

#endif // ____x_ABI_CWindows_CFoundation_CCollections_CIPropertySet_FWD_DEFINED__





#ifndef ____x_ABI_CWindows_CFoundation_CIClosable_FWD_DEFINED__
#define ____x_ABI_CWindows_CFoundation_CIClosable_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CFoundation_CIClosable __x_ABI_CWindows_CFoundation_CIClosable;

#endif // ____x_ABI_CWindows_CFoundation_CIClosable_FWD_DEFINED__


#ifndef ____x_ABI_CWindows_CFoundation_CIMemoryBuffer_FWD_DEFINED__
#define ____x_ABI_CWindows_CFoundation_CIMemoryBuffer_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CFoundation_CIMemoryBuffer __x_ABI_CWindows_CFoundation_CIMemoryBuffer;

#endif // ____x_ABI_CWindows_CFoundation_CIMemoryBuffer_FWD_DEFINED__




#ifndef ____x_ABI_CWindows_CGraphics_CDirectX_CDirect3D11_CIDirect3DDevice_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDirectX_CDirect3D11_CIDirect3DDevice_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CGraphics_CDirectX_CDirect3D11_CIDirect3DDevice __x_ABI_CWindows_CGraphics_CDirectX_CDirect3D11_CIDirect3DDevice;

#endif // ____x_ABI_CWindows_CGraphics_CDirectX_CDirect3D11_CIDirect3DDevice_FWD_DEFINED__







typedef struct __x_ABI_CWindows_CGraphics_CDisplayAdapterId __x_ABI_CWindows_CGraphics_CDisplayAdapterId;




typedef enum __x_ABI_CWindows_CGraphics_CImaging_CBitmapAlphaMode __x_ABI_CWindows_CGraphics_CImaging_CBitmapAlphaMode;


typedef enum __x_ABI_CWindows_CGraphics_CImaging_CBitmapPixelFormat __x_ABI_CWindows_CGraphics_CImaging_CBitmapPixelFormat;




#ifndef ____x_ABI_CWindows_CMedia_CIVideoFrame_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CIVideoFrame_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CMedia_CIVideoFrame __x_ABI_CWindows_CMedia_CIVideoFrame;

#endif // ____x_ABI_CWindows_CMedia_CIVideoFrame_FWD_DEFINED__




#ifndef ____x_ABI_CWindows_CStorage_CIStorageFile_FWD_DEFINED__
#define ____x_ABI_CWindows_CStorage_CIStorageFile_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CStorage_CIStorageFile __x_ABI_CWindows_CStorage_CIStorageFile;

#endif // ____x_ABI_CWindows_CStorage_CIStorageFile_FWD_DEFINED__




#ifndef ____x_ABI_CWindows_CStorage_CStreams_CIBuffer_FWD_DEFINED__
#define ____x_ABI_CWindows_CStorage_CStreams_CIBuffer_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CStorage_CStreams_CIBuffer __x_ABI_CWindows_CStorage_CStreams_CIBuffer;

#endif // ____x_ABI_CWindows_CStorage_CStreams_CIBuffer_FWD_DEFINED__


#ifndef ____x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStreamReference_FWD_DEFINED__
#define ____x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStreamReference_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStreamReference __x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStreamReference;

#endif // ____x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStreamReference_FWD_DEFINED__







typedef enum __x_ABI_CWindows_CAI_CMachineLearning_CLearningModelDeviceKind __x_ABI_CWindows_CAI_CMachineLearning_CLearningModelDeviceKind;


typedef enum __x_ABI_CWindows_CAI_CMachineLearning_CLearningModelFeatureKind __x_ABI_CWindows_CAI_CMachineLearning_CLearningModelFeatureKind;


typedef enum __x_ABI_CWindows_CAI_CMachineLearning_CTensorKind __x_ABI_CWindows_CAI_CMachineLearning_CTensorKind;































































































/*
 *
 * Struct Windows.AI.MachineLearning.LearningModelDeviceKind
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 */

#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CAI_CMachineLearning_CLearningModelDeviceKind
{
    LearningModelDeviceKind_Default = 0,
    LearningModelDeviceKind_Cpu = 1,
    LearningModelDeviceKind_DirectX = 2,
    LearningModelDeviceKind_DirectXHighPerformance = 3,
    LearningModelDeviceKind_DirectXMinPower = 4,
};
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.AI.MachineLearning.LearningModelFeatureKind
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 */

#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CAI_CMachineLearning_CLearningModelFeatureKind
{
    LearningModelFeatureKind_Tensor = 0,
    LearningModelFeatureKind_Sequence = 1,
    LearningModelFeatureKind_Map = 2,
    LearningModelFeatureKind_Image = 3,
};
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.AI.MachineLearning.TensorKind
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 */

#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CAI_CMachineLearning_CTensorKind
{
    TensorKind_Undefined = 0,
    TensorKind_Float = 1,
    TensorKind_UInt8 = 2,
    TensorKind_Int8 = 3,
    TensorKind_UInt16 = 4,
    TensorKind_Int16 = 5,
    TensorKind_Int32 = 6,
    TensorKind_Int64 = 7,
    TensorKind_String = 8,
    TensorKind_Boolean = 9,
    TensorKind_Float16 = 10,
    TensorKind_Double = 11,
    TensorKind_UInt32 = 12,
    TensorKind_UInt64 = 13,
    TensorKind_Complex64 = 14,
    TensorKind_Complex128 = 15,
};
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.IImageFeatureDescriptor
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.ImageFeatureDescriptor
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_IImageFeatureDescriptor[] = L"Windows.AI.MachineLearning.IImageFeatureDescriptor";
/* [object, uuid("365585A5-171A-4A2A-985F-265159D3895A"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptorVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_BitmapPixelFormat )(
        __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CGraphics_CImaging_CBitmapPixelFormat * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_BitmapAlphaMode )(
        __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CGraphics_CImaging_CBitmapAlphaMode * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Width )(
        __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor * This,
        /* [retval, out] */__RPC__out UINT32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Height )(
        __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor * This,
        /* [retval, out] */__RPC__out UINT32 * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptorVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptorVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor_get_BitmapPixelFormat(This,value) \
    ( (This)->lpVtbl->get_BitmapPixelFormat(This,value) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor_get_BitmapAlphaMode(This,value) \
    ( (This)->lpVtbl->get_BitmapAlphaMode(This,value) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor_get_Width(This,value) \
    ( (This)->lpVtbl->get_Width(This,value) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor_get_Height(This,value) \
    ( (This)->lpVtbl->get_Height(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureDescriptor_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.IImageFeatureValue
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.ImageFeatureValue
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValue_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValue_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_IImageFeatureValue[] = L"Windows.AI.MachineLearning.IImageFeatureValue";
/* [object, uuid("F0414FD9-C9AA-4405-B7FB-94F87C8A3037"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValue * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValue * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValue * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValue * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValue * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValue * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_VideoFrame )(
        __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValue * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CMedia_CIVideoFrame * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValue
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValue_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValue_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValue_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValue_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValue_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValue_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValue_get_VideoFrame(This,value) \
    ( (This)->lpVtbl->get_VideoFrame(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValue;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValue_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.IImageFeatureValueStatics
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.ImageFeatureValue
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_IImageFeatureValueStatics[] = L"Windows.AI.MachineLearning.IImageFeatureValueStatics";
/* [object, uuid("1BC317FD-23CB-4610-B085-C8E1C87EBAA0"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *CreateFromVideoFrame )(
        __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CMedia_CIVideoFrame * image,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValue * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueStaticsVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueStatics_CreateFromVideoFrame(This,image,result) \
    ( (This)->lpVtbl->CreateFromVideoFrame(This,image,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueStatics;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CIImageFeatureValueStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ILearningModel
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.LearningModel
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModel_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModel_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ILearningModel[] = L"Windows.AI.MachineLearning.ILearningModel";
/* [object, uuid("5B8E4920-489F-4E86-9128-265A327B78FA"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Author )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Name )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Domain )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Description )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Version )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel * This,
        /* [retval, out] */__RPC__out INT64 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Metadata )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel * This,
        /* [retval, out] */__RPC__deref_out_opt __FIMapView_2_HSTRING_HSTRING * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_InputFeatures )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_OutputFeatures )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CAI__CMachineLearning__CILearningModelFeatureDescriptor * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel_get_Author(This,value) \
    ( (This)->lpVtbl->get_Author(This,value) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel_get_Name(This,value) \
    ( (This)->lpVtbl->get_Name(This,value) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel_get_Domain(This,value) \
    ( (This)->lpVtbl->get_Domain(This,value) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel_get_Description(This,value) \
    ( (This)->lpVtbl->get_Description(This,value) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel_get_Version(This,value) \
    ( (This)->lpVtbl->get_Version(This,value) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel_get_Metadata(This,value) \
    ( (This)->lpVtbl->get_Metadata(This,value) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel_get_InputFeatures(This,value) \
    ( (This)->lpVtbl->get_InputFeatures(This,value) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel_get_OutputFeatures(This,value) \
    ( (This)->lpVtbl->get_OutputFeatures(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CILearningModel;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModel_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ILearningModelBinding
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.LearningModelBinding
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ILearningModelBinding[] = L"Windows.AI.MachineLearning.ILearningModelBinding";
/* [object, uuid("EA312F20-168F-4F8C-94FE-2E7AC31B4AA8"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [overload] */HRESULT ( STDMETHODCALLTYPE *Bind )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding * This,
        /* [in] */__RPC__in HSTRING name,
        /* [in] */__RPC__in_opt IInspectable * value
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *BindWithProperties )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding * This,
        /* [in] */__RPC__in HSTRING name,
        /* [in] */__RPC__in_opt IInspectable * value,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CFoundation_CCollections_CIPropertySet * props
        );
    HRESULT ( STDMETHODCALLTYPE *Clear )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding * This
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding_Bind(This,name,value) \
    ( (This)->lpVtbl->Bind(This,name,value) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding_BindWithProperties(This,name,value,props) \
    ( (This)->lpVtbl->BindWithProperties(This,name,value,props) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding_Clear(This) \
    ( (This)->lpVtbl->Clear(This) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ILearningModelBindingFactory
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.LearningModelBinding
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ILearningModelBindingFactory[] = L"Windows.AI.MachineLearning.ILearningModelBindingFactory";
/* [object, uuid("C95F7A7A-E788-475E-8917-23AA381FAF0B"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingFactoryVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingFactory * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingFactory * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingFactory * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingFactory * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingFactory * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingFactory * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *CreateFromSession )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingFactory * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession * session,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingFactoryVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingFactory
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingFactoryVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingFactory_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingFactory_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingFactory_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingFactory_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingFactory_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingFactory_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingFactory_CreateFromSession(This,session,value) \
    ( (This)->lpVtbl->CreateFromSession(This,session,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingFactory;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBindingFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ILearningModelDevice
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.LearningModelDevice
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ILearningModelDevice[] = L"Windows.AI.MachineLearning.ILearningModelDevice";
/* [object, uuid("F5C2C8FE-3F56-4A8C-AC5F-FDB92D8B8252"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_AdapterId )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CGraphics_CDisplayAdapterId * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Direct3D11Device )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CGraphics_CDirectX_CDirect3D11_CIDirect3DDevice * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice_get_AdapterId(This,value) \
    ( (This)->lpVtbl->get_AdapterId(This,value) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice_get_Direct3D11Device(This,value) \
    ( (This)->lpVtbl->get_Direct3D11Device(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ILearningModelDeviceFactory
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.LearningModelDevice
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ILearningModelDeviceFactory[] = L"Windows.AI.MachineLearning.ILearningModelDeviceFactory";
/* [object, uuid("9CFFD74D-B1E5-4F20-80AD-0A56690DB06B"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceFactoryVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceFactory * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceFactory * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceFactory * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceFactory * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceFactory * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceFactory * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *Create )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceFactory * This,
        /* [in] */__x_ABI_CWindows_CAI_CMachineLearning_CLearningModelDeviceKind deviceKind,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceFactoryVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceFactory
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceFactoryVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceFactory_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceFactory_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceFactory_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceFactory_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceFactory_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceFactory_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceFactory_Create(This,deviceKind,value) \
    ( (This)->lpVtbl->Create(This,deviceKind,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceFactory;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ILearningModelDeviceStatics
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.LearningModelDevice
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ILearningModelDeviceStatics[] = L"Windows.AI.MachineLearning.ILearningModelDeviceStatics";
/* [object, uuid("49F32107-A8BF-42BB-92C7-10B12DC5D21F"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *CreateFromDirect3D11Device )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CGraphics_CDirectX_CDirect3D11_CIDirect3DDevice * device,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceStaticsVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceStatics_CreateFromDirect3D11Device(This,device,result) \
    ( (This)->lpVtbl->CreateFromDirect3D11Device(This,device,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceStatics;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDeviceStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ILearningModelEvaluationResult
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.LearningModelEvaluationResult
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ILearningModelEvaluationResult[] = L"Windows.AI.MachineLearning.ILearningModelEvaluationResult";
/* [object, uuid("B2F9BFCD-960E-49C0-8593-EB190AE3EEE2"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResultVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_CorrelationId )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ErrorStatus )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult * This,
        /* [retval, out] */__RPC__out INT32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Succeeded )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Outputs )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult * This,
        /* [retval, out] */__RPC__deref_out_opt __FIMapView_2_HSTRING_IInspectable * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResultVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult_get_CorrelationId(This,value) \
    ( (This)->lpVtbl->get_CorrelationId(This,value) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult_get_ErrorStatus(This,value) \
    ( (This)->lpVtbl->get_ErrorStatus(This,value) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult_get_Succeeded(This,value) \
    ( (This)->lpVtbl->get_Succeeded(This,value) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult_get_Outputs(This,value) \
    ( (This)->lpVtbl->get_Outputs(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ILearningModelFeatureDescriptor
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ILearningModelFeatureDescriptor[] = L"Windows.AI.MachineLearning.ILearningModelFeatureDescriptor";
/* [object, uuid("BC08CF7C-6ED0-4004-97BA-B9A2EECD2B4F"), contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptorVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Name )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Description )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Kind )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CAI_CMachineLearning_CLearningModelFeatureKind * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsRequired )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptorVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptorVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor_get_Name(This,value) \
    ( (This)->lpVtbl->get_Name(This,value) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor_get_Description(This,value) \
    ( (This)->lpVtbl->get_Description(This,value) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor_get_Kind(This,value) \
    ( (This)->lpVtbl->get_Kind(This,value) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor_get_IsRequired(This,value) \
    ( (This)->lpVtbl->get_IsRequired(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ILearningModelFeatureValue
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureValue_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureValue_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ILearningModelFeatureValue[] = L"Windows.AI.MachineLearning.ILearningModelFeatureValue";
/* [object, uuid("F51005DB-4085-4DFE-9FED-95EB0C0CF75C"), contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureValueVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureValue * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureValue * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureValue * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureValue * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureValue * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureValue * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Kind )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureValue * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CAI_CMachineLearning_CLearningModelFeatureKind * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureValueVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureValue
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureValueVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureValue_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureValue_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureValue_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureValue_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureValue_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureValue_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureValue_get_Kind(This,value) \
    ( (This)->lpVtbl->get_Kind(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureValue;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureValue_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ILearningModelOperatorProvider
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProvider_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProvider_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ILearningModelOperatorProvider[] = L"Windows.AI.MachineLearning.ILearningModelOperatorProvider";
/* [object, uuid("2A222E5D-AFB1-47ED-BFAD-B5B3A459EC04"), contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProviderVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProvider * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProvider * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProvider * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProvider * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProvider * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProvider * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProviderVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProvider
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProviderVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProvider_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProvider_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProvider_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProvider_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProvider_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProvider_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProvider;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProvider_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ILearningModelSession
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.LearningModelSession
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ILearningModelSession[] = L"Windows.AI.MachineLearning.ILearningModelSession";
/* [object, uuid("8E58F8F6-B787-4C11-90F0-7129AECA74A9"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Model )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Device )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_EvaluationProperties )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CCollections_CIPropertySet * * value
        );
    HRESULT ( STDMETHODCALLTYPE *EvaluateAsync )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding * bindings,
        /* [in] */__RPC__in HSTRING correlationId,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *EvaluateFeaturesAsync )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession * This,
        /* [in] */__RPC__in_opt __FIMap_2_HSTRING_IInspectable * features,
        /* [in] */__RPC__in HSTRING correlationId,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModelEvaluationResult * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *Evaluate )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelBinding * bindings,
        /* [in] */__RPC__in HSTRING correlationId,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult * * result
        );
    HRESULT ( STDMETHODCALLTYPE *EvaluateFeatures )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession * This,
        /* [in] */__RPC__in_opt __FIMap_2_HSTRING_IInspectable * features,
        /* [in] */__RPC__in HSTRING correlationId,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelEvaluationResult * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession_get_Model(This,value) \
    ( (This)->lpVtbl->get_Model(This,value) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession_get_Device(This,value) \
    ( (This)->lpVtbl->get_Device(This,value) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession_get_EvaluationProperties(This,value) \
    ( (This)->lpVtbl->get_EvaluationProperties(This,value) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession_EvaluateAsync(This,bindings,correlationId,operation) \
    ( (This)->lpVtbl->EvaluateAsync(This,bindings,correlationId,operation) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession_EvaluateFeaturesAsync(This,features,correlationId,operation) \
    ( (This)->lpVtbl->EvaluateFeaturesAsync(This,features,correlationId,operation) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession_Evaluate(This,bindings,correlationId,result) \
    ( (This)->lpVtbl->Evaluate(This,bindings,correlationId,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession_EvaluateFeatures(This,features,correlationId,result) \
    ( (This)->lpVtbl->EvaluateFeatures(This,features,correlationId,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ILearningModelSessionFactory
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.LearningModelSession
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ILearningModelSessionFactory[] = L"Windows.AI.MachineLearning.ILearningModelSessionFactory";
/* [object, uuid("0F6B881D-1C9B-47B6-BFE0-F1CF62A67579"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactoryVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *CreateFromModel )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel * model,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession * * value
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromModelOnDevice )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel * model,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice * deviceToRunOn,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactoryVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactoryVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory_CreateFromModel(This,model,value) \
    ( (This)->lpVtbl->CreateFromModel(This,model,value) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory_CreateFromModelOnDevice(This,model,deviceToRunOn,value) \
    ( (This)->lpVtbl->CreateFromModelOnDevice(This,model,deviceToRunOn,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ILearningModelSessionFactory2
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.LearningModelSession
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ILearningModelSessionFactory2[] = L"Windows.AI.MachineLearning.ILearningModelSessionFactory2";
/* [object, uuid("4E5C88BF-0A1F-5FEC-ADE0-2FD91E4EF29B"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *CreateFromModelOnDeviceWithSessionOptions )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory2 * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel * model,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelDevice * deviceToRunOn,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptions * learningModelSessionOptions,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSession * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory2Vtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory2
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory2_CreateFromModelOnDeviceWithSessionOptions(This,model,deviceToRunOn,learningModelSessionOptions,value) \
    ( (This)->lpVtbl->CreateFromModelOnDeviceWithSessionOptions(This,model,deviceToRunOn,learningModelSessionOptions,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory2;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionFactory2_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.AI.MachineLearning.ILearningModelSessionOptions
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.LearningModelSessionOptions
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptions_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptions_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ILearningModelSessionOptions[] = L"Windows.AI.MachineLearning.ILearningModelSessionOptions";
/* [object, uuid("B8F63FA1-134D-5133-8CFF-3A5C3C263BEB"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptionsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptions * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptions * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptions * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptions * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptions * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptions * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_BatchSizeOverride )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptions * This,
        /* [retval, out] */__RPC__out UINT32 * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_BatchSizeOverride )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptions * This,
        /* [in] */UINT32 value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptionsVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptions
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptionsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptions_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptions_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptions_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptions_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptions_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptions_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptions_get_BatchSizeOverride(This,value) \
    ( (This)->lpVtbl->get_BatchSizeOverride(This,value) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptions_put_BatchSizeOverride(This,value) \
    ( (This)->lpVtbl->put_BatchSizeOverride(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptions;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelSessionOptions_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.AI.MachineLearning.ILearningModelStatics
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.LearningModel
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ILearningModelStatics[] = L"Windows.AI.MachineLearning.ILearningModelStatics";
/* [object, uuid("E3B977E8-6952-4E47-8EF4-1F7F07897C6D"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [overload] */HRESULT ( STDMETHODCALLTYPE *LoadFromStorageFileAsync )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CStorage_CIStorageFile * modelFile,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel * * operation
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *LoadFromStreamAsync )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStreamReference * modelStream,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel * * operation
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *LoadFromFilePath )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics * This,
        /* [in] */__RPC__in HSTRING filePath,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel * * result
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *LoadFromStream )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStreamReference * modelStream,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel * * result
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *LoadFromStorageFileWithOperatorProviderAsync )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CStorage_CIStorageFile * modelFile,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProvider * operatorProvider,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel * * operation
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *LoadFromStreamWithOperatorProviderAsync )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStreamReference * modelStream,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProvider * operatorProvider,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CAI__CMachineLearning__CLearningModel * * operation
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *LoadFromFilePathWithOperatorProvider )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics * This,
        /* [in] */__RPC__in HSTRING filePath,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProvider * operatorProvider,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel * * result
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *LoadFromStreamWithOperatorProvider )(
        __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStreamReference * modelStream,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelOperatorProvider * operatorProvider,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CILearningModel * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStaticsVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics_LoadFromStorageFileAsync(This,modelFile,operation) \
    ( (This)->lpVtbl->LoadFromStorageFileAsync(This,modelFile,operation) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics_LoadFromStreamAsync(This,modelStream,operation) \
    ( (This)->lpVtbl->LoadFromStreamAsync(This,modelStream,operation) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics_LoadFromFilePath(This,filePath,result) \
    ( (This)->lpVtbl->LoadFromFilePath(This,filePath,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics_LoadFromStream(This,modelStream,result) \
    ( (This)->lpVtbl->LoadFromStream(This,modelStream,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics_LoadFromStorageFileWithOperatorProviderAsync(This,modelFile,operatorProvider,operation) \
    ( (This)->lpVtbl->LoadFromStorageFileWithOperatorProviderAsync(This,modelFile,operatorProvider,operation) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics_LoadFromStreamWithOperatorProviderAsync(This,modelStream,operatorProvider,operation) \
    ( (This)->lpVtbl->LoadFromStreamWithOperatorProviderAsync(This,modelStream,operatorProvider,operation) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics_LoadFromFilePathWithOperatorProvider(This,filePath,operatorProvider,result) \
    ( (This)->lpVtbl->LoadFromFilePathWithOperatorProvider(This,filePath,operatorProvider,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics_LoadFromStreamWithOperatorProvider(This,modelStream,operatorProvider,result) \
    ( (This)->lpVtbl->LoadFromStreamWithOperatorProvider(This,modelStream,operatorProvider,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CILearningModelStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.IMapFeatureDescriptor
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.MapFeatureDescriptor
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptor_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptor_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_IMapFeatureDescriptor[] = L"Windows.AI.MachineLearning.IMapFeatureDescriptor";
/* [object, uuid("530424BD-A257-436D-9E60-C2981F7CC5C4"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptorVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptor * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptor * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptor * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptor * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptor * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptor * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_KeyKind )(
        __x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptor * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CAI_CMachineLearning_CTensorKind * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ValueDescriptor )(
        __x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptor * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptorVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptor
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptorVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptor_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptor_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptor_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptor_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptor_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptor_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptor_get_KeyKind(This,value) \
    ( (This)->lpVtbl->get_KeyKind(This,value) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptor_get_ValueDescriptor(This,value) \
    ( (This)->lpVtbl->get_ValueDescriptor(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptor;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CIMapFeatureDescriptor_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ISequenceFeatureDescriptor
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.SequenceFeatureDescriptor
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CISequenceFeatureDescriptor_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CISequenceFeatureDescriptor_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ISequenceFeatureDescriptor[] = L"Windows.AI.MachineLearning.ISequenceFeatureDescriptor";
/* [object, uuid("84F6945A-562B-4D62-A851-739ACED96668"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CISequenceFeatureDescriptorVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CISequenceFeatureDescriptor * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CISequenceFeatureDescriptor * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CISequenceFeatureDescriptor * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CISequenceFeatureDescriptor * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CISequenceFeatureDescriptor * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CISequenceFeatureDescriptor * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ElementDescriptor )(
        __x_ABI_CWindows_CAI_CMachineLearning_CISequenceFeatureDescriptor * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CILearningModelFeatureDescriptor * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CISequenceFeatureDescriptorVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CISequenceFeatureDescriptor
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CISequenceFeatureDescriptorVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CISequenceFeatureDescriptor_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CISequenceFeatureDescriptor_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CISequenceFeatureDescriptor_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CISequenceFeatureDescriptor_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CISequenceFeatureDescriptor_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CISequenceFeatureDescriptor_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CISequenceFeatureDescriptor_get_ElementDescriptor(This,value) \
    ( (This)->lpVtbl->get_ElementDescriptor(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CISequenceFeatureDescriptor;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CISequenceFeatureDescriptor_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensor
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Any object which implements this interface must also implement the following interfaces:
 *     Windows.AI.MachineLearning.ILearningModelFeatureValue
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensor_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensor_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensor[] = L"Windows.AI.MachineLearning.ITensor";
/* [object, uuid("05489593-A305-4A25-AD09-440119B4B7F6"), contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensor * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensor * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensor * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensor * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensor * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensor * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_TensorKind )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensor * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CAI_CMachineLearning_CTensorKind * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Shape )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensor * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1___z__zint64 * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensor
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensor_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensor_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensor_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensor_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensor_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensor_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensor_get_TensorKind(This,value) \
    ( (This)->lpVtbl->get_TensorKind(This,value) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensor_get_Shape(This,value) \
    ( (This)->lpVtbl->get_Shape(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensor;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensor_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorBoolean
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorBoolean
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorBoolean[] = L"Windows.AI.MachineLearning.ITensorBoolean";
/* [object, uuid("50F311ED-29E9-4A5C-A44D-8FC512584EED"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetAsVectorView )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_boolean * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean_GetAsVectorView(This,result) \
    ( (This)->lpVtbl->GetAsVectorView(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorBooleanStatics
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorBoolean
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorBooleanStatics[] = L"Windows.AI.MachineLearning.ITensorBooleanStatics";
/* [object, uuid("2796862C-2357-49A7-B476-D0AA3DFE6866"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [overload] */HRESULT ( STDMETHODCALLTYPE *Create )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean * * result
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *Create2 )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromArray )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [in] */UINT32 __dataSize,
        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) boolean * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromIterable )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [in] */__RPC__in_opt __FIIterable_1_boolean * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStaticsVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics_Create(This,result) \
    ( (This)->lpVtbl->Create(This,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics_Create2(This,shape,result) \
    ( (This)->lpVtbl->Create2(This,shape,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics_CreateFromArray(This,shape,__dataSize,data,result) \
    ( (This)->lpVtbl->CreateFromArray(This,shape,__dataSize,data,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics_CreateFromIterable(This,shape,data,result) \
    ( (This)->lpVtbl->CreateFromIterable(This,shape,data,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorBooleanStatics2
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorBoolean
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorBooleanStatics2[] = L"Windows.AI.MachineLearning.ITensorBooleanStatics2";
/* [object, uuid("A3A4A501-6A2D-52D7-B04B-C435BAEE0115"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *CreateFromShapeArrayAndDataArray )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2 * This,
        /* [in] */UINT32 __shapeSize,
        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
        /* [in] */UINT32 __dataSize,
        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) boolean * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromBuffer )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2 * This,
        /* [in] */UINT32 __shapeSize,
        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CStorage_CStreams_CIBuffer * buffer,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorBoolean * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2Vtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2_CreateFromShapeArrayAndDataArray(This,__shapeSize,shape,__dataSize,data,result) \
    ( (This)->lpVtbl->CreateFromShapeArrayAndDataArray(This,__shapeSize,shape,__dataSize,data,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2_CreateFromBuffer(This,__shapeSize,shape,buffer,result) \
    ( (This)->lpVtbl->CreateFromBuffer(This,__shapeSize,shape,buffer,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorBooleanStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorDouble
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorDouble
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorDouble[] = L"Windows.AI.MachineLearning.ITensorDouble";
/* [object, uuid("91E41252-7A8F-4F0E-A28F-9637FFC8A3D0"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetAsVectorView )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_double * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble_GetAsVectorView(This,result) \
    ( (This)->lpVtbl->GetAsVectorView(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorDoubleStatics
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorDouble
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorDoubleStatics[] = L"Windows.AI.MachineLearning.ITensorDoubleStatics";
/* [object, uuid("A86693C5-9538-44E7-A3CA-5DF374A5A70C"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [overload] */HRESULT ( STDMETHODCALLTYPE *Create )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble * * result
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *Create2 )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromArray )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [in] */UINT32 __dataSize,
        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) DOUBLE * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromIterable )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [in] */__RPC__in_opt __FIIterable_1_double * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStaticsVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics_Create(This,result) \
    ( (This)->lpVtbl->Create(This,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics_Create2(This,shape,result) \
    ( (This)->lpVtbl->Create2(This,shape,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics_CreateFromArray(This,shape,__dataSize,data,result) \
    ( (This)->lpVtbl->CreateFromArray(This,shape,__dataSize,data,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics_CreateFromIterable(This,shape,data,result) \
    ( (This)->lpVtbl->CreateFromIterable(This,shape,data,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorDoubleStatics2
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorDouble
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorDoubleStatics2[] = L"Windows.AI.MachineLearning.ITensorDoubleStatics2";
/* [object, uuid("93A570DE-5E9A-5094-85C8-592C655E68AC"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *CreateFromShapeArrayAndDataArray )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2 * This,
        /* [in] */UINT32 __shapeSize,
        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
        /* [in] */UINT32 __dataSize,
        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) DOUBLE * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromBuffer )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2 * This,
        /* [in] */UINT32 __shapeSize,
        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CStorage_CStreams_CIBuffer * buffer,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorDouble * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2Vtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2_CreateFromShapeArrayAndDataArray(This,__shapeSize,shape,__dataSize,data,result) \
    ( (This)->lpVtbl->CreateFromShapeArrayAndDataArray(This,__shapeSize,shape,__dataSize,data,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2_CreateFromBuffer(This,__shapeSize,shape,buffer,result) \
    ( (This)->lpVtbl->CreateFromBuffer(This,__shapeSize,shape,buffer,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorDoubleStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorFeatureDescriptor
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorFeatureDescriptor
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptor_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptor_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorFeatureDescriptor[] = L"Windows.AI.MachineLearning.ITensorFeatureDescriptor";
/* [object, uuid("74455C80-946A-4310-A19C-EE0AF028FCE4"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptorVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptor * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptor * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptor * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptor * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptor * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptor * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_TensorKind )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptor * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CAI_CMachineLearning_CTensorKind * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Shape )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptor * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1___z__zint64 * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptorVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptor
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptorVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptor_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptor_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptor_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptor_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptor_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptor_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptor_get_TensorKind(This,value) \
    ( (This)->lpVtbl->get_TensorKind(This,value) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptor_get_Shape(This,value) \
    ( (This)->lpVtbl->get_Shape(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptor;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorFeatureDescriptor_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorFloat
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorFloat
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorFloat[] = L"Windows.AI.MachineLearning.ITensorFloat";
/* [object, uuid("F2282D82-AA02-42C8-A0C8-DF1EFC9676E1"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetAsVectorView )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_float * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat_GetAsVectorView(This,result) \
    ( (This)->lpVtbl->GetAsVectorView(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorFloat16Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorFloat16Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorFloat16Bit[] = L"Windows.AI.MachineLearning.ITensorFloat16Bit";
/* [object, uuid("0AB994FC-5B89-4C3C-B5E4-5282A5316C0A"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetAsVectorView )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_float * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit_GetAsVectorView(This,result) \
    ( (This)->lpVtbl->GetAsVectorView(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorFloat16BitStatics
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorFloat16Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorFloat16BitStatics[] = L"Windows.AI.MachineLearning.ITensorFloat16BitStatics";
/* [object, uuid("A52DB6F5-318A-44D4-820B-0CDC7054A84A"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [overload] */HRESULT ( STDMETHODCALLTYPE *Create )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit * * result
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *Create2 )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromArray )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [in] */UINT32 __dataSize,
        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) FLOAT * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromIterable )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [in] */__RPC__in_opt __FIIterable_1_float * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStaticsVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics_Create(This,result) \
    ( (This)->lpVtbl->Create(This,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics_Create2(This,shape,result) \
    ( (This)->lpVtbl->Create2(This,shape,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics_CreateFromArray(This,shape,__dataSize,data,result) \
    ( (This)->lpVtbl->CreateFromArray(This,shape,__dataSize,data,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics_CreateFromIterable(This,shape,data,result) \
    ( (This)->lpVtbl->CreateFromIterable(This,shape,data,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorFloat16BitStatics2
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorFloat16Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorFloat16BitStatics2[] = L"Windows.AI.MachineLearning.ITensorFloat16BitStatics2";
/* [object, uuid("68545726-2DC7-51BF-B470-0B344CC2A1BC"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *CreateFromShapeArrayAndDataArray )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2 * This,
        /* [in] */UINT32 __shapeSize,
        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
        /* [in] */UINT32 __dataSize,
        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) FLOAT * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromBuffer )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2 * This,
        /* [in] */UINT32 __shapeSize,
        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CStorage_CStreams_CIBuffer * buffer,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16Bit * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2Vtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2_CreateFromShapeArrayAndDataArray(This,__shapeSize,shape,__dataSize,data,result) \
    ( (This)->lpVtbl->CreateFromShapeArrayAndDataArray(This,__shapeSize,shape,__dataSize,data,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2_CreateFromBuffer(This,__shapeSize,shape,buffer,result) \
    ( (This)->lpVtbl->CreateFromBuffer(This,__shapeSize,shape,buffer,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat16BitStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorFloatStatics
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorFloat
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorFloatStatics[] = L"Windows.AI.MachineLearning.ITensorFloatStatics";
/* [object, uuid("DBCD395B-3BA3-452F-B10D-3C135E573FA9"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [overload] */HRESULT ( STDMETHODCALLTYPE *Create )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat * * result
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *Create2 )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromArray )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [in] */UINT32 __dataSize,
        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) FLOAT * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromIterable )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [in] */__RPC__in_opt __FIIterable_1_float * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStaticsVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics_Create(This,result) \
    ( (This)->lpVtbl->Create(This,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics_Create2(This,shape,result) \
    ( (This)->lpVtbl->Create2(This,shape,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics_CreateFromArray(This,shape,__dataSize,data,result) \
    ( (This)->lpVtbl->CreateFromArray(This,shape,__dataSize,data,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics_CreateFromIterable(This,shape,data,result) \
    ( (This)->lpVtbl->CreateFromIterable(This,shape,data,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorFloatStatics2
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorFloat
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorFloatStatics2[] = L"Windows.AI.MachineLearning.ITensorFloatStatics2";
/* [object, uuid("24610BC1-5E44-5713-B281-8F4AD4D555E8"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *CreateFromShapeArrayAndDataArray )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2 * This,
        /* [in] */UINT32 __shapeSize,
        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
        /* [in] */UINT32 __dataSize,
        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) FLOAT * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromBuffer )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2 * This,
        /* [in] */UINT32 __shapeSize,
        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CStorage_CStreams_CIBuffer * buffer,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloat * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2Vtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2_CreateFromShapeArrayAndDataArray(This,__shapeSize,shape,__dataSize,data,result) \
    ( (This)->lpVtbl->CreateFromShapeArrayAndDataArray(This,__shapeSize,shape,__dataSize,data,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2_CreateFromBuffer(This,__shapeSize,shape,buffer,result) \
    ( (This)->lpVtbl->CreateFromBuffer(This,__shapeSize,shape,buffer,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorFloatStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorInt16Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorInt16Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorInt16Bit[] = L"Windows.AI.MachineLearning.ITensorInt16Bit";
/* [object, uuid("98A32D39-E6D6-44AF-8AFA-BAEBC44DC020"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetAsVectorView )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_short * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit_GetAsVectorView(This,result) \
    ( (This)->lpVtbl->GetAsVectorView(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorInt16BitStatics
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorInt16Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorInt16BitStatics[] = L"Windows.AI.MachineLearning.ITensorInt16BitStatics";
/* [object, uuid("98646293-266E-4B1A-821F-E60D70898B91"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [overload] */HRESULT ( STDMETHODCALLTYPE *Create )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit * * result
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *Create2 )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromArray )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [in] */UINT32 __dataSize,
        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) INT16 * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromIterable )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [in] */__RPC__in_opt __FIIterable_1_short * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStaticsVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics_Create(This,result) \
    ( (This)->lpVtbl->Create(This,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics_Create2(This,shape,result) \
    ( (This)->lpVtbl->Create2(This,shape,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics_CreateFromArray(This,shape,__dataSize,data,result) \
    ( (This)->lpVtbl->CreateFromArray(This,shape,__dataSize,data,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics_CreateFromIterable(This,shape,data,result) \
    ( (This)->lpVtbl->CreateFromIterable(This,shape,data,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorInt16BitStatics2
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorInt16Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorInt16BitStatics2[] = L"Windows.AI.MachineLearning.ITensorInt16BitStatics2";
/* [object, uuid("0CD70CF4-696C-5E5F-95D8-5EBF9670148B"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *CreateFromShapeArrayAndDataArray )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2 * This,
        /* [in] */UINT32 __shapeSize,
        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
        /* [in] */UINT32 __dataSize,
        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) INT16 * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromBuffer )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2 * This,
        /* [in] */UINT32 __shapeSize,
        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CStorage_CStreams_CIBuffer * buffer,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16Bit * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2Vtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2_CreateFromShapeArrayAndDataArray(This,__shapeSize,shape,__dataSize,data,result) \
    ( (This)->lpVtbl->CreateFromShapeArrayAndDataArray(This,__shapeSize,shape,__dataSize,data,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2_CreateFromBuffer(This,__shapeSize,shape,buffer,result) \
    ( (This)->lpVtbl->CreateFromBuffer(This,__shapeSize,shape,buffer,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt16BitStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorInt32Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorInt32Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorInt32Bit[] = L"Windows.AI.MachineLearning.ITensorInt32Bit";
/* [object, uuid("2C0C28D3-207C-4486-A7D2-884522C5E589"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetAsVectorView )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_int * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit_GetAsVectorView(This,result) \
    ( (This)->lpVtbl->GetAsVectorView(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorInt32BitStatics
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorInt32Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorInt32BitStatics[] = L"Windows.AI.MachineLearning.ITensorInt32BitStatics";
/* [object, uuid("6539864B-52FA-4E35-907C-834CAC417B50"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [overload] */HRESULT ( STDMETHODCALLTYPE *Create )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit * * result
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *Create2 )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromArray )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [in] */UINT32 __dataSize,
        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) INT32 * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromIterable )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [in] */__RPC__in_opt __FIIterable_1_int * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStaticsVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics_Create(This,result) \
    ( (This)->lpVtbl->Create(This,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics_Create2(This,shape,result) \
    ( (This)->lpVtbl->Create2(This,shape,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics_CreateFromArray(This,shape,__dataSize,data,result) \
    ( (This)->lpVtbl->CreateFromArray(This,shape,__dataSize,data,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics_CreateFromIterable(This,shape,data,result) \
    ( (This)->lpVtbl->CreateFromIterable(This,shape,data,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorInt32BitStatics2
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorInt32Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorInt32BitStatics2[] = L"Windows.AI.MachineLearning.ITensorInt32BitStatics2";
/* [object, uuid("7C4B079A-E956-5CE0-A3BD-157D9D79B5EC"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *CreateFromShapeArrayAndDataArray )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2 * This,
        /* [in] */UINT32 __shapeSize,
        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
        /* [in] */UINT32 __dataSize,
        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) INT32 * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromBuffer )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2 * This,
        /* [in] */UINT32 __shapeSize,
        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CStorage_CStreams_CIBuffer * buffer,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32Bit * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2Vtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2_CreateFromShapeArrayAndDataArray(This,__shapeSize,shape,__dataSize,data,result) \
    ( (This)->lpVtbl->CreateFromShapeArrayAndDataArray(This,__shapeSize,shape,__dataSize,data,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2_CreateFromBuffer(This,__shapeSize,shape,buffer,result) \
    ( (This)->lpVtbl->CreateFromBuffer(This,__shapeSize,shape,buffer,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt32BitStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorInt64Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorInt64Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorInt64Bit[] = L"Windows.AI.MachineLearning.ITensorInt64Bit";
/* [object, uuid("499665BA-1FA2-45AD-AF25-A0BD9BDA4C87"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetAsVectorView )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1___z__zint64 * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit_GetAsVectorView(This,result) \
    ( (This)->lpVtbl->GetAsVectorView(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorInt64BitStatics
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorInt64Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorInt64BitStatics[] = L"Windows.AI.MachineLearning.ITensorInt64BitStatics";
/* [object, uuid("9648AD9D-1198-4D74-9517-783AB62B9CC2"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [overload] */HRESULT ( STDMETHODCALLTYPE *Create )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit * * result
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *Create2 )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromArray )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [in] */UINT32 __dataSize,
        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) INT64 * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromIterable )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStaticsVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics_Create(This,result) \
    ( (This)->lpVtbl->Create(This,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics_Create2(This,shape,result) \
    ( (This)->lpVtbl->Create2(This,shape,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics_CreateFromArray(This,shape,__dataSize,data,result) \
    ( (This)->lpVtbl->CreateFromArray(This,shape,__dataSize,data,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics_CreateFromIterable(This,shape,data,result) \
    ( (This)->lpVtbl->CreateFromIterable(This,shape,data,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorInt64BitStatics2
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorInt64Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorInt64BitStatics2[] = L"Windows.AI.MachineLearning.ITensorInt64BitStatics2";
/* [object, uuid("6D3D9DCB-FF40-5EC2-89FE-084E2B6BC6DB"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *CreateFromShapeArrayAndDataArray )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2 * This,
        /* [in] */UINT32 __shapeSize,
        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
        /* [in] */UINT32 __dataSize,
        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) INT64 * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromBuffer )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2 * This,
        /* [in] */UINT32 __shapeSize,
        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CStorage_CStreams_CIBuffer * buffer,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64Bit * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2Vtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2_CreateFromShapeArrayAndDataArray(This,__shapeSize,shape,__dataSize,data,result) \
    ( (This)->lpVtbl->CreateFromShapeArrayAndDataArray(This,__shapeSize,shape,__dataSize,data,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2_CreateFromBuffer(This,__shapeSize,shape,buffer,result) \
    ( (This)->lpVtbl->CreateFromBuffer(This,__shapeSize,shape,buffer,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt64BitStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorInt8Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorInt8Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorInt8Bit[] = L"Windows.AI.MachineLearning.ITensorInt8Bit";
/* [object, uuid("CDDD97C5-FFD8-4FEF-AEFB-30E1A485B2EE"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetAsVectorView )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_byte * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit_GetAsVectorView(This,result) \
    ( (This)->lpVtbl->GetAsVectorView(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorInt8BitStatics
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorInt8Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorInt8BitStatics[] = L"Windows.AI.MachineLearning.ITensorInt8BitStatics";
/* [object, uuid("B1A12284-095C-4C76-A661-AC4CEE1F3E8B"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [overload] */HRESULT ( STDMETHODCALLTYPE *Create )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit * * result
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *Create2 )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromArray )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [in] */UINT32 __dataSize,
        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) BYTE * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromIterable )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [in] */__RPC__in_opt __FIIterable_1_byte * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStaticsVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics_Create(This,result) \
    ( (This)->lpVtbl->Create(This,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics_Create2(This,shape,result) \
    ( (This)->lpVtbl->Create2(This,shape,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics_CreateFromArray(This,shape,__dataSize,data,result) \
    ( (This)->lpVtbl->CreateFromArray(This,shape,__dataSize,data,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics_CreateFromIterable(This,shape,data,result) \
    ( (This)->lpVtbl->CreateFromIterable(This,shape,data,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorInt8BitStatics2
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorInt8Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorInt8BitStatics2[] = L"Windows.AI.MachineLearning.ITensorInt8BitStatics2";
/* [object, uuid("C0D59637-C468-56FB-9535-C052BDB93DC0"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *CreateFromShapeArrayAndDataArray )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2 * This,
        /* [in] */UINT32 __shapeSize,
        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
        /* [in] */UINT32 __dataSize,
        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) BYTE * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromBuffer )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2 * This,
        /* [in] */UINT32 __shapeSize,
        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CStorage_CStreams_CIBuffer * buffer,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8Bit * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2Vtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2_CreateFromShapeArrayAndDataArray(This,__shapeSize,shape,__dataSize,data,result) \
    ( (This)->lpVtbl->CreateFromShapeArrayAndDataArray(This,__shapeSize,shape,__dataSize,data,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2_CreateFromBuffer(This,__shapeSize,shape,buffer,result) \
    ( (This)->lpVtbl->CreateFromBuffer(This,__shapeSize,shape,buffer,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorInt8BitStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorString
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorString
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorString_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorString_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorString[] = L"Windows.AI.MachineLearning.ITensorString";
/* [object, uuid("582335C8-BDB1-4610-BC75-35E9CBF009B7"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorString * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorString * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorString * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorString * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorString * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorString * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetAsVectorView )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorString * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_HSTRING * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorString
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorString_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorString_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorString_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorString_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorString_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorString_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorString_GetAsVectorView(This,result) \
    ( (This)->lpVtbl->GetAsVectorView(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorString;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorString_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorStringStatics
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorString
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorStringStatics[] = L"Windows.AI.MachineLearning.ITensorStringStatics";
/* [object, uuid("83623324-CF26-4F17-A2D4-20EF8D097D53"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [overload] */HRESULT ( STDMETHODCALLTYPE *Create )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorString * * result
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *Create2 )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorString * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromArray )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [in] */UINT32 __dataSize,
        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) HSTRING * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorString * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromIterable )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorString * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStaticsVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics_Create(This,result) \
    ( (This)->lpVtbl->Create(This,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics_Create2(This,shape,result) \
    ( (This)->lpVtbl->Create2(This,shape,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics_CreateFromArray(This,shape,__dataSize,data,result) \
    ( (This)->lpVtbl->CreateFromArray(This,shape,__dataSize,data,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics_CreateFromIterable(This,shape,data,result) \
    ( (This)->lpVtbl->CreateFromIterable(This,shape,data,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorStringStatics2
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorString
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorStringStatics2[] = L"Windows.AI.MachineLearning.ITensorStringStatics2";
/* [object, uuid("9E355ED0-C8E2-5254-9137-0193A3668FD8"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *CreateFromShapeArrayAndDataArray )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics2 * This,
        /* [in] */UINT32 __shapeSize,
        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
        /* [in] */UINT32 __dataSize,
        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) HSTRING * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorString * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics2Vtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics2
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics2_CreateFromShapeArrayAndDataArray(This,__shapeSize,shape,__dataSize,data,result) \
    ( (This)->lpVtbl->CreateFromShapeArrayAndDataArray(This,__shapeSize,shape,__dataSize,data,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics2;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorStringStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorUInt16Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorUInt16Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorUInt16Bit[] = L"Windows.AI.MachineLearning.ITensorUInt16Bit";
/* [object, uuid("68140F4B-23C0-42F3-81F6-A891C011BC3F"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetAsVectorView )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_UINT16 * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit_GetAsVectorView(This,result) \
    ( (This)->lpVtbl->GetAsVectorView(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorUInt16BitStatics
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorUInt16Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorUInt16BitStatics[] = L"Windows.AI.MachineLearning.ITensorUInt16BitStatics";
/* [object, uuid("5DF745DD-028A-481A-A27C-C7E6435E52DD"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [overload] */HRESULT ( STDMETHODCALLTYPE *Create )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit * * result
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *Create2 )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromArray )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [in] */UINT32 __dataSize,
        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) UINT16 * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromIterable )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [in] */__RPC__in_opt __FIIterable_1_UINT16 * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStaticsVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics_Create(This,result) \
    ( (This)->lpVtbl->Create(This,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics_Create2(This,shape,result) \
    ( (This)->lpVtbl->Create2(This,shape,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics_CreateFromArray(This,shape,__dataSize,data,result) \
    ( (This)->lpVtbl->CreateFromArray(This,shape,__dataSize,data,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics_CreateFromIterable(This,shape,data,result) \
    ( (This)->lpVtbl->CreateFromIterable(This,shape,data,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorUInt16BitStatics2
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorUInt16Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorUInt16BitStatics2[] = L"Windows.AI.MachineLearning.ITensorUInt16BitStatics2";
/* [object, uuid("8AF40C64-D69F-5315-9348-490877BBD642"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *CreateFromShapeArrayAndDataArray )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2 * This,
        /* [in] */UINT32 __shapeSize,
        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
        /* [in] */UINT32 __dataSize,
        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) UINT16 * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromBuffer )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2 * This,
        /* [in] */UINT32 __shapeSize,
        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CStorage_CStreams_CIBuffer * buffer,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16Bit * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2Vtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2_CreateFromShapeArrayAndDataArray(This,__shapeSize,shape,__dataSize,data,result) \
    ( (This)->lpVtbl->CreateFromShapeArrayAndDataArray(This,__shapeSize,shape,__dataSize,data,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2_CreateFromBuffer(This,__shapeSize,shape,buffer,result) \
    ( (This)->lpVtbl->CreateFromBuffer(This,__shapeSize,shape,buffer,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt16BitStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorUInt32Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorUInt32Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorUInt32Bit[] = L"Windows.AI.MachineLearning.ITensorUInt32Bit";
/* [object, uuid("D8C9C2FF-7511-45A3-BFAC-C38F370D2237"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetAsVectorView )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_UINT32 * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit_GetAsVectorView(This,result) \
    ( (This)->lpVtbl->GetAsVectorView(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorUInt32BitStatics
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorUInt32Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorUInt32BitStatics[] = L"Windows.AI.MachineLearning.ITensorUInt32BitStatics";
/* [object, uuid("417C3837-E773-4378-8E7F-0CC33DBEA697"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [overload] */HRESULT ( STDMETHODCALLTYPE *Create )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit * * result
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *Create2 )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromArray )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [in] */UINT32 __dataSize,
        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) UINT32 * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromIterable )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [in] */__RPC__in_opt __FIIterable_1_UINT32 * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStaticsVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics_Create(This,result) \
    ( (This)->lpVtbl->Create(This,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics_Create2(This,shape,result) \
    ( (This)->lpVtbl->Create2(This,shape,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics_CreateFromArray(This,shape,__dataSize,data,result) \
    ( (This)->lpVtbl->CreateFromArray(This,shape,__dataSize,data,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics_CreateFromIterable(This,shape,data,result) \
    ( (This)->lpVtbl->CreateFromIterable(This,shape,data,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorUInt32BitStatics2
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorUInt32Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorUInt32BitStatics2[] = L"Windows.AI.MachineLearning.ITensorUInt32BitStatics2";
/* [object, uuid("EF1A1F1C-314E-569D-B496-5C8447D20CD2"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *CreateFromShapeArrayAndDataArray )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2 * This,
        /* [in] */UINT32 __shapeSize,
        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
        /* [in] */UINT32 __dataSize,
        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) UINT32 * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromBuffer )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2 * This,
        /* [in] */UINT32 __shapeSize,
        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CStorage_CStreams_CIBuffer * buffer,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32Bit * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2Vtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2_CreateFromShapeArrayAndDataArray(This,__shapeSize,shape,__dataSize,data,result) \
    ( (This)->lpVtbl->CreateFromShapeArrayAndDataArray(This,__shapeSize,shape,__dataSize,data,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2_CreateFromBuffer(This,__shapeSize,shape,buffer,result) \
    ( (This)->lpVtbl->CreateFromBuffer(This,__shapeSize,shape,buffer,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt32BitStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorUInt64Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorUInt64Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorUInt64Bit[] = L"Windows.AI.MachineLearning.ITensorUInt64Bit";
/* [object, uuid("2E70FFAD-04BF-4825-839A-82BAEF8C7886"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetAsVectorView )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_UINT64 * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit_GetAsVectorView(This,result) \
    ( (This)->lpVtbl->GetAsVectorView(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorUInt64BitStatics
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorUInt64Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorUInt64BitStatics[] = L"Windows.AI.MachineLearning.ITensorUInt64BitStatics";
/* [object, uuid("7A7E20EB-242F-47CB-A9C6-F602ECFBFEE4"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [overload] */HRESULT ( STDMETHODCALLTYPE *Create )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit * * result
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *Create2 )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromArray )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [in] */UINT32 __dataSize,
        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) UINT64 * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromIterable )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [in] */__RPC__in_opt __FIIterable_1_UINT64 * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStaticsVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics_Create(This,result) \
    ( (This)->lpVtbl->Create(This,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics_Create2(This,shape,result) \
    ( (This)->lpVtbl->Create2(This,shape,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics_CreateFromArray(This,shape,__dataSize,data,result) \
    ( (This)->lpVtbl->CreateFromArray(This,shape,__dataSize,data,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics_CreateFromIterable(This,shape,data,result) \
    ( (This)->lpVtbl->CreateFromIterable(This,shape,data,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorUInt64BitStatics2
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorUInt64Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorUInt64BitStatics2[] = L"Windows.AI.MachineLearning.ITensorUInt64BitStatics2";
/* [object, uuid("085A687D-67E1-5B1E-B232-4FABE9CA20B3"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *CreateFromShapeArrayAndDataArray )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2 * This,
        /* [in] */UINT32 __shapeSize,
        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
        /* [in] */UINT32 __dataSize,
        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) UINT64 * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromBuffer )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2 * This,
        /* [in] */UINT32 __shapeSize,
        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CStorage_CStreams_CIBuffer * buffer,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64Bit * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2Vtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2_CreateFromShapeArrayAndDataArray(This,__shapeSize,shape,__dataSize,data,result) \
    ( (This)->lpVtbl->CreateFromShapeArrayAndDataArray(This,__shapeSize,shape,__dataSize,data,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2_CreateFromBuffer(This,__shapeSize,shape,buffer,result) \
    ( (This)->lpVtbl->CreateFromBuffer(This,__shapeSize,shape,buffer,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt64BitStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorUInt8Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorUInt8Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorUInt8Bit[] = L"Windows.AI.MachineLearning.ITensorUInt8Bit";
/* [object, uuid("58E1AE27-622B-48E3-BE22-D867AED1DAAC"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetAsVectorView )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_byte * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit_GetAsVectorView(This,result) \
    ( (This)->lpVtbl->GetAsVectorView(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorUInt8BitStatics
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorUInt8Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorUInt8BitStatics[] = L"Windows.AI.MachineLearning.ITensorUInt8BitStatics";
/* [object, uuid("05F67583-BC24-4220-8A41-2DCD8C5ED33C"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [overload] */HRESULT ( STDMETHODCALLTYPE *Create )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit * * result
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *Create2 )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromArray )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [in] */UINT32 __dataSize,
        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) BYTE * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromIterable )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1___z__zint64 * shape,
        /* [in] */__RPC__in_opt __FIIterable_1_byte * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStaticsVtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics_Create(This,result) \
    ( (This)->lpVtbl->Create(This,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics_Create2(This,shape,result) \
    ( (This)->lpVtbl->Create2(This,shape,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics_CreateFromArray(This,shape,__dataSize,data,result) \
    ( (This)->lpVtbl->CreateFromArray(This,shape,__dataSize,data,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics_CreateFromIterable(This,shape,data,result) \
    ( (This)->lpVtbl->CreateFromIterable(This,shape,data,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.AI.MachineLearning.ITensorUInt8BitStatics2
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.AI.MachineLearning.TensorUInt8Bit
 *
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_AI_MachineLearning_ITensorUInt8BitStatics2[] = L"Windows.AI.MachineLearning.ITensorUInt8BitStatics2";
/* [object, uuid("2BA042D6-373E-5A3A-A2FC-A6C41BD52789"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *CreateFromShapeArrayAndDataArray )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2 * This,
        /* [in] */UINT32 __shapeSize,
        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
        /* [in] */UINT32 __dataSize,
        /* [size_is(__dataSize), in] */__RPC__in_ecount_full(__dataSize) BYTE * data,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromBuffer )(
        __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2 * This,
        /* [in] */UINT32 __shapeSize,
        /* [size_is(__shapeSize), in] */__RPC__in_ecount_full(__shapeSize) INT64 * shape,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CStorage_CStreams_CIBuffer * buffer,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8Bit * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2Vtbl;

interface __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2
{
    CONST_VTBL struct __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2_CreateFromShapeArrayAndDataArray(This,__shapeSize,shape,__dataSize,data,result) \
    ( (This)->lpVtbl->CreateFromShapeArrayAndDataArray(This,__shapeSize,shape,__dataSize,data,result) )

#define __x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2_CreateFromBuffer(This,__shapeSize,shape,buffer,result) \
    ( (This)->lpVtbl->CreateFromBuffer(This,__shapeSize,shape,buffer,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2;
#endif /* !defined(____x_ABI_CWindows_CAI_CMachineLearning_CITensorUInt8BitStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000


/*
 *
 * Class Windows.AI.MachineLearning.ImageFeatureDescriptor
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.IImageFeatureDescriptor ** Default Interface **
 *    Windows.AI.MachineLearning.ILearningModelFeatureDescriptor
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_ImageFeatureDescriptor_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_ImageFeatureDescriptor_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_ImageFeatureDescriptor[] = L"Windows.AI.MachineLearning.ImageFeatureDescriptor";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.ImageFeatureValue
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.AI.MachineLearning.IImageFeatureValueStatics interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.IImageFeatureValue ** Default Interface **
 *    Windows.AI.MachineLearning.ILearningModelFeatureValue
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_ImageFeatureValue_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_ImageFeatureValue_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_ImageFeatureValue[] = L"Windows.AI.MachineLearning.ImageFeatureValue";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.LearningModel
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.AI.MachineLearning.ILearningModelStatics interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ILearningModel ** Default Interface **
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_LearningModel_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_LearningModel_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_LearningModel[] = L"Windows.AI.MachineLearning.LearningModel";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.LearningModelBinding
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via the Windows.AI.MachineLearning.ILearningModelBindingFactory interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ILearningModelBinding ** Default Interface **
 *    Windows.Foundation.Collections.IMapView_2_HSTRING,IInspectable
 *    Windows.Foundation.Collections.IIterable_1___FIKeyValuePair_2_HSTRING_IInspectable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_LearningModelBinding_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_LearningModelBinding_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_LearningModelBinding[] = L"Windows.AI.MachineLearning.LearningModelBinding";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.LearningModelDevice
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via the Windows.AI.MachineLearning.ILearningModelDeviceFactory interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.AI.MachineLearning.ILearningModelDeviceStatics interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ILearningModelDevice ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_LearningModelDevice_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_LearningModelDevice_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_LearningModelDevice[] = L"Windows.AI.MachineLearning.LearningModelDevice";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.LearningModelEvaluationResult
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ILearningModelEvaluationResult ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_LearningModelEvaluationResult_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_LearningModelEvaluationResult_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_LearningModelEvaluationResult[] = L"Windows.AI.MachineLearning.LearningModelEvaluationResult";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.LearningModelSession
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via the Windows.AI.MachineLearning.ILearningModelSessionFactory2 interface starting with version 2.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *   Type can be activated via the Windows.AI.MachineLearning.ILearningModelSessionFactory interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ILearningModelSession ** Default Interface **
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_LearningModelSession_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_LearningModelSession_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_LearningModelSession[] = L"Windows.AI.MachineLearning.LearningModelSession";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.LearningModelSessionOptions
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 2.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 2.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ILearningModelSessionOptions ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_LearningModelSessionOptions_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_LearningModelSessionOptions_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_LearningModelSessionOptions[] = L"Windows.AI.MachineLearning.LearningModelSessionOptions";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x20000


/*
 *
 * Class Windows.AI.MachineLearning.MapFeatureDescriptor
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.IMapFeatureDescriptor ** Default Interface **
 *    Windows.AI.MachineLearning.ILearningModelFeatureDescriptor
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_MapFeatureDescriptor_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_MapFeatureDescriptor_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_MapFeatureDescriptor[] = L"Windows.AI.MachineLearning.MapFeatureDescriptor";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.SequenceFeatureDescriptor
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ISequenceFeatureDescriptor ** Default Interface **
 *    Windows.AI.MachineLearning.ILearningModelFeatureDescriptor
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_SequenceFeatureDescriptor_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_SequenceFeatureDescriptor_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_SequenceFeatureDescriptor[] = L"Windows.AI.MachineLearning.SequenceFeatureDescriptor";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.TensorBoolean
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorBooleanStatics2 interface starting with version 2.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorBooleanStatics interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ITensorBoolean ** Default Interface **
 *    Windows.AI.MachineLearning.ITensor
 *    Windows.AI.MachineLearning.ILearningModelFeatureValue
 *    Windows.Foundation.IMemoryBuffer
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_TensorBoolean_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_TensorBoolean_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_TensorBoolean[] = L"Windows.AI.MachineLearning.TensorBoolean";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.TensorDouble
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorDoubleStatics2 interface starting with version 2.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorDoubleStatics interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ITensorDouble ** Default Interface **
 *    Windows.AI.MachineLearning.ITensor
 *    Windows.AI.MachineLearning.ILearningModelFeatureValue
 *    Windows.Foundation.IMemoryBuffer
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_TensorDouble_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_TensorDouble_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_TensorDouble[] = L"Windows.AI.MachineLearning.TensorDouble";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.TensorFeatureDescriptor
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ITensorFeatureDescriptor ** Default Interface **
 *    Windows.AI.MachineLearning.ILearningModelFeatureDescriptor
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_TensorFeatureDescriptor_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_TensorFeatureDescriptor_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_TensorFeatureDescriptor[] = L"Windows.AI.MachineLearning.TensorFeatureDescriptor";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.TensorFloat
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorFloatStatics2 interface starting with version 2.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorFloatStatics interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ITensorFloat ** Default Interface **
 *    Windows.AI.MachineLearning.ITensor
 *    Windows.AI.MachineLearning.ILearningModelFeatureValue
 *    Windows.Foundation.IMemoryBuffer
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_TensorFloat_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_TensorFloat_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_TensorFloat[] = L"Windows.AI.MachineLearning.TensorFloat";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.TensorFloat16Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorFloat16BitStatics2 interface starting with version 2.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorFloat16BitStatics interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ITensorFloat16Bit ** Default Interface **
 *    Windows.AI.MachineLearning.ITensor
 *    Windows.AI.MachineLearning.ILearningModelFeatureValue
 *    Windows.Foundation.IMemoryBuffer
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_TensorFloat16Bit_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_TensorFloat16Bit_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_TensorFloat16Bit[] = L"Windows.AI.MachineLearning.TensorFloat16Bit";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.TensorInt16Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorInt16BitStatics2 interface starting with version 2.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorInt16BitStatics interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ITensorInt16Bit ** Default Interface **
 *    Windows.AI.MachineLearning.ITensor
 *    Windows.AI.MachineLearning.ILearningModelFeatureValue
 *    Windows.Foundation.IMemoryBuffer
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_TensorInt16Bit_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_TensorInt16Bit_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_TensorInt16Bit[] = L"Windows.AI.MachineLearning.TensorInt16Bit";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.TensorInt32Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorInt32BitStatics2 interface starting with version 2.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorInt32BitStatics interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ITensorInt32Bit ** Default Interface **
 *    Windows.AI.MachineLearning.ITensor
 *    Windows.AI.MachineLearning.ILearningModelFeatureValue
 *    Windows.Foundation.IMemoryBuffer
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_TensorInt32Bit_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_TensorInt32Bit_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_TensorInt32Bit[] = L"Windows.AI.MachineLearning.TensorInt32Bit";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.TensorInt64Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorInt64BitStatics2 interface starting with version 2.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorInt64BitStatics interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ITensorInt64Bit ** Default Interface **
 *    Windows.AI.MachineLearning.ITensor
 *    Windows.AI.MachineLearning.ILearningModelFeatureValue
 *    Windows.Foundation.IMemoryBuffer
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_TensorInt64Bit_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_TensorInt64Bit_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_TensorInt64Bit[] = L"Windows.AI.MachineLearning.TensorInt64Bit";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.TensorInt8Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorInt8BitStatics2 interface starting with version 2.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorInt8BitStatics interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ITensorInt8Bit ** Default Interface **
 *    Windows.AI.MachineLearning.ITensor
 *    Windows.AI.MachineLearning.ILearningModelFeatureValue
 *    Windows.Foundation.IMemoryBuffer
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_TensorInt8Bit_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_TensorInt8Bit_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_TensorInt8Bit[] = L"Windows.AI.MachineLearning.TensorInt8Bit";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.TensorString
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorStringStatics2 interface starting with version 2.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorStringStatics interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ITensorString ** Default Interface **
 *    Windows.AI.MachineLearning.ITensor
 *    Windows.AI.MachineLearning.ILearningModelFeatureValue
 *    Windows.Foundation.IMemoryBuffer
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_TensorString_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_TensorString_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_TensorString[] = L"Windows.AI.MachineLearning.TensorString";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.TensorUInt16Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorUInt16BitStatics2 interface starting with version 2.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorUInt16BitStatics interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ITensorUInt16Bit ** Default Interface **
 *    Windows.AI.MachineLearning.ITensor
 *    Windows.AI.MachineLearning.ILearningModelFeatureValue
 *    Windows.Foundation.IMemoryBuffer
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_TensorUInt16Bit_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_TensorUInt16Bit_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_TensorUInt16Bit[] = L"Windows.AI.MachineLearning.TensorUInt16Bit";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.TensorUInt32Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorUInt32BitStatics2 interface starting with version 2.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorUInt32BitStatics interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ITensorUInt32Bit ** Default Interface **
 *    Windows.AI.MachineLearning.ITensor
 *    Windows.AI.MachineLearning.ILearningModelFeatureValue
 *    Windows.Foundation.IMemoryBuffer
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_TensorUInt32Bit_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_TensorUInt32Bit_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_TensorUInt32Bit[] = L"Windows.AI.MachineLearning.TensorUInt32Bit";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.TensorUInt64Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorUInt64BitStatics2 interface starting with version 2.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorUInt64BitStatics interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ITensorUInt64Bit ** Default Interface **
 *    Windows.AI.MachineLearning.ITensor
 *    Windows.AI.MachineLearning.ILearningModelFeatureValue
 *    Windows.Foundation.IMemoryBuffer
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_TensorUInt64Bit_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_TensorUInt64Bit_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_TensorUInt64Bit[] = L"Windows.AI.MachineLearning.TensorUInt64Bit";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.AI.MachineLearning.TensorUInt8Bit
 *
 * Introduced to Windows.AI.MachineLearning.MachineLearningContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorUInt8BitStatics2 interface starting with version 2.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *   Static Methods exist on the Windows.AI.MachineLearning.ITensorUInt8BitStatics interface starting with version 1.0 of the Windows.AI.MachineLearning.MachineLearningContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.AI.MachineLearning.ITensorUInt8Bit ** Default Interface **
 *    Windows.AI.MachineLearning.ITensor
 *    Windows.AI.MachineLearning.ILearningModelFeatureValue
 *    Windows.Foundation.IMemoryBuffer
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_AI_MachineLearning_TensorUInt8Bit_DEFINED
#define RUNTIMECLASS_Windows_AI_MachineLearning_TensorUInt8Bit_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_AI_MachineLearning_TensorUInt8Bit[] = L"Windows.AI.MachineLearning.TensorUInt8Bit";
#endif
#endif // WINDOWS_AI_MACHINELEARNING_MACHINELEARNINGCONTRACT_VERSION >= 0x10000




#endif // defined(__cplusplus)
#pragma pop_macro("MIDL_CONST_ID")
// Restore the original value of the 'DEPRECATED' macro
#pragma pop_macro("DEPRECATED")

#ifdef __clang__
#pragma clang diagnostic pop // deprecated-declarations
#else
#pragma warning(pop)
#endif
#endif // __windows2Eai2Emachinelearning_p_h__

#endif // __windows2Eai2Emachinelearning_h__
