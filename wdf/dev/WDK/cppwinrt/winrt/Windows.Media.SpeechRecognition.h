// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Globalization.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Media.SpeechRecognition.2.h"
#include "winrt/Windows.Media.h"

namespace winrt::impl {

template <typename D> Windows::Media::SpeechRecognition::SpeechRecognitionResultStatus consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionCompletedEventArgs<D>::Status() const
{
    Windows::Media::SpeechRecognition::SpeechRecognitionResultStatus value{};
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionCompletedEventArgs)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::SpeechRecognition::SpeechRecognitionResult consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionResultGeneratedEventArgs<D>::Result() const
{
    Windows::Media::SpeechRecognition::SpeechRecognitionResult value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionResultGeneratedEventArgs)->get_Result(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionSession<D>::AutoStopSilenceTimeout() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionSession)->get_AutoStopSilenceTimeout(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionSession<D>::AutoStopSilenceTimeout(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionSession)->put_AutoStopSilenceTimeout(get_abi(value)));
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionSession<D>::StartAsync() const
{
    Windows::Foundation::IAsyncAction value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionSession)->StartAsync(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionSession<D>::StartAsync(Windows::Media::SpeechRecognition::SpeechContinuousRecognitionMode const& mode) const
{
    Windows::Foundation::IAsyncAction value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionSession)->StartWithModeAsync(get_abi(mode), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionSession<D>::StopAsync() const
{
    Windows::Foundation::IAsyncAction value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionSession)->StopAsync(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionSession<D>::CancelAsync() const
{
    Windows::Foundation::IAsyncAction value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionSession)->CancelAsync(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionSession<D>::PauseAsync() const
{
    Windows::Foundation::IAsyncAction value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionSession)->PauseAsync(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionSession<D>::Resume() const
{
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionSession)->Resume());
}

template <typename D> winrt::event_token consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionSession<D>::Completed(Windows::Foundation::TypedEventHandler<Windows::Media::SpeechRecognition::SpeechContinuousRecognitionSession, Windows::Media::SpeechRecognition::SpeechContinuousRecognitionCompletedEventArgs> const& value) const
{
    winrt::event_token returnValue{};
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionSession)->add_Completed(get_abi(value), put_abi(returnValue)));
    return returnValue;
}

template <typename D> typename consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionSession<D>::Completed_revoker consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionSession<D>::Completed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::SpeechRecognition::SpeechContinuousRecognitionSession, Windows::Media::SpeechRecognition::SpeechContinuousRecognitionCompletedEventArgs> const& value) const
{
    return impl::make_event_revoker<D, Completed_revoker>(this, Completed(value));
}

template <typename D> void consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionSession<D>::Completed(winrt::event_token const& value) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionSession)->remove_Completed(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionSession<D>::ResultGenerated(Windows::Foundation::TypedEventHandler<Windows::Media::SpeechRecognition::SpeechContinuousRecognitionSession, Windows::Media::SpeechRecognition::SpeechContinuousRecognitionResultGeneratedEventArgs> const& value) const
{
    winrt::event_token returnValue{};
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionSession)->add_ResultGenerated(get_abi(value), put_abi(returnValue)));
    return returnValue;
}

template <typename D> typename consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionSession<D>::ResultGenerated_revoker consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionSession<D>::ResultGenerated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::SpeechRecognition::SpeechContinuousRecognitionSession, Windows::Media::SpeechRecognition::SpeechContinuousRecognitionResultGeneratedEventArgs> const& value) const
{
    return impl::make_event_revoker<D, ResultGenerated_revoker>(this, ResultGenerated(value));
}

template <typename D> void consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionSession<D>::ResultGenerated(winrt::event_token const& value) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionSession)->remove_ResultGenerated(get_abi(value)));
}

template <typename D> Windows::Media::SpeechRecognition::SpeechRecognitionResultStatus consume_Windows_Media_SpeechRecognition_ISpeechRecognitionCompilationResult<D>::Status() const
{
    Windows::Media::SpeechRecognition::SpeechRecognitionResultStatus value{};
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognitionCompilationResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_SpeechRecognition_ISpeechRecognitionConstraint<D>::IsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognitionConstraint)->get_IsEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_SpeechRecognition_ISpeechRecognitionConstraint<D>::IsEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognitionConstraint)->put_IsEnabled(value));
}

template <typename D> hstring consume_Windows_Media_SpeechRecognition_ISpeechRecognitionConstraint<D>::Tag() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognitionConstraint)->get_Tag(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_SpeechRecognition_ISpeechRecognitionConstraint<D>::Tag(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognitionConstraint)->put_Tag(get_abi(value)));
}

template <typename D> Windows::Media::SpeechRecognition::SpeechRecognitionConstraintType consume_Windows_Media_SpeechRecognition_ISpeechRecognitionConstraint<D>::Type() const
{
    Windows::Media::SpeechRecognition::SpeechRecognitionConstraintType value{};
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognitionConstraint)->get_Type(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::SpeechRecognition::SpeechRecognitionConstraintProbability consume_Windows_Media_SpeechRecognition_ISpeechRecognitionConstraint<D>::Probability() const
{
    Windows::Media::SpeechRecognition::SpeechRecognitionConstraintProbability value{};
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognitionConstraint)->get_Probability(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_SpeechRecognition_ISpeechRecognitionConstraint<D>::Probability(Windows::Media::SpeechRecognition::SpeechRecognitionConstraintProbability const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognitionConstraint)->put_Probability(get_abi(value)));
}

template <typename D> Windows::Storage::StorageFile consume_Windows_Media_SpeechRecognition_ISpeechRecognitionGrammarFileConstraint<D>::GrammarFile() const
{
    Windows::Storage::StorageFile value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognitionGrammarFileConstraint)->get_GrammarFile(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::SpeechRecognition::SpeechRecognitionGrammarFileConstraint consume_Windows_Media_SpeechRecognition_ISpeechRecognitionGrammarFileConstraintFactory<D>::Create(Windows::Storage::StorageFile const& file) const
{
    Windows::Media::SpeechRecognition::SpeechRecognitionGrammarFileConstraint constraint{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognitionGrammarFileConstraintFactory)->Create(get_abi(file), put_abi(constraint)));
    return constraint;
}

template <typename D> Windows::Media::SpeechRecognition::SpeechRecognitionGrammarFileConstraint consume_Windows_Media_SpeechRecognition_ISpeechRecognitionGrammarFileConstraintFactory<D>::CreateWithTag(Windows::Storage::StorageFile const& file, param::hstring const& tag) const
{
    Windows::Media::SpeechRecognition::SpeechRecognitionGrammarFileConstraint constraint{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognitionGrammarFileConstraintFactory)->CreateWithTag(get_abi(file), get_abi(tag), put_abi(constraint)));
    return constraint;
}

template <typename D> hstring consume_Windows_Media_SpeechRecognition_ISpeechRecognitionHypothesis<D>::Text() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognitionHypothesis)->get_Text(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::SpeechRecognition::SpeechRecognitionHypothesis consume_Windows_Media_SpeechRecognition_ISpeechRecognitionHypothesisGeneratedEventArgs<D>::Hypothesis() const
{
    Windows::Media::SpeechRecognition::SpeechRecognitionHypothesis value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognitionHypothesisGeneratedEventArgs)->get_Hypothesis(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_Media_SpeechRecognition_ISpeechRecognitionListConstraint<D>::Commands() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognitionListConstraint)->get_Commands(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::SpeechRecognition::SpeechRecognitionListConstraint consume_Windows_Media_SpeechRecognition_ISpeechRecognitionListConstraintFactory<D>::Create(param::iterable<hstring> const& commands) const
{
    Windows::Media::SpeechRecognition::SpeechRecognitionListConstraint constraint{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognitionListConstraintFactory)->Create(get_abi(commands), put_abi(constraint)));
    return constraint;
}

template <typename D> Windows::Media::SpeechRecognition::SpeechRecognitionListConstraint consume_Windows_Media_SpeechRecognition_ISpeechRecognitionListConstraintFactory<D>::CreateWithTag(param::iterable<hstring> const& commands, param::hstring const& tag) const
{
    Windows::Media::SpeechRecognition::SpeechRecognitionListConstraint constraint{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognitionListConstraintFactory)->CreateWithTag(get_abi(commands), get_abi(tag), put_abi(constraint)));
    return constraint;
}

template <typename D> Windows::Media::SpeechRecognition::SpeechRecognitionAudioProblem consume_Windows_Media_SpeechRecognition_ISpeechRecognitionQualityDegradingEventArgs<D>::Problem() const
{
    Windows::Media::SpeechRecognition::SpeechRecognitionAudioProblem value{};
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognitionQualityDegradingEventArgs)->get_Problem(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::SpeechRecognition::SpeechRecognitionResultStatus consume_Windows_Media_SpeechRecognition_ISpeechRecognitionResult<D>::Status() const
{
    Windows::Media::SpeechRecognition::SpeechRecognitionResultStatus value{};
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognitionResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_SpeechRecognition_ISpeechRecognitionResult<D>::Text() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognitionResult)->get_Text(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::SpeechRecognition::SpeechRecognitionConfidence consume_Windows_Media_SpeechRecognition_ISpeechRecognitionResult<D>::Confidence() const
{
    Windows::Media::SpeechRecognition::SpeechRecognitionConfidence value{};
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognitionResult)->get_Confidence(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::SpeechRecognition::SpeechRecognitionSemanticInterpretation consume_Windows_Media_SpeechRecognition_ISpeechRecognitionResult<D>::SemanticInterpretation() const
{
    Windows::Media::SpeechRecognition::SpeechRecognitionSemanticInterpretation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognitionResult)->get_SemanticInterpretation(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::SpeechRecognition::SpeechRecognitionResult> consume_Windows_Media_SpeechRecognition_ISpeechRecognitionResult<D>::GetAlternates(uint32_t maxAlternates) const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::SpeechRecognition::SpeechRecognitionResult> alternates{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognitionResult)->GetAlternates(maxAlternates, put_abi(alternates)));
    return alternates;
}

template <typename D> Windows::Media::SpeechRecognition::ISpeechRecognitionConstraint consume_Windows_Media_SpeechRecognition_ISpeechRecognitionResult<D>::Constraint() const
{
    Windows::Media::SpeechRecognition::ISpeechRecognitionConstraint value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognitionResult)->get_Constraint(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_Media_SpeechRecognition_ISpeechRecognitionResult<D>::RulePath() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognitionResult)->get_RulePath(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_Media_SpeechRecognition_ISpeechRecognitionResult<D>::RawConfidence() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognitionResult)->get_RawConfidence(&value));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Media_SpeechRecognition_ISpeechRecognitionResult2<D>::PhraseStartTime() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognitionResult2)->get_PhraseStartTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_SpeechRecognition_ISpeechRecognitionResult2<D>::PhraseDuration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognitionResult2)->get_PhraseDuration(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::Collections::IVectorView<hstring>> consume_Windows_Media_SpeechRecognition_ISpeechRecognitionSemanticInterpretation<D>::Properties() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::Collections::IVectorView<hstring>> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognitionSemanticInterpretation)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::SpeechRecognition::SpeechRecognitionScenario consume_Windows_Media_SpeechRecognition_ISpeechRecognitionTopicConstraint<D>::Scenario() const
{
    Windows::Media::SpeechRecognition::SpeechRecognitionScenario value{};
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognitionTopicConstraint)->get_Scenario(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_SpeechRecognition_ISpeechRecognitionTopicConstraint<D>::TopicHint() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognitionTopicConstraint)->get_TopicHint(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::SpeechRecognition::SpeechRecognitionTopicConstraint consume_Windows_Media_SpeechRecognition_ISpeechRecognitionTopicConstraintFactory<D>::Create(Windows::Media::SpeechRecognition::SpeechRecognitionScenario const& scenario, param::hstring const& topicHint) const
{
    Windows::Media::SpeechRecognition::SpeechRecognitionTopicConstraint constraint{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognitionTopicConstraintFactory)->Create(get_abi(scenario), get_abi(topicHint), put_abi(constraint)));
    return constraint;
}

template <typename D> Windows::Media::SpeechRecognition::SpeechRecognitionTopicConstraint consume_Windows_Media_SpeechRecognition_ISpeechRecognitionTopicConstraintFactory<D>::CreateWithTag(Windows::Media::SpeechRecognition::SpeechRecognitionScenario const& scenario, param::hstring const& topicHint, param::hstring const& tag) const
{
    Windows::Media::SpeechRecognition::SpeechRecognitionTopicConstraint constraint{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognitionTopicConstraintFactory)->CreateWithTag(get_abi(scenario), get_abi(topicHint), get_abi(tag), put_abi(constraint)));
    return constraint;
}

template <typename D> Windows::Globalization::Language consume_Windows_Media_SpeechRecognition_ISpeechRecognizer<D>::CurrentLanguage() const
{
    Windows::Globalization::Language language{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizer)->get_CurrentLanguage(put_abi(language)));
    return language;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Media::SpeechRecognition::ISpeechRecognitionConstraint> consume_Windows_Media_SpeechRecognition_ISpeechRecognizer<D>::Constraints() const
{
    Windows::Foundation::Collections::IVector<Windows::Media::SpeechRecognition::ISpeechRecognitionConstraint> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizer)->get_Constraints(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::SpeechRecognition::SpeechRecognizerTimeouts consume_Windows_Media_SpeechRecognition_ISpeechRecognizer<D>::Timeouts() const
{
    Windows::Media::SpeechRecognition::SpeechRecognizerTimeouts value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizer)->get_Timeouts(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::SpeechRecognition::SpeechRecognizerUIOptions consume_Windows_Media_SpeechRecognition_ISpeechRecognizer<D>::UIOptions() const
{
    Windows::Media::SpeechRecognition::SpeechRecognizerUIOptions value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizer)->get_UIOptions(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::SpeechRecognition::SpeechRecognitionCompilationResult> consume_Windows_Media_SpeechRecognition_ISpeechRecognizer<D>::CompileConstraintsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::SpeechRecognition::SpeechRecognitionCompilationResult> asyncOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizer)->CompileConstraintsAsync(put_abi(asyncOperation)));
    return asyncOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::SpeechRecognition::SpeechRecognitionResult> consume_Windows_Media_SpeechRecognition_ISpeechRecognizer<D>::RecognizeAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::SpeechRecognition::SpeechRecognitionResult> asyncOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizer)->RecognizeAsync(put_abi(asyncOperation)));
    return asyncOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::SpeechRecognition::SpeechRecognitionResult> consume_Windows_Media_SpeechRecognition_ISpeechRecognizer<D>::RecognizeWithUIAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::SpeechRecognition::SpeechRecognitionResult> asyncOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizer)->RecognizeWithUIAsync(put_abi(asyncOperation)));
    return asyncOperation;
}

template <typename D> winrt::event_token consume_Windows_Media_SpeechRecognition_ISpeechRecognizer<D>::RecognitionQualityDegrading(Windows::Foundation::TypedEventHandler<Windows::Media::SpeechRecognition::SpeechRecognizer, Windows::Media::SpeechRecognition::SpeechRecognitionQualityDegradingEventArgs> const& speechRecognitionQualityDegradingHandler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizer)->add_RecognitionQualityDegrading(get_abi(speechRecognitionQualityDegradingHandler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Media_SpeechRecognition_ISpeechRecognizer<D>::RecognitionQualityDegrading_revoker consume_Windows_Media_SpeechRecognition_ISpeechRecognizer<D>::RecognitionQualityDegrading(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::SpeechRecognition::SpeechRecognizer, Windows::Media::SpeechRecognition::SpeechRecognitionQualityDegradingEventArgs> const& speechRecognitionQualityDegradingHandler) const
{
    return impl::make_event_revoker<D, RecognitionQualityDegrading_revoker>(this, RecognitionQualityDegrading(speechRecognitionQualityDegradingHandler));
}

template <typename D> void consume_Windows_Media_SpeechRecognition_ISpeechRecognizer<D>::RecognitionQualityDegrading(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizer)->remove_RecognitionQualityDegrading(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_Media_SpeechRecognition_ISpeechRecognizer<D>::StateChanged(Windows::Foundation::TypedEventHandler<Windows::Media::SpeechRecognition::SpeechRecognizer, Windows::Media::SpeechRecognition::SpeechRecognizerStateChangedEventArgs> const& stateChangedHandler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizer)->add_StateChanged(get_abi(stateChangedHandler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Media_SpeechRecognition_ISpeechRecognizer<D>::StateChanged_revoker consume_Windows_Media_SpeechRecognition_ISpeechRecognizer<D>::StateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::SpeechRecognition::SpeechRecognizer, Windows::Media::SpeechRecognition::SpeechRecognizerStateChangedEventArgs> const& stateChangedHandler) const
{
    return impl::make_event_revoker<D, StateChanged_revoker>(this, StateChanged(stateChangedHandler));
}

template <typename D> void consume_Windows_Media_SpeechRecognition_ISpeechRecognizer<D>::StateChanged(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizer)->remove_StateChanged(get_abi(cookie)));
}

template <typename D> Windows::Media::SpeechRecognition::SpeechContinuousRecognitionSession consume_Windows_Media_SpeechRecognition_ISpeechRecognizer2<D>::ContinuousRecognitionSession() const
{
    Windows::Media::SpeechRecognition::SpeechContinuousRecognitionSession value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizer2)->get_ContinuousRecognitionSession(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::SpeechRecognition::SpeechRecognizerState consume_Windows_Media_SpeechRecognition_ISpeechRecognizer2<D>::State() const
{
    Windows::Media::SpeechRecognition::SpeechRecognizerState value{};
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizer2)->get_State(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_SpeechRecognition_ISpeechRecognizer2<D>::StopRecognitionAsync() const
{
    Windows::Foundation::IAsyncAction value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizer2)->StopRecognitionAsync(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_SpeechRecognition_ISpeechRecognizer2<D>::HypothesisGenerated(Windows::Foundation::TypedEventHandler<Windows::Media::SpeechRecognition::SpeechRecognizer, Windows::Media::SpeechRecognition::SpeechRecognitionHypothesisGeneratedEventArgs> const& value) const
{
    winrt::event_token returnValue{};
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizer2)->add_HypothesisGenerated(get_abi(value), put_abi(returnValue)));
    return returnValue;
}

template <typename D> typename consume_Windows_Media_SpeechRecognition_ISpeechRecognizer2<D>::HypothesisGenerated_revoker consume_Windows_Media_SpeechRecognition_ISpeechRecognizer2<D>::HypothesisGenerated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::SpeechRecognition::SpeechRecognizer, Windows::Media::SpeechRecognition::SpeechRecognitionHypothesisGeneratedEventArgs> const& value) const
{
    return impl::make_event_revoker<D, HypothesisGenerated_revoker>(this, HypothesisGenerated(value));
}

template <typename D> void consume_Windows_Media_SpeechRecognition_ISpeechRecognizer2<D>::HypothesisGenerated(winrt::event_token const& value) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizer2)->remove_HypothesisGenerated(get_abi(value)));
}

template <typename D> Windows::Media::SpeechRecognition::SpeechRecognizer consume_Windows_Media_SpeechRecognition_ISpeechRecognizerFactory<D>::Create(Windows::Globalization::Language const& language) const
{
    Windows::Media::SpeechRecognition::SpeechRecognizer recognizer{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizerFactory)->Create(get_abi(language), put_abi(recognizer)));
    return recognizer;
}

template <typename D> Windows::Media::SpeechRecognition::SpeechRecognizerState consume_Windows_Media_SpeechRecognition_ISpeechRecognizerStateChangedEventArgs<D>::State() const
{
    Windows::Media::SpeechRecognition::SpeechRecognizerState value{};
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizerStateChangedEventArgs)->get_State(put_abi(value)));
    return value;
}

template <typename D> Windows::Globalization::Language consume_Windows_Media_SpeechRecognition_ISpeechRecognizerStatics<D>::SystemSpeechLanguage() const
{
    Windows::Globalization::Language language{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizerStatics)->get_SystemSpeechLanguage(put_abi(language)));
    return language;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Globalization::Language> consume_Windows_Media_SpeechRecognition_ISpeechRecognizerStatics<D>::SupportedTopicLanguages() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Globalization::Language> languages{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizerStatics)->get_SupportedTopicLanguages(put_abi(languages)));
    return languages;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Globalization::Language> consume_Windows_Media_SpeechRecognition_ISpeechRecognizerStatics<D>::SupportedGrammarLanguages() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Globalization::Language> languages{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizerStatics)->get_SupportedGrammarLanguages(put_abi(languages)));
    return languages;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Media_SpeechRecognition_ISpeechRecognizerStatics2<D>::TrySetSystemSpeechLanguageAsync(Windows::Globalization::Language const& speechLanguage) const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizerStatics2)->TrySetSystemSpeechLanguageAsync(get_abi(speechLanguage), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_SpeechRecognition_ISpeechRecognizerTimeouts<D>::InitialSilenceTimeout() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizerTimeouts)->get_InitialSilenceTimeout(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_SpeechRecognition_ISpeechRecognizerTimeouts<D>::InitialSilenceTimeout(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizerTimeouts)->put_InitialSilenceTimeout(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_SpeechRecognition_ISpeechRecognizerTimeouts<D>::EndSilenceTimeout() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizerTimeouts)->get_EndSilenceTimeout(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_SpeechRecognition_ISpeechRecognizerTimeouts<D>::EndSilenceTimeout(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizerTimeouts)->put_EndSilenceTimeout(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_SpeechRecognition_ISpeechRecognizerTimeouts<D>::BabbleTimeout() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizerTimeouts)->get_BabbleTimeout(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_SpeechRecognition_ISpeechRecognizerTimeouts<D>::BabbleTimeout(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizerTimeouts)->put_BabbleTimeout(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_SpeechRecognition_ISpeechRecognizerUIOptions<D>::ExampleText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizerUIOptions)->get_ExampleText(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_SpeechRecognition_ISpeechRecognizerUIOptions<D>::ExampleText(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizerUIOptions)->put_ExampleText(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_SpeechRecognition_ISpeechRecognizerUIOptions<D>::AudiblePrompt() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizerUIOptions)->get_AudiblePrompt(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_SpeechRecognition_ISpeechRecognizerUIOptions<D>::AudiblePrompt(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizerUIOptions)->put_AudiblePrompt(get_abi(value)));
}

template <typename D> bool consume_Windows_Media_SpeechRecognition_ISpeechRecognizerUIOptions<D>::IsReadBackEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizerUIOptions)->get_IsReadBackEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_SpeechRecognition_ISpeechRecognizerUIOptions<D>::IsReadBackEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizerUIOptions)->put_IsReadBackEnabled(value));
}

template <typename D> bool consume_Windows_Media_SpeechRecognition_ISpeechRecognizerUIOptions<D>::ShowConfirmation() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizerUIOptions)->get_ShowConfirmation(&value));
    return value;
}

template <typename D> void consume_Windows_Media_SpeechRecognition_ISpeechRecognizerUIOptions<D>::ShowConfirmation(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::ISpeechRecognizerUIOptions)->put_ShowConfirmation(value));
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_SpeechRecognition_IVoiceCommandManager<D>::InstallCommandSetsFromStorageFileAsync(Windows::Storage::StorageFile const& file) const
{
    Windows::Foundation::IAsyncAction installAction{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::IVoiceCommandManager)->InstallCommandSetsFromStorageFileAsync(get_abi(file), put_abi(installAction)));
    return installAction;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Media::SpeechRecognition::VoiceCommandSet> consume_Windows_Media_SpeechRecognition_IVoiceCommandManager<D>::InstalledCommandSets() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Media::SpeechRecognition::VoiceCommandSet> voiceCommandSets{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::IVoiceCommandManager)->get_InstalledCommandSets(put_abi(voiceCommandSets)));
    return voiceCommandSets;
}

template <typename D> hstring consume_Windows_Media_SpeechRecognition_IVoiceCommandSet<D>::Language() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::IVoiceCommandSet)->get_Language(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_SpeechRecognition_IVoiceCommandSet<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::IVoiceCommandSet)->get_Name(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_SpeechRecognition_IVoiceCommandSet<D>::SetPhraseListAsync(param::hstring const& phraseListName, param::async_iterable<hstring> const& phraseList) const
{
    Windows::Foundation::IAsyncAction updateAction{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::SpeechRecognition::IVoiceCommandSet)->SetPhraseListAsync(get_abi(phraseListName), get_abi(phraseList), put_abi(updateAction)));
    return updateAction;
}

template <typename D>
struct produce<D, Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionCompletedEventArgs> : produce_base<D, Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionCompletedEventArgs>
{
    int32_t WINRT_CALL get_Status(Windows::Media::SpeechRecognition::SpeechRecognitionResultStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Media::SpeechRecognition::SpeechRecognitionResultStatus));
            *value = detach_from<Windows::Media::SpeechRecognition::SpeechRecognitionResultStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionResultGeneratedEventArgs> : produce_base<D, Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionResultGeneratedEventArgs>
{
    int32_t WINRT_CALL get_Result(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Result, WINRT_WRAP(Windows::Media::SpeechRecognition::SpeechRecognitionResult));
            *value = detach_from<Windows::Media::SpeechRecognition::SpeechRecognitionResult>(this->shim().Result());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionSession> : produce_base<D, Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionSession>
{
    int32_t WINRT_CALL get_AutoStopSilenceTimeout(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoStopSilenceTimeout, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().AutoStopSilenceTimeout());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AutoStopSilenceTimeout(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoStopSilenceTimeout, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().AutoStopSilenceTimeout(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *value = detach_from<Windows::Foundation::IAsyncAction>(this->shim().StartAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartWithModeAsync(Windows::Media::SpeechRecognition::SpeechContinuousRecognitionMode mode, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Media::SpeechRecognition::SpeechContinuousRecognitionMode const);
            *value = detach_from<Windows::Foundation::IAsyncAction>(this->shim().StartAsync(*reinterpret_cast<Windows::Media::SpeechRecognition::SpeechContinuousRecognitionMode const*>(&mode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *value = detach_from<Windows::Foundation::IAsyncAction>(this->shim().StopAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CancelAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CancelAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *value = detach_from<Windows::Foundation::IAsyncAction>(this->shim().CancelAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PauseAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PauseAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *value = detach_from<Windows::Foundation::IAsyncAction>(this->shim().PauseAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Resume() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Resume, WINRT_WRAP(void));
            this->shim().Resume();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Completed(void* value, winrt::event_token* returnValue) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Completed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::SpeechRecognition::SpeechContinuousRecognitionSession, Windows::Media::SpeechRecognition::SpeechContinuousRecognitionCompletedEventArgs> const&);
            *returnValue = detach_from<winrt::event_token>(this->shim().Completed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::SpeechRecognition::SpeechContinuousRecognitionSession, Windows::Media::SpeechRecognition::SpeechContinuousRecognitionCompletedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Completed(winrt::event_token value) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Completed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Completed(*reinterpret_cast<winrt::event_token const*>(&value));
        return 0;
    }

    int32_t WINRT_CALL add_ResultGenerated(void* value, winrt::event_token* returnValue) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResultGenerated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::SpeechRecognition::SpeechContinuousRecognitionSession, Windows::Media::SpeechRecognition::SpeechContinuousRecognitionResultGeneratedEventArgs> const&);
            *returnValue = detach_from<winrt::event_token>(this->shim().ResultGenerated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::SpeechRecognition::SpeechContinuousRecognitionSession, Windows::Media::SpeechRecognition::SpeechContinuousRecognitionResultGeneratedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ResultGenerated(winrt::event_token value) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ResultGenerated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ResultGenerated(*reinterpret_cast<winrt::event_token const*>(&value));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::SpeechRecognition::ISpeechRecognitionCompilationResult> : produce_base<D, Windows::Media::SpeechRecognition::ISpeechRecognitionCompilationResult>
{
    int32_t WINRT_CALL get_Status(Windows::Media::SpeechRecognition::SpeechRecognitionResultStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Media::SpeechRecognition::SpeechRecognitionResultStatus));
            *value = detach_from<Windows::Media::SpeechRecognition::SpeechRecognitionResultStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::SpeechRecognition::ISpeechRecognitionConstraint> : produce_base<D, Windows::Media::SpeechRecognition::ISpeechRecognitionConstraint>
{
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

    int32_t WINRT_CALL put_IsEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabled, WINRT_WRAP(void), bool);
            this->shim().IsEnabled(value);
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

    int32_t WINRT_CALL get_Type(Windows::Media::SpeechRecognition::SpeechRecognitionConstraintType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(Windows::Media::SpeechRecognition::SpeechRecognitionConstraintType));
            *value = detach_from<Windows::Media::SpeechRecognition::SpeechRecognitionConstraintType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Probability(Windows::Media::SpeechRecognition::SpeechRecognitionConstraintProbability* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Probability, WINRT_WRAP(Windows::Media::SpeechRecognition::SpeechRecognitionConstraintProbability));
            *value = detach_from<Windows::Media::SpeechRecognition::SpeechRecognitionConstraintProbability>(this->shim().Probability());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Probability(Windows::Media::SpeechRecognition::SpeechRecognitionConstraintProbability value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Probability, WINRT_WRAP(void), Windows::Media::SpeechRecognition::SpeechRecognitionConstraintProbability const&);
            this->shim().Probability(*reinterpret_cast<Windows::Media::SpeechRecognition::SpeechRecognitionConstraintProbability const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::SpeechRecognition::ISpeechRecognitionGrammarFileConstraint> : produce_base<D, Windows::Media::SpeechRecognition::ISpeechRecognitionGrammarFileConstraint>
{
    int32_t WINRT_CALL get_GrammarFile(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GrammarFile, WINRT_WRAP(Windows::Storage::StorageFile));
            *value = detach_from<Windows::Storage::StorageFile>(this->shim().GrammarFile());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::SpeechRecognition::ISpeechRecognitionGrammarFileConstraintFactory> : produce_base<D, Windows::Media::SpeechRecognition::ISpeechRecognitionGrammarFileConstraintFactory>
{
    int32_t WINRT_CALL Create(void* file, void** constraint) noexcept final
    {
        try
        {
            *constraint = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Media::SpeechRecognition::SpeechRecognitionGrammarFileConstraint), Windows::Storage::StorageFile const&);
            *constraint = detach_from<Windows::Media::SpeechRecognition::SpeechRecognitionGrammarFileConstraint>(this->shim().Create(*reinterpret_cast<Windows::Storage::StorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithTag(void* file, void* tag, void** constraint) noexcept final
    {
        try
        {
            *constraint = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithTag, WINRT_WRAP(Windows::Media::SpeechRecognition::SpeechRecognitionGrammarFileConstraint), Windows::Storage::StorageFile const&, hstring const&);
            *constraint = detach_from<Windows::Media::SpeechRecognition::SpeechRecognitionGrammarFileConstraint>(this->shim().CreateWithTag(*reinterpret_cast<Windows::Storage::StorageFile const*>(&file), *reinterpret_cast<hstring const*>(&tag)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::SpeechRecognition::ISpeechRecognitionHypothesis> : produce_base<D, Windows::Media::SpeechRecognition::ISpeechRecognitionHypothesis>
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
};

template <typename D>
struct produce<D, Windows::Media::SpeechRecognition::ISpeechRecognitionHypothesisGeneratedEventArgs> : produce_base<D, Windows::Media::SpeechRecognition::ISpeechRecognitionHypothesisGeneratedEventArgs>
{
    int32_t WINRT_CALL get_Hypothesis(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Hypothesis, WINRT_WRAP(Windows::Media::SpeechRecognition::SpeechRecognitionHypothesis));
            *value = detach_from<Windows::Media::SpeechRecognition::SpeechRecognitionHypothesis>(this->shim().Hypothesis());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::SpeechRecognition::ISpeechRecognitionListConstraint> : produce_base<D, Windows::Media::SpeechRecognition::ISpeechRecognitionListConstraint>
{
    int32_t WINRT_CALL get_Commands(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Commands, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().Commands());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::SpeechRecognition::ISpeechRecognitionListConstraintFactory> : produce_base<D, Windows::Media::SpeechRecognition::ISpeechRecognitionListConstraintFactory>
{
    int32_t WINRT_CALL Create(void* commands, void** constraint) noexcept final
    {
        try
        {
            *constraint = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Media::SpeechRecognition::SpeechRecognitionListConstraint), Windows::Foundation::Collections::IIterable<hstring> const&);
            *constraint = detach_from<Windows::Media::SpeechRecognition::SpeechRecognitionListConstraint>(this->shim().Create(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&commands)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithTag(void* commands, void* tag, void** constraint) noexcept final
    {
        try
        {
            *constraint = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithTag, WINRT_WRAP(Windows::Media::SpeechRecognition::SpeechRecognitionListConstraint), Windows::Foundation::Collections::IIterable<hstring> const&, hstring const&);
            *constraint = detach_from<Windows::Media::SpeechRecognition::SpeechRecognitionListConstraint>(this->shim().CreateWithTag(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&commands), *reinterpret_cast<hstring const*>(&tag)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::SpeechRecognition::ISpeechRecognitionQualityDegradingEventArgs> : produce_base<D, Windows::Media::SpeechRecognition::ISpeechRecognitionQualityDegradingEventArgs>
{
    int32_t WINRT_CALL get_Problem(Windows::Media::SpeechRecognition::SpeechRecognitionAudioProblem* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Problem, WINRT_WRAP(Windows::Media::SpeechRecognition::SpeechRecognitionAudioProblem));
            *value = detach_from<Windows::Media::SpeechRecognition::SpeechRecognitionAudioProblem>(this->shim().Problem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::SpeechRecognition::ISpeechRecognitionResult> : produce_base<D, Windows::Media::SpeechRecognition::ISpeechRecognitionResult>
{
    int32_t WINRT_CALL get_Status(Windows::Media::SpeechRecognition::SpeechRecognitionResultStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Media::SpeechRecognition::SpeechRecognitionResultStatus));
            *value = detach_from<Windows::Media::SpeechRecognition::SpeechRecognitionResultStatus>(this->shim().Status());
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

    int32_t WINRT_CALL get_Confidence(Windows::Media::SpeechRecognition::SpeechRecognitionConfidence* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Confidence, WINRT_WRAP(Windows::Media::SpeechRecognition::SpeechRecognitionConfidence));
            *value = detach_from<Windows::Media::SpeechRecognition::SpeechRecognitionConfidence>(this->shim().Confidence());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SemanticInterpretation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SemanticInterpretation, WINRT_WRAP(Windows::Media::SpeechRecognition::SpeechRecognitionSemanticInterpretation));
            *value = detach_from<Windows::Media::SpeechRecognition::SpeechRecognitionSemanticInterpretation>(this->shim().SemanticInterpretation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAlternates(uint32_t maxAlternates, void** alternates) noexcept final
    {
        try
        {
            *alternates = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAlternates, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::SpeechRecognition::SpeechRecognitionResult>), uint32_t);
            *alternates = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::SpeechRecognition::SpeechRecognitionResult>>(this->shim().GetAlternates(maxAlternates));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Constraint(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Constraint, WINRT_WRAP(Windows::Media::SpeechRecognition::ISpeechRecognitionConstraint));
            *value = detach_from<Windows::Media::SpeechRecognition::ISpeechRecognitionConstraint>(this->shim().Constraint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RulePath(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RulePath, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().RulePath());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RawConfidence(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RawConfidence, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().RawConfidence());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::SpeechRecognition::ISpeechRecognitionResult2> : produce_base<D, Windows::Media::SpeechRecognition::ISpeechRecognitionResult2>
{
    int32_t WINRT_CALL get_PhraseStartTime(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhraseStartTime, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().PhraseStartTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PhraseDuration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhraseDuration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().PhraseDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::SpeechRecognition::ISpeechRecognitionSemanticInterpretation> : produce_base<D, Windows::Media::SpeechRecognition::ISpeechRecognitionSemanticInterpretation>
{
    int32_t WINRT_CALL get_Properties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::Collections::IVectorView<hstring>>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::Collections::IVectorView<hstring>>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::SpeechRecognition::ISpeechRecognitionTopicConstraint> : produce_base<D, Windows::Media::SpeechRecognition::ISpeechRecognitionTopicConstraint>
{
    int32_t WINRT_CALL get_Scenario(Windows::Media::SpeechRecognition::SpeechRecognitionScenario* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Scenario, WINRT_WRAP(Windows::Media::SpeechRecognition::SpeechRecognitionScenario));
            *value = detach_from<Windows::Media::SpeechRecognition::SpeechRecognitionScenario>(this->shim().Scenario());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TopicHint(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TopicHint, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TopicHint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::SpeechRecognition::ISpeechRecognitionTopicConstraintFactory> : produce_base<D, Windows::Media::SpeechRecognition::ISpeechRecognitionTopicConstraintFactory>
{
    int32_t WINRT_CALL Create(Windows::Media::SpeechRecognition::SpeechRecognitionScenario scenario, void* topicHint, void** constraint) noexcept final
    {
        try
        {
            *constraint = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Media::SpeechRecognition::SpeechRecognitionTopicConstraint), Windows::Media::SpeechRecognition::SpeechRecognitionScenario const&, hstring const&);
            *constraint = detach_from<Windows::Media::SpeechRecognition::SpeechRecognitionTopicConstraint>(this->shim().Create(*reinterpret_cast<Windows::Media::SpeechRecognition::SpeechRecognitionScenario const*>(&scenario), *reinterpret_cast<hstring const*>(&topicHint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithTag(Windows::Media::SpeechRecognition::SpeechRecognitionScenario scenario, void* topicHint, void* tag, void** constraint) noexcept final
    {
        try
        {
            *constraint = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithTag, WINRT_WRAP(Windows::Media::SpeechRecognition::SpeechRecognitionTopicConstraint), Windows::Media::SpeechRecognition::SpeechRecognitionScenario const&, hstring const&, hstring const&);
            *constraint = detach_from<Windows::Media::SpeechRecognition::SpeechRecognitionTopicConstraint>(this->shim().CreateWithTag(*reinterpret_cast<Windows::Media::SpeechRecognition::SpeechRecognitionScenario const*>(&scenario), *reinterpret_cast<hstring const*>(&topicHint), *reinterpret_cast<hstring const*>(&tag)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::SpeechRecognition::ISpeechRecognitionVoiceCommandDefinitionConstraint> : produce_base<D, Windows::Media::SpeechRecognition::ISpeechRecognitionVoiceCommandDefinitionConstraint>
{};

template <typename D>
struct produce<D, Windows::Media::SpeechRecognition::ISpeechRecognizer> : produce_base<D, Windows::Media::SpeechRecognition::ISpeechRecognizer>
{
    int32_t WINRT_CALL get_CurrentLanguage(void** language) noexcept final
    {
        try
        {
            *language = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentLanguage, WINRT_WRAP(Windows::Globalization::Language));
            *language = detach_from<Windows::Globalization::Language>(this->shim().CurrentLanguage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Constraints(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Constraints, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Media::SpeechRecognition::ISpeechRecognitionConstraint>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Media::SpeechRecognition::ISpeechRecognitionConstraint>>(this->shim().Constraints());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Timeouts(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Timeouts, WINRT_WRAP(Windows::Media::SpeechRecognition::SpeechRecognizerTimeouts));
            *value = detach_from<Windows::Media::SpeechRecognition::SpeechRecognizerTimeouts>(this->shim().Timeouts());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UIOptions(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UIOptions, WINRT_WRAP(Windows::Media::SpeechRecognition::SpeechRecognizerUIOptions));
            *value = detach_from<Windows::Media::SpeechRecognition::SpeechRecognizerUIOptions>(this->shim().UIOptions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CompileConstraintsAsync(void** asyncOperation) noexcept final
    {
        try
        {
            *asyncOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompileConstraintsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::SpeechRecognition::SpeechRecognitionCompilationResult>));
            *asyncOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::SpeechRecognition::SpeechRecognitionCompilationResult>>(this->shim().CompileConstraintsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RecognizeAsync(void** asyncOperation) noexcept final
    {
        try
        {
            *asyncOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecognizeAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::SpeechRecognition::SpeechRecognitionResult>));
            *asyncOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::SpeechRecognition::SpeechRecognitionResult>>(this->shim().RecognizeAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RecognizeWithUIAsync(void** asyncOperation) noexcept final
    {
        try
        {
            *asyncOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecognizeWithUIAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::SpeechRecognition::SpeechRecognitionResult>));
            *asyncOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::SpeechRecognition::SpeechRecognitionResult>>(this->shim().RecognizeWithUIAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_RecognitionQualityDegrading(void* speechRecognitionQualityDegradingHandler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecognitionQualityDegrading, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::SpeechRecognition::SpeechRecognizer, Windows::Media::SpeechRecognition::SpeechRecognitionQualityDegradingEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().RecognitionQualityDegrading(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::SpeechRecognition::SpeechRecognizer, Windows::Media::SpeechRecognition::SpeechRecognitionQualityDegradingEventArgs> const*>(&speechRecognitionQualityDegradingHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RecognitionQualityDegrading(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RecognitionQualityDegrading, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RecognitionQualityDegrading(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_StateChanged(void* stateChangedHandler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::SpeechRecognition::SpeechRecognizer, Windows::Media::SpeechRecognition::SpeechRecognizerStateChangedEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().StateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::SpeechRecognition::SpeechRecognizer, Windows::Media::SpeechRecognition::SpeechRecognizerStateChangedEventArgs> const*>(&stateChangedHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_StateChanged(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(StateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().StateChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::SpeechRecognition::ISpeechRecognizer2> : produce_base<D, Windows::Media::SpeechRecognition::ISpeechRecognizer2>
{
    int32_t WINRT_CALL get_ContinuousRecognitionSession(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContinuousRecognitionSession, WINRT_WRAP(Windows::Media::SpeechRecognition::SpeechContinuousRecognitionSession));
            *value = detach_from<Windows::Media::SpeechRecognition::SpeechContinuousRecognitionSession>(this->shim().ContinuousRecognitionSession());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_State(Windows::Media::SpeechRecognition::SpeechRecognizerState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::Media::SpeechRecognition::SpeechRecognizerState));
            *value = detach_from<Windows::Media::SpeechRecognition::SpeechRecognizerState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopRecognitionAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopRecognitionAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *value = detach_from<Windows::Foundation::IAsyncAction>(this->shim().StopRecognitionAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_HypothesisGenerated(void* value, winrt::event_token* returnValue) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HypothesisGenerated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::SpeechRecognition::SpeechRecognizer, Windows::Media::SpeechRecognition::SpeechRecognitionHypothesisGeneratedEventArgs> const&);
            *returnValue = detach_from<winrt::event_token>(this->shim().HypothesisGenerated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::SpeechRecognition::SpeechRecognizer, Windows::Media::SpeechRecognition::SpeechRecognitionHypothesisGeneratedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_HypothesisGenerated(winrt::event_token value) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(HypothesisGenerated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().HypothesisGenerated(*reinterpret_cast<winrt::event_token const*>(&value));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::SpeechRecognition::ISpeechRecognizerFactory> : produce_base<D, Windows::Media::SpeechRecognition::ISpeechRecognizerFactory>
{
    int32_t WINRT_CALL Create(void* language, void** recognizer) noexcept final
    {
        try
        {
            *recognizer = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Media::SpeechRecognition::SpeechRecognizer), Windows::Globalization::Language const&);
            *recognizer = detach_from<Windows::Media::SpeechRecognition::SpeechRecognizer>(this->shim().Create(*reinterpret_cast<Windows::Globalization::Language const*>(&language)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::SpeechRecognition::ISpeechRecognizerStateChangedEventArgs> : produce_base<D, Windows::Media::SpeechRecognition::ISpeechRecognizerStateChangedEventArgs>
{
    int32_t WINRT_CALL get_State(Windows::Media::SpeechRecognition::SpeechRecognizerState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::Media::SpeechRecognition::SpeechRecognizerState));
            *value = detach_from<Windows::Media::SpeechRecognition::SpeechRecognizerState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::SpeechRecognition::ISpeechRecognizerStatics> : produce_base<D, Windows::Media::SpeechRecognition::ISpeechRecognizerStatics>
{
    int32_t WINRT_CALL get_SystemSpeechLanguage(void** language) noexcept final
    {
        try
        {
            *language = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemSpeechLanguage, WINRT_WRAP(Windows::Globalization::Language));
            *language = detach_from<Windows::Globalization::Language>(this->shim().SystemSpeechLanguage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedTopicLanguages(void** languages) noexcept final
    {
        try
        {
            *languages = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedTopicLanguages, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Globalization::Language>));
            *languages = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Globalization::Language>>(this->shim().SupportedTopicLanguages());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedGrammarLanguages(void** languages) noexcept final
    {
        try
        {
            *languages = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedGrammarLanguages, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Globalization::Language>));
            *languages = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Globalization::Language>>(this->shim().SupportedGrammarLanguages());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::SpeechRecognition::ISpeechRecognizerStatics2> : produce_base<D, Windows::Media::SpeechRecognition::ISpeechRecognizerStatics2>
{
    int32_t WINRT_CALL TrySetSystemSpeechLanguageAsync(void* speechLanguage, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySetSystemSpeechLanguageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Globalization::Language const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TrySetSystemSpeechLanguageAsync(*reinterpret_cast<Windows::Globalization::Language const*>(&speechLanguage)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::SpeechRecognition::ISpeechRecognizerTimeouts> : produce_base<D, Windows::Media::SpeechRecognition::ISpeechRecognizerTimeouts>
{
    int32_t WINRT_CALL get_InitialSilenceTimeout(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InitialSilenceTimeout, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().InitialSilenceTimeout());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InitialSilenceTimeout(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InitialSilenceTimeout, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().InitialSilenceTimeout(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EndSilenceTimeout(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndSilenceTimeout, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().EndSilenceTimeout());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EndSilenceTimeout(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndSilenceTimeout, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().EndSilenceTimeout(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BabbleTimeout(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BabbleTimeout, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().BabbleTimeout());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BabbleTimeout(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BabbleTimeout, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().BabbleTimeout(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::SpeechRecognition::ISpeechRecognizerUIOptions> : produce_base<D, Windows::Media::SpeechRecognition::ISpeechRecognizerUIOptions>
{
    int32_t WINRT_CALL get_ExampleText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExampleText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ExampleText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ExampleText(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExampleText, WINRT_WRAP(void), hstring const&);
            this->shim().ExampleText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudiblePrompt(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudiblePrompt, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AudiblePrompt());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AudiblePrompt(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudiblePrompt, WINRT_WRAP(void), hstring const&);
            this->shim().AudiblePrompt(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsReadBackEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsReadBackEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsReadBackEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsReadBackEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsReadBackEnabled, WINRT_WRAP(void), bool);
            this->shim().IsReadBackEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShowConfirmation(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowConfirmation, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ShowConfirmation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ShowConfirmation(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowConfirmation, WINRT_WRAP(void), bool);
            this->shim().ShowConfirmation(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::SpeechRecognition::IVoiceCommandManager> : produce_base<D, Windows::Media::SpeechRecognition::IVoiceCommandManager>
{
    int32_t WINRT_CALL InstallCommandSetsFromStorageFileAsync(void* file, void** installAction) noexcept final
    {
        try
        {
            *installAction = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InstallCommandSetsFromStorageFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::StorageFile const);
            *installAction = detach_from<Windows::Foundation::IAsyncAction>(this->shim().InstallCommandSetsFromStorageFileAsync(*reinterpret_cast<Windows::Storage::StorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InstalledCommandSets(void** voiceCommandSets) noexcept final
    {
        try
        {
            *voiceCommandSets = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InstalledCommandSets, WINRT_WRAP(Windows::Foundation::Collections::IMapView<hstring, Windows::Media::SpeechRecognition::VoiceCommandSet>));
            *voiceCommandSets = detach_from<Windows::Foundation::Collections::IMapView<hstring, Windows::Media::SpeechRecognition::VoiceCommandSet>>(this->shim().InstalledCommandSets());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::SpeechRecognition::IVoiceCommandSet> : produce_base<D, Windows::Media::SpeechRecognition::IVoiceCommandSet>
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

    int32_t WINRT_CALL SetPhraseListAsync(void* phraseListName, void* phraseList, void** updateAction) noexcept final
    {
        try
        {
            *updateAction = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPhraseListAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const, Windows::Foundation::Collections::IIterable<hstring> const);
            *updateAction = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetPhraseListAsync(*reinterpret_cast<hstring const*>(&phraseListName), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&phraseList)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Media::SpeechRecognition {

inline SpeechRecognitionGrammarFileConstraint::SpeechRecognitionGrammarFileConstraint(Windows::Storage::StorageFile const& file) :
    SpeechRecognitionGrammarFileConstraint(impl::call_factory<SpeechRecognitionGrammarFileConstraint, Windows::Media::SpeechRecognition::ISpeechRecognitionGrammarFileConstraintFactory>([&](auto&& f) { return f.Create(file); }))
{}

inline SpeechRecognitionGrammarFileConstraint::SpeechRecognitionGrammarFileConstraint(Windows::Storage::StorageFile const& file, param::hstring const& tag) :
    SpeechRecognitionGrammarFileConstraint(impl::call_factory<SpeechRecognitionGrammarFileConstraint, Windows::Media::SpeechRecognition::ISpeechRecognitionGrammarFileConstraintFactory>([&](auto&& f) { return f.CreateWithTag(file, tag); }))
{}

inline SpeechRecognitionListConstraint::SpeechRecognitionListConstraint(param::iterable<hstring> const& commands) :
    SpeechRecognitionListConstraint(impl::call_factory<SpeechRecognitionListConstraint, Windows::Media::SpeechRecognition::ISpeechRecognitionListConstraintFactory>([&](auto&& f) { return f.Create(commands); }))
{}

inline SpeechRecognitionListConstraint::SpeechRecognitionListConstraint(param::iterable<hstring> const& commands, param::hstring const& tag) :
    SpeechRecognitionListConstraint(impl::call_factory<SpeechRecognitionListConstraint, Windows::Media::SpeechRecognition::ISpeechRecognitionListConstraintFactory>([&](auto&& f) { return f.CreateWithTag(commands, tag); }))
{}

inline SpeechRecognitionTopicConstraint::SpeechRecognitionTopicConstraint(Windows::Media::SpeechRecognition::SpeechRecognitionScenario const& scenario, param::hstring const& topicHint) :
    SpeechRecognitionTopicConstraint(impl::call_factory<SpeechRecognitionTopicConstraint, Windows::Media::SpeechRecognition::ISpeechRecognitionTopicConstraintFactory>([&](auto&& f) { return f.Create(scenario, topicHint); }))
{}

inline SpeechRecognitionTopicConstraint::SpeechRecognitionTopicConstraint(Windows::Media::SpeechRecognition::SpeechRecognitionScenario const& scenario, param::hstring const& topicHint, param::hstring const& tag) :
    SpeechRecognitionTopicConstraint(impl::call_factory<SpeechRecognitionTopicConstraint, Windows::Media::SpeechRecognition::ISpeechRecognitionTopicConstraintFactory>([&](auto&& f) { return f.CreateWithTag(scenario, topicHint, tag); }))
{}

inline SpeechRecognizer::SpeechRecognizer() :
    SpeechRecognizer(impl::call_factory<SpeechRecognizer>([](auto&& f) { return f.template ActivateInstance<SpeechRecognizer>(); }))
{}

inline SpeechRecognizer::SpeechRecognizer(Windows::Globalization::Language const& language) :
    SpeechRecognizer(impl::call_factory<SpeechRecognizer, Windows::Media::SpeechRecognition::ISpeechRecognizerFactory>([&](auto&& f) { return f.Create(language); }))
{}

inline Windows::Globalization::Language SpeechRecognizer::SystemSpeechLanguage()
{
    return impl::call_factory<SpeechRecognizer, Windows::Media::SpeechRecognition::ISpeechRecognizerStatics>([&](auto&& f) { return f.SystemSpeechLanguage(); });
}

inline Windows::Foundation::Collections::IVectorView<Windows::Globalization::Language> SpeechRecognizer::SupportedTopicLanguages()
{
    return impl::call_factory<SpeechRecognizer, Windows::Media::SpeechRecognition::ISpeechRecognizerStatics>([&](auto&& f) { return f.SupportedTopicLanguages(); });
}

inline Windows::Foundation::Collections::IVectorView<Windows::Globalization::Language> SpeechRecognizer::SupportedGrammarLanguages()
{
    return impl::call_factory<SpeechRecognizer, Windows::Media::SpeechRecognition::ISpeechRecognizerStatics>([&](auto&& f) { return f.SupportedGrammarLanguages(); });
}

inline Windows::Foundation::IAsyncOperation<bool> SpeechRecognizer::TrySetSystemSpeechLanguageAsync(Windows::Globalization::Language const& speechLanguage)
{
    return impl::call_factory<SpeechRecognizer, Windows::Media::SpeechRecognition::ISpeechRecognizerStatics2>([&](auto&& f) { return f.TrySetSystemSpeechLanguageAsync(speechLanguage); });
}

inline Windows::Foundation::IAsyncAction VoiceCommandManager::InstallCommandSetsFromStorageFileAsync(Windows::Storage::StorageFile const& file)
{
    return impl::call_factory<VoiceCommandManager, Windows::Media::SpeechRecognition::IVoiceCommandManager>([&](auto&& f) { return f.InstallCommandSetsFromStorageFileAsync(file); });
}

inline Windows::Foundation::Collections::IMapView<hstring, Windows::Media::SpeechRecognition::VoiceCommandSet> VoiceCommandManager::InstalledCommandSets()
{
    return impl::call_factory<VoiceCommandManager, Windows::Media::SpeechRecognition::IVoiceCommandManager>([&](auto&& f) { return f.InstalledCommandSets(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionCompletedEventArgs> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionResultGeneratedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionResultGeneratedEventArgs> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionSession> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionSession> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionCompilationResult> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionCompilationResult> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionConstraint> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionConstraint> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionGrammarFileConstraint> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionGrammarFileConstraint> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionGrammarFileConstraintFactory> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionGrammarFileConstraintFactory> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionHypothesis> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionHypothesis> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionHypothesisGeneratedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionHypothesisGeneratedEventArgs> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionListConstraint> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionListConstraint> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionListConstraintFactory> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionListConstraintFactory> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionQualityDegradingEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionQualityDegradingEventArgs> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionResult> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionResult> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionResult2> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionResult2> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionSemanticInterpretation> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionSemanticInterpretation> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionTopicConstraint> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionTopicConstraint> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionTopicConstraintFactory> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionTopicConstraintFactory> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionVoiceCommandDefinitionConstraint> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionVoiceCommandDefinitionConstraint> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognizer> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::ISpeechRecognizer> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognizer2> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::ISpeechRecognizer2> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerFactory> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerFactory> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerStatics> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerStatics> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerStatics2> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerStatics2> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerTimeouts> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerTimeouts> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerUIOptions> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerUIOptions> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::IVoiceCommandManager> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::IVoiceCommandManager> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::IVoiceCommandSet> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::IVoiceCommandSet> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::SpeechContinuousRecognitionCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::SpeechContinuousRecognitionCompletedEventArgs> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::SpeechContinuousRecognitionResultGeneratedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::SpeechContinuousRecognitionResultGeneratedEventArgs> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::SpeechContinuousRecognitionSession> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::SpeechContinuousRecognitionSession> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionCompilationResult> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionCompilationResult> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionGrammarFileConstraint> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionGrammarFileConstraint> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionHypothesis> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionHypothesis> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionHypothesisGeneratedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionHypothesisGeneratedEventArgs> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionListConstraint> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionListConstraint> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionQualityDegradingEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionQualityDegradingEventArgs> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionResult> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionResult> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionSemanticInterpretation> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionSemanticInterpretation> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionTopicConstraint> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionTopicConstraint> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionVoiceCommandDefinitionConstraint> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionVoiceCommandDefinitionConstraint> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::SpeechRecognizer> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::SpeechRecognizer> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::SpeechRecognizerStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::SpeechRecognizerStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::SpeechRecognizerTimeouts> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::SpeechRecognizerTimeouts> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::SpeechRecognizerUIOptions> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::SpeechRecognizerUIOptions> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::VoiceCommandManager> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::VoiceCommandManager> {};
template<> struct hash<winrt::Windows::Media::SpeechRecognition::VoiceCommandSet> : winrt::impl::hash_base<winrt::Windows::Media::SpeechRecognition::VoiceCommandSet> {};

}
