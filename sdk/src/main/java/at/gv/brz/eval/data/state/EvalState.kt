/*
 * Copyright (c) 2021 Ubique Innovation AG <https://www.ubique.ch>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */

package at.gv.brz.eval.data.state

import at.gv.brz.eval.models.DccHolder
import at.gv.brz.eval.nationalrules.NationalRulesError
import at.gv.brz.eval.nationalrules.ValidityRange


sealed class DecodeState {
	data class SUCCESS(val dccHolder: DccHolder) : DecodeState()
	data class ERROR(val error: Error) : DecodeState()
}

/**
 * Verification Result for a single region that was validated
 */
data class VerificationRegionResult(val region: String?, val valid: Boolean)

/**
 * Verification Result for a single certificate. If verification was successful, it
 * contains the verification results for all regions
 */
sealed class VerificationResultStatus {
	object LOADING: VerificationResultStatus()
	object SIGNATURE_INVALID: VerificationResultStatus()
	object ERROR: VerificationResultStatus()
	object TIMEMISSING: VerificationResultStatus()
	object DATAEXPIRED: VerificationResultStatus()
	data class SUCCESS(val results: List<VerificationRegionResult>): VerificationResultStatus()

	fun isInvalid(): Boolean {
		if (this is SIGNATURE_INVALID || this is ERROR || this.containsOnlyInvalidVerification()) {
			return true
		}
		return false
	}

	fun containsOnlyInvalidVerification(): Boolean {
		if (this is SUCCESS) {
			return this.results.none { it.valid }
		}
		return false
	}

	fun results(): List<VerificationRegionResult> {
		if (this is SUCCESS) {
			return this.results
		}
		return listOf()
	}
}

sealed class CheckSignatureState {
	object SUCCESS : CheckSignatureState()
	data class INVALID(val signatureErrorCode: String) : CheckSignatureState()
	object LOADING : CheckSignatureState()
	data class ERROR(val error: Error) : CheckSignatureState()
}

sealed class CheckRevocationState {
	object SUCCESS : CheckRevocationState()
	object INVALID : CheckRevocationState()
	object LOADING : CheckRevocationState()
	data class ERROR(val error: Error) : CheckRevocationState()
}

sealed class CheckNationalRulesState {
	data class SUCCESS(val validityRange: ValidityRange) : CheckNationalRulesState()
	data class NOT_YET_VALID(val validityRange: ValidityRange, val ruleId: String? = null) : CheckNationalRulesState()
	data class NOT_VALID_ANYMORE(val validityRange: ValidityRange, val ruleId: String? = null) : CheckNationalRulesState()
	data class INVALID(val nationalRulesError: NationalRulesError, val ruleId: String? = null) : CheckNationalRulesState()
	object LOADING : CheckNationalRulesState()
	data class ERROR(val error: Error) : CheckNationalRulesState()

	fun validityRange(): ValidityRange? = when (this) {
		is NOT_VALID_ANYMORE -> validityRange
		is NOT_YET_VALID -> validityRange
		is SUCCESS -> validityRange
		else -> null
	}
}

sealed class TrustListState {
	object SUCCESS : TrustListState()
	data class ERROR(val error: Error) : TrustListState()
}

data class Error(val code: String, val message: String? = null, val dccHolder: DccHolder? = null)
