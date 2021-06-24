/*
 * Copyright (c) 2021 Ubique Innovation AG <https://www.ubique.ch>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */

package at.gv.brz.eval.verification

import at.gv.brz.eval.Eval
import at.gv.brz.eval.data.EvalErrorCodes
import at.gv.brz.eval.data.state.CheckNationalRulesState
import at.gv.brz.eval.data.state.CheckRevocationState
import at.gv.brz.eval.data.state.CheckSignatureState
import at.gv.brz.eval.data.state.Error
import at.gv.brz.eval.data.state.VerificationState
import at.gv.brz.eval.models.DccHolder
import at.gv.brz.eval.models.Jwks
import at.gv.brz.eval.models.RevokedCertificates
import at.gv.brz.eval.models.RuleSet
import at.gv.brz.eval.models.TrustList
import at.gv.brz.eval.nationalrules.NationalRulesVerifier
import at.gv.brz.eval.nationalrules.ValidityRange
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.withContext

internal class CertificateVerifier(private val nationalRulesVerifier: NationalRulesVerifier) {

	suspend fun verify(dccHolder: DccHolder, trustList: TrustList): VerificationState = withContext(Dispatchers.Default) {
		// Execute all three checks in parallel...
		val checkSignatureStateDeferred = async { checkSignature(dccHolder, trustList.signatures) }
		// TODO: AT - Disable checks for revocation and national rules
		//val checkRevocationStateDeferred = async { checkRevocationStatus(dccHolder, trustList.revokedCertificates) }
		//val checkNationalRulesStateDeferred = async { checkNationalRules(dccHolder, nationalRulesVerifier, trustList.ruleSet) }

		// ... but wait for all of them to finish
		val checkSignatureState = checkSignatureStateDeferred.await()

		// TODO: AT - Disable checks for revocation and national rules
		//val checkRevocationState = checkRevocationStateDeferred.await()
		//val checkNationalRulesState = checkNationalRulesStateDeferred.await()

		if (checkSignatureState is CheckSignatureState.ERROR) {
			VerificationState.ERROR(checkSignatureState.error, null /*checkNationalRulesState.validityRange() */)
		} /*else if (checkRevocationState is CheckRevocationState.ERROR) {
			VerificationState.ERROR(checkRevocationState.error, checkNationalRulesState.validityRange())
		} else if (checkNationalRulesState is CheckNationalRulesState.ERROR) {
			VerificationState.ERROR(checkNationalRulesState.error, null)
		}*/ else if (
			checkSignatureState == CheckSignatureState.SUCCESS
			/*&& checkRevocationState == CheckRevocationState.SUCCESS
			&& checkNationalRulesState is CheckNationalRulesState.SUCCESS*/
		) {
			VerificationState.SUCCESS(ValidityRange(null, null) /*checkNationalRulesState.validityRange*/)
		} else if (
			checkSignatureState is CheckSignatureState.INVALID
			/*|| checkRevocationState is CheckRevocationState.INVALID
			|| checkNationalRulesState is CheckNationalRulesState.INVALID
			|| checkNationalRulesState is CheckNationalRulesState.NOT_YET_VALID
			|| checkNationalRulesState is CheckNationalRulesState.NOT_VALID_ANYMORE*/
		) {
			VerificationState.INVALID(
				checkSignatureState, null, null, null /* checkRevocationState, checkNationalRulesState,
				checkNationalRulesState.validityRange()*/
			)
		} else {
			VerificationState.LOADING
		}
	}

	private suspend fun checkSignature(dccHolder: DccHolder, signatures: Jwks) = withContext(Dispatchers.Default) {
		try {
			Eval.checkSignature(dccHolder, signatures)
		} catch (e: Exception) {
			CheckSignatureState.ERROR(Error(EvalErrorCodes.SIGNATURE_UNKNOWN, e.message.toString(), dccHolder))
		}
	}

	private suspend fun checkRevocationStatus(
		dccHolder: DccHolder,
		revokedCertificates: RevokedCertificates
	) = withContext(Dispatchers.Default) {
		try {
			Eval.checkRevocationStatus(dccHolder, revokedCertificates)
		} catch (e: Exception) {
			CheckRevocationState.ERROR(Error(EvalErrorCodes.REVOCATION_UNKNOWN, e.message.toString(), dccHolder))
		}
	}

	private suspend fun checkNationalRules(
		dccHolder: DccHolder,
		nationalRulesVerifier: NationalRulesVerifier,
		ruleSet: RuleSet
	) = withContext(Dispatchers.Default) {
		try {
			Eval.checkNationalRules(dccHolder, nationalRulesVerifier, ruleSet)
		} catch (e: Exception) {
			CheckNationalRulesState.ERROR(Error(EvalErrorCodes.RULESET_UNKNOWN, e.message.toString(), dccHolder))
		}
	}

}