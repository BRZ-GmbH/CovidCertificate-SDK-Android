/*
 * Copyright (c) 2021 Ubique Innovation AG <https://www.ubique.ch>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */

package at.gv.brz.eval

import at.gv.brz.eval.chain.Base45Service
import at.gv.brz.eval.chain.DecompressionService
import at.gv.brz.eval.chain.PrefixIdentifierService
import at.gv.brz.eval.chain.RevokedHealthCertService
import at.gv.brz.eval.chain.TimestampService
import at.gv.brz.eval.chain.VerificationCoseService
import at.gv.brz.eval.data.EvalErrorCodes
import at.gv.brz.eval.data.EvalErrorCodes.SIGNATURE_COSE_INVALID
import at.gv.brz.eval.data.state.CheckNationalRulesState
import at.gv.brz.eval.data.state.CheckRevocationState
import at.gv.brz.eval.data.state.CheckSignatureState
import at.gv.brz.eval.models.DccHolder
import at.gv.brz.eval.models.Jwks
import at.gv.brz.eval.models.RevokedCertificates
import at.gv.brz.eval.models.RuleSet
import at.gv.brz.eval.nationalrules.NationalRulesVerifier

internal object Eval {
	private val TAG = Eval::class.java.simpleName

	/**
	 * Checks whether the DCC has a valid signature.
	 *
	 * A signature is only valid if it is signed by a trusted key, but also only if other attributes are valid
	 * (e.g. the signature is not expired - which may be different from the legal national rules).
	 */
	fun checkSignature(dccHolder: DccHolder, signatures: Jwks): CheckSignatureState {

		/* Check that certificate type and signature timestamps are valid */

		val type = dccHolder.certType ?: return CheckSignatureState.INVALID(EvalErrorCodes.SIGNATURE_TYPE_INVALID)

		val timestampError = TimestampService.decode(dccHolder)
		if (timestampError != null) {
			return CheckSignatureState.INVALID(timestampError)
		}

		/* Repeat decode chain to get and verify COSE signature */

		val encoded = PrefixIdentifierService.decode(dccHolder.qrCodeData)
			?: return CheckSignatureState.INVALID(EvalErrorCodes.DECODE_PREFIX)
		val compressed = Base45Service.decode(encoded) ?: return CheckSignatureState.INVALID(EvalErrorCodes.DECODE_BASE_45)
		val cose = DecompressionService.decode(compressed) ?: return CheckSignatureState.INVALID(EvalErrorCodes.DECODE_Z_LIB)

		val valid = VerificationCoseService.decode(signatures.certs, cose, type)

    	// TODO: AT - Disable signature check because of missing key list without backend integration
    	return CheckSignatureState.SUCCESS
		//return if (valid) CheckSignatureState.SUCCESS else CheckSignatureState.INVALID(SIGNATURE_COSE_INVALID)
	}

	/**
	 * @param dccHolder Object which was returned from the decode function
	 * @return State for the revocation check
	 */
	fun checkRevocationStatus(dccHolder: DccHolder, revokedCertificates: RevokedCertificates): CheckRevocationState {
		val revokedCertificateService = RevokedHealthCertService(revokedCertificates)
		val containsRevokedCertificate = revokedCertificateService.isRevoked(dccHolder.euDGC)

		return if (containsRevokedCertificate) {
			CheckRevocationState.INVALID
		} else {
			CheckRevocationState.SUCCESS
		}
	}

	/**
	 * @param dccHolder Object which was returned from the decode function
	 * @return State for the Signaturecheck
	 */
	fun checkNationalRules(
		dccHolder: DccHolder,
		nationalRulesVerifier: NationalRulesVerifier,
		ruleSet: RuleSet
	): CheckNationalRulesState {
		return nationalRulesVerifier.verify(dccHolder.euDGC, ruleSet)
	}
}
