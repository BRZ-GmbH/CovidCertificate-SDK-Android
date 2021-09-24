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
import at.gv.brz.eval.data.state.*
import at.gv.brz.eval.models.DccHolder
import at.gv.brz.eval.models.TrustList
import ehn.techiop.hcert.kotlin.rules.BusinessRulesContainer
import ehn.techiop.hcert.kotlin.trust.TrustListV2
import ehn.techiop.hcert.kotlin.valueset.ValueSetContainer
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.withContext
import java.time.ZonedDateTime

internal class CertificateVerifier() {

	suspend fun verify(dccHolder: DccHolder, trustList: TrustList, validationClock: ZonedDateTime?, schemaJson: String, countryCode: String, regions: List<String>, checkDefaultRegion: Boolean): VerificationResultStatus = withContext(Dispatchers.Default) {
		val checkSignatureStateDeferred = async { checkSignature(dccHolder, trustList.signatures) }
		val deferredStates: MutableList<Deferred<VerificationResultStatus>> = mutableListOf()

		if (validationClock != null) {
			if (checkDefaultRegion) {
				deferredStates.add(async {
					checkNationalRules(
						dccHolder,
						validationClock,
						trustList.businessRules,
						trustList.valueSets,
						schemaJson,
						countryCode,
						null
					)
				})
			}
			regions.forEach {
				deferredStates.add(async {
					checkNationalRules(
						dccHolder,
						validationClock,
						trustList.businessRules,
						trustList.valueSets,
						schemaJson,
						countryCode,
						it
					)
				})
			}
		}

		val checkSignatureState = checkSignatureStateDeferred.await()
		val checkNationalRulesStates = deferredStates.map { it.await() }

		if (checkSignatureState is VerificationResultStatus.ERROR) {
			VerificationResultStatus.ERROR
		} else if (checkSignatureState is VerificationResultStatus.SIGNATURE_INVALID) {
			VerificationResultStatus.SIGNATURE_INVALID
		} else {
			if (checkNationalRulesStates.all { it is VerificationResultStatus.SUCCESS }) {
				if (validationClock != null) {
					val results =
						checkNationalRulesStates.flatMap { (it as VerificationResultStatus.SUCCESS).results }
					VerificationResultStatus.SUCCESS(results)
				} else {
					VerificationResultStatus.TIMEMISSING
				}
			} else {
				VerificationResultStatus.ERROR
			}
		}

	private suspend fun checkSignature(dccHolder: DccHolder, signatures: TrustListV2) = withContext(Dispatchers.Default) {
		try {
			Eval.checkSignature(dccHolder, signatures)
		} catch (e: Exception) {
			VerificationResultStatus.ERROR
		}
	}

	private suspend fun checkNationalRules(
		dccHolder: DccHolder,
		validationClock: ZonedDateTime,
		businessRules: BusinessRulesContainer,
		valueSets: ValueSetContainer,
		schemaJson: String,
		countryCode: String,
		region: String?
	) = withContext(Dispatchers.Default) {
		try {
			Eval.checkNationalRules(dccHolder, validationClock, businessRules, valueSets, schemaJson, countryCode, region)
		} catch (e: Exception) {
			VerificationResultStatus.SUCCESS(listOf(VerificationRegionResult(region, false)))
		}
	}

}