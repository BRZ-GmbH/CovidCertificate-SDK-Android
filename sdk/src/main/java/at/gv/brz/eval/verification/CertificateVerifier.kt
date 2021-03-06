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
import at.gv.brz.eval.certificateType
import at.gv.brz.eval.data.state.*
import at.gv.brz.eval.models.DccHolder
import at.gv.brz.eval.models.TrustList
import at.gv.brz.eval.utils.validUntilDate
import com.fasterxml.jackson.databind.JsonNode
import dgca.verifier.app.engine.data.CertificateType
import dgca.verifier.app.engine.data.Rule
import ehn.techiop.hcert.kotlin.chain.impl.TrustListCertificateRepository
import ehn.techiop.hcert.kotlin.trust.TrustListV2
import kotlinx.coroutines.*
import java.time.ZonedDateTime

internal class CertificateVerifier() {

	suspend fun verify(dccHolder: DccHolder, trustList: TrustList, validationClock: ZonedDateTime?, certificateSchema: JsonNode, countryCode: String, regions: List<String>, checkDefaultRegion: Boolean): VerificationResultStatus = withContext(Dispatchers.Default) {
		val checkSignatureStateDeferred = async { checkSignature(dccHolder, trustList.signatures, trustList.nationalSignatures) }
		val deferredStates: MutableList<Deferred<VerificationResultStatus>> = mutableListOf()

		if (validationClock != null) {
			if (dccHolder.certificateType() == CertificateType.VACCINATION_EXEMPTION) {
				deferredStates.add(CompletableDeferred(VerificationResultStatus.SUCCESS(listOf(VerificationRegionResult(null, dccHolder.euDGC.vaccinationExemptions?.first()?.validUntilDate()?.isAfter(validationClock.toLocalDateTime()) == true, null)))))
			} else {
				if (checkDefaultRegion) {
					deferredStates.add(async {
						checkNationalRules(
							dccHolder,
							validationClock,
							trustList.businessRules,
							trustList.valueSets,
							certificateSchema,
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
							certificateSchema,
							countryCode,
							it
						)
					})
				}
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
	}

	private suspend fun checkSignature(dccHolder: DccHolder, signatures: TrustListCertificateRepository, nationalSignatures: TrustListCertificateRepository) = withContext(Dispatchers.Default) {
		try {
			Eval.checkSignature(dccHolder, signatures, nationalSignatures)
		} catch (e: Exception) {
			VerificationResultStatus.ERROR
		}
	}

	private suspend fun checkNationalRules(
		dccHolder: DccHolder,
		validationClock: ZonedDateTime,
		businessRules: List<Rule>,
		valueSets: Map<String, List<String>>,
		certificateSchema: JsonNode,
		countryCode: String,
		region: String?
	) = withContext(Dispatchers.Default) {
		try {
			Eval.checkNationalRules(dccHolder, validationClock, businessRules, valueSets, certificateSchema, countryCode, region)
		} catch (e: Exception) {
			VerificationResultStatus.SUCCESS(listOf(VerificationRegionResult(region, false, null)))
		}
	}

}