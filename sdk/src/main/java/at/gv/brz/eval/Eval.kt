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

import at.gv.brz.eval.chain.LocalCwtService
import at.gv.brz.eval.data.state.*
import at.gv.brz.eval.models.CertType
import at.gv.brz.eval.models.DccHolder
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import com.fasterxml.jackson.module.kotlin.readValue
import dgca.verifier.app.engine.DefaultAffectedFieldsDataRetriever
import dgca.verifier.app.engine.DefaultCertLogicEngine
import dgca.verifier.app.engine.DefaultJsonLogicValidator
import dgca.verifier.app.engine.Result
import dgca.verifier.app.engine.data.*
import ehn.techiop.hcert.kotlin.chain.Chain
import ehn.techiop.hcert.kotlin.chain.DelegatingChain
import ehn.techiop.hcert.kotlin.chain.impl.*
import eu.ehn.dcc.certlogic.JsonDateTime
import eu.ehn.dcc.certlogic.evaluate
import kotlinx.datetime.Clock
import java.time.OffsetDateTime
import java.time.ZoneId
import java.time.ZonedDateTime

internal object Eval {
	private val TAG = Eval::class.java.simpleName

	/**
	 * Checks whether the DCC has a valid signature.
	 *
	 * A signature is only valid if it is signed by a trusted key, but also only if other attributes are valid
	 * (e.g. the signature is not expired - which may be different from the legal national rules).
	 */
	fun checkSignature(dccHolder: DccHolder, signatures: TrustListCertificateRepository, nationalSignatures: TrustListCertificateRepository): VerificationResultStatus {
		try {
			val euContextService = DefaultContextIdentifierService("HC1:")
			val euChain = Chain(
				DefaultHigherOrderValidationService(),
				DefaultSchemaValidationService(),
				DefaultCborService(),
				LocalCwtService(clock = Clock.System),
				DefaultCoseService(signatures),
				DefaultCompressorService(),
				DefaultBase45Service(),
				euContextService
			)

			val atContextService = DefaultContextIdentifierService("AT1:")
			val atChain = Chain(
				DefaultHigherOrderValidationService(),
				DefaultSchemaValidationService(false, arrayOf("AT-1.0.0")),
				DefaultCborService(),
				LocalCwtService(clock = Clock.System),
				DefaultCoseService(nationalSignatures),
				DefaultCompressorService(),
				DefaultBase45Service(),
				atContextService
			)

			val chain = DelegatingChain(euChain, euContextService, atChain, atContextService)

			val result = chain.decode(dccHolder.qrCodeData)
			if (result.verificationResult.error == null) {
				return VerificationResultStatus.SUCCESS(listOf())
			} else {
				return VerificationResultStatus.SIGNATURE_INVALID
			}
		} catch(e: Throwable) {}
		return VerificationResultStatus.SIGNATURE_INVALID
	}

	/**
	 * @param dccHolder Object which was returned from the decode function
	 * @return State for the Signaturecheck
	 */
	fun checkNationalRules(
		dccHolder: DccHolder,
		validationClock: ZonedDateTime,
		businessRules: List<Rule>,
		valueSets: Map<String, List<String>>,
		certificateSchema: JsonNode,
		countryCode: String,
		region: String?
	): VerificationResultStatus {
		if (dccHolder.certificateType() == CertificateType.VACCINATION_EXEMPTION) {
			return VerificationResultStatus.SUCCESS(listOf())
		}
		val objectMapper = ObjectMapper().apply {
			this.findAndRegisterModules()
			registerModule(JavaTimeModule())
		}

		val logicEngine = DefaultCertLogicEngine(DefaultAffectedFieldsDataRetriever(certificateSchema, objectMapper), DefaultJsonLogicValidator())

		val valueSetMap = valueSets

		val certificateType = dccHolder.certificateType()
		val ruleCertificateType = dccHolder.ruleCertificateType()

		val certLogicRules = businessRules.filter {
			it.countryCode.equals(countryCode, ignoreCase = true)
					&& validationClock.isAfter(it.validFrom)
					&& validationClock.isBefore(it.validTo)
					&& (it.ruleCertificateType == RuleCertificateType.GENERAL || it.ruleCertificateType == ruleCertificateType)
					&& it.region == region
		}


		val externalParameter = ExternalParameter(
			validationClock = validationClock,
			valueSets = valueSetMap,
			countryCode = countryCode,
			exp = dccHolder.expirationTime!!.atZone(ZoneId.systemDefault()),
			iat = dccHolder.issuedAt!!.atZone(ZoneId.systemDefault()),
			issuerCountryCode = countryCode,
			kid = dccHolder.issuer!!,
			region = region ?: ""
		)

		val certificatePayload = objectMapper.writeValueAsString(dccHolder.euDGC)
		val validationResult = logicEngine.validate(certificateType, dccHolder.euDGC.version, certLogicRules, externalParameter, certificatePayload)

		val failedValidations = validationResult.filter { it.result == Result.FAIL }
		if (failedValidations.isEmpty()) {
			val metadataRules = businessRules.filter {
				it.countryCode.equals(countryCode, ignoreCase = true)
						&& validationClock.isAfter(it.validFrom)
						&& validationClock.isBefore(it.validTo)
						&& (it.ruleCertificateType == RuleCertificateType.GENERAL || it.ruleCertificateType == ruleCertificateType)
						&& it.region == ("$region-MD")
			}

			val dataJsonNode = prepareData(objectMapper, externalParameter, certificatePayload)

			var validUntil: OffsetDateTime? = null
			for (rule in metadataRules) {
				try {
					val value = evaluate(rule.logic, dataJsonNode)
					if (value is JsonDateTime) {
						validUntil = value.temporalValue()
						break
					}
				} catch (e: Exception){}
			}

			return VerificationResultStatus.SUCCESS(listOf(VerificationRegionResult(region, true, validUntil)))
		} else {
			return VerificationResultStatus.SUCCESS(listOf(VerificationRegionResult(region, false, null)))
		}
	}

	private fun prepareData(
		objectMapper: ObjectMapper,
		externalParameter: ExternalParameter,
		payload: String
	): ObjectNode = objectMapper.createObjectNode().apply {
		this.set<JsonNode>(
			"external",
			objectMapper.readValue(objectMapper.writeValueAsString(externalParameter))
		)
		this.set<JsonNode>(
			"payload",
			objectMapper.readValue<JsonNode>(payload)
		)
	}
}

fun DccHolder.certificateType(): CertificateType {
	when (this.certType) {
		CertType.VACCINATION -> return CertificateType.VACCINATION
		CertType.RECOVERY -> return CertificateType.RECOVERY
		CertType.VACCINATION_EXEMPTION -> return CertificateType.VACCINATION_EXEMPTION
		else -> return CertificateType.TEST
	}
}

fun DccHolder.ruleCertificateType(): RuleCertificateType? {
	when (this.certType) {
		CertType.VACCINATION -> return RuleCertificateType.VACCINATION
		CertType.RECOVERY -> return RuleCertificateType.RECOVERY
		CertType.TEST -> return RuleCertificateType.TEST
		else -> return null
	}
}