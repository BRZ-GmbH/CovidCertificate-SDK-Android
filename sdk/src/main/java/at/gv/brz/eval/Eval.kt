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
import at.gv.brz.eval.chain.VerificationCoseService
import at.gv.brz.eval.data.state.*
import at.gv.brz.eval.models.CertType
import at.gv.brz.eval.models.DccHolder
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import dgca.verifier.app.engine.DefaultAffectedFieldsDataRetriever
import dgca.verifier.app.engine.DefaultCertLogicEngine
import dgca.verifier.app.engine.DefaultJsonLogicValidator
import dgca.verifier.app.engine.Result
import dgca.verifier.app.engine.data.*
import dgca.verifier.app.engine.data.source.remote.rules.RuleRemote
import dgca.verifier.app.engine.data.source.remote.rules.toRule
import dgca.verifier.app.engine.data.source.remote.valuesets.ValueSetRemote
import dgca.verifier.app.engine.data.source.remote.valuesets.toValueSet
import ehn.techiop.hcert.kotlin.rules.BusinessRulesContainer
import ehn.techiop.hcert.kotlin.trust.TrustListV2
import ehn.techiop.hcert.kotlin.valueset.ValueSetContainer
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
	fun checkSignature(dccHolder: DccHolder, signatures: TrustListV2): VerificationResultStatus {

		/* Check that certificate type and signature timestamps are valid */

		val type = dccHolder.certType ?: return VerificationResultStatus.ERROR

		/* Repeat decode chain to get and verify COSE signature */
		val encoded = PrefixIdentifierService.decode(dccHolder.qrCodeData)
			?: return VerificationResultStatus.ERROR
		val compressed = Base45Service.decode(encoded) ?: return VerificationResultStatus.ERROR
		val cose = DecompressionService.decode(compressed) ?: return VerificationResultStatus.ERROR

		val valid = VerificationCoseService.decode(signatures.certificates, cose, type)

		return if (valid) VerificationResultStatus.SUCCESS(listOf()) else VerificationResultStatus.SIGNATURE_INVALID
	}

	/**
	 * @param dccHolder Object which was returned from the decode function
	 * @return State for the Signaturecheck
	 */
	fun checkNationalRules(
		dccHolder: DccHolder,
		validationClock: ZonedDateTime,
		businessRules: BusinessRulesContainer,
		valueSets: ValueSetContainer,
		schemaJson: String,
		countryCode: String,
		region: String?
	): VerificationResultStatus {
		val objectMapper = ObjectMapper().apply { this.findAndRegisterModules()
		registerModule(JavaTimeModule())
		}

		val schema = objectMapper.readValue(schemaJson, JsonNode::class.java)

		val logicEngine = DefaultCertLogicEngine(DefaultAffectedFieldsDataRetriever(schema, objectMapper), DefaultJsonLogicValidator())

		val valueSetMap = valueSets.valueSets.map {
			val valueSet = objectMapper.readValue(it.valueSet, ValueSetRemote::class.java).toValueSet()
			val values = valueSet.valueSetValues.fieldNames().asSequence().toList()
			it.name to values
		}.toMap()

		val certificateType = dccHolder.certificateType()
		val ruleCertificateType = dccHolder.ruleCertificateType()

		val certLogicRules = businessRules.rules.map {
			objectMapper.readValue(it.rule, RuleRemote::class.java).toRule()
		}.filter {
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
			return VerificationResultStatus.SUCCESS(listOf(VerificationRegionResult(region, true)))
		} else {
			return VerificationResultStatus.SUCCESS(listOf(VerificationRegionResult(region, false)))
		}
	}
}

fun DccHolder.certificateType(): CertificateType {
	when (this.certType) {
		CertType.VACCINATION -> return CertificateType.VACCINATION
		CertType.RECOVERY -> return CertificateType.RECOVERY
		else -> return CertificateType.TEST
	}
}

fun DccHolder.ruleCertificateType(): RuleCertificateType {
	when (this.certType) {
		CertType.VACCINATION -> return RuleCertificateType.VACCINATION
		CertType.RECOVERY -> return RuleCertificateType.RECOVERY
		else -> return RuleCertificateType.TEST
	}
}