/*
 * Copyright (c) 2021 Ubique Innovation AG <https://www.ubique.ch>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */

package at.gv.brz.eval.data

import dgca.verifier.app.engine.data.Rule
import ehn.techiop.hcert.kotlin.rules.BusinessRulesContainer
import ehn.techiop.hcert.kotlin.trust.TrustListV2
import ehn.techiop.hcert.kotlin.valueset.ValueSetContainer

interface TrustListStore {

	var certificateSignatures: TrustListV2?
	var trustlistContentHash: Int
	var trustlistLastUpdate: Long

	var valueSets: ValueSetContainer?
	var mappedValueSets: Map<String, List<String>>?
	var valueSetsContentHash: Int
	var valueSetsLastUpdate: Long

	var businessRules: BusinessRulesContainer?
	var mappedBusinessRules: List<Rule>?
	var businessRulesContentHash: Int
	var businessRulesLastUpdate: Long

	fun areTrustlistCertificatesValid(): Boolean
	fun areValueSetsValid(): Boolean
	fun areBusinessRulesValid(): Boolean

	fun shouldUpdateTrustListCertificates(): Boolean
	fun shouldUpdateValueSets(): Boolean
	fun shouldUpdateBusinessRules(): Boolean

	fun dataExpired(): Boolean

}