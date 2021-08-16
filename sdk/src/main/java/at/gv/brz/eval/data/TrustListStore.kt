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

import at.gv.brz.eval.models.Jwks
import at.gv.brz.eval.models.RevokedCertificates
import at.gv.brz.eval.models.RuleSet
import ehn.techiop.hcert.kotlin.rules.BusinessRulesContainer
import ehn.techiop.hcert.kotlin.trust.TrustListV2
import ehn.techiop.hcert.kotlin.valueset.ValueSetContainer

interface TrustListStore {

	var certificateSignatures: TrustListV2?

	var valueSets: ValueSetContainer?

	var businessRules: BusinessRulesContainer?

	fun areTrustlistCertificatesValid(): Boolean
	fun areValueSetsValid(): Boolean
	fun areBusinessRulesValid(): Boolean

	fun shouldUpdateTrustListCertificates(): Boolean
	fun shouldUpdateValueSets(): Boolean
	fun shouldUpdateBusinessRules(): Boolean

	fun dataExpired(): Boolean

}