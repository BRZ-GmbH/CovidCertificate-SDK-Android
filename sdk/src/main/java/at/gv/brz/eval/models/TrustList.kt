/*
 * Copyright (c) 2021 Ubique Innovation AG <https://www.ubique.ch>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */

package at.gv.brz.eval.models

import com.lyft.kronos.KronosClock
import dgca.verifier.app.engine.data.Rule
import ehn.techiop.hcert.kotlin.trust.TrustListV2

data class TrustList(
	val signatures: TrustListV2,
	val valueSets: Map<String, List<String>>,
	val businessRules: List<Rule>,
	val kronosClock: KronosClock
)
