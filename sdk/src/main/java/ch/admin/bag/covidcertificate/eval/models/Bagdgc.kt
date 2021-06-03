/*
 * Copyright (c) 2021 Ubique Innovation AG <https://www.ubique.ch>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */

package ch.admin.bag.covidcertificate.eval.models

import ch.admin.bag.covidcertificate.eval.data.Eudgc
import java.io.Serializable
import java.time.Instant


data class Bagdgc(
	val dgc: Eudgc,
	val qrCodeData: String,
	val expirationTime: Instant? = null,
	val issuedAt: Instant? = null,
	val issuer: String? = null,
) : Serializable {

	var certType: CertType? = null
		internal set

	override fun equals(other: Any?): Boolean {
		if (this === other) return true
		if (javaClass != other?.javaClass) return false

		other as Bagdgc

		if (dgc != other.dgc) return false
		if (qrCodeData != other.qrCodeData) return false

		return true
	}

	override fun hashCode(): Int {
		var result = dgc.hashCode()
		result = 31 * result + qrCodeData.hashCode()
		return result
	}

}



