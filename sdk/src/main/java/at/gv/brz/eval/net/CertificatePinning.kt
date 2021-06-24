/*
 * Copyright (c) 2021 Ubique Innovation AG <https://www.ubique.ch>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */

package at.gv.brz.eval.net

import at.gv.brz.eval.BuildConfig
import okhttp3.CertificatePinner

object CertificatePinning {

	private val CERTIFICATE_PINNER_DISABLED = CertificatePinner.DEFAULT
	private val CERTIFICATE_PINNER_LIVE = CertificatePinner.Builder()
		.build()

	val pinner: CertificatePinner
		get() = if (BuildConfig.DEBUG) CERTIFICATE_PINNER_DISABLED else CERTIFICATE_PINNER_LIVE

}