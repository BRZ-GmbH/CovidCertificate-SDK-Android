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

import android.net.ConnectivityManager
import at.gv.brz.eval.data.state.VerificationResultStatus
import at.gv.brz.eval.models.DccHolder
import at.gv.brz.eval.models.TrustList
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.InputStream

class CertificateVerificationTask(val dccHolder: DccHolder, val connectivityManager: ConnectivityManager, val schemaJson: String, val countryCode: String, val regions: List<String>, val checkDefaultRegion: Boolean) {

	private val mutableVerificationStateFlow = MutableStateFlow<VerificationResultStatus>(VerificationResultStatus.LOADING)
	val verificationStateFlow = mutableVerificationStateFlow.asStateFlow()

	/**
	 * Execute this verification task with the specified verifier and trust list
	 */
	internal suspend fun execute(verifier: CertificateVerifier, trustList: TrustList?) {
		if (trustList != null) {
			val state = verifier.verify(dccHolder, trustList, trustList.kronosClock, schemaJson, countryCode, regions, checkDefaultRegion)
			mutableVerificationStateFlow.emit(state)
		} else {
			mutableVerificationStateFlow.emit(
				VerificationResultStatus.DATAEXPIRED
			)
		}
	}

}
