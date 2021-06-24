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
import at.gv.brz.eval.data.EvalErrorCodes
import at.gv.brz.eval.data.state.Error
import at.gv.brz.eval.data.state.VerificationState
import at.gv.brz.eval.models.DccHolder
import at.gv.brz.eval.models.TrustList
import at.gv.brz.eval.utils.NetworkUtil
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

class CertificateVerificationTask(val dccHolder: DccHolder, val connectivityManager: ConnectivityManager) {

	private val mutableVerificationStateFlow = MutableStateFlow<VerificationState>(VerificationState.LOADING)
	val verificationStateFlow = mutableVerificationStateFlow.asStateFlow()

	/**
	 * Execute this verification task with the specified verifier and trust list
	 */
	internal suspend fun execute(verifier: CertificateVerifier, trustList: TrustList?) {
		if (trustList != null) {
			val state = verifier.verify(dccHolder, trustList)
			mutableVerificationStateFlow.emit(state)
		} else {
			val hasNetwork = NetworkUtil.isNetworkAvailable(connectivityManager)
			if (hasNetwork) {
				mutableVerificationStateFlow.emit(
					VerificationState.ERROR(
						Error(EvalErrorCodes.GENERAL_NETWORK_FAILURE, dccHolder = dccHolder), null
					)
				)
			} else {
				mutableVerificationStateFlow.emit(
					VerificationState.ERROR(
						Error(EvalErrorCodes.GENERAL_OFFLINE, dccHolder = dccHolder), null
					)
				)
			}
		}
	}

}
