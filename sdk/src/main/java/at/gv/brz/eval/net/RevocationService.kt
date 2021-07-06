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

import at.gv.brz.eval.models.RevokedCertificates
import retrofit2.Response
import retrofit2.http.GET
import retrofit2.http.Headers

interface RevocationService {

	@Headers("Accept: application/json+jws")
	@GET("revocationList")
	suspend fun getRevokedCertificates(): Response<RevokedCertificates>

}