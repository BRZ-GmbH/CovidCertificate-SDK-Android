/*
 * Copyright (c) 2021 Ubique Innovation AG <https://www.ubique.ch>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */

package at.gv.brz.eval.repository

import at.gv.brz.eval.data.TrustListStore
import at.gv.brz.eval.models.*
import at.gv.brz.eval.net.BusinessRulesService
import at.gv.brz.eval.net.TrustlistService
import at.gv.brz.eval.net.ValueSetsService
import com.lyft.kronos.KronosClock
import ehn.techiop.hcert.kotlin.chain.CertificateRepository
import ehn.techiop.hcert.kotlin.chain.impl.PrefilledCertificateRepository
import ehn.techiop.hcert.kotlin.rules.BusinessRulesDecodeService
import ehn.techiop.hcert.kotlin.trust.SignedData
import ehn.techiop.hcert.kotlin.trust.TrustListDecodeService
import ehn.techiop.hcert.kotlin.valueset.ValueSetDecodeService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.Instant

internal class TrustListRepository(
	private val trustlistService: TrustlistService,
	private val valueSetsService: ValueSetsService,
	private val businessRulesService: BusinessRulesService,
	private val store: TrustListStore,
	private val trustAnchor: String,
	private val kronosClock: KronosClock,
) {

	/**
	 * Refresh the trust list if necessary. This will check for the presence and validity of the certificate signatures,
	 * revoked certificates and rule set and load them from the backend if necessary. Set the [forceRefresh] flag to always load
	 * the data from the server.
	 *
	 * @param forceRefresh False to only load data from the server if it is missing or outdated, true to always load from the server
	 */
	suspend fun refreshTrustList(forceRefresh: Boolean) = withContext(Dispatchers.IO) {
		var refreshedSignatures = false
		var refreshedValueSets = false
		var refreshedRules = false
		listOf(
			launch { refreshedSignatures = refreshCertificateSignatures(forceRefresh) },
			launch { refreshedRules = refreshBusinessRules(forceRefresh) },
			launch { refreshedValueSets = refreshValueSets(forceRefresh) }
		).joinAll()

		refreshedSignatures || refreshedValueSets || refreshedRules
	}

	/**
	 * Get the trust list from the provider or null if at least one of the values is not set
	 */
	fun getTrustList(): TrustList? {
		return if (store.areTrustlistCertificatesValid() && store.areValueSetsValid() && store.areBusinessRulesValid() && !store.dataExpired()) {
			val signatures = store.certificateSignatures
			val valueSets = store.mappedValueSets
			val businessRules = store.mappedBusinessRules

			if (signatures != null && valueSets != null && businessRules != null) {
				TrustList(signatures, valueSets, businessRules, kronosClock)
			} else {
				null
			}
		} else {
			null
		}
	}

	private suspend fun refreshCertificateSignatures(forceRefresh: Boolean, isRecursive: Boolean = false): Boolean =
		withContext(Dispatchers.IO) {
			val shouldLoadSignatures =
				forceRefresh || !store.areTrustlistCertificatesValid() || store.shouldUpdateTrustListCertificates()
			if (shouldLoadSignatures) {
				val trustListSignatureResponse = trustlistService.getTrustlistSignature()
				val trustlistSignatureBody = trustListSignatureResponse.body()

				if (trustListSignatureResponse.isSuccessful && trustlistSignatureBody != null) {
					val signatureBytes = trustlistSignatureBody.bytes()
					val contentHash = signatureBytes.contentHashCode()

					if (contentHash != store.trustlistContentHash) {
						val trustlistResponse = trustlistService.getTrustlist()
						val trustlistBody = trustlistResponse.body()
						if (trustlistResponse.isSuccessful && trustlistBody != null) {
							val signedData =
								SignedData(trustlistBody.bytes(), signatureBytes)
							val trustAnchorRepository: CertificateRepository =
								PrefilledCertificateRepository(trustAnchor)
							val service = TrustListDecodeService(
								trustAnchorRepository,
								KronosTimeClock(kronosClock)
							)
							val result = service.decode(signedData)
							if (!result.second.certificates.isEmpty()) {
								store.certificateSignatures = result.second
								store.trustlistContentHash = contentHash
							}
						}
						true
					} else {
						store.trustlistLastUpdate = Instant.now().toEpochMilli()
						// Return true if trust list needs to be forced to update (either invalid or not present)
						!store.areTrustlistCertificatesValid() || store.shouldUpdateTrustListCertificates()
					}
				} else {
					false
				}
			} else {
				false
			}
		}

	private suspend fun refreshValueSets(forceRefresh: Boolean): Boolean = withContext(Dispatchers.IO) {
		val shouldLoadValueSets = forceRefresh || !store.areValueSetsValid() || store.shouldUpdateValueSets()
		if (shouldLoadValueSets) {
			val signatureResponse = valueSetsService.getValueSetsSignature()
			val signatureBody = signatureResponse.body()
			if (signatureResponse.isSuccessful && signatureBody != null) {
				val signatureBytes = signatureBody.bytes()
				val contentHash = signatureBytes.contentHashCode()
				if (contentHash != store.valueSetsContentHash) {
					val valueSetsResponse = valueSetsService.getValueSets()
					val valueSetsBody = valueSetsResponse.body()
					if (valueSetsResponse.isSuccessful && valueSetsBody != null) {
						val signedData = SignedData(valueSetsBody.bytes(), signatureBytes)
						val trustAnchorRepository: CertificateRepository =
							PrefilledCertificateRepository(trustAnchor)

						val service = ValueSetDecodeService(
							trustAnchorRepository,
							KronosTimeClock(kronosClock)
						)
						val result = service.decode(signedData)
						if (!result.second.valueSets.isEmpty()) {
							store.valueSets = result.second
							store.valueSetsContentHash = contentHash
						}
					}
					true
				} else {
					store.valueSetsLastUpdate = Instant.now().toEpochMilli()
					// Return true if value sets needs to be forced to update (either invalid or not present)
					!store.areValueSetsValid() || store.shouldUpdateValueSets()
				}
			} else {
				false
			}
		} else {
			false
		}
	}

	private suspend fun refreshBusinessRules(forceRefresh: Boolean): Boolean = withContext(Dispatchers.IO) {
		val shouldLoadBusinessRules = forceRefresh || !store.areBusinessRulesValid() || store.shouldUpdateBusinessRules()
		if (shouldLoadBusinessRules) {
			val signatureResponse = businessRulesService.getBusinessRulesSignature()
			val signatureBody = signatureResponse.body()
			if (signatureResponse.isSuccessful && signatureBody != null) {
				val signatureBytes = signatureBody.bytes()
				val contentHash = signatureBytes.contentHashCode()
				if (contentHash != store.businessRulesContentHash) {
					val businessRulesResponse = businessRulesService.getBusinessRules()
					val businessRulesBody = businessRulesResponse.body()
					if (businessRulesResponse.isSuccessful && businessRulesBody != null) {
						val signedData =
							SignedData(businessRulesBody.bytes(), signatureBytes)
						val trustAnchorRepository: CertificateRepository =
							PrefilledCertificateRepository(trustAnchor)

						val service = BusinessRulesDecodeService(
							trustAnchorRepository,
							KronosTimeClock(kronosClock)
						)
						val result = service.decode(signedData)
						if (!result.second.rules.isEmpty()) {
							store.businessRules = result.second
							store.businessRulesContentHash = contentHash
						}
					}
					true
				} else {
					store.businessRulesLastUpdate = Instant.now().toEpochMilli()
					// Return true if value sets needs to be forced to update (either invalid or not present)
					!store.areBusinessRulesValid() || store.shouldUpdateBusinessRules()
				}
			} else {
				false
			}
		} else {
			false
		}
	}
}