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

import android.content.Context
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleObserver
import androidx.lifecycle.OnLifecycleEvent
import androidx.lifecycle.coroutineScope
import at.gv.brz.eval.data.CertificateSecureStorage
import at.gv.brz.eval.data.Config
import at.gv.brz.eval.data.moshi.RawJsonStringAdapter
import at.gv.brz.eval.nationalrules.NationalRulesVerifier
import at.gv.brz.eval.net.ApiKeyInterceptor
import at.gv.brz.eval.net.CertificatePinning
import at.gv.brz.eval.net.CertificateService
import at.gv.brz.eval.net.JwsInterceptor
import at.gv.brz.eval.net.RevocationService
import at.gv.brz.eval.net.RuleSetService
import at.gv.brz.eval.net.UserAgentInterceptor
import at.gv.brz.eval.repository.TrustListRepository
import at.gv.brz.eval.verification.CertificateVerificationController
import at.gv.brz.eval.verification.CertificateVerifier
import at.gv.brz.eval.BuildConfig
import com.squareup.moshi.Moshi
import okhttp3.Cache
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory
import retrofit2.converter.scalars.ScalarsConverterFactory
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.*
import java.util.concurrent.TimeUnit
import kotlin.concurrent.timer

object CovidCertificateSdk {

	private const val ROOT_CA_TYPE = "X.509"
	// TODO AT: Disable backend integration
	private const val ASSET_PATH_ROOT_CA = ""

	private val TRUST_LIST_REFRESH_INTERVAL = TimeUnit.HOURS.toMillis(1L)

	private lateinit var certificateVerificationController: CertificateVerificationController
	private var isInitialized = false
	private var trustListRefreshTimer: Timer? = null
	private var trustListLifecycleObserver: TrustListLifecycleObserver? = null

	fun init(context: Context) {
		// TODO: AT - Disable backend integration
		/*val retrofit = createRetrofit(context)
		val certificateService = retrofit.create(CertificateService::class.java)
		val revocationService = retrofit.create(RevocationService::class.java)
		val ruleSetService = retrofit.create(RuleSetService::class.java)*/

		val certificateStorage = CertificateSecureStorage.getInstance(context)
		val trustListRepository = TrustListRepository(null, null, null, /*certificateService, revocationService, ruleSetService, */certificateStorage)
		val nationalRulesVerifier = NationalRulesVerifier(context)
		val certificateVerifier = CertificateVerifier(nationalRulesVerifier)
		certificateVerificationController = CertificateVerificationController(trustListRepository, certificateVerifier)

		isInitialized = true
	}

	fun registerWithLifecycle(lifecycle: Lifecycle) {
		requireInitialized()

		trustListLifecycleObserver = TrustListLifecycleObserver(lifecycle)
		trustListLifecycleObserver?.register(lifecycle)
	}

	fun unregisterWithLifecycle(lifecycle: Lifecycle) {
		requireInitialized()

		trustListLifecycleObserver?.unregister(lifecycle)
		trustListLifecycleObserver = null
	}

	fun getCertificateVerificationController(): CertificateVerificationController {
		requireInitialized()
		return certificateVerificationController
	}

	fun getRootCa(context: Context): X509Certificate {
		val certificateFactory = CertificateFactory.getInstance(ROOT_CA_TYPE)
		val inputStream = context.assets.open(ASSET_PATH_ROOT_CA)
		return certificateFactory.generateCertificate(inputStream) as X509Certificate
	}

	fun getExpectedCommonName() = BuildConfig.LEAF_CERT_CN

	private fun requireInitialized() {
		if (!isInitialized) {
			throw IllegalStateException("CovidCertificateSdk must be initialized by calling init(context)")
		}
	}

	private fun createRetrofit(context: Context): Retrofit {
		val rootCa = getRootCa(context)
		val expectedCommonName = getExpectedCommonName()
		val okHttpBuilder = OkHttpClient.Builder()
			.certificatePinner(CertificatePinning.pinner)
			.addInterceptor(JwsInterceptor(rootCa, expectedCommonName))
			.addInterceptor(ApiKeyInterceptor())
			.addInterceptor(UserAgentInterceptor(Config.userAgent))

		val cacheSize = 5 * 1024 * 1024 // 5 MB
		val cache = Cache(context.cacheDir, cacheSize.toLong())
		okHttpBuilder.cache(cache)

		if (BuildConfig.DEBUG) {
			val httpInterceptor = HttpLoggingInterceptor().setLevel(HttpLoggingInterceptor.Level.BODY)
			okHttpBuilder.addInterceptor(httpInterceptor)
		}

		return Retrofit.Builder()
			.baseUrl(BuildConfig.BASE_URL_TRUST_LIST)
			.client(okHttpBuilder.build())
			.addConverterFactory(ScalarsConverterFactory.create())
			.addConverterFactory(MoshiConverterFactory.create(Moshi.Builder().add(RawJsonStringAdapter()).build()))
			.build()
	}

	internal class TrustListLifecycleObserver(private val lifecycle: Lifecycle) : LifecycleObserver {
		fun register(lifecycle: Lifecycle) {
			lifecycle.addObserver(this)
		}

		fun unregister(lifecycle: Lifecycle) {
			lifecycle.removeObserver(this)
		}

		@OnLifecycleEvent(Lifecycle.Event.ON_START)
		fun onStart() {
			trustListRefreshTimer?.cancel()
			trustListRefreshTimer = timer(initialDelay = TRUST_LIST_REFRESH_INTERVAL, period = TRUST_LIST_REFRESH_INTERVAL) {
				certificateVerificationController.refreshTrustList(lifecycle.coroutineScope)
			}
		}

		@OnLifecycleEvent(Lifecycle.Event.ON_STOP)
		fun onStop() {
			trustListRefreshTimer?.cancel()
		}
	}

}