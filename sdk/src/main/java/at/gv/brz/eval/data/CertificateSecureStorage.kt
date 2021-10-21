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

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import at.gv.brz.eval.data.moshi.RawJsonStringAdapter
import at.gv.brz.eval.utils.SingletonHolder
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import dgca.verifier.app.engine.data.Rule
import dgca.verifier.app.engine.data.source.remote.rules.RuleRemote
import dgca.verifier.app.engine.data.source.remote.rules.toRule
import dgca.verifier.app.engine.data.source.remote.valuesets.ValueSetRemote
import dgca.verifier.app.engine.data.source.remote.valuesets.toValueSet
import ehn.techiop.hcert.kotlin.rules.BusinessRulesContainer
import ehn.techiop.hcert.kotlin.trust.TrustListV2
import ehn.techiop.hcert.kotlin.valueset.ValueSetContainer
import java.io.IOException
import java.security.GeneralSecurityException
import java.time.Instant
import java.util.concurrent.TimeUnit

internal class CertificateSecureStorage private constructor(private val context: Context) : TrustListStore {

	companion object : SingletonHolder<CertificateSecureStorage, Context>(::CertificateSecureStorage) {
		private const val PREFERENCES_NAME = "CertificateSecureStorage"
		private const val FILE_PATH_CERTIFICATE_SIGNATURES = "signatures.json"
		private const val FILE_PATH_VALUESETS = "valuesets.json"
		private const val FILE_PATH_RULESET = "businessrules.json"

		private const val KEY_TRUSTLIST_LAST_UPDATE = "KEY_TRUSTLIST_LAST_UPDATE"
		private const val KEY_VALUESETS_LAST_UPDATE = "KEY_VALUESETS_LAST_UPDATE"
		private const val KEY_RULESET_LAST_UPDATE = "KEY_RULESET_LAST_UPDATE"

		private const val KEY_TRUSTLIST_CONTENT_HASH = "KEY_TRUSTLIST_CONTENT_HASH"
		private const val KEY_VALUESETS_CONTENT_HASH = "KEY_VALUESETS_CONTENT_HASH"
		private const val KEY_RULESET_CONTENT_HASH = "KEY_RULESET_CONTENT_HASH"

		private val TRUSTLIST_UPDATE_INTERVAL = TimeUnit.HOURS.toMillis(24L)
		private val VALUESETS_UPDATE_INTERVAL = TimeUnit.HOURS.toMillis(24L)
		private val RULESET_UPDATE_INTERVAL = TimeUnit.HOURS.toMillis(24L)

		private val TRUSTLIST_MAX_AGE = TimeUnit.HOURS.toMillis(72L)
		private val VALUESETS_MAX_AGE = TimeUnit.HOURS.toMillis(72L)
		private val RULESET_MAX_AGE = TimeUnit.HOURS.toMillis(72L)

		private val moshi = Moshi.Builder().add(RawJsonStringAdapter()).addLast(
			KotlinJsonAdapterFactory()
		).build()
		private val trustListAdapter = moshi.adapter(TrustListV2::class.java)
		private val valueSetsAdapter = moshi.adapter(ValueSetContainer::class.java)
		private val businessRulesAdapter = moshi.adapter(BusinessRulesContainer::class.java)
	}

	private val certificateFileStorage = EncryptedFileStorage(FILE_PATH_CERTIFICATE_SIGNATURES)
	private val valueSetsFileStorage = EncryptedFileStorage(FILE_PATH_VALUESETS)
	private val ruleSetFileStorage = EncryptedFileStorage(FILE_PATH_RULESET)

	private val preferences = initializeSharedPreferences(context)

	@Synchronized
	private fun initializeSharedPreferences(context: Context): SharedPreferences {
		return try {
			createEncryptedSharedPreferences(context)
		} catch (e: GeneralSecurityException) {
			throw RuntimeException(e)
		} catch (e: IOException) {
			throw RuntimeException(e)
		}
	}

	/**
	 * Create or obtain an encrypted SharedPreferences instance. Note that this method is synchronized because the AndroidX
	 * Security library is not thread-safe.
	 * @see [https://developer.android.com/topic/security/data](https://developer.android.com/topic/security/data)
	 */
	@Synchronized
	@Throws(GeneralSecurityException::class, IOException::class)
	private fun createEncryptedSharedPreferences(context: Context): SharedPreferences {
		val masterKeys = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)
		return EncryptedSharedPreferences
			.create(
				PREFERENCES_NAME, masterKeys, context, EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
				EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
			)
	}

	override var certificateSignatures: TrustListV2? = null
		get() {
			if (field == null) {
				field = certificateFileStorage.read(context)?.let { trustListAdapter.fromJson(it) }
			}
			return field
		}
		set(value) {
			certificateFileStorage.write(context, trustListAdapter.toJson(value))
			trustlistLastUpdate = Instant.now().toEpochMilli()
			field = value
		}

	override var valueSets: ValueSetContainer? = null
		get() {
			if (field == null) {
				field = valueSetsFileStorage.read(context)?.let { valueSetsAdapter.fromJson(it) }
			}
			return field
		}
		set(value) {
			valueSetsFileStorage.write(context, valueSetsAdapter.toJson(value))
			valueSetsLastUpdate = Instant.now().toEpochMilli()
			field = value
			mappedValueSets = null
		}

	override var mappedValueSets: Map<String, List<String>>? = null
		get() {
			if (field == null) {
				val valueSetsToParse = valueSets
				if (valueSetsToParse != null) {
					val objectMapper = ObjectMapper().apply { this.findAndRegisterModules()
						registerModule(JavaTimeModule())
					}
					field = valueSetsToParse.valueSets.map {
						val valueSet =
							objectMapper.readValue(it.valueSet, ValueSetRemote::class.java)
								.toValueSet()
						val values = valueSet.valueSetValues.fieldNames().asSequence().toList()
						it.name to values
					}.toMap()
				}
			}
			return field
		}

	override var businessRules: BusinessRulesContainer? = null
		get() {
			if (field == null) {
				field = ruleSetFileStorage.read(context)?.let { businessRulesAdapter.fromJson(it) }
			}
			return field
		}
		set(value) {
			ruleSetFileStorage.write(context, businessRulesAdapter.toJson(value))
			businessRulesLastUpdate = Instant.now().toEpochMilli()
			field = value
			mappedBusinessRules = null
		}

	override var mappedBusinessRules: List<Rule>? = null
		get() {
			if (field == null) {
				val businessRulesToParse = businessRules
				if (businessRulesToParse != null) {
					val objectMapper = ObjectMapper().apply { this.findAndRegisterModules()
						registerModule(JavaTimeModule())
					}

					field = businessRulesToParse.rules.map {
						objectMapper.readValue(it.rule, RuleRemote::class.java).toRule()
					}
				}
			}
			return field
		}

	override var trustlistLastUpdate: Long
		get() = preferences.getLong(KEY_TRUSTLIST_LAST_UPDATE, 0L)
		set(value) {
			preferences.edit().putLong(KEY_TRUSTLIST_LAST_UPDATE, value).apply()
		}

	override var valueSetsLastUpdate: Long
		get() = preferences.getLong(KEY_VALUESETS_LAST_UPDATE, 0L)
		set(value) {
			preferences.edit().putLong(KEY_VALUESETS_LAST_UPDATE, value).apply()
		}

	override var businessRulesLastUpdate: Long
		get() = preferences.getLong(KEY_RULESET_LAST_UPDATE, 0L)
		set(value) {
			preferences.edit().putLong(KEY_RULESET_LAST_UPDATE, value).apply()
		}

	override var trustlistContentHash: Int
		get() = preferences.getInt(KEY_TRUSTLIST_CONTENT_HASH, 0)
		set(value) {
			preferences.edit().putInt(KEY_TRUSTLIST_CONTENT_HASH, value).apply()
		}

	override var valueSetsContentHash: Int
		get() = preferences.getInt(KEY_VALUESETS_CONTENT_HASH, 0)
		set(value) {
			preferences.edit().putInt(KEY_VALUESETS_CONTENT_HASH, value).apply()
		}

	override var businessRulesContentHash: Int
		get() = preferences.getInt(KEY_RULESET_CONTENT_HASH, 0)
		set(value) {
			preferences.edit().putInt(KEY_RULESET_CONTENT_HASH, value).apply()
		}

	override fun shouldUpdateTrustListCertificates(): Boolean {
		return trustlistLastUpdate == 0L || (Instant.now().toEpochMilli() - trustlistLastUpdate) > TRUSTLIST_UPDATE_INTERVAL
	}

	override fun shouldUpdateValueSets(): Boolean {
		return valueSetsLastUpdate == 0L || (Instant.now().toEpochMilli() - valueSetsLastUpdate) > VALUESETS_UPDATE_INTERVAL
	}

	override fun shouldUpdateBusinessRules(): Boolean {
		return businessRulesLastUpdate == 0L || (Instant.now().toEpochMilli() - businessRulesLastUpdate) > RULESET_UPDATE_INTERVAL
	}

	override fun areTrustlistCertificatesValid(): Boolean {
		return certificateSignatures != null
	}

	override fun areValueSetsValid(): Boolean {
		return valueSets != null
	}

	override fun areBusinessRulesValid(): Boolean {
		return businessRules != null
	}

	override fun dataExpired(): Boolean {
		if (trustlistLastUpdate == 0L || valueSetsLastUpdate == 0L || businessRulesLastUpdate == 0L) {
			return true
		}

		if ((Instant.now().toEpochMilli() - trustlistLastUpdate) > TRUSTLIST_MAX_AGE) {
			return true
		}
		if ((Instant.now().toEpochMilli() - valueSetsLastUpdate) > VALUESETS_MAX_AGE) {
			return true
		}
		if ((Instant.now().toEpochMilli() - businessRulesLastUpdate) > RULESET_MAX_AGE) {
			return true
		}
		return false
	}
}