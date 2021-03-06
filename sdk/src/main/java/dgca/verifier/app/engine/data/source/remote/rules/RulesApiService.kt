/*
 *  ---license-start
 *  eu-digital-green-certificates / dgca-verifier-app-android
 *  ---
 *  Copyright (C) 2021 T-Systems International GmbH and all other contributors
 *  ---
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *  ---license-end
 *
 *  Created by osarapulov on 6/25/21 9:21 AM
 */

package dgca.verifier.app.engine.data.source.remote.rules

import retrofit2.Response
import retrofit2.http.GET
import retrofit2.http.Url

interface RulesApiService {

    @GET
    suspend fun getRuleIdentifiers(@Url rulesUrl: String): Response<List<RuleIdentifierRemote>>

    @GET
    suspend fun getRules(@Url url: String): Response<List<RuleRemote>>

    @GET
    suspend fun getRule(@Url url: String): Response<RuleRemote>
}