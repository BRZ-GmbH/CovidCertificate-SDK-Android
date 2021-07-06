/*
 * Copyright (c) 2021 Ubique Innovation AG <https://www.ubique.ch>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */

package at.gv.brz.eval.nationalrules

import at.gv.brz.eval.data.EvalErrorCodes

enum class NationalRulesError(val message: String, val errorCode: String) {
	NO_VALID_DATE("Not a valid Date format", EvalErrorCodes.NO_VALID_DATE),
	NO_VALID_PRODUCT("Product is not registered", EvalErrorCodes.NO_VALID_PRODUCT),
	WRONG_DISEASE_TARGET("Only SarsCov2 is a valid disease target", EvalErrorCodes.WRONG_DISEASE_TARGET),
	WRONG_TEST_TYPE("Test type invalid", EvalErrorCodes.WRONG_TEST_TYPE),
	POSITIVE_RESULT("Test result was positive", EvalErrorCodes.POSITIVE_RESULT),
	NOT_FULLY_PROTECTED("Missing vaccine shots, only partially protected", EvalErrorCodes.NOT_FULLY_PROTECTED),
	TOO_MANY_VACCINE_ENTRIES("Certificate contains more than one vaccine entries", EvalErrorCodes.TOO_MANY_VACCINE_ENTRIES),
	TOO_MANY_TEST_ENTRIES("Certificate contains more than one test entries", EvalErrorCodes.TOO_MANY_TEST_ENTRIES),
	TOO_MANY_RECOVERY_ENTRIES("Certificate contains more than one recovery entries", EvalErrorCodes.TOO_MANY_RECOVERY_ENTRIES),
	UNKNOWN_RULE_FAILED("An unknown rule failed to verify", EvalErrorCodes.UNKNOWN_RULE_FAILED)
}