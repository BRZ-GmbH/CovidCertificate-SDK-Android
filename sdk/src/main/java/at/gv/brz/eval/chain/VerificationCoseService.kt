/**
 * Adapted from https://github.com/ehn-digital-green-development/hcert-kotlin
 * published under Apache-2.0 License.
 */
package at.gv.brz.eval.chain

import COSE.MessageTag
import COSE.OneKey
import COSE.Sign1Message
import at.gv.brz.eval.models.CertType
import ehn.techiop.hcert.kotlin.trust.TrustedCertificateV2

internal object VerificationCoseService {
	private val TAG = VerificationCoseService::class.java.simpleName

	fun decode(
		keys: Array<TrustedCertificateV2>,
		input: ByteArray,
		type: CertType
	): Boolean {

		val signature: Sign1Message = try {
			(Sign1Message.DecodeFromBytes(input, MessageTag.Sign1) as Sign1Message)
		} catch (e: Throwable) {
			null
		} ?: return false

		for (k in keys) {
			val pk = k.toCertificateAdapter().certificate.publicKey
			//val pk = k.getPublicKey() ?: continue

			try {
				val pubKey = OneKey(pk, null)
				if (signature.validate(pubKey)) {
 					return true
				}
			} catch (ignored: Throwable) {
			}
		}

		return false
	}

}