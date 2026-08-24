package com.agentguard.companion

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import java.security.MessageDigest

/**
 * Reads an installed app's signing-certificate digest from the platform.
 *
 * AgentScan (arXiv 2505.12981) reports package-name forgery succeeding against
 * **all four** system-interacting agents it tested. The reason is structural: a
 * package name is a string the attacker picks, so an allow-list keyed on it gates
 * nothing. A malicious APK installs itself as `com.sankuai.meituan` and inherits
 * whatever that name was trusted for.
 *
 * The signing certificate is the part the attacker cannot produce without the
 * publisher's private key. This object asks `PackageManager` for it, which matters
 * more than it looks: the digest comes from the **OS**, not from the agent and not
 * from the event stream. An attestation the agent handed us would be worth exactly
 * as much as the package name — that is, nothing. This is the difference between
 * moving the trust boundary and pretending to.
 *
 * ### What it cannot tell you
 *
 * - **Nothing here verifies that a digest is the *right* one.** That is the
 *   registry's job (`policies/known-apps.yaml`), and a registry with the wrong
 *   digest pinned is worse than none: it looks verified and verifies nothing. The
 *   digests shipped in this repo are deliberately obvious fixtures.
 * - **A signature proves a publisher, not good behaviour.** Meituan signed by
 *   Meituan is still Meituan doing whatever Meituan does.
 * - **Package visibility is restricted from Android 11 (API 30).** Without a
 *   matching `<queries>` entry or `QUERY_ALL_PACKAGES`, `getPackageInfo` throws
 *   `NameNotFoundException` for apps we cannot see — indistinguishable from "not
 *   installed" if we swallowed it. [attest] therefore returns a typed failure and
 *   the engine reports `APP-UNATTESTED` rather than treating an unreadable app as
 *   unverified-but-fine, or as verified.
 * - **Multiple signers** are normal (rotation, or a multiply-signed APK). All are
 *   returned in one comma-separated `signer_sha256`, and a match against any
 *   accepted digest verifies. Returning only the first would fail
 *   legitimately-rotated apps.
 */
object AppAttestor {

    /**
     * Result of attesting one package.
     *
     * A sealed type rather than a nullable string, because "could not read" and
     * "read, and here are the digests" must not collapse into the same value —
     * that collapse is how a guard ends up reporting an unverifiable app as clean.
     */
    sealed class Attestation {
        /** Lowercase hex SHA-256 of each signing certificate, in platform order. */
        data class Signed(val packageName: String, val sha256: List<String>) : Attestation()

        /** The package exists but reports no signature at all. */
        data class Unsigned(val packageName: String) : Attestation()

        /** We could not read it. [reason] is the exception class, not a guess. */
        data class Unreadable(val packageName: String, val reason: String) : Attestation()

        /** The digest to send, or null when there is nothing to claim. */
        val primaryDigest: String?
            get() = (this as? Signed)?.sha256?.firstOrNull()

        /** All digests, for a policy that accepts a rotated key. */
        val digests: List<String>
            get() = (this as? Signed)?.sha256 ?: emptyList()
    }

    /**
     * SHA-256 of every signing certificate for [packageName].
     *
     * Uses `GET_SIGNING_CERTIFICATES` from API 28 and the deprecated
     * `GET_SIGNATURES` below it. On API 28+ `apkContentsSigners` is preferred over
     * `signingCertificateHistory`: history includes *former* keys, so matching
     * against it would accept a certificate the publisher has since rotated away
     * from — which is precisely the key most likely to have leaked.
     */
    @Suppress("DEPRECATION")
    fun attest(context: Context, packageName: String): Attestation {
        val pm = context.packageManager
        return try {
            val signatures: Array<Signature> = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val info = pm.getPackageInfo(
                    packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES,
                )
                val signing = info.signingInfo
                    ?: return Attestation.Unsigned(packageName)
                // Current signers only, whether the APK has one or several.
                // `signingCertificateHistory` would let a rotated-away (possibly
                // compromised) key still verify, which is the wrong direction.
                signing.apkContentsSigners
            } else {
                pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES).signatures
                    ?: return Attestation.Unsigned(packageName)
            }
            if (signatures.isEmpty()) {
                return Attestation.Unsigned(packageName)
            }
            Attestation.Signed(packageName, signatures.map { sha256Hex(it.toByteArray()) })
        } catch (e: PackageManager.NameNotFoundException) {
            // From API 30 this is also what package-visibility filtering looks
            // like, so it does not mean "not installed".
            Attestation.Unreadable(packageName, "NameNotFoundException")
        } catch (e: Exception) {
            Attestation.Unreadable(packageName, e.javaClass.simpleName)
        }
    }

    /**
     * Metadata to attach to a GuardEvent so the engine can resolve identity.
     *
     * Omits `signer_sha256` entirely when there is nothing to attest, rather than
     * sending an empty string: the engine distinguishes "no attestation" from "a
     * digest that did not match", and an empty value would blur the two.
     */
    fun eventMetadata(context: Context, packageName: String): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        out["package"] = packageName
        when (val a = attest(context, packageName)) {
            // One key, comma-separated when an APK has several current signers or is
            // mid key-rotation. Splitting the primary from the rest across two keys
            // let a *wrong* primary be whitewashed by an accepted alternate.
            is Attestation.Signed -> out["signer_sha256"] = a.sha256.joinToString(",")
            is Attestation.Unsigned -> out["attest_error"] = "unsigned"
            is Attestation.Unreadable -> out["attest_error"] = a.reason
        }
        return out
    }

    private fun sha256Hex(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        val sb = StringBuilder(digest.size * 2)
        for (b in digest) {
            sb.append(HEX[(b.toInt() shr 4) and 0xf])
            sb.append(HEX[b.toInt() and 0xf])
        }
        return sb.toString()
    }

    private val HEX = "0123456789abcdef".toCharArray()

    /**
     * Per-package attestation cache for the process lifetime.
     *
     * [attest] does a binder call into `PackageManager`, and the accessibility
     * service emits an event for every screen change — attesting per event would put
     * an IPC on the hot path. A package's signing certificate cannot change without
     * a reinstall, which kills the app being observed, so caching is sound as well
     * as necessary.
     *
     * `Unreadable` results are cached too, deliberately: on Android 11+ an app
     * outside our `<queries>` list is *permanently* invisible to us, so retrying it
     * on every screen change would be a binder call per frame that always fails.
     */
    class SignerCache(private val context: Context) {
        private val cache = HashMap<String, Attestation>()

        @Synchronized
        fun attestation(packageName: String): Attestation =
            cache.getOrPut(packageName) { attest(context, packageName) }

        @Synchronized
        fun clear() = cache.clear()

        /** Metadata for an event, or an empty map when there is nothing to say. */
        fun metadata(packageName: String?): Map<String, String> {
            if (packageName.isNullOrBlank()) return emptyMap()
            val out = LinkedHashMap<String, String>()
            when (val a = attestation(packageName)) {
                is Attestation.Signed ->
                    // One key, comma-separated. A second `signer_sha256_all` key let a
                    // wrong primary digest be whitewashed by an accepted alternate.
                    out["signer_sha256"] = a.sha256.joinToString(",")
                is Attestation.Unsigned -> out["attest_error"] = "unsigned"
                is Attestation.Unreadable -> out["attest_error"] = a.reason
            }
            return out
        }
    }
}
