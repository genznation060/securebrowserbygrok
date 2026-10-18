package com.securebrowse.policy

/**
 * Administrator-controlled browsing rules.
 *
 * An empty allowlist means nothing on the network is approved. Defaults are
 * fail-closed: HTTPS only, third-party resources blocked, downloads off.
 */
data class DomainEntry(
    val host: String,
    val allowSubdomains: Boolean,
)

data class BrowserPolicy(
    val entries: List<DomainEntry> = emptyList(),
    val homepage: String? = null,
    val javascriptEnabled: Boolean = true,
    val blockThirdPartyResources: Boolean = true,
    val allowDownloads: Boolean = false,
    val allowThirdPartyCookies: Boolean = false,
    val kioskAutoStart: Boolean = true,
    val strictKioskRestrictions: Boolean = false,
) {
    fun isHostAllowed(host: String): Boolean = matchingEntry(host) != null

    fun matchingEntry(host: String): DomainEntry? {
        val normalized = HostNames.normalize(host) ?: return null
        return entries.firstOrNull { entry ->
            HostNames.matches(normalized, entry.host, entry.allowSubdomains)
        }
    }
}

class PolicyFormatException(message: String) : Exception(message)

sealed class PolicyEdit {
    data class Saved(val policy: BrowserPolicy) : PolicyEdit()
    data class Rejected(val message: String) : PolicyEdit()
}
