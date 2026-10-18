package com.securebrowse.policy

interface StringStore {
    fun read(): String?
    fun write(value: String)
}

class MemoryStringStore(initial: String? = null) : StringStore {
    private var value: String? = initial
    override fun read(): String? = value
    override fun write(value: String) {
        this.value = value
    }
}

class PolicyRepository(private val store: StringStore) {
    fun get(): BrowserPolicy {
        val raw = store.read() ?: return BrowserPolicy()
        return PolicyCodec.decode(raw)
    }

    fun getOrNull(): BrowserPolicy? = try {
        get()
    } catch (_: Exception) {
        null
    }

    fun replace(policy: BrowserPolicy) {
        validate(policy)
        store.write(PolicyCodec.encode(policy))
    }

    fun addHost(rawInput: String, allowSubdomains: Boolean): PolicyEdit {
        val current = getOrNull() ?: return PolicyEdit.Rejected(
            "Stored allowlist is unreadable. Reset it or import a replacement before editing.",
        )
        val host = interpretHost(rawInput) ?: return PolicyEdit.Rejected(
            "Enter a domain like wikipedia.org, or a full https address.",
        )
        PublicSuffixGuard.rejectionReason(host)?.let { return PolicyEdit.Rejected(it) }
        if (current.entries.size >= PolicyCodec.MAX_ENTRIES && current.entries.none { it.host == host }) {
            return PolicyEdit.Rejected("The allowlist is full.")
        }
        val updated = current.entries.filterNot { it.host == host } + DomainEntry(host, allowSubdomains)
        val next = current.copy(entries = updated.sortedBy { it.host })
        return try {
            replace(next)
            PolicyEdit.Saved(next)
        } catch (ex: PolicyFormatException) {
            PolicyEdit.Rejected(ex.message ?: "Could not save that domain.")
        }
    }

    fun removeHost(host: String): PolicyEdit {
        val current = getOrNull() ?: return PolicyEdit.Rejected(
            "Stored allowlist is unreadable. Reset it or import a replacement before editing.",
        )
        val normalized = HostNames.normalize(host) ?: return PolicyEdit.Rejected("That domain is not valid.")
        val nextEntries = current.entries.filterNot { it.host == normalized }
        var next = current.copy(entries = nextEntries)
        if (next.homepage != null) {
            val decision = UrlPolicy.evaluate(next.homepage, next, UrlPolicy.Purpose.MAIN_FRAME)
            if (!decision.allowed) next = next.copy(homepage = null)
        }
        replace(next)
        return PolicyEdit.Saved(next)
    }

    fun setHomepage(raw: String?): PolicyEdit {
        val current = getOrNull() ?: return PolicyEdit.Rejected(
            "Stored allowlist is unreadable. Reset it or import a replacement before editing.",
        )
        val trimmed = raw?.trim().orEmpty()
        if (trimmed.isEmpty()) {
            val next = current.copy(homepage = null)
            replace(next)
            return PolicyEdit.Saved(next)
        }
        val decision = UrlPolicy.evaluate(trimmed, current, UrlPolicy.Purpose.MAIN_FRAME)
        if (!decision.allowed) {
            return PolicyEdit.Rejected(
                "Homepage must be an https site already on the allowlist. ${BlockMessages.detail(decision)}",
            )
        }
        val next = current.copy(homepage = trimmed)
        replace(next)
        return PolicyEdit.Saved(next)
    }

    fun updateFlags(
        javascriptEnabled: Boolean,
        blockThirdPartyResources: Boolean,
        allowDownloads: Boolean,
        allowThirdPartyCookies: Boolean,
        kioskAutoStart: Boolean,
        strictKioskRestrictions: Boolean,
    ): PolicyEdit {
        val current = getOrNull() ?: return PolicyEdit.Rejected(
            "Stored allowlist is unreadable. Reset it or import a replacement before editing.",
        )
        val next = current.copy(
            javascriptEnabled = javascriptEnabled,
            blockThirdPartyResources = blockThirdPartyResources,
            allowDownloads = allowDownloads,
            allowThirdPartyCookies = allowThirdPartyCookies,
            kioskAutoStart = kioskAutoStart,
            strictKioskRestrictions = strictKioskRestrictions,
        )
        replace(next)
        return PolicyEdit.Saved(next)
    }

    fun importDocument(json: String): PolicyEdit {
        return try {
            val decoded = PolicyCodec.decode(json)
            replace(decoded)
            PolicyEdit.Saved(decoded)
        } catch (ex: PolicyFormatException) {
            PolicyEdit.Rejected(ex.message ?: "Could not read that allowlist.")
        }
    }

    fun exportDocument(): String = PolicyCodec.encode(get())

    private fun validate(policy: BrowserPolicy) {
        if (policy.entries.size > PolicyCodec.MAX_ENTRIES) {
            throw PolicyFormatException("Too many domains.")
        }
        policy.entries.forEach { entry ->
            if (HostNames.normalize(entry.host) != entry.host) {
                throw PolicyFormatException("Domain ${entry.host} is not normalized.")
            }
            PublicSuffixGuard.rejectionReason(entry.host)?.let { throw PolicyFormatException(it) }
        }
        if (policy.homepage != null) {
            val decision = UrlPolicy.evaluate(policy.homepage, policy, UrlPolicy.Purpose.MAIN_FRAME)
            if (!decision.allowed) throw PolicyFormatException("Homepage is not approved.")
        }
    }

    private fun interpretHost(rawInput: String): String? {
        val trimmed = rawInput.trim()
        if (trimmed.startsWith("*.") || trimmed.contains('*')) return null
        if ("://" in trimmed) {
            val decision = UrlPolicy.evaluate(trimmed, BrowserPolicy(), UrlPolicy.Purpose.MAIN_FRAME)
            if (decision.reason == UrlPolicy.BlockReason.CREDENTIALS_IN_URL ||
                decision.reason == UrlPolicy.BlockReason.CLEARTEXT_HTTP ||
                decision.reason == UrlPolicy.BlockReason.UNSUPPORTED_SCHEME ||
                decision.reason == UrlPolicy.BlockReason.INVALID
            ) {
                return null
            }
            return decision.host
        }
        return HostNames.normalize(trimmed)
    }
}
