package com.sentrix.security.firewall

/**
 * FirewallRuleEvaluator
 *
 * Low-level deterministic rule-matching component used by the
 * SentriX firewall engine.
 *
 * Responsibilities:
 *
 * - Match network requests against firewall rules.
 * - Match domains.
 * - Match IP addresses.
 * - Match ports and port ranges.
 * - Match applications/packages.
 * - Match protocols.
 * - Match generic network targets.
 * - Respect rule priority.
 * - Return the highest-priority matching rule.
 * - Provide detailed evaluation information.
 *
 * This class DOES NOT:
 *
 * - Start/stop firewall protection.
 * - Manage Android Service lifecycle.
 * - Persist rules.
 * - Modify network traffic.
 * - Perform network calls.
 * - Query external threat intelligence.
 *
 * Those responsibilities belong to:
 *
 * FirewallService
 * FirewallManager
 * FirewallRuleManager
 * FirewallEngine
 * ThreatIntelligence components
 *
 * Runtime flow:
 *
 * FirewallNetworkRequest
 *          |
 *          v
 * FirewallEngine
 *          |
 *          v
 * FirewallRuleEvaluator
 *          |
 *          ├── Priority ordering
 *          ├── Application matching
 *          ├── Domain matching
 *          ├── IP matching
 *          ├── Port matching
 *          ├── Protocol matching
 *          └── Network matching
 *          |
 *          v
 * Matching FirewallRule
 */
class FirewallRuleEvaluator {

    companion object {

        /**
         * Maximum number of rules evaluated in one operation.
         *
         * This prevents accidental resource exhaustion if a
         * malformed rule collection is supplied.
         */
        private const val MAX_EVALUATION_RULES =
            10_000

        /**
         * Maximum number of labels accepted for a domain.
         */
        private const val MAX_DOMAIN_LABELS =
            127

        /**
         * Maximum supported domain length.
         */
        private const val MAX_DOMAIN_LENGTH =
            253

        /**
         * Wildcard token.
         */
        private const val WILDCARD =
            "*"
    }

    /**
     * Evaluates a network request against the supplied firewall rules.
     *
     * Rules are evaluated from highest priority to lowest priority.
     *
     * If multiple rules match:
     *
     *     priority 1000 -> BLOCK
     *     priority 500  -> ALLOW
     *
     * the BLOCK rule wins because it has higher priority.
     *
     * If two rules have the same priority, their deterministic
     * secondary ordering is used.
     */
    fun evaluate(
        request: FirewallNetworkRequest,
        rules: Collection<FirewallRule>
    ): FirewallEvaluationResult {

        require(
            rules.size <= MAX_EVALUATION_RULES
        ) {
            "Firewall rule collection exceeds the evaluation limit."
        }

        validateRequest(
            request
        )

        val activeRules =
            rules
                .asSequence()
                .filter {
                    it.enabled
                }
                .sortedWith(
                    compareByDescending<FirewallRule> {
                        it.priority
                    }.thenBy {
                        it.id
                    }
                )
                .toList()

        var evaluatedCount =
            0

        for (
            rule in activeRules
        ) {

            evaluatedCount++

            if (
                matches(
                    request,
                    rule
                )
            ) {

                return FirewallEvaluationResult(
                    decision =
                        rule.action,

                    matchedRule =
                        rule,

                    reason =
                        buildMatchReason(
                            request,
                            rule
                        ),

                    evaluatedRules =
                        evaluatedCount,

                    protectionActive =
                        true
                )
            }
        }

        return FirewallEvaluationResult(
            decision =
                FirewallDecision.ALLOW,

            matchedRule =
                null,

            reason =
                "No enabled firewall rule matched the request.",

            evaluatedRules =
                evaluatedCount,

            protectionActive =
                true
        )
    }

    /**
     * Performs detailed rule evaluation.
     *
     * Unlike evaluate(), this method returns all matching rules.
     *
     * This is useful for:
     *
     * - diagnostics
     * - security reports
     * - debugging
     * - rule-management UI
     * - audit logs
     */
    fun evaluateDetailed(
        request: FirewallNetworkRequest,
        rules: Collection<FirewallRule>
    ): FirewallDetailedEvaluationResult {

        require(
            rules.size <= MAX_EVALUATION_RULES
        ) {
            "Firewall rule collection exceeds the evaluation limit."
        }

        validateRequest(
            request
        )

        val activeRules =
            rules
                .asSequence()
                .filter {
                    it.enabled
                }
                .sortedWith(
                    compareByDescending<FirewallRule> {
                        it.priority
                    }.thenBy {
                        it.id
                    }
                )
                .toList()

        val matches =
            mutableListOf<FirewallRuleMatch>()

        for (
            rule in activeRules
        ) {

            val matched =
                matches(
                    request,
                    rule
                )

            if (
                matched
            ) {

                matches.add(
                    FirewallRuleMatch(
                        rule =
                            rule,

                        matchType =
                            determineMatchType(
                                request,
                                rule
                            ),

                        priority =
                            rule.priority
                    )
                )
            }
        }

        val winningRule =
            matches.firstOrNull()

        val decision =
            winningRule
                ?.rule
                ?.action
                ?: FirewallDecision.ALLOW

        return FirewallDetailedEvaluationResult(
            decision =
                decision,

            winningRule =
                winningRule?.rule,

            matchingRules =
                matches,

            evaluatedRules =
                activeRules.size,

            reason =
                if (
                    winningRule != null
                ) {

                    buildMatchReason(
                        request,
                        winningRule.rule
                    )

                } else {

                    "No enabled firewall rule matched the request."
                }
        )
    }

    /**
     * Determines whether a request matches a specific rule.
     */
    fun matches(
        request: FirewallNetworkRequest,
        rule: FirewallRule
    ): Boolean {

        if (
            !rule.enabled
        ) {
            return false
        }

        /*
         * Application/package restriction.
         *
         * If the rule specifies a package name, the request must
         * originate from that package.
         */
        if (
            !matchesPackageRestriction(
                request,
                rule
            )
        ) {

            return false
        }

        /*
         * Protocol restriction.
         */
        if (
            !matchesProtocol(
                request,
                rule
            )
        ) {

            return false
        }

        /*
         * Explicit port restriction.
         */
        if (
            !matchesExplicitPort(
                request,
                rule
            )
        ) {

            return false
        }

        /*
         * Target-specific matching.
         */
        return when (
            rule.type
        ) {

            FirewallRuleType.DOMAIN ->
                matchesDomain(
                    request.host,
                    rule.target
                )

            FirewallRuleType.IP ->
                matchesIp(
                    request,
                    rule.target
                )

            FirewallRuleType.PORT ->
                matchesPort(
                    request.port,
                    rule.target
                )

            FirewallRuleType.APPLICATION ->
                matchesApplication(
                    request.packageName,
                    rule.target
                )

            FirewallRuleType.PROTOCOL ->
                matchesProtocolTarget(
                    request.protocol,
                    rule.target
                )

            FirewallRuleType.NETWORK ->
                matchesNetwork(
                    request,
                    rule.target
                )

            FirewallRuleType.DEFAULT ->
                true
        }
    }

    /**
     * Checks application/package restrictions.
     */
    private fun matchesPackageRestriction(
        request: FirewallNetworkRequest,
        rule: FirewallRule
    ): Boolean {

        val requiredPackage =
            rule.packageName
                ?.trim()
                ?.takeIf {
                    it.isNotEmpty()
                }

        if (
            requiredPackage == null
        ) {

            return true
        }

        val requestPackage =
            request.packageName
                ?.trim()
                ?.takeIf {
                    it.isNotEmpty()
                }
                ?: return false

        return matchesWildcardString(
            value =
                requestPackage,
            pattern =
                requiredPackage
        )
    }

    /**
     * Checks protocol restriction.
     */
    private fun matchesProtocol(
        request: FirewallNetworkRequest,
        rule: FirewallRule
    ): Boolean {

        if (
            rule.protocol ==
            FirewallProtocol.ANY
        ) {

            return true
        }

        return request.protocol ==
                rule.protocol
    }

    /**
     * Checks the optional explicit port on FirewallRule.
     *
     * This is separate from FirewallRuleType.PORT because a domain
     * rule can also restrict traffic to a particular port.
     */
    private fun matchesExplicitPort(
        request: FirewallNetworkRequest,
        rule: FirewallRule
    ): Boolean {

        val requiredPort =
            rule.port
                ?: return true

        val requestPort =
            request.port
                ?: return false

        return requestPort ==
                requiredPort
    }

    /**
     * Matches a domain.
     *
     * Supported examples:
     *
     * example.com
     * www.example.com
     * *.example.com
     *
     * A wildcard domain does not match unrelated domains.
     */
    fun matchesDomain(
        host: String?,
        target: String
    ): Boolean {

        val normalizedHost =
            normalizeDomain(
                host
            )
                ?: return false

        val normalizedTarget =
            normalizeDomainPattern(
                target
            )

        if (
            normalizedTarget.isBlank()
        ) {

            return false
        }

        if (
            normalizedTarget ==
            WILDCARD
        ) {

            return true
        }

        /*
         * Exact match.
         */
        if (
            normalizedHost ==
            normalizedTarget
        ) {

            return true
        }

        /*
         * Subdomain wildcard.
         *
         * *.example.com
         *
         * matches:
         *
         * login.example.com
         * secure.login.example.com
         *
         * but not:
         *
         * example.com
         */
        if (
            normalizedTarget.startsWith(
                "*."
            )
        ) {

            val suffix =
                normalizedTarget
                    .removePrefix(
                        "*."
                    )

            if (
                suffix.isBlank()
            ) {

                return false
            }

            return normalizedHost
                .endsWith(
                    ".$suffix"
                )
        }

        return false
    }

    /**
     * Matches an IP address.
     *
     * Supports:
     *
     * - exact IPv4
     * - exact IPv6
     * - wildcard IPv4 patterns
     * - CIDR IPv4
     */
    fun matchesIp(
        request: FirewallNetworkRequest,
        target: String
    ): Boolean {

        val normalizedTarget =
            target
                .trim()
                .lowercase()

        if (
            normalizedTarget.isBlank()
        ) {

            return false
        }

        val candidates =
            listOfNotNull(
                request.host,
                request.sourceIp
            )

        /*
         * CIDR support.
         */
        if (
            normalizedTarget.contains(
                "/"
            )
        ) {

            return candidates.any {
                matchesCidr(
                    ip =
                        it,
                    cidr =
                        normalizedTarget
                )
            }
        }

        /*
         * Wildcard IP.
         *
         * Example:
         *
         * 192.168.1.*
         */
        if (
            normalizedTarget.contains(
                "*"
            )
        ) {

            return candidates.any {
                matchesWildcardString(
                    value =
                        it,
                    pattern =
                        normalizedTarget
                )
            }
        }

        /*
         * Exact IP match.
         */
        return candidates.any {
            normalizeIp(
                it
            ) ==
                    normalizeIp(
                        normalizedTarget
                    )
        }
    }

    /**
     * Matches a port.
     *
     * Supported:
     *
     * 443
     * 80
     * 1000-2000
     * *
     */
    fun matchesPort(
        port: Int?,
        target: String
    ): Boolean {

        if (
            port == null
        ) {

            return false
        }

        val normalizedTarget =
            target.trim()

        if (
            normalizedTarget ==
            WILDCARD
        ) {

            return true
        }

        /*
         * Exact port.
         */
        normalizedTarget
            .toIntOrNull()
            ?.let {

                return port ==
                        it
            }

        /*
         * Port range.
         */
        val parts =
            normalizedTarget
                .split(
                    "-"
                )

        if (
            parts.size == 2
        ) {

            val start =
                parts[0]
                    .trim()
                    .toIntOrNull()

            val end =
                parts[1]
                    .trim()
                    .toIntOrNull()

            if (
                start == null ||
                end == null
            ) {

                return false
            }

            if (
                start !in 1..65535 ||
                end !in 1..65535
            ) {

                return false
            }

            return if (
                start <= end
            ) {

                port in start..end

            } else {

                port in end..start
            }
        }

        return false
    }

    /**
     * Matches Android application package name.
     */
    fun matchesApplication(
        packageName: String?,
        target: String
    ): Boolean {

        if (
            packageName.isNullOrBlank()
        ) {

            return false
        }

        return matchesWildcardString(
            value =
                packageName,
            pattern =
                target
        )
    }

    /**
     * Matches a protocol rule.
     */
    fun matchesProtocolTarget(
        protocol: FirewallProtocol,
        target: String
    ): Boolean {

        val normalizedTarget =
            target
                .trim()
                .uppercase()

        if (
            normalizedTarget ==
            WILDCARD ||
            normalizedTarget ==
            FirewallProtocol.ANY.name
        ) {

            return true
        }

        return protocol.name ==
                normalizedTarget
    }

    /**
     * Matches generic network targets.
     *
     * A NETWORK rule may match:
     *
     * - domain
     * - IP
     * - wildcard
     */
    fun matchesNetwork(
        request: FirewallNetworkRequest,
        target: String
    ): Boolean {

        if (
            target.trim() ==
            WILDCARD
        ) {

            return true
        }

        return matchesDomain(
            request.host,
            target
        ) ||
                matchesIp(
                    request,
                    target
                )
    }

    /**
     * Returns the match type used by a rule.
     */
    private fun determineMatchType(
        request: FirewallNetworkRequest,
        rule: FirewallRule
    ): FirewallMatchType {

        return when (
            rule.type
        ) {

            FirewallRuleType.DOMAIN ->
                FirewallMatchType.DOMAIN

            FirewallRuleType.IP ->
                FirewallMatchType.IP

            FirewallRuleType.PORT ->
                FirewallMatchType.PORT

            FirewallRuleType.APPLICATION ->
                FirewallMatchType.APPLICATION

            FirewallRuleType.PROTOCOL ->
                FirewallMatchType.PROTOCOL

            FirewallRuleType.NETWORK -> {

                when {

                    matchesDomain(
                        request.host,
                        rule.target
                    ) ->
                        FirewallMatchType.DOMAIN

                    matchesIp(
                        request,
                        rule.target
                    ) ->
                        FirewallMatchType.IP

                    else ->
                        FirewallMatchType.NETWORK
                }
            }

            FirewallRuleType.DEFAULT ->
                FirewallMatchType.DEFAULT
        }
    }

    /**
     * Builds an explanation for a successful match.
     */
    private fun buildMatchReason(
        request: FirewallNetworkRequest,
        rule: FirewallRule
    ): String {

        val matchType =
            determineMatchType(
                request,
                rule
            )

        return buildString {

            append(
                "Matched firewall rule "
            )

            append(
                "'${rule.name}'"
            )

            append(
                " [${rule.id}]"
            )

            append(
                ". "
            )

            append(
                "Match type="
            )

            append(
                matchType.name
            )

            append(
                ", priority="
            )

            append(
                rule.priority
            )

            append(
                ", action="
            )

            append(
                rule.action.name
            )

            append(
                "."
            )
        }
    }

    /**
     * Wildcard string matcher.
     *
     * Supports:
     *
     * *
     * com.example.*
     * *.example.com
     */
    private fun matchesWildcardString(
        value: String,
        pattern: String
    ): Boolean {

        val normalizedValue =
            value
                .trim()
                .lowercase()

        val normalizedPattern =
            pattern
                .trim()
                .lowercase()

        if (
            normalizedPattern ==
            WILDCARD
        ) {

            return true
        }

        if (
            !normalizedPattern.contains(
                WILDCARD
            )
        ) {

            return normalizedValue ==
                    normalizedPattern
        }

        /*
         * Convert wildcard pattern into a safe regular expression.
         */
        val regex =
            normalizedPattern
                .split(
                    "*"
                )
                .joinToString(
                    separator = ".*"
                ) {
                    Regex.escape(
                        it
                    )
                }
                .toRegex()

        return regex.matches(
            normalizedValue
        )
    }

    /**
     * Matches an IPv4 address against CIDR notation.
     *
     * Example:
     *
     * 192.168.1.20
     * against
     * 192.168.1.0/24
     */
    private fun matchesCidr(
        ip: String,
        cidr: String
    ): Boolean {

        val parts =
            cidr
                .trim()
                .split(
                    "/"
                )

        if (
            parts.size != 2
        ) {

            return false
        }

        val network =
            ipv4ToLong(
                parts[0]
            )
                ?: return false

        val prefix =
            parts[1]
                .toIntOrNull()
                ?: return false

        if (
            prefix !in 0..32
        ) {

            return false
        }

        val candidate =
            ipv4ToLong(
                ip
            )
                ?: return false

        val mask =
            if (
                prefix == 0
            ) {

                0L

            } else {

                (0xFFFFFFFFL shl
                        (32 - prefix)) and
                        0xFFFFFFFFL
            }

        return (
            network and mask
            ) ==
                (
                    candidate and mask
                )
    }

    /**
     * Converts IPv4 to unsigned 32-bit representation.
     */
    private fun ipv4ToLong(
        address: String
    ): Long? {

        val parts =
            address
                .trim()
                .split(
                    "."
                )

        if (
            parts.size != 4
        ) {

            return null
        }

        var result =
            0L

        for (
            part in parts
        ) {

            val value =
                part.toIntOrNull()
                    ?: return null

            if (
                value !in 0..255
            ) {

                return null
            }

            result =
                (
                    result shl 8
                    ) or
                        value.toLong()
        }

        return result
    }

    /**
     * Normalizes a domain.
     */
    private fun normalizeDomain(
        value: String?
    ): String? {

        if (
            value.isNullOrBlank()
        ) {

            return null
        }

        var normalized =
            value
                .trim()
                .lowercase()

        /*
         * Remove URL scheme if a caller supplied a complete URL.
         */
        normalized =
            normalized
                .removePrefix(
                    "https://"
                )
                .removePrefix(
                    "http://"
                )

        /*
         * Remove path.
         */
        normalized =
            normalized
                .substringBefore(
                    "/"
                )

        /*
         * Remove query.
         */
        normalized =
            normalized
                .substringBefore(
                    "?"
                )

        /*
         * Remove fragment.
         */
        normalized =
            normalized
                .substringBefore(
                    "#"
                )

        /*
         * Remove optional port.
         *
         * IPv6 is handled separately because ':' is part of the
         * address itself.
         */
        if (
            normalized.count {
                it == ':'
            } == 1
        ) {

            normalized =
                normalized
                    .substringBefore(
                        ":"
                    )
        }

        normalized =
            normalized
                .trimEnd(
                    '.'
                )

        if (
            normalized.length >
            MAX_DOMAIN_LENGTH
        ) {

            return null
        }

        if (
            normalized.isBlank()
        ) {

            return null
        }

        val labels =
            normalized.split(
                "."
            )

        if (
            labels.size >
            MAX_DOMAIN_LABELS
        ) {

            return null
        }

        return normalized
    }

    /**
     * Normalizes a domain rule pattern.
     */
    private fun normalizeDomainPattern(
        value: String
    ): String {

        val trimmed =
            value
                .trim()
                .lowercase()

        if (
            trimmed ==
            WILDCARD
        ) {

            return WILDCARD
        }

        val wildcard =
            trimmed
                .startsWith(
                    "*."
                )

        val base =
            if (
                wildcard
            ) {

                trimmed
                    .removePrefix(
                        "*."
                    )

            } else {

                trimmed
            }

        val normalized =
            normalizeDomain(
                base
            )
                ?: return ""

        return if (
            wildcard
        ) {

            "*.$normalized"

        } else {

            normalized
        }
    }

    /**
     * Normalizes an IP address.
     */
    private fun normalizeIp(
        value: String
    ): String {

        return value
            .trim()
            .lowercase()
            .removePrefix(
                "["
            )
            .removeSuffix(
                "]"
            )
    }

    /**
     * Validates a firewall request.
     */
    private fun validateRequest(
        request: FirewallNetworkRequest
    ) {

        require(
            request.host.isNotBlank()
        ) {
            "Firewall request host cannot be blank."
        }

        request.port?.let {

            require(
                it in 1..65535
            ) {
                "Firewall request port must be between 1 and 65535."
            }
        }

        require(
            request.host.length <=
                    512
        ) {
            "Firewall request host is too long."
        }
    }
}

/**
 * Detailed firewall evaluation result.
 */
data class FirewallDetailedEvaluationResult(

    /**
     * Final decision based on the highest-priority matching rule.
     */
    val decision:
        FirewallDecision,

    /**
     * Winning rule.
     */
    val winningRule:
        FirewallRule?,

    /**
     * Every rule that matched.
     */
    val matchingRules:
        List<FirewallRuleMatch>,

    /**
     * Number of active rules evaluated.
     */
    val evaluatedRules:
        Int,

    /**
     * Human-readable explanation.
     */
    val reason:
        String
)

/**
 * Individual rule match information.
 */
data class FirewallRuleMatch(

    /**
     * Matching rule.
     */
    val rule:
        FirewallRule,

    /**
     * Type of match.
     */
    val matchType:
        FirewallMatchType,

    /**
     * Priority used for ordering.
     */
    val priority:
        Int
)

/**
 * Firewall match categories.
 */
enum class FirewallMatchType {

    DOMAIN,

    IP,

    PORT,

    APPLICATION,

    PROTOCOL,

    NETWORK,

    DEFAULT
}
