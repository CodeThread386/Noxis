package com.security.guardian.network

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.URL
import java.util.concurrent.ConcurrentHashMap

/**
 * Industry-grade Universal Ad Blocker
 * Blocks ads from websites, apps, YouTube, and all other sources
 * Uses multiple ad block lists and domain filtering
 */
class AdBlocker(private val context: Context) {
    
    private val TAG = "AdBlocker"
    
    // Popular ad block lists (URLs) - Brave-style aggressive blocking
    private val adBlockLists = listOf(
        "https://easylist.to/easylist/easylist.txt", // EasyList - primary list
        "https://easylist.to/easylist/easyprivacy.txt", // EasyPrivacy - tracking protection
        "https://easylist-downloads.adblockplus.org/antiadblockfilters.txt", // Anti-adblock killer
        "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt", // AdGuard mobile filters
        "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext", // Peter Lowe's Ad server list
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", // Steven Black's hosts file
        "https://someonewhocares.org/hosts/zero/hosts", // Dan Pollock's hosts file
        "https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt", // AdAway hosts
        "https://raw.githubusercontent.com/jdlingyu/ad-wars/master/hosts", // Ad Wars hosts
    )
    
    // YouTube-specific ad domains - More aggressive (Brave-style)
    private val youtubeAdDomains = setOf(
        "googlevideo.com", // YouTube video CDN (will filter by URL pattern)
        "youtube.com",
        "youtube.googleapis.com",
        "youtubei.googleapis.com",
        "doubleclick.net", // Google DoubleClick ads
        "doubleclick.com",
        "googleadservices.com", // Google Ad Services
        "googleadservices.net",
        "googlesyndication.com", // Google Ad Syndication
        "ads.youtube.com", // YouTube ads
        "adservice.google.com", // Google ad service
        "adservice.google.co.in",
        "adservice.google.co.uk",
        "googleads.g.doubleclick.net", // Google DoubleClick ads
        "pagead2.googlesyndication.com",
        "tpc.googlesyndication.com",
        "www.googletagservices.com",
        "www.googleadservices.com",
        "adclick.g.doubleclick.net",
        "pubads.g.doubleclick.net",
        "securepubads.g.doubleclick.net",
    )
    
    // Known ad serving domains (commonly used)
    private val commonAdDomains = setOf(
        "advertising.com",
        "adsystem.com",
        "adsrvr.org",
        "adtechus.com",
        "amazon-adsystem.com",
        "appnexus.com",
        "casalemedia.com",
        "criteo.com",
        "facebook.com/tr", // Facebook Pixel
        "facebook.net",
        "google-analytics.com",
        "googletagmanager.com",
        "scorecardresearch.com",
        "taboola.com",
        "outbrain.com",
        "pubmatic.com",
        "rubiconproject.com",
        "openx.net",
        "adnxs.com",
        "2mdn.net", // Google/DoubleClick
        "admob.com",
        "adcolony.com",
        "unityads.unity3d.com",
        "vungle.com",
        "ironsource.mobi",
        "chartboost.com",
        "tapjoy.com",
        "applovin.com",
        "fyber.com",
        "inmobi.com",
        "mopub.com",
        "adsafeprotected.com",
        "advertising.amazon.com",
        "flurry.com",
        "adjust.com",
        "amplitude.com",
        "branch.io",
        "mixpanel.com",
        "segment.io",
        "newrelic.com",
    )
    
    // Blocked domains cache (domain -> timestamp)
    private val blockedDomains = ConcurrentHashMap<String, Long>()
    
    // Domain patterns to block (wildcards, regex patterns)
    private val blockedPatterns = mutableSetOf<String>()
    
    private val prefs: SharedPreferences = context.getSharedPreferences("ad_blocker", Context.MODE_PRIVATE)
    
    companion object {
        const val PREF_AD_BLOCKER_ENABLED = "ad_blocker_enabled"
        const val PREF_LAST_UPDATE = "ad_blocker_last_update"
        const val UPDATE_INTERVAL_DAYS = 1L // Update lists daily
        
        // Block any domain containing these keywords (Brave-style)
        private val adKeywords = setOf(
            "ad", "ads", "advert", "advertising", "advertisement",
            "banner", "promo", "promotion", "sponsor", "sponsored",
            "tracker", "tracking", "analytics", "statistics",
            "pixel", "beacon", "tag", "script"
        )
    }
    
    init {
        loadBlockedDomains()
    }
    
    /**
     * Check if ad blocker is enabled
     */
    fun isEnabled(): Boolean {
        return prefs.getBoolean(PREF_AD_BLOCKER_ENABLED, true) // Enabled by default
    }
    
    /**
     * Enable/disable ad blocker
     */
    fun setEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(PREF_AD_BLOCKER_ENABLED, enabled).apply()
        Log.d(TAG, "Ad blocker ${if (enabled) "enabled" else "disabled"}")
    }
    
    /**
     * Check if a domain should be blocked (ads) - Brave-style aggressive blocking
     */
    fun shouldBlock(domain: String?): Boolean {
        if (!isEnabled() || domain == null || domain.isEmpty()) {
            return false
        }
        
        val normalizedDomain = normalizeDomain(domain)
        if (normalizedDomain.isEmpty()) {
            return false
        }
        
        // Aggressive: Block any domain containing "ad", "ads", "advert", "advertising" in subdomain
        // (Brave does this to catch ad subdomains)
        val domainParts = normalizedDomain.split(".")
        if (domainParts.any { part ->
            part.lowercase().let { p ->
                p.contains("ad") && p.length > 2 && p != "android" && p != "adobe" && p != "adobecloud"
            }
        }) {
            // Exception: Known legitimate domains (whitelist)
            val whitelist = setOf(
                "adobe.com", "adobecloud.com", "android.com", "adventofcode.com",
                "adventist.org", "adidas.com", "adp.com"
            )
            if (!whitelist.any { normalizedDomain.contains(it) || normalizedDomain.endsWith(".$it") }) {
                return true
            }
        }
        
        // Check exact match in blocked domains
        if (blockedDomains.containsKey(normalizedDomain)) {
            return true
        }
        
        // Check YouTube-specific ad domains (more aggressive matching)
        if (youtubeAdDomains.any { 
            normalizedDomain == it || 
            normalizedDomain.endsWith(".$it") ||
            normalizedDomain.contains(it)
        }) {
            return true
        }
        
        // Check common ad domains (more aggressive)
        if (commonAdDomains.any { 
            normalizedDomain == it || 
            normalizedDomain.endsWith(".$it") ||
            normalizedDomain.contains(it)
        }) {
            return true
        }
        
        // Check patterns (wildcard matching)
        for (pattern in blockedPatterns) {
            if (matchesPattern(normalizedDomain, pattern)) {
                return true
            }
        }
        
        // Check subdomain matching (Brave-style: check all subdomain combinations)
        val parts = normalizedDomain.split(".")
        for (i in parts.indices) {
            val subdomain = parts.subList(i, parts.size).joinToString(".")
            if (blockedDomains.containsKey(subdomain)) {
                return true
            }
            // Also check if subdomain itself contains ad keywords
            if (i < parts.size - 1) {
                val sub = parts.subList(i, parts.size - 1).joinToString(".")
                if (sub.contains("ad") || sub.contains("ads") || sub.contains("advert")) {
                    return true
                }
            }
        }
        
        // Block Google Play ad domains specifically
        if (normalizedDomain.contains("play.google.com") || 
            normalizedDomain.contains("play.googleapis.com") ||
            normalizedDomain.contains("gplay-services")) {
            return true
        }
        
        return false
    }
    
    /**
     * Normalize domain name (remove protocol, www, trailing slashes)
     */
    private fun normalizeDomain(domain: String): String {
        return domain
            .lowercase()
            .removePrefix("http://")
            .removePrefix("https://")
            .removePrefix("www.")
            .split("/")[0] // Remove path
            .split(":")[0] // Remove port
            .trim()
    }
    
    /**
     * Check if domain matches a pattern (wildcard support)
     */
    private fun matchesPattern(domain: String, pattern: String): Boolean {
        return when {
            pattern.startsWith("*.") -> {
                val baseDomain = pattern.removePrefix("*.")
                domain.endsWith(".$baseDomain") || domain == baseDomain
            }
            pattern.endsWith(".*") -> {
                val baseDomain = pattern.removeSuffix(".*")
                domain.startsWith("$baseDomain.") || domain == baseDomain
            }
            pattern.contains("*") -> {
                // Simple wildcard matching
                val regex = pattern.replace("*", ".*").toRegex()
                regex.matches(domain)
            }
            else -> domain == pattern || domain.endsWith(".$pattern")
        }
    }
    
    /**
     * Load blocked domains from SharedPreferences and lists
     */
    private fun loadBlockedDomains() {
        // Load from cache
        val cachedDomains = prefs.getStringSet("blocked_domains_cache", emptySet())
        cachedDomains?.forEach { domain ->
            blockedDomains[domain] = System.currentTimeMillis()
        }
        
        // Load patterns
        val cachedPatterns = prefs.getStringSet("blocked_patterns_cache", emptySet())
        blockedPatterns.addAll(cachedPatterns ?: emptySet())
        
        // Add YouTube and common ad domains
        youtubeAdDomains.forEach { blockedDomains[it] = System.currentTimeMillis() }
        commonAdDomains.forEach { blockedDomains[it] = System.currentTimeMillis() }
        
        Log.d(TAG, "Loaded ${blockedDomains.size} blocked domains and ${blockedPatterns.size} patterns")
    }
    
    /**
     * Download and parse ad block lists from the internet
     */
    suspend fun updateAdBlockLists(): Boolean = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Starting ad block list update...")
            val newDomains = mutableSetOf<String>()
            val newPatterns = mutableSetOf<String>()
            
            for (listUrl in adBlockLists) {
                try {
                    val url = URL(listUrl)
                    val connection = url.openConnection()
                    connection.connectTimeout = 10000
                    connection.readTimeout = 10000
                    
                    BufferedReader(InputStreamReader(connection.getInputStream())).use { reader ->
                        var line: String?
                        while (reader.readLine().also { line = it } != null) {
                            line?.let { processAdBlockLine(it, newDomains, newPatterns) }
                        }
                    }
                    
                    Log.d(TAG, "Downloaded list from: $listUrl")
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to download list from $listUrl: ${e.message}")
                    // Continue with other lists
                }
            }
            
            // Merge with existing domains
            newDomains.forEach { blockedDomains[it] = System.currentTimeMillis() }
            blockedPatterns.addAll(newPatterns)
            
            // Save to cache
            prefs.edit()
                .putStringSet("blocked_domains_cache", blockedDomains.keys)
                .putStringSet("blocked_patterns_cache", blockedPatterns)
                .putLong(PREF_LAST_UPDATE, System.currentTimeMillis())
                .apply()
            
            Log.d(TAG, "Updated ad block lists: ${blockedDomains.size} domains, ${blockedPatterns.size} patterns")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Error updating ad block lists", e)
            false
        }
    }
    
    /**
     * Process a line from an ad block list (EasyList format, hosts format, etc.)
     */
    private fun processAdBlockLine(line: String, domains: MutableSet<String>, patterns: MutableSet<String>) {
        val trimmed = line.trim()
        
        // Skip comments and empty lines
        if (trimmed.isEmpty() || trimmed.startsWith("#") || trimmed.startsWith("!") || trimmed.startsWith("[") || trimmed.startsWith("@")) {
            return
        }
        
        // Hosts file format: 127.0.0.1 domain.com
        if (trimmed.startsWith("127.0.0.1") || trimmed.startsWith("0.0.0.0")) {
            val parts = trimmed.split("\\s+".toRegex())
            if (parts.size >= 2) {
                val domain = normalizeDomain(parts[1])
                if (domain.isNotEmpty()) {
                    domains.add(domain)
                }
            }
            return
        }
        
        // EasyList/AdBlock format: ||domain.com^
        if (trimmed.startsWith("||") && trimmed.contains("^")) {
            val domain = trimmed.substring(2, trimmed.indexOf("^"))
            val normalized = normalizeDomain(domain)
            if (normalized.isNotEmpty()) {
                domains.add(normalized)
            }
            return
        }
        
        // EasyList format: |http://domain.com
        if (trimmed.startsWith("|http://") || trimmed.startsWith("|https://")) {
            val url = trimmed.substring(1)
            val domain = normalizeDomain(url)
            if (domain.isNotEmpty()) {
                domains.add(domain)
            }
            return
        }
        
        // Domain pattern: domain.com
        if (trimmed.contains(".") && !trimmed.contains(" ") && !trimmed.contains("/")) {
            val normalized = normalizeDomain(trimmed)
            if (normalized.isNotEmpty() && !normalized.contains(" ")) {
                domains.add(normalized)
            }
        }
        
        // Wildcard patterns
        if (trimmed.contains("*")) {
            patterns.add(trimmed)
        }
    }
    
    /**
     * Check if update is needed
     */
    fun isUpdateNeeded(): Boolean {
        val lastUpdate = prefs.getLong(PREF_LAST_UPDATE, 0)
        val daysSinceUpdate = (System.currentTimeMillis() - lastUpdate) / (24 * 60 * 60 * 1000)
        return daysSinceUpdate >= UPDATE_INTERVAL_DAYS
    }
    
    /**
     * Get statistics
     */
    fun getStats(): AdBlockerStats {
        return AdBlockerStats(
            totalBlockedDomains = blockedDomains.size,
            totalPatterns = blockedPatterns.size,
            isEnabled = isEnabled(),
            lastUpdate = prefs.getLong(PREF_LAST_UPDATE, 0)
        )
    }
    
    /**
     * Check if YouTube ad should be blocked (by URL path) - Brave-style aggressive
     * Enhanced to catch more YouTube ad patterns
     */
    fun isYouTubeAd(url: String): Boolean {
        if (!isEnabled()) return false
        
        if (url.isBlank()) return false
        
        val lowerUrl = url.lowercase()
        
        // YouTube ad URL patterns (Brave-style comprehensive)
        val youtubeAdPatterns = listOf(
            "/ptracking",
            "/pagead",
            "/api/stats/ads",
            "/api/stats/qoe",
            "/api/stats/watchtime",
            "/api/stats/atr",
            "/get_video_info?",
            "adformat",
            "ad_type",
            "ad_break",
            "ad_slot",
            "ad_cpn",
            "ad_tag",
            "googleadservices",
            "doubleclick",
            "adsafeprotected",
            "adserver",
            "advertising",
            "advertisement",
            "adsense",
            "adview",
            "advert",
            "instream",
            "midroll",
            "preroll",
            "postroll",
            "companion",
            "overlay",
            "annotation",
            "clickthrough",
            "clicktracking",
            "viewability",
            "impression",
            "videoad",
            "youtube.com/watch?",
            "youtube.com/embed?",
            "/youtubei/v1/player/ad",
            "/youtubei/v1/player/ads",
            "/youtubei/v1/get_midroll_info",
            "/youtubei/v1/get_preroll",
            "csi.gstatic.com",
            "pagead2.googlesyndication.com",
            "tpc.googlesyndication.com"
        )
        
        // Check if URL contains any ad pattern
        if (youtubeAdPatterns.any { lowerUrl.contains(it) }) {
            return true
        }
        
        // Special case: googlevideo.com with ad parameters (CRITICAL for YouTube ads)
        if (lowerUrl.contains("googlevideo.com")) {
            // Block if contains ad-related parameters
            val adParams = listOf(
                "adformat", "ad_type", "ad_break", "instream", "adslot",
                "ad_cpn", "ad_tag", "ad_sys", "ad_source", "ad_net",
                "ad_v", "ad_cl", "ad_exp", "ad_id", "ad_inst"
            )
            if (adParams.any { lowerUrl.contains(it) }) {
                return true
            }
            
            // Block googlevideo.com URLs that are likely ads based on path
            if (lowerUrl.contains("/videoplayback")) {
                // Check for ad-related query parameters
                if (lowerUrl.contains("&ad") || lowerUrl.contains("?ad") || 
                    lowerUrl.contains("adformat=") || lowerUrl.contains("ad_type=")) {
                    return true
                }
                
                // Block if itag is very low (ads often use low quality)
                val itagMatch = Regex("itag=(\\d+)").find(lowerUrl)
                if (itagMatch != null) {
                    val itag = itagMatch.groupValues[1].toIntOrNull()
                    // Very low itag (< 18) often indicates ads
                    if (itag != null && itag < 18) {
                        return true
                    }
                }
            }
            
            // Block specific googlevideo.com subdomains known for ads
            if (lowerUrl.contains("redirector.googlevideo.com") ||
                lowerUrl.contains("r1---") || lowerUrl.contains("r2---") ||
                lowerUrl.contains("r3---") || lowerUrl.contains("r4---")) {
                // These are often used for ad delivery
                if (lowerUrl.contains("ad") || lowerUrl.contains("track")) {
                    return true
                }
            }
        }
        
        // Block YouTube API endpoints that serve ads
        if (lowerUrl.contains("youtube.com") || lowerUrl.contains("youtube.googleapis.com")) {
            // Block ad-related API endpoints
            if (lowerUrl.contains("/api/stats") || 
                lowerUrl.contains("/ptracking") ||
                lowerUrl.contains("/pagead") ||
                lowerUrl.contains("/get_midroll") ||
                lowerUrl.contains("/get_preroll") ||
                lowerUrl.contains("/youtubei/v1/player/ad")) {
                return true
            }
        }
        
        // Block Google Play ads
        if (lowerUrl.contains("google-play-services") || 
            lowerUrl.contains("play.google.com/store") ||
            lowerUrl.contains("googleads") ||
            lowerUrl.contains("admob") ||
            lowerUrl.contains("adservice.google")) {
            return true
        }
        
        // Block DoubleClick and Google ad services
        if (lowerUrl.contains("doubleclick.net") ||
            lowerUrl.contains("doubleclick.com") ||
            lowerUrl.contains("googlesyndication.com") ||
            lowerUrl.contains("googleadservices.com")) {
            return true
        }
        
        return false
    }
    
    data class AdBlockerStats(
        val totalBlockedDomains: Int,
        val totalPatterns: Int,
        val isEnabled: Boolean,
        val lastUpdate: Long
    )
}
