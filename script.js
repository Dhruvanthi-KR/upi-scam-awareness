/**
 * UPI SCAM AWARENESS - Enhanced Scam Detection System
 * Detects various scam techniques and provides detailed threat analysis
 * Author: Dhruvanthi-KR
 * Last Updated: 2026-03-26
 */

// ==================== SCAM DETECTION KEYWORDS ====================

// Comprehensive list of suspicious keywords used in scams
const SUSPICIOUS_KEYWORDS = [
    // Reward-related terms
    "reward", "rewards", "prize", "prizes", "cashback", "cash-back",
    "bonus", "bonuses",
    
    // Free/Offer terms
    "free", "claim", "unlimited", "special", "exclusive", "offer",
    
    // Urgency terms
    "urgent", "hurry", "limited time", "act now", "quickly",
    
    // Payment/UPI terms
    "verify", "confirm", "update", "activate", "validate",
    
    // Account terms
    "account", "identity", "details", "information", "credentials",
    
    // Common scam words
    "receive", "money", "congratulations", "selected", "winner",
    
    // Misspellings (common in scams)
    "recieve", "occured", "seperate", "untill", "reword", "casback",
    "paytm", "gpay", "googlepay", "upi", "phonepay", "truecaller"
];

// Legitimate domain whitelist - these are SAFE
const LEGITIMATE_DOMAINS = [
    "google.com", "paytm.com", "phonepe.com", "googlepay.app",
    "paypal.com", "icici.com", "hdfc.com", "axis.com", "sbi.com",
    "truecaller.com", "whatsapp.com", "instagram.com", "facebook.com",
    "amazon.com", "flipkart.com", "twitter.com", "linkedin.com",
    "github.com", "stackoverflow.com", "www.google.com", "www.paytm.com",
    "www.phonepe.com", "www.icici.com", "www.hdfc.com"
];

// Suspicious domain extensions used by scammers
const SUSPICIOUS_EXTENSIONS = [
    ".xyz", ".click", ".top", ".download", ".review", ".space",
    ".stream", ".loan", ".tk", ".cf", ".ga", ".ml", ".online",
    ".site", ".website", ".pw", ".cc", ".bid", ".date", ".trade",
    ".rocks", ".monster", ".zip", ".info", ".asia", ".club",
    ".win", ".work", ".faith", ".life", ".tech"
];

// Fake brand prefixes used in domain spoofing attacks
const FAKE_BRAND_PREFIXES = [
    "gpay", "paytm", "paypal", "upi", "phonepay", "phonepe",
    "googlepay", "truecaller", "icici", "hdfc", "axis", "sbi",
    "amazon", "flipkart", "whatsapp", "google"
];

// URL shortener services (can hide true destination)
const URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "ow.ly", "t.co", "goo.gl",
    "is.gd", "buff.ly", "adf.ly", "shorte.st", "short.cm"
];

// ==================== THREAT SCORING KEYWORDS ====================

// High-risk keyword combinations that indicate scams
const SCAM_COMBINATIONS = {
    "reward-free": 45,
    "cashback-free": 45,
    "reward-claim": 45,
    "bonus-cashback": 45,
    "verify-account": 50,
    "confirm-identity": 50,
    "update-urgent": 40,
    "urgent-verify": 40,
    "claim-reward": 45,
    "limited-time": 35,
    "act-now": 35
};

// ==================== MAIN DETECTION FUNCTION ====================

/**
 * Main function to check if a link is suspicious
 * Performs comprehensive scam analysis
 */
function checkLink() {
    let link = document.getElementById("linkInput").value.trim();
    
    // Validate input
    if (!link) {
        showError("Please enter a URL to check");
        return;
    }
    
    // Convert to lowercase for comparison
    link = link.toLowerCase();
    
    // Calculate threat score
    let threatScore = 0;
    let foundThreats = [];
    let foundKeywords = [];
    
    // STEP 1: Check URL format validity
    if (!isValidUrlFormat(link)) {
        threatScore += 30;
        foundThreats.push("⚠ Invalid URL format (missing http:// or https://)");
    }
    
    // STEP 2: Check for brand spoofing
    let brandSpoofingScore = detectBrandSpoofing(link);
    if (brandSpoofingScore > 0) {
        threatScore += brandSpoofingScore;
        foundThreats.push("🚨 Domain spoofing detected (fake brand prefix)");
    }
    
    // STEP 3: Check for suspicious domain extension
    let extensionScore = checkSuspiciousExtension(link);
    if (extensionScore > 0) {
        threatScore += extensionScore;
        foundThreats.push("⚠ Suspicious domain extension detected");
    }
    
    // STEP 4: Check if URL is from shortener service
    let shortenerScore = detectUrlShortener(link);
    if (shortenerScore > 0) {
        threatScore += shortenerScore;
        foundThreats.push("⚠ URL shortener detected (hides true destination)");
    }
    
    // STEP 5: Check for leetspeak/obfuscation
    if (detectLeetspeak(link)) {
        threatScore += 25;
        foundThreats.push("⚠ Leetspeak/number substitution detected");
    }
    
    // STEP 6: Check for domain obfuscation
    if (detectObfuscation(link)) {
        threatScore += 20;
        foundThreats.push("⚠ Domain obfuscation detected (excessive hyphens)");
    }
    
    // STEP 7: Check for domain spoofing pattern
    if (detectDomainSpoofing(link)) {
        threatScore += 30;
        foundThreats.push("⚠ Domain spoofing pattern detected");
    }
    
    // STEP 8: Check for IP address
    if (detectIPAddress(link)) {
        threatScore += 25;
        foundThreats.push("⚠ IP address used instead of domain");
    }
    
    // STEP 9: Check for suspicious keywords
    let keywordScore = detectSuspiciousKeywords(link);
    if (keywordScore.score > 0) {
        threatScore += keywordScore.score;
        foundKeywords = keywordScore.keywords;
        foundKeywords.forEach(keyword => {
            foundThreats.push(`⚠ Keyword detected: "${keyword}"`);
        });
    }
    
    // STEP 10: Check for keyword combinations
    let combinationScore = detectKeywordCombinations(link);
    if (combinationScore > 0) {
        threatScore += combinationScore;
        foundThreats.push("🚨 High-risk keyword combination detected");
    }
    
    // STEP 11: Check if domain is legitimate (whitelist)
    if (isLegitimateDomaim(link)) {
        threatScore = Math.max(0, threatScore - 50);
        foundThreats = [];
        foundThreats.push("✅ Legitimate domain verified");
    }
    
    // STEP 12: Check for extremely long URLs
    if (link.length > 150) {
        threatScore += 20;
        foundThreats.push("⚠ Extremely long URL (may hide malicious intent)");
    }
    
    // Clamp threat score to 0-100
    threatScore = Math.min(100, Math.max(0, threatScore));
    
    // Generate detailed analysis
    let analysis = generateDetailedAnalysis(link, threatScore, foundThreats, foundKeywords);
    
    // Display results
    displayDetailedResults(analysis);
}

// ==================== DETECTION FUNCTIONS ====================

/**
 * Checks if URL has valid format
 */
function isValidUrlFormat(url) {
    return url.startsWith("http://") || url.startsWith("https://");
}

/**
 * Detects brand spoofing - when domain starts with fake brand names
 * Example: gpay-reward-free.com (fakes Google Pay)
 */
function detectBrandSpoofing(url) {
    // Extract domain part
    let domain = url.split("//")[1]; // Remove protocol
    if (!domain) return 0;
    
    domain = domain.split("/")[0]; // Get only domain
    domain = domain.replace("www.", ""); // Remove www
    
    // Check if starts with fake brand
    for (let brand of FAKE_BRAND_PREFIXES) {
        if (domain.startsWith(brand + "-") || domain.startsWith(brand + ".")) {
            return 40; // High threat score
        }
    }
    
    return 0;
}

/**
 * Checks for suspicious domain extensions
 */
function checkSuspiciousExtension(url) {
    for (let ext of SUSPICIOUS_EXTENSIONS) {
        if (url.includes(ext)) {
            return 25;
        }
    }
    return 0;
}

/**
 * Detects if URL uses shortener services
 */
function detectUrlShortener(url) {
    for (let shortener of URL_SHORTENERS) {
        if (url.includes(shortener)) {
            return 30;
        }
    }
    return 0;
}

/**
 * Detects leetspeak - number substitution like g00gle, p4ytm
 */
function detectLeetspeak(url) {
    // Common leetspeak patterns: 0=o, 1=i/l, 3=e, 4=a, 5=s, 7=t, 8=b, 9=g
    const leetspeakPattern = /[0134578]/g;
    const matches = url.match(leetspeakPattern);
    
    // If multiple numbers found, likely leetspeak
    return matches && matches.length >= 2;
}

/**
 * Detects domain obfuscation - excessive hyphens or dots
 * Example: goo--gl---e--pay.xyz
 */
function detectObfuscation(url) {
    // Check for multiple consecutive hyphens or dots
    if (url.includes("--") || url.includes("...")) {
        return true;
    }
    
    // Check domain part for many hyphens
    let domain = url.split("//")[1].split("/")[0];
    let hyphenCount = (domain.match(/-/g) || []).length;
    
    // More than 3 hyphens in domain is suspicious
    return hyphenCount > 3;
}

/**
 * Detects domain spoofing - fake subdomains
 * Example: google.com.xyz.phishing.top
 */
function detectDomainSpoofing(url) {
    let domain = url.split("//")[1].split("/")[0];
    
    // Check if legitimate domain name appears but not as main domain
    for (let legit of LEGITIMATE_DOMAINS) {
        let legitClean = legit.replace("www.", "");
        
        // If legitimate domain is in URL but not main domain, it's spoofing
        if (domain.includes(legitClean) && !domain.endsWith(legitClean)) {
            return true;
        }
    }
    
    return false;
}

/**
 * Detects if URL uses IP address instead of domain
 * Example: http://192.168.1.1/pay
 */
function detectIPAddress(url) {
    const ipPattern = /\b(\d{1,3}\.){3}\d{1,3}\b/;
    return ipPattern.test(url);
}

/**
 * Detects suspicious keywords and returns score and found keywords
 */
function detectSuspiciousKeywords(url) {
    let score = 0;
    let keywords = [];
    
    for (let keyword of SUSPICIOUS_KEYWORDS) {
        if (url.includes(keyword)) {
            score += 5;
            keywords.push(keyword);
        }
    }
    
    return { score: score, keywords: keywords };
}

/**
 * Detects high-risk keyword combinations
 * Example: "reward" + "free" = scam indicator
 */
function detectKeywordCombinations(url) {
    let score = 0;
    
    for (let combination in SCAM_COMBINATIONS) {
        let [keyword1, keyword2] = combination.split("-");
        
        if (url.includes(keyword1) && url.includes(keyword2)) {
            score += SCAM_COMBINATIONS[combination];
            break; // Only count highest scoring combination
        }
    }
    
    return score;
}

/**
 * Checks if domain is legitimate (whitelist)
 */
function isLegitimateDomaim(url) {
    let domain = url.split("//")[1];
    if (!domain) return false;
    
    domain = domain.split("/")[0];
    domain = domain.replace("www.", "");
    
    for (let legit of LEGITIMATE_DOMAINS) {
        if (domain === legit.replace("www.", "")) {
            return true;
        }
    }
    
    return false;
}

// ==================== ANALYSIS & DISPLAY FUNCTIONS ====================

/**
 * Generates detailed threat analysis report
 */
function generateDetailedAnalysis(url, threatScore, threats, keywords) {
    let riskLevel = getRiskLevel(threatScore);
    let riskColor = getRiskColor(threatScore);
    let recommendation = getRecommendation(threatScore);
    
    return {
        url: url,
        threatScore: threatScore,
        riskLevel: riskLevel,
        riskColor: riskColor,
        threats: threats,
        keywords: keywords,
        recommendation: recommendation
    };
}

/**
 * Determines risk level based on threat score
 */
function getRiskLevel(score) {
    if (score <= 30) return "🟢 LOW RISK";
    if (score <= 50) return "🟡 MEDIUM RISK";
    if (score <= 70) return "🟠 HIGH RISK";
    return "🔴 VERY HIGH RISK";
}

/**
 * Determines color for risk level
 */
function getRiskColor(score) {
    if (score <= 30) return "green";
    if (score <= 50) return "gold";
    if (score <= 70) return "orange";
    return "red";
}

/**
 * Gets safety recommendation based on threat score
 */
function getRecommendation(score) {
    if (score <= 30) {
        return "✅ This link appears safe, but always verify before sharing personal information.";
    } else if (score <= 50) {
        return "⚠ Be cautious! Verify the sender before clicking. Don't enter personal information.";
    } else if (score <= 70) {
        return "🚨 High risk detected! DO NOT click this link. Do not enter any personal information.";
    } else {
        return "🚨 VERY HIGH RISK! This is likely a scam. DO NOT click or share. Report to cybercrime.gov.in";
    }
}

/**
 * Displays detailed results in HTML
 */
function displayDetailedResults(analysis) {
    let resultsDiv = document.getElementById("detailedResults");
    
    // Calculate progress bar width
    let progressWidth = analysis.threatScore;
    
    // Build threat list
    let threatsList = analysis.threats
        .map(threat => `<li>${threat}</li>`)
        .join("");
    
    // Build keywords list
    let keywordsList = analysis.keywords.length > 0
        ? analysis.keywords.map(kw => `<span class="keyword-badge">${kw}</span>`).join("")
        : "<span style='color: #888;'>No suspicious keywords found</span>";
    
    // Generate HTML
    let html = `
        <div class="result-container" style="border-left: 5px solid ${analysis.riskColor};">
            <div class="result-header">
                <h3>Analysis Results</h3>
            </div>
            
            <div class="result-item">
                <strong>URL Checked:</strong>
                <span class="url-display">${analysis.url}</span>
            </div>
            
            <div class="result-item">
                <strong>Risk Level:</strong>
                <span class="risk-level" style="color: ${analysis.riskColor}; font-weight: bold;">
                    ${analysis.riskLevel}
                </span>
            </div>
            
            <div class="result-item">
                <strong>Threat Score:</strong>
                <div class="threat-score-container">
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: ${progressWidth}%; background-color: ${analysis.riskColor};">
                            ${analysis.threatScore}/100
                        </div>
                    </div>
                </div>
            </div>
            
            ${analysis.threats.length > 0 ? `
                <div class="result-item">
                    <strong>🚨 Threats Detected:</strong>
                    <ul class="threats-list">
                        ${threatsList}
                    </ul>
                </div>
            ` : ""}
            
            ${analysis.keywords.length > 0 ? `
                <div class="result-item">
                    <strong>🔍 Found Keywords:</strong>
                    <div class="keywords-container">
                        ${keywordsList}
                    </div>
                </div>
            ` : ""}
            
            <div class="result-item recommendation">
                <strong>💡 Recommendation:</strong>
                <p>${analysis.recommendation}</p>
            </div>
            
            <div class="result-item safety-tips">
                <strong>🛡 Safety Tips:</strong>
                <ul>
                    <li>Never enter UPI PIN on any website</li>
                    <li>Official apps never send payment links via SMS/Email</li>
                    <li>Always verify sender identity</li>
                    <li>When in doubt, call the organization directly</li>
                    <li>Report scams to: 1930 (Cyber Crime Helpline)</li>
                    <li>Visit: cybercrime.gov.in for more info</li>
                </ul>
            </div>
        </div>
    `;
    
    // Display results
    resultsDiv.innerHTML = html;
    resultsDiv.style.display = "block";
    
    // Scroll to results
    resultsDiv.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

/**
 * Shows error message
 */
function showError(message) {
    let resultsDiv = document.getElementById("detailedResults");
    resultsDiv.innerHTML = `
        <div class="error-message">
            <strong>⚠ Error:</strong> ${message}
        </div>
    `;
    resultsDiv.style.display = "block";
}

// ==================== QUIZ FUNCTIONS ====================

/**
 * Correct answer for quiz
 */
function correct() {
    document.getElementById("quizResult").innerHTML =
        "✅ Correct! UPI PIN should only be entered inside official apps, never on websites.";
    document.getElementById("quizResult").style.color = "green";
    document.getElementById("quizResult").style.fontWeight = "bold";
}

/**
 * Wrong answer for quiz
 */
function wrong() {
    document.getElementById("quizResult").innerHTML =
        "❌ Wrong! Never enter your UPI PIN on websites. Always use official apps only.";
    document.getElementById("quizResult").style.color = "red";
    document.getElementById("quizResult").style.fontWeight = "bold";
}

// ==================== INITIALIZATION ====================

/**
 * Clear results when page loads
 */
document.addEventListener("DOMContentLoaded", function() {
    let resultsDiv = document.getElementById("detailedResults");
    if (resultsDiv) {
        resultsDiv.style.display = "none";
    }
});