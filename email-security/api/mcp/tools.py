"""
MCP Tools for Email Security Analysis

These tools can be used by MCP-compatible agents to analyze email threats.
"""

import re
from urllib.parse import urlparse
from dataclasses import dataclass


@dataclass
class ToolResult:
    """Result from an MCP tool execution."""
    success: bool
    data: dict
    message: str


class EmailSecurityTools:
    """Collection of MCP tools for email security analysis."""

    @staticmethod
    def check_sender_reputation(sender_email: str) -> ToolResult:
        """
        Analyze sender email address for reputation indicators.

        Args:
            sender_email: The sender's email address

        Returns:
            ToolResult with reputation analysis
        """
        indicators = []
        risk_score = 0.0

        # Extract domain
        try:
            domain = sender_email.split("@")[1].lower()
        except IndexError:
            return ToolResult(
                success=False,
                data={},
                message="Invalid email address format",
            )

        # Check for free email providers (not inherently bad but noteworthy)
        free_providers = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"]
        if domain in free_providers:
            indicators.append({
                "type": "info",
                "message": f"Free email provider: {domain}",
            })

        # Check for suspicious TLDs
        suspicious_tlds = [".xyz", ".top", ".click", ".loan", ".work", ".gq", ".ml", ".tk", ".cf"]
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                risk_score += 0.3
                indicators.append({
                    "type": "warning",
                    "message": f"High-risk TLD: {tld}",
                })
                break

        # Check for typosquatting of known brands
        brand_patterns = {
            "paypal": r"paypa[l1i]|payp[a@]l",
            "amazon": r"amaz[o0]n|amzon|amazn",
            "google": r"g[o0]{2}gle|googl[e3]|go0gle",
            "microsoft": r"micr[o0]s[o0]ft|mircosoft|microsft",
            "apple": r"app[l1]e|aple|applle",
        }

        for brand, pattern in brand_patterns.items():
            if re.search(pattern, domain) and brand not in domain:
                risk_score += 0.5
                indicators.append({
                    "type": "danger",
                    "message": f"Possible typosquatting of {brand}",
                })

        # Check domain age (simulated - in production would use WHOIS)
        newly_registered_keywords = ["temp", "new", "fresh", "instant"]
        if any(kw in domain for kw in newly_registered_keywords):
            risk_score += 0.2
            indicators.append({
                "type": "warning",
                "message": "Domain name suggests newly registered",
            })

        return ToolResult(
            success=True,
            data={
                "sender": sender_email,
                "domain": domain,
                "risk_score": min(risk_score, 1.0),
                "indicators": indicators,
            },
            message=f"Analyzed sender reputation: risk_score={min(risk_score, 1.0):.2f}",
        )

    @staticmethod
    def analyze_headers(headers: dict) -> ToolResult:
        """
        Analyze email headers for spoofing and authentication issues.

        Args:
            headers: Dictionary of email headers

        Returns:
            ToolResult with header analysis
        """
        findings = []
        risk_score = 0.0

        # Check Authentication-Results
        auth_results = headers.get("Authentication-Results", "").lower()
        if auth_results:
            if "spf=fail" in auth_results or "spf=softfail" in auth_results:
                risk_score += 0.3
                findings.append({
                    "type": "danger",
                    "header": "SPF",
                    "message": "SPF authentication failed",
                })
            elif "spf=pass" in auth_results:
                findings.append({
                    "type": "success",
                    "header": "SPF",
                    "message": "SPF authentication passed",
                })

            if "dkim=fail" in auth_results:
                risk_score += 0.3
                findings.append({
                    "type": "danger",
                    "header": "DKIM",
                    "message": "DKIM signature invalid",
                })
            elif "dkim=pass" in auth_results:
                findings.append({
                    "type": "success",
                    "header": "DKIM",
                    "message": "DKIM signature valid",
                })

            if "dmarc=fail" in auth_results:
                risk_score += 0.4
                findings.append({
                    "type": "danger",
                    "header": "DMARC",
                    "message": "DMARC policy failed",
                })

        # Check for header mismatches
        from_header = headers.get("From", "")
        reply_to = headers.get("Reply-To", "")
        if from_header and reply_to and from_header.lower() != reply_to.lower():
            # Extract domains
            try:
                from_domain = from_header.split("@")[1].split(">")[0].lower()
                reply_domain = reply_to.split("@")[1].split(">")[0].lower()
                if from_domain != reply_domain:
                    risk_score += 0.3
                    findings.append({
                        "type": "warning",
                        "header": "Reply-To",
                        "message": f"Reply-To domain ({reply_domain}) differs from From ({from_domain})",
                    })
            except IndexError:
                pass

        # Check X-Originating-IP
        originating_ip = headers.get("X-Originating-IP", "")
        if originating_ip:
            findings.append({
                "type": "info",
                "header": "X-Originating-IP",
                "message": f"Originating IP: {originating_ip}",
            })

        # Check Received headers for suspicious relays
        received = headers.get("Received", "")
        if "localhost" in received.lower() or "127.0.0.1" in received:
            findings.append({
                "type": "info",
                "header": "Received",
                "message": "Email relayed through localhost",
            })

        return ToolResult(
            success=True,
            data={
                "risk_score": min(risk_score, 1.0),
                "findings": findings,
                "headers_checked": len(headers),
            },
            message=f"Analyzed {len(headers)} headers: risk_score={min(risk_score, 1.0):.2f}",
        )

    @staticmethod
    def scan_urls(body: str) -> ToolResult:
        """
        Extract and analyze URLs from email body.

        Args:
            body: Email body text

        Returns:
            ToolResult with URL analysis
        """
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, body)

        if not urls:
            return ToolResult(
                success=True,
                data={"urls": [], "risk_score": 0.0},
                message="No URLs found in email body",
            )

        analyzed_urls = []
        max_risk = 0.0

        for url in urls[:10]:  # Limit to first 10 URLs
            parsed = urlparse(url)
            url_risk = 0.0
            indicators = []

            # Check for IP address
            if re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc):
                url_risk += 0.4
                indicators.append("Uses IP address instead of domain")

            # Check for URL shorteners
            shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly"]
            if parsed.netloc.lower() in shorteners:
                url_risk += 0.3
                indicators.append("URL shortener detected")

            # Check for suspicious TLDs
            suspicious_tlds = [".xyz", ".top", ".click", ".loan", ".work"]
            for tld in suspicious_tlds:
                if parsed.netloc.lower().endswith(tld):
                    url_risk += 0.2
                    indicators.append(f"Suspicious TLD: {tld}")
                    break

            # Check for suspicious path patterns
            suspicious_paths = ["/login", "/signin", "/verify", "/secure", "/update", "/confirm"]
            for path in suspicious_paths:
                if path in parsed.path.lower():
                    url_risk += 0.2
                    indicators.append(f"Suspicious path: {path}")
                    break

            # Check for data exfil patterns in query
            if parsed.query and ("email=" in parsed.query or "user=" in parsed.query):
                url_risk += 0.3
                indicators.append("Query contains user data fields")

            max_risk = max(max_risk, url_risk)
            analyzed_urls.append({
                "url": url[:100],
                "domain": parsed.netloc,
                "risk_score": min(url_risk, 1.0),
                "indicators": indicators,
            })

        return ToolResult(
            success=True,
            data={
                "urls": analyzed_urls,
                "total_urls": len(urls),
                "risk_score": min(max_risk, 1.0),
            },
            message=f"Analyzed {len(analyzed_urls)} URLs: max_risk={min(max_risk, 1.0):.2f}",
        )

    @staticmethod
    def check_attachments(attachments: list[dict]) -> ToolResult:
        """
        Analyze email attachments for potential threats.

        Args:
            attachments: List of attachment dicts with 'filename' and 'content_type'

        Returns:
            ToolResult with attachment analysis
        """
        if not attachments:
            return ToolResult(
                success=True,
                data={"attachments": [], "risk_score": 0.0},
                message="No attachments to analyze",
            )

        # Dangerous extensions
        dangerous_extensions = {
            ".exe": 1.0, ".scr": 1.0, ".bat": 0.9, ".cmd": 0.9,
            ".com": 0.9, ".pif": 1.0, ".vbs": 0.9, ".js": 0.8,
            ".jar": 0.8, ".msi": 0.8, ".ps1": 0.9, ".hta": 0.9,
            ".wsf": 0.8, ".lnk": 0.7,
        }

        # Suspicious but not always dangerous
        suspicious_extensions = {
            ".zip": 0.3, ".rar": 0.3, ".7z": 0.3,
            ".doc": 0.2, ".docm": 0.5, ".xlsm": 0.5,
            ".iso": 0.4, ".img": 0.4,
        }

        analyzed = []
        max_risk = 0.0

        for att in attachments:
            filename = att.get("filename", "unknown").lower()
            content_type = att.get("content_type", "")
            risk = 0.0
            indicators = []

            # Check extension
            for ext, ext_risk in dangerous_extensions.items():
                if filename.endswith(ext):
                    risk = max(risk, ext_risk)
                    indicators.append(f"Dangerous extension: {ext}")
                    break

            if not indicators:
                for ext, ext_risk in suspicious_extensions.items():
                    if filename.endswith(ext):
                        risk = max(risk, ext_risk)
                        indicators.append(f"Potentially suspicious extension: {ext}")
                        break

            # Check for double extensions
            double_ext_pattern = r'\.[a-z]{2,4}\.(exe|scr|bat|cmd|js|vbs|jar)$'
            if re.search(double_ext_pattern, filename):
                risk = 1.0
                indicators.append("Double extension detected (malware obfuscation)")

            # Check content type mismatches
            if content_type:
                if "executable" in content_type.lower() or "x-msdownload" in content_type.lower():
                    risk = max(risk, 0.9)
                    indicators.append(f"Executable content type: {content_type}")

            max_risk = max(max_risk, risk)
            analyzed.append({
                "filename": att.get("filename", "unknown"),
                "content_type": content_type,
                "risk_score": risk,
                "indicators": indicators,
            })

        return ToolResult(
            success=True,
            data={
                "attachments": analyzed,
                "total_attachments": len(attachments),
                "risk_score": max_risk,
            },
            message=f"Analyzed {len(analyzed)} attachments: max_risk={max_risk:.2f}",
        )

    @staticmethod
    def detect_social_engineering(subject: str, body: str) -> ToolResult:
        """
        Detect social engineering tactics in email content.

        Args:
            subject: Email subject line
            body: Email body text

        Returns:
            ToolResult with social engineering analysis
        """
        tactics = []
        risk_score = 0.0
        combined_text = f"{subject} {body}".lower()

        # Urgency tactics
        urgency_patterns = [
            (r"urgent|immediate|asap|right away", "Urgency pressure"),
            (r"expires? (today|soon|in \d+)", "Time-limited pressure"),
            (r"act now|don't wait|limited time", "Call to immediate action"),
            (r"final (notice|warning|reminder)", "Final notice pressure"),
        ]

        for pattern, tactic in urgency_patterns:
            if re.search(pattern, combined_text):
                risk_score += 0.2
                tactics.append({
                    "category": "urgency",
                    "tactic": tactic,
                    "severity": "medium",
                })

        # Authority tactics
        authority_patterns = [
            (r"(ceo|cfo|director|manager|boss) (asked|requested|needs)", "Authority impersonation"),
            (r"(legal|compliance|hr|it) department", "Department authority"),
            (r"official notice|legal action|lawsuit", "Legal threat"),
            (r"(police|fbi|irs|government)", "Government impersonation"),
        ]

        for pattern, tactic in authority_patterns:
            if re.search(pattern, combined_text):
                risk_score += 0.25
                tactics.append({
                    "category": "authority",
                    "tactic": tactic,
                    "severity": "high",
                })

        # Fear tactics
        fear_patterns = [
            (r"account (suspended|locked|terminated|compromised)", "Account threat"),
            (r"unauthorized (access|activity|transaction)", "Unauthorized activity fear"),
            (r"security (breach|alert|warning)", "Security fear"),
            (r"identity (theft|stolen)", "Identity theft fear"),
        ]

        for pattern, tactic in fear_patterns:
            if re.search(pattern, combined_text):
                risk_score += 0.25
                tactics.append({
                    "category": "fear",
                    "tactic": tactic,
                    "severity": "high",
                })

        # Reward/greed tactics
        reward_patterns = [
            (r"(won|winner|winning|prize|reward)", "Prize/reward bait"),
            (r"free (gift|money|offer)", "Free offer bait"),
            (r"(lottery|inheritance|million)", "Financial windfall"),
            (r"exclusive (offer|deal|opportunity)", "Exclusive opportunity"),
        ]

        for pattern, tactic in reward_patterns:
            if re.search(pattern, combined_text):
                risk_score += 0.2
                tactics.append({
                    "category": "greed",
                    "tactic": tactic,
                    "severity": "medium",
                })

        # Curiosity tactics
        curiosity_patterns = [
            (r"you won't believe", "Curiosity bait"),
            (r"see (attached|photo|document)", "Attachment curiosity"),
            (r"check this out|look at this", "Link curiosity"),
        ]

        for pattern, tactic in curiosity_patterns:
            if re.search(pattern, combined_text):
                risk_score += 0.15
                tactics.append({
                    "category": "curiosity",
                    "tactic": tactic,
                    "severity": "low",
                })

        return ToolResult(
            success=True,
            data={
                "tactics_detected": tactics,
                "total_tactics": len(tactics),
                "risk_score": min(risk_score, 1.0),
                "categories": list(set(t["category"] for t in tactics)),
            },
            message=f"Detected {len(tactics)} social engineering tactics: risk_score={min(risk_score, 1.0):.2f}",
        )
