#!/usr/bin/env python3
import sys
import qrcode
import argparse
import os
from PIL import Image, ImageDraw, ImageFont

# Colors
RED = '\033[91m'
GREEN = '\033[92m'
RESET = '\033[0m'

def generate_quishing_payload(url, output_file="attack.png", logo_path=None):
    """
    Generate a malicious QR Code (Quishing)
    """
    print(f"{GREEN}[*] Generating Quishing Payload for: {url}{RESET}")
    
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4,
    )
    qr.add_data(url)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white").convert('RGB')
    
    # Add logo if provided
    if logo_path and os.path.exists(logo_path):
        logo = Image.open(logo_path)
        logo_size = 50
        logo = logo.resize((logo_size, logo_size))
        pos = ((img.size[0] - logo_size) // 2, (img.size[1] - logo_size) // 2)
        img.paste(logo, pos)
        print(f"{GREEN}[+] Logo embedded.{RESET}")

    # Add deceptive text below
    width, height = img.size
    new_height = height + 50
    final_img = Image.new('RGB', (width, new_height), 'white')
    final_img.paste(img, (0, 0))
    
    draw = ImageDraw.Draw(final_img)
    try:
        # Default font
        font = ImageFont.load_default()
    except:
        font = None
        
    text = "SCAN TO VERIFY IDENTITY"
    text_bbox = draw.textbbox((0, 0), text, font=font)
    text_width = text_bbox[2] - text_bbox[0]
    draw.text(((width - text_width) / 2, height + 10), text, fill="black", font=font)
    
    final_img.save(output_file)
    print(f"{GREEN}[SUCCESS] Payload saved to: {output_file}{RESET}")
    print(f"{RED}[!] WARNING: Use only for authorized Red Team engagements.{RESET}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vantablack Quishing Generator")
    parser.add_argument("--url", required=True, help="Target Phishing URL")
    parser.add_argument("--out", default="payload_qr.png", help="Output filename")
    
    args = parser.parse_args()
    
    generate_quishing_payload(args.url, args.out)
