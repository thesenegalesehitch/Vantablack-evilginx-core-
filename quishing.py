#!/usr/bin/env python3
"""
Vantablack Quishing Generator
=============================
Génération de QR codes de phishing (quishing) pour engagements Red Team
autorisés : payload malveillant, logo embarqué, texte d'appât.

Utilisable :
  - En CLI   : python quishing.py --url https:// phishing.host/login --out attack.png
  - En lib   : from quishing import QuishingGenerator
"""
from __future__ import annotations

import argparse
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

import qrcode
from PIL import Image, ImageDraw, ImageFont

# Colors
RED = '\033[91m'
GREEN = '\033[92m'
RESET = '\033[0m'

class QuishingGenerator:
    """Générateur de QR codes de phishing (interface objet pour l'orchestrateur).

    Chaque ``generate()`` produit un PNG dans le dossier de sortie et
    retourne un dict sérialisable (chemin, URL encodée, métadonnées).
    En cas d'absence des libs natives (qrcode/PIL), retourne un résultat
    dégradé ``success=False`` au lieu de lever une exception — l'orchestrateur
    godmode continue sa campagne.
    """

    def __init__(self, output_dir: str = "captures/quishing") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        url: str,
        scale: int = 10,
        output_file: Optional[str] = None,
        logo_path: Optional[str] = None,
        text: str = "SCAN TO VERIFY IDENTITY",
    ) -> Dict[str, Any]:
        """Génère le PNG du QR code et retourne ses métadonnées."""
        payload_id = str(uuid.uuid4())[:8]
        fname = output_file or f"quishing_{payload_id}_{int(time.time())}.png"
        out_path = self.output_dir / fname
        try:
            generate_quishing_payload(
                url,
                output_file=str(out_path),
                logo_path=logo_path,
                text=text,
                box_size=max(2, int(scale)),
                quiet=True,
            )
            return {
                "success": True,
                "payload_id": payload_id,
                "path": str(out_path),
                "url": url,
                "scale": scale,
            }
        except Exception as exc:  # noqa: BLE001 — dégradé, jamais bloquant
            return {
                "success": False,
                "payload_id": payload_id,
                "path": str(out_path),
                "url": url,
                "error": f"{type(exc).__name__}: {exc}",
            }


def generate_quishing_payload(url, output_file="attack.png", logo_path=None,
                              text="SCAN TO VERIFY IDENTITY", box_size=10,
                              quiet=False):
    """
    Generate a malicious QR Code (Quishing)
    """
    if not quiet:
        print(f"{GREEN}[*] Generating Quishing Payload for: {url}{RESET}")
    
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=box_size,
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
        
    text_bbox = draw.textbbox((0, 0), text, font=font)
    text_width = text_bbox[2] - text_bbox[0]
    draw.text(((width - text_width) / 2, height + 10), text, fill="black", font=font)
    
    final_img.save(output_file)
    if not quiet:
        print(f"{GREEN}[SUCCESS] Payload saved to: {output_file}{RESET}")
        print(f"{RED}[!] WARNING: Use only for authorized Red Team engagements.{RESET}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vantablack Quishing Generator")
    parser.add_argument("--url", required=True, help="Target Phishing URL")
    parser.add_argument("--out", default="payload_qr.png", help="Output filename")
    
    args = parser.parse_args()
    
    generate_quishing_payload(args.url, args.out)
