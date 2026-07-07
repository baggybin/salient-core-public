"""Overlay clean text onto Atlas-generated diagram bases (v4).

Pipeline (see docs/IMAGES.md):
  1. Generate base image — Nano Banana Pro Ultra (hero + social) and
     Seedream v4.5 (without-kernel) on Atlas Cloud.
  2. Resize base to working size: 2400-wide hero, 1600x900 social,
     1280x1280 without-kernel.
  3. Run this script to overlay clean text and paint over any stray
     model-rendered labels.

v4 palette: dark navy background (#02101F) sampled from the Nano
Banana bases. Title and tagline use the bright cyan the model paints
for the bus glow.

v4 adjustments from v3:
  - Palette updated to match the Nano Banana / Seedream v4.5 bases
    (darker background, brighter cyan).
  - social overlay uses brighter title color and lighter URL color so
    it reads on the near-black base.
"""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent

PROP_BOLD = "/usr/share/fonts/noto/NotoSans-Bold.ttf"
PROP_REG = "/usr/share/fonts/noto/NotoSans-Regular.ttf"
MONO = "/usr/share/fonts/noto/NotoSansMono-Regular.ttf"

SLATE_900 = (15, 23, 42)
SLATE_700 = (51, 65, 85)
SLATE_500 = (100, 116, 139)
SLATE_200 = (226, 232, 240)
BLUE_500 = (59, 130, 246)
BLUE_700 = (29, 78, 216)
EMERALD_500 = (16, 185, 129)
EMERALD_700 = (4, 120, 87)
WHITE = (255, 255, 255)

# Palette sampled from imgs/hero-bus.jpg (Nano Banana Pro Ultra).
NAVY_BG = (2, 16, 31)           # #02101F — background
NAVY_SHADOW = (15, 38, 65)     # mid-navy for secondary text
CYAN = (68, 245, 255)          # #44F5FF — bus glow / accent
CYAN_BRIGHT = (180, 250, 255)  # lighter cyan for headings
CYAN_DEEP = (24, 60, 88)       # deeper cyan for subdued text


def text_width(font: ImageFont.FreeTypeFont, text: str) -> int:
    bbox = font.getbbox(text)
    return bbox[2] - bbox[0]


def overlay_social_preview(
    src: Path,
    dst: Path,
    title: str = "salient-core",
    tagline: str = "a multi-agent coordination kernel",
    license_: str = "Apache-2.0",
    url: str = "github.com/baggybin/salient-core",
) -> None:
    img = Image.open(src).convert("RGB")
    W, H = img.size
    draw = ImageDraw.Draw(img)
    # The model-rendered base has the bus + nodes on the right; we put the
    # text on the LEFT so the eye reads left-to-right (title -> tagline ->
    # chip -> url) with the bus as the visual anchor on the right.
    left_x = int(W * 0.06)

    f_title = ImageFont.truetype(PROP_BOLD, int(H * 0.13))
    f_tag = ImageFont.truetype(PROP_REG, int(H * 0.045))
    f_chip = ImageFont.truetype(MONO, int(H * 0.038))
    f_url = ImageFont.truetype(MONO, int(H * 0.038))

    # Title
    draw.text((left_x, int(H * 0.32)), title, font=f_title, fill=CYAN_BRIGHT)
    # Tagline
    draw.text((left_x, int(H * 0.50)), tagline, font=f_tag, fill=CYAN)
    # Apache chip
    chip_text = f" {license_} "
    cw = text_width(f_chip, chip_text)
    chip_y = int(H * 0.62)
    draw.rounded_rectangle(
        (left_x - 4, chip_y - 4, left_x + cw + 4, chip_y + int(H * 0.06) + 4),
        radius=12,
        fill=CYAN,
    )
    draw.text((left_x, chip_y), chip_text, font=f_chip, fill=NAVY_BG)
    # URL
    draw.text((left_x, int(H * 0.74)), url, font=f_url, fill=NAVY_SHADOW)
    img.save(dst, "JPEG", quality=92)


def overlay_without_kernel(src: Path, dst: Path) -> None:
    img = Image.open(src).convert("RGB")
    W, H = img.size
    draw = ImageDraw.Draw(img)
    # Sized for a 1280x1280 base; scales with H.
    f_h = ImageFont.truetype(PROP_BOLD, int(H * 0.038))
    f_cap = ImageFont.truetype(PROP_REG, int(H * 0.022))

    # Panels split by vertical divider near x=W/2. The headers sit in
    # the upper margin (dark navy + decorative PCB); the captions sit in
    # the lower margin (same). Paint the model-rendered labels in those
    # margins with the dark background, then draw bright text.
    top_band_y0 = int(H * 0.02)
    top_band_y1 = int(H * 0.10)
    bot_band_y0 = int(H * 0.88)
    bot_band_y1 = int(H * 0.98)
    draw.rectangle((0, top_band_y0, W, top_band_y1), fill=NAVY_BG)
    draw.rectangle((0, bot_band_y0, W, bot_band_y1), fill=NAVY_BG)
    # Re-stroke the vertical divider through the bands so the two panels
    # still read as separated in the margins.
    divider_x = W // 2
    draw.rectangle((divider_x - 1, top_band_y0, divider_x + 1, top_band_y1),
                   fill=CYAN_DEEP)
    draw.rectangle((divider_x - 1, bot_band_y0, divider_x + 1, bot_band_y1),
                   fill=CYAN_DEEP)

    # Headers — center over each panel half. Mixed case + smaller font
    # keeps them inside their panel without colliding at the divider.
    cx_l = divider_x // 2
    cx_r = divider_x + (W - divider_x) // 2
    head_y = top_band_y0 + int((top_band_y1 - top_band_y0) * 0.27)
    head_l = "without coordination"
    head_r = "with salient-core"
    draw.text((cx_l - text_width(f_h, head_l) // 2, head_y),
              head_l, font=f_h, fill=WHITE)
    draw.text((cx_r - text_width(f_h, head_r) // 2, head_y),
              head_r, font=f_h, fill=CYAN_BRIGHT)

    # Captions — mid-tone, slightly brighter than NAVY_SHADOW so they
    # actually read on the dark band.
    cap_l = "cycles, stalls, leaked intent"
    cap_r = "typed bus + cycle detection + gates"
    cap_y = bot_band_y0 + int((bot_band_y1 - bot_band_y0) * 0.30)
    cap_color = (110, 145, 175)
    draw.text((cx_l - text_width(f_cap, cap_l) // 2, cap_y),
              cap_l, font=f_cap, fill=cap_color)
    draw.text((cx_r - text_width(f_cap, cap_r) // 2, cap_y),
              cap_r, font=f_cap, fill=cap_color)
    img.save(dst, "PNG", optimize=True)


def main() -> None:
    overlay_social_preview(
        ROOT / "social-base_1600.jpeg",
        ROOT / "social-preview.jpg",
    )
    overlay_without_kernel(
        ROOT / "without-kernel-wider_1600.jpeg",
        ROOT / "without-kernel-comparison.png",
    )
    print("Done.")


if __name__ == "__main__":
    main()
