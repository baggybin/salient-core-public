# README images — how they were made

A short note on the three generated images in `imgs/` — `hero-bus.jpg`,
`social-preview.jpg`, and `without-kernel-comparison.png` — so future
regeneration is reproducible.

## Pipeline

Two Atlas Cloud models, both at the 90% discount:

| Model | Used for | Cost |
| --- | --- | --- |
| `google/nano-banana-pro/text-to-image-ultra` | hero + social base | ~$0.15/req |
| `bytedance/seedream-v4.5` | without-kernel base | ~$0.0036/req |

**Nano Banana Pro Ultra** won the head-to-head against Seedream v4.5
and FLUX.2 Pro for this aesthetic: it nailed the dark-navy + glowing
neon-edged glass bus + PCB trace + monospace-data-readout look, kept
the agent labels in order (`agent-1` through `agent-8`), and produced
clean dark space on the left for the social overlay. Seedream v4.5
got hex color literals (`34d399`, `fbbf24`, ...) into the agent
labels on the first try, and FLUX.2 Pro's output was simpler (no PCB
traces, no data readouts, no shield). Seedream v4.5 was the better
fit for the without-kernel comparison though — its panels came out
with crisp neon-edged frames around the two sides (red on left,
cyan on right), which Nano Banana missed.

Flow:

1. Submit with `atlas_generate_image`. Full prompt per image below.
2. Poll `atlas_get_prediction` until `status == "completed"`.
3. Resize the 4K/2K raw output down with Pillow
   (`Image.LANCZOS`, JPEG `quality=92`, `optimize=True`).
4. Run `imgs/_overlay.py` for `social-preview.jpg` and
   `without-kernel-comparison.png`. The overlay paints clean Noto
   Sans text and occludes any stray model-rendered labels using
   palette tokens matched to the Nano Banana bases (`NAVY_BG`,
   `CYAN`, `CYAN_BRIGHT`, `NAVY_SHADOW` in `imgs/_overlay.py`).
   The hero has no text overlay — it's final after resize.

## Palette

Sampled from `imgs/hero-bus.jpg` (Nano Banana Pro Ultra). The dark
navy is much darker than the Seedream v5 Lite originals (which were
sampled at `#191f35`); the new background is `#02101F`.

| token            | hex       | used for                                  |
| ---------------- | --------- | ----------------------------------------- |
| `NAVY_BG`        | `#02101F` | hero / social background; band paint-over |
| `NAVY_SHADOW`    | `#0F2641` | secondary text                            |
| `CYAN`           | `#44F5FF` | bus glow, agent nodes, chip accent        |
| `CYAN_BRIGHT`    | `#B4FAFF` | hero / social title                       |
| `CYAN_DEEP`      | `#183C58` | mid-tone cyan accents                     |

## Prompts

Three prompts, reproduced verbatim from the Atlas submissions used
to produce the current images.

### `hero-bus.jpg`

Model: Nano Banana Pro Ultra, 16:9, 4K.

```
A cinematic 16:9 hero banner for a software project called
"salient-core" — a high-tech neural-interconnect visualization.
Style: dark futuristic technical illustration with glowing neon
panels, clean vector aesthetic, no photographic content, no
characters, no people, no AI-style imagery.

Background: very dark navy gradient (#0a1220 fading to #0d1b2a) with
a thin subtle grid pattern in faint cyan (#1a3a5a). Soft volumetric
cyan glow accents.

Center composition: a single horizontal glowing data bus / pipeline
rendered as a frosted-glass neon-edged rectangular tube. Outer glow:
bright cyan #22d3ee. Inner glass: dark with subtle gradient from
#0a2030 to #103050. The bus runs across the middle of the frame,
occupying about 70% of the width, with rounded ends and a bright cyan
rim-light along its top and bottom edges.

On top of the bus, evenly spaced along its length, sit 8 small agent
node panels — each a tiny rounded rectangle with a glowing neon
border (varied colors: cyan, mint green #34d399, soft amber #fbbf24,
dusty rose #f472b6, sky blue #38bdf8, violet #a78bfa), each labeled
with crisp white sans-serif text "agent-1" through "agent-8". Thin
glowing connector lines drop from each agent down into the bus, with
small bright dots where they intersect the bus surface.

Beneath the bus: a faint knowledge graph — thin lines and small
nodes in muted blue (#3b82f6 at 30% opacity), forming a delicate
web. Do not draw any text inside the graph.

Around the edges of the canvas: thin PCB / circuit-board traces in
dim cyan, with small data readout labels in dim gray (#475569)
reading things like "BUS_MCP_v2", "0x4A2F", "AGENT_CTX", tiny
numeric readouts, monospace font, very subtle so they read as
decoration rather than content. A tiny wordmark "salient-core" in
crisp white sans-serif in the top-left corner, small caps. A tiny
tagline "a multi-agent coordination kernel" in dim cyan directly
beneath it.

Bottom-right corner: a small glowing cyan shield icon with a check
mark inside, suggesting a policy gate. Soft outer glow on the shield.

No other text, no URLs, no captions, no watermarks, no stock
imagery, no icons beyond the agent nodes and shield. Crisp
typography, vector aesthetic, dark and moody but readable,
professional software product hero.
```

Post-process: resize to 2400×~1340, save JPEG `quality=92`. No
text overlay — the wordmark, tagline, agent labels, and decorative
labels are all rendered by the model.

### `social-preview.jpg` — base

Model: Nano Banana Pro Ultra, 16:9, 4K.

```
A 16:9 social-card background for a software project. Style: dark
futuristic technical illustration with glowing neon panels, clean
vector aesthetic, no photographic content, no characters, no people,
no AI-style imagery.

Background: very dark navy gradient (#0a1220 to #0d1b2a) with a
thin subtle grid pattern in faint cyan (#1a3a5a). Soft volumetric
cyan glow accents.

Composition: a single horizontal glowing data bus / pipeline
rendered as a frosted-glass neon-edged rectangular tube. Outer glow:
bright cyan #22d3ee. Inner glass: dark with subtle gradient. The bus
is positioned in the RIGHT-CENTER of the frame, occupying about
50-55% of the canvas WIDTH (NOT extending to the right edge — leave
at least 5% margin from the right edge), and is positioned in the
LOWER half (vertical center around 55-60% from top). It is moderately
sized — about 12% of canvas height.

On top of the bus, evenly spaced along its length, sit 6 small agent
node panels — each a tiny rounded rectangle with a glowing neon
border in a distinct color (cyan, mint green #34d399, soft amber
#fbbf24, dusty rose #f472b6, sky blue #38bdf8, violet #a78bfa). Thin
glowing connector lines drop from each agent down into the bus.

The LEFT 45-50% of the frame and the entire upper half should be
deliberately left mostly empty / darker — a clean dark navy area
with only faint glow, thin PCB traces in dim cyan, and very subtle
small monospace data readout labels in dim gray (#475569) reading
things like "0x4A2F", "BUS_MCP_v2", "AGENT_CTX" — purely decorative.
This space is reserved for text overlay later.

Beneath the bus: a faint knowledge graph web of thin lines and small
nodes in muted blue (#3b82f6 at 30% opacity).

Around the edges of the canvas: thin PCB / circuit-board traces in
dim cyan, forming subtle frame corners. Very subtle small monospace
data readouts in the margins. Bottom-right corner (still in the bus
zone): a small glowing cyan shield icon with a check mark inside.

No people, no icons beyond the agent nodes and shield. Crisp
professional software product aesthetic, dark and moody but
readable.
```

Post-process: resize to 1600×~894, then run
`overlay_social_preview` to paint title / tagline / `Apache-2.0`
chip / URL on the left. The overlay positions everything relative
to image height, so the result renders identically at any base
size.

### `without-kernel-comparison.png` — base

Model: Seedream v4.5, 4096×4096.

```
A side-by-side comparison diagram with two square panels. Style:
dark futuristic technical illustration with glowing neon panels,
clean vector aesthetic, no photographic content, no characters, no
people, no AI-style imagery.

Background: very dark navy gradient (#0a1220 to #0d1b2a) with a
thin subtle grid pattern in faint cyan (#1a3a5a). Soft volumetric
glow accents.

Two equal panels side-by-side, each filling half the canvas
horizontally, separated by a thin vertical glowing cyan divider line
(#22d3ee at 60% opacity).

LEFT PANEL ("chaotic"): a tangled mess of curved arrows forming
cycles and feedback loops. Many small rounded-rectangle nodes
scattered around in red (#ef4444) and dusty orange (#f97316), with
overlapping arrows going in multiple directions, some crossing each
other, several arrows visibly trapped in loops. Color accents: muted
red, dusty orange. Small decorative "stall" symbols — tiny clock
icons drawn as simple circles with a hand, glowing red — at 2 or 3
nodes. Subtle red glow emanating from the panel. Faint PCB traces in
dim red around the panel edges.

RIGHT PANEL ("ordered"): a clean horizontal cyan bus / pipeline in
the middle with a soft outer glow (#22d3ee). 6 small agent node
panels sit evenly on top of the bus, each a rounded rectangle with a
glowing neon border in a distinct color (mint green #34d399, soft
amber #fbbf24, dusty rose #f472b6, sky blue #38bdf8, violet
#a78bfa, cyan #22d3ee), each with a tiny glowing downward connector
into the bus. A few arrows cycle cleanly through the bus rather than
tangling — entering one side of the bus and exiting the other,
drawn in bright cyan with a soft glow. A small green glowing
checkmark shield icon (#10b981) at one corner of the bus suggesting
a policy gate. Subtle cyan glow emanating from the panel. Faint PCB
traces in dim cyan around the panel edges.

Both panels share the same vertical extent. Around the edges of the
canvas: thin PCB / circuit-board traces in dim cyan, with very
subtle small monospace data readout labels in dim gray (#475569)
reading things like "0x4A2F", "BUS_MCP_v2", "AGENT_CTX" — purely
decorative.

No people, no icons beyond the tiny clocks and shield described, no
logos, no stock imagery. Professional software product diagram, dark
and moody but readable.
```

Post-process: resize to 1280×1280, then run
`overlay_without_kernel`. The overlay paints two `NAVY_BG` bands
(top 2%–10% and bottom 88%–98%) over whatever the model put there,
re-strokes the cyan divider through the bands, then draws clean
headers (`without coordination` / `with salient-core`, mixed case)
and captions (`cycles, stalls, leaked intent` / `typed bus + cycle
detection + gates`) centered in each panel half. The bands fully
occlude any model-rendered stray text in those margins.

## Re-rendering

```bash
# 1. Submit (one shot per image)
#    hero + social: model=google/nano-banana-pro/text-to-image-ultra,
#                    aspect_ratio=16:9, resolution=4k, output_format=png
#    without-kernel: model=bytedance/seedream-v4.5,
#                    size=4096*4096, output_format=auto (jpeg default)
#    Use atlas_generate_image with the model id above, then
#    atlas_get_prediction until status == "completed".

# 2. Download to /tmp/salient-imgs/ at the canonical base names
curl -sSL -o /tmp/salient-imgs/hero.png                   <prediction-url>
curl -sSL -o /tmp/salient-imgs/social-base.png            <prediction-url>
curl -sSL -o /tmp/salient-imgs/without-kernel-base.jpeg   <prediction-url>

# 3. Resize to working sizes
python3 - <<'PY'
from PIL import Image
hero = Image.open('/tmp/salient-imgs/hero.png').convert('RGB')
nw = 2400; nh = int(hero.size[1] * nw / hero.size[0])
hero.resize((nw, nh), Image.LANCZOS).save(
    'imgs/hero-bus.jpg', 'JPEG', quality=92, optimize=True)

social = Image.open('/tmp/salient-imgs/social-base.png').convert('RGB')
nw = 1600; nh = int(social.size[1] * nw / social.size[0])
social.resize((nw, nh), Image.LANCZOS).save(
    'imgs/social-base_1600.jpeg', 'JPEG', quality=92, optimize=True)

wk = Image.open('/tmp/salient-imgs/without-kernel-base.jpeg').convert('RGB')
wk.resize((1280, 1280), Image.LANCZOS).save(
    'imgs/without-kernel-wider_1600.jpeg', 'JPEG', quality=92, optimize=True)
PY

# 4. Overlay text and finalize (hero is already final)
python3 -m imgs._overlay
# This writes imgs/social-preview.jpg and imgs/without-kernel-comparison.png.
```

Tip: Nano Banana Pro Ultra is non-deterministic and won't take a
`seed` parameter; the same prompt produces slightly different label
positions each run. If a label lands awkwardly, regenerate once or
two more times before tweaking the prompt — re-rendering is cheap
(~$0.15 per image). Seedream v4.5 has the same property but at
~$0.0036 per image.

## Things deliberately not done

- The README "What's in the kernel" feature grid is plain HTML
  tables, not generated images. Generating six flat cards and
  sizing them to match the existing inline grid was more cost
  than benefit; the HTML reads fine on GitHub.
- No social-card image for the GitHub repo settings (1280×640).
  The `imgs/social-preview.jpg` is repurposed as the README's
  bottom image, not the actual repo social preview.
- No SVG variants. Nano Banana's output is raster; an SVG hand-built
  from the same labels would be sharper at very high DPI but
  hasn't been worth the maintenance so far.