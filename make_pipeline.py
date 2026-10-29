#!/usr/bin/env python3
"""Redraw the benchmark pipeline figure (Fig. 1).

Writes pipeline.pdf (vector) and pipeline.png (300 dpi). Palette and
typography follow make_figures.py so the figure set stays consistent.
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

plt.rcParams.update({"font.family": "DejaVu Sans", "savefig.bbox": "tight"})
OI = {"blue": "#0072B2", "green": "#009E73", "black": "#222222"}

fig, ax = plt.subplots(figsize=(7.4, 2.9))
ax.set_xlim(-2.5, 102.5); ax.set_ylim(-2.0, 65.0); ax.axis("off")

BW, BH, TOP = 17.2, 18.0, 36.0
GAP = (100 - 5 * BW) / 4.0
XS = [i * (BW + GAP) for i in range(5)]
TITLE_FS, SUB_FS = 10.0, 7.3

def box(x, y, w, h, title, sub, edge=OI["black"], face="white", lw=1.4, z=3):
    ax.add_patch(FancyBboxPatch((x, y), w, h,
                 boxstyle="round,pad=0.4,rounding_size=1.8",
                 linewidth=lw, edgecolor=edge, facecolor=face, zorder=z))
    ax.text(x + w / 2, y + h - 5.0, title, ha="center", va="center",
            fontsize=TITLE_FS, fontweight="bold", color=OI["black"],
            zorder=z + 1, linespacing=1.15)
    ax.text(x + w / 2, y + 5.2, sub, ha="center", va="center",
            fontsize=SUB_FS, color="#4a4a4a", zorder=z + 1, linespacing=1.35)

def arrow(pts, color=OI["black"], lw=1.5):
    for a, b in zip(pts, pts[1:-1]):
        ax.plot([a[0], b[0]], [a[1], b[1]], color=color, lw=lw,
                solid_capstyle="round", zorder=2)
    ax.add_patch(FancyArrowPatch(pts[-2], pts[-1], arrowstyle="-|>",
                 mutation_scale=12, linewidth=lw, color=color,
                 shrinkA=0, shrinkB=0, zorder=2))

# stacked sheets behind the scanner box, showing six configurations
for dy in (2.4, 1.2):
    ax.add_patch(FancyBboxPatch((XS[2] + dy, TOP + dy), BW, BH,
                 boxstyle="round,pad=0.4,rounding_size=1.8",
                 linewidth=1.0, edgecolor="#bdbdbd", facecolor="#f6f6f6", zorder=1))

box(XS[0], TOP, BW, BH, "Generator",      "recoverability\nverified")
box(XS[1], TOP, BW, BH, "Corpus",         "14,040 files\n3 carriers")
box(XS[2], TOP, BW, BH, "Scanners",       "4 tools\n6 configurations")
box(XS[3], TOP, BW, BH, "Matcher",        "line or value\nmatch")
box(XS[4], TOP, BW, BH, "Metrics",        "retention, index\nand coverage",
    edge=OI["green"], face="#e9f7f2", lw=1.8)

ymid = TOP + BH / 2
for i in range(4):
    arrow([(XS[i] + BW + 0.6, ymid), (XS[i + 1] - 0.6, ymid)])

# taxonomy feeds the generator
ax.text(XS[0] + BW / 2, TOP + BH + 7.0, "Taxonomy (Section IV)", ha="center",
        va="center", fontsize=8.8, style="italic", color=OI["blue"])
arrow([(XS[0] + BW / 2, TOP + BH + 4.4), (XS[0] + BW / 2, TOP + BH + 0.6)],
      color=OI["blue"], lw=1.3)

# ground-truth manifest, on its own path, never scanned
MX, MW, MY, MH = XS[1], BW * 3 + GAP * 2, 3.0, 16.0
box(MX, MY, MW, MH, "Ground-truth manifest",
    "value, line and transformation of each sample,\nwritten outside the scanned tree",
    edge=OI["blue"], face="#e8f2fa", lw=1.5)

gx, mxr = XS[0] + BW / 2, XS[3] + BW / 2
elbow = MY + MH / 2
arrow([(gx, TOP - 0.6), (gx, elbow), (MX - 0.6, elbow)], color=OI["blue"], lw=1.4)
arrow([(mxr, MY + MH + 0.6), (mxr, TOP - 0.6)], color=OI["blue"], lw=1.4)

fig.savefig("pipeline.pdf", pad_inches=0.04)
fig.savefig("pipeline.png", dpi=300, pad_inches=0.04)
print("wrote pipeline.pdf / pipeline.png")
