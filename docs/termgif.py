"""Draw a terminal GIF from ANSI-coloured output.

    from termgif import Scene, build
    build([Scene(title, cmd, ansi_text, intro=None)], "out.gif")

Each scene: a blinking prompt, the command typed, the output revealed a few lines at
a time, then a hold. Colours come from the 16-colour SGR codes rich emits with
color_system="standard" (or FORCE_COLOR=1 on a pipe). Needs Pillow and a monospace TTF.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

COLS = 86
FONT_SIZE = 14
LINE_H = 18
PAD_X, PAD_Y, BAR_H = 18, 14, 34
BG, BAR, TEXT, CURSOR = (11, 11, 13), (24, 23, 26), (230, 225, 216), (255, 77, 109)
PALETTE = {
    30: (60, 60, 64), 31: (255, 107, 107), 32: (79, 209, 161), 33: (245, 196, 81), 34: (130, 170, 255), 35: (199, 146, 234), 36: (127, 215, 255), 37: (230, 225, 216),
    90: (124, 120, 115), 91: (255, 130, 130), 92: (110, 230, 180), 93: (250, 210, 110), 94: (150, 185, 255), 95: (215, 170, 245), 96: (160, 225, 255), 97: (245, 242, 236),
}
SGR = re.compile(r"\x1b\[([0-9;]*)m")
OTHER_ESC = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

Seg = tuple[str, tuple[int, int, int], bool]


def _font(bold: bool = False) -> ImageFont.FreeTypeFont:
    for p in ["C:/Windows/Fonts/CascadiaMono.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", "/System/Library/Fonts/Menlo.ttc"]:
        if Path(p).exists():
            f = ImageFont.truetype(p, FONT_SIZE)
            if bold and "Cascadia" in p:
                try:
                    f.set_variation_by_name("Bold")
                except Exception:  # noqa: BLE001
                    pass
            return f
    return ImageFont.load_default()


FONT, FONT_B = _font(), _font(bold=True)
CHAR_W = FONT.getlength("M")


def parse_ansi(text: str) -> list[list[Seg]]:
    lines: list[list[Seg]] = []
    text = re.sub(r"\x1b\[\?25[lh]", "", text)  # cursor show/hide from a live status
    for line in text.replace("\r\n", "\n").split("\n"):
        line = OTHER_ESC.sub(lambda m: m.group(0) if m.group(0).endswith("m") else "", line)
        if "\r" in line:
            line = line.rsplit("\r", 1)[-1]  # a live status overwrote itself; keep what was drawn last
        if re.match(r"^(\x1b\[[0-9;]*m)*\s*[⠀-⣿]", line):
            continue  # a spinner frame
        segs: list[Seg] = []
        color, bold, pos = TEXT, False, 0
        for m in SGR.finditer(line):
            if m.start() > pos:
                segs.append((line[pos:m.start()], color, bold))
            for code in (m.group(1) or "0").split(";"):
                c = int(code or 0)
                if c == 0:
                    color, bold = TEXT, False
                elif c == 1:
                    bold = True
                elif c == 2:
                    color = PALETTE[90]
                elif c == 39:
                    color = TEXT
                elif c in PALETTE:
                    color = PALETTE[c]
            pos = m.end()
        if pos < len(line):
            segs.append((line[pos:], color, bold))
        lines.append(segs)
    while lines and not "".join(t for t, _, _ in lines[-1]).strip():
        lines.pop()
    return lines


def plain(row: list[Seg]) -> str:
    return "".join(t for t, _, _ in row)


def draw_frame(rows: list[list[Seg]], height_lines: int, title: str, cols: int = COLS) -> Image.Image:
    w = int(PAD_X * 2 + CHAR_W * cols)
    h = BAR_H + PAD_Y * 2 + LINE_H * height_lines
    img = Image.new("RGB", (w, h), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, w, BAR_H], fill=BAR)
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([14 + i * 20, 11, 26 + i * 20, 23], fill=c)
    d.text((w / 2 - FONT.getlength(title) / 2, 8), title, font=FONT, fill=(150, 146, 140))
    y = BAR_H + PAD_Y
    visible = rows[-height_lines:] if len(rows) > height_lines else rows
    for segs in visible:
        x = PAD_X
        for text, color, bold in segs:
            d.text((x, y), text, font=FONT_B if bold else FONT, fill=color)
            x += FONT.getlength(text)
        y += LINE_H
    return img


def prompt_row(cmd: str, cursor: bool, user: str) -> list[Seg]:
    row: list[Seg] = [(user + " ", PALETTE[32], False), (cmd, TEXT, False)]
    if cursor:
        row.append(("█", CURSOR, False))
    return row


@dataclass
class Scene:
    title: str
    cmd: str
    ansi: str
    intro: str | None = None
    hold: int = 16
    user: str = "reda@laptop:~$"


def build(scenes: list[Scene], out: str | Path, height: int | None = None, cols: int = COLS) -> None:
    parsed = [parse_ansi(s.ansi) for s in scenes]
    # never clip: widen the window to the longest line a scene actually produced
    longest = max((len(plain(r)) for rows in parsed for r in rows), default=0)
    cols = max(cols, longest + 1)
    if height is None:
        height = max(len(rows) + (2 if s.intro else 1) for rows, s in zip(parsed, scenes)) + 1
    frames: list[Image.Image] = []
    durations: list[int] = []
    for s, rows in zip(scenes, parsed):
        base: list[list[Seg]] = [[(s.intro, PALETTE[90], False)]] if s.intro else []
        for cur in (True, False, True):
            frames.append(draw_frame(base + [prompt_row("", cur, s.user)], height, s.title, cols)); durations.append(260)
        for i in range(1, len(s.cmd) + 1):
            frames.append(draw_frame(base + [prompt_row(s.cmd[:i], True, s.user)], height, s.title, cols)); durations.append(70 if len(s.cmd) > 30 else 110)
        frames.append(draw_frame(base + [prompt_row(s.cmd, False, s.user)], height, s.title, cols)); durations.append(350)
        shown = base + [prompt_row(s.cmd, False, s.user)]
        step = 3 if len(rows) > 24 else 2
        for i in range(0, len(rows), step):
            shown = base + [prompt_row(s.cmd, False, s.user)] + rows[: i + step]
            frames.append(draw_frame(shown, height, s.title, cols)); durations.append(55)
        for _ in range(s.hold):
            frames.append(draw_frame(shown, height, s.title, cols)); durations.append(130)
    pal = [f.quantize(colors=96, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE) for f in frames]
    out = Path(out)
    pal[0].save(out, save_all=True, append_images=pal[1:], duration=durations, loop=0, optimize=True, disposal=1)
    print(f"wrote {out}: {len(frames)} frames, {frames[0].size[0]}x{frames[0].size[1]}, {out.stat().st_size / 1024:.0f} KB, {sum(durations) / 1000:.1f} s")


def cut_before(ansi: str, marker: str) -> str:
    """Keep the output up to (not including) the first line containing `marker`."""
    lines = ansi.split("\n")
    for i, line in enumerate(lines):
        if marker in SGR.sub("", line):
            return "\n".join(lines[:i]).rstrip()
    return ansi


def first_lines(ansi: str, n: int) -> str:
    return "\n".join(ansi.split("\n")[:n])
