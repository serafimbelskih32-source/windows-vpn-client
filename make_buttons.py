"""Draws the download buttons for the README (docs/dl-*.png) in the app's style: hard outline, hard shadow, a blue
download tile. Uses Bahnschrift, which ships with Windows."""
import os

from PIL import Image, ImageDraw, ImageFont

INK, BLUE, PAPER, MUTE, WHITE = (18, 21, 27), (30, 60, 255), (246, 247, 248), (85, 92, 103), (255, 255, 255)
FONT = r"C:\Windows\Fonts\bahnschrift.ttf"

BUTTONS = [
    ("dl-windows.png", "Windows", "10 и 11", True),
    ("dl-linux-x86_64.png", "Linux", "x86_64", False),
    ("dl-linux-arm64.png", "Linux", "ARM64", False),
    ("dl-macos-arm64.png", "macOS", "Apple Silicon (M1 и новее)", False),
    ("dl-macos-x86_64.png", "macOS", "Intel", False),
]


def font(size, weight):
    f = ImageFont.truetype(FONT, size)
    try:
        f.set_variation_by_axes([weight, 100])
    except Exception:
        pass
    return f


def button(path, title, sub, primary):
    W, H, o = 560, 132, 10
    im = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    x0, y0, x1, y1 = 2, 2, W - o - 2, H - o - 2
    d.rectangle((x0 + o, y0 + o, x1 + o, y1 + o), fill=INK)  # hard shadow
    d.rectangle((x0, y0, x1, y1), fill=BLUE if primary else PAPER, outline=INK, width=5)
    th = y1 - y0 - 10
    tile = (x0 + 5, y0 + 5, x0 + 5 + th, y0 + 5 + th)
    d.rectangle(tile, fill=INK if primary else BLUE)
    cx, cy, s = (tile[0] + tile[2]) / 2, (tile[1] + tile[3]) / 2, th * 0.2
    d.rectangle((cx - s * 0.4, cy - s * 1.35, cx + s * 0.4, cy + s * 0.1), fill=WHITE)             # arrow shaft
    d.polygon([(cx - s * 1.05, cy + s * 0.0), (cx + s * 1.05, cy + s * 0.0), (cx, cy + s * 1.15)], fill=WHITE)  # head
    d.rectangle((cx - s * 1.2, cy + s * 1.55, cx + s * 1.2, cy + s * 1.9), fill=WHITE)             # the tray it lands in
    tx = tile[2] + 30
    fg, sub_fg = (WHITE, (201, 209, 255)) if primary else (INK, MUTE)
    d.text((tx, y0 + 16), title, font=font(50, 700), fill=fg)
    d.text((tx, y0 + 76), sub, font=font(27, 500), fill=sub_fg)
    im.save(path)


if __name__ == "__main__":
    os.makedirs("docs", exist_ok=True)
    for name, title, sub, primary in BUTTONS:
        button(os.path.join("docs", name), title, sub, primary)
    print("buttons:", [b[0] for b in BUTTONS])
