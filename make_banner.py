"""Draws the images for the GitHub page: docs/banner.png (README header) and docs/social-preview.png (1280x640,
upload it in Settings > Social preview). Uses Bahnschrift, which ships with Windows."""
import os

from PIL import Image, ImageDraw, ImageFont

from make_icon import draw

BG, INK, BLUE, PAPER, MUTE = (227, 229, 232), (18, 21, 27), (30, 60, 255), (246, 247, 248), (85, 92, 103)
FONT = r"C:\Windows\Fonts\bahnschrift.ttf"


def font(size, weight=700):
    f = ImageFont.truetype(FONT, size)
    try:
        f.set_variation_by_axes([weight, 100])  # wght, wdth (100 = normal width)
    except Exception:
        pass
    return f


TEXT = {"ru": ("VPN-клиент", "Вставил подписку. Выбрал сервер. Нажал кнопку."),
        "en": ("VPN client", "Paste a subscription. Pick a server. Press connect.")}


def banner(w, h, path, lang="ru"):
    im = Image.new("RGB", (w, h), BG)
    d = ImageDraw.Draw(im)
    s = int(h * 0.62)  # icon size
    ix, iy = int(h * 0.19), (h - s) // 2
    im.paste(draw(1024).resize((s, s), Image.LANCZOS), (ix, iy), draw(1024).resize((s, s), Image.LANCZOS))
    tx = ix + s + int(h * 0.12)
    d.text((tx, int(h * 0.20)), TEXT[lang][0], font=font(int(h * 0.27)), fill=INK)
    d.text((tx, int(h * 0.55)), TEXT[lang][1], font=font(int(h * 0.075), 500), fill=MUTE)
    # the three systems as hard-edged tags, like the buttons in the app
    x, y, fs = tx, int(h * 0.72), int(h * 0.062)
    for label in ("Windows", "Linux", "macOS"):
        f = font(fs, 700)
        tw = d.textlength(label, font=f)
        pad = int(h * 0.03)
        d.rectangle((x + 6, y + 6, x + tw + 2 * pad + 6, y + fs + 2 * pad + 6), fill=INK)
        d.rectangle((x, y, x + tw + 2 * pad, y + fs + 2 * pad), fill=PAPER, outline=INK, width=3)
        d.text((x + pad, y + pad - 2), label, font=f, fill=INK)
        x += tw + 2 * pad + int(h * 0.06)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    im.save(path)


if __name__ == "__main__":
    banner(1600, 480, os.path.join("docs", "banner.png"))
    banner(1280, 640, os.path.join("docs", "social-preview-ru.png"))
    banner(1600, 480, os.path.join("docs", "banner-en.png"), "en")
    banner(1280, 640, os.path.join("docs", "social-preview.png"), "en")  # the one to upload: English first
