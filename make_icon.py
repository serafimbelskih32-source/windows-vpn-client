"""Draws the app icon: icon.png (Linux window), icon.ico (Windows), icon.icns (macOS bundle)."""
from PIL import Image, ImageDraw

INK, BLUE, WHITE = (18, 21, 27, 255), (30, 60, 255, 255), (255, 255, 255, 255)
SMALL = (16, 20, 24, 30, 32, 36, 40, 48)  # sizes Windows uses for the title bar, taskbar and tray at 100-200 % scaling
LARGE = (64, 96, 128, 256)


def ring(d, k):
    """Power symbol; `k` = pixels per master unit."""
    cx, cy, r, w = 465, 485, 235, 84
    d.arc((cx * k - r * k, cy * k - r * k, cx * k + r * k, cy * k + r * k), start=312, end=228, fill=WHITE,
          width=max(1, round(w * k)))
    d.rectangle((round((cx - w // 2) * k), round((cy - r - 70) * k), round((cx + w // 2) * k) - 1, round((cy - 20) * k) - 1),
                fill=WHITE)


def draw(n=1024):
    im = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    d.rectangle((130, 130, 980, 980), fill=INK)                        # hard shadow
    d.rectangle((40, 40, 890, 890), fill=BLUE, outline=INK, width=44)  # slab
    ring(d, 1)
    return im


def draw_small(n):
    """The same icon built for an n x n pixel grid: the slab, its outline and the shadow sit exactly on pixel
    boundaries (a downscaled master leaves them half-covered, which reads as blur at 16-48 px); only the ring is smoothed."""
    k = n / 1024
    s = lambda v: round(v * k)  # noqa: E731
    im = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    d.rectangle((s(130), s(130), s(980) - 1, s(980) - 1), fill=INK)
    d.rectangle((s(40), s(40), s(890) - 1, s(890) - 1), fill=INK)
    edge = max(1, s(44))
    d.rectangle((s(40) + edge, s(40) + edge, s(890) - 1 - edge, s(890) - 1 - edge), fill=BLUE)
    ss = 8  # smooth the arc only: draw it 8x larger on its own layer and shrink
    layer = Image.new("RGBA", (n * ss, n * ss), (0, 0, 0, 0))
    ring(ImageDraw.Draw(layer), k * ss)
    return Image.alpha_composite(im, layer.resize((n, n), Image.LANCZOS))


if __name__ == "__main__":
    big = draw()
    big.resize((256, 256), Image.LANCZOS).save("icon.png")
    frames = {n: draw_small(n) for n in SMALL}
    frames.update({n: big.resize((n, n), Image.LANCZOS) for n in LARGE})
    order = sorted(frames)
    frames[256].save("icon.ico", format="ICO", sizes=[(n, n) for n in order],
                     append_images=[frames[n] for n in order if n != 256])
    big.save("icon.icns")
