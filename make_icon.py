from PIL import Image, ImageDraw

INK, BLUE, WHITE = (18, 21, 27, 255), (30, 60, 255, 255), (255, 255, 255, 255)
N = 1024
im = Image.new("RGBA", (N, N), (0, 0, 0, 0))
d = ImageDraw.Draw(im)
d.rectangle((130, 130, 980, 980), fill=INK)                       # hard shadow
d.rectangle((40, 40, 890, 890), fill=BLUE, outline=INK, width=44)  # slab
cx, cy, r, w = 465, 485, 235, 84
d.arc((cx - r, cy - r, cx + r, cy + r), start=312, end=228, fill=WHITE, width=w)  # power ring, gap on top
d.rectangle((cx - w // 2, cy - r - 70, cx + w // 2, cy - 20), fill=WHITE)         # power bar
im.resize((256, 256), Image.LANCZOS).save("icon_preview.png")
big = im.resize((256, 256), Image.LANCZOS)
big.save("icon.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
