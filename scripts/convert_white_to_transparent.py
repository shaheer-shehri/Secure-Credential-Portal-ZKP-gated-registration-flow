from pathlib import Path

from PIL import Image


def convert_white_to_transparent(image_path: Path, threshold: int = 245) -> None:
    image_path = image_path.resolve()
    img = Image.open(image_path).convert("RGBA")
    new_pixels = []
    for r, g, b, a in img.getdata():
        if r >= threshold and g >= threshold and b >= threshold:
            new_pixels.append((r, g, b, 0))
        else:
            new_pixels.append((r, g, b, a))
    img.putdata(new_pixels)
    img.save(image_path, "WEBP")
    print(f"Updated {image_path}")


if __name__ == "__main__":
    convert_white_to_transparent(Path("web_project/static/log1.webp"))
