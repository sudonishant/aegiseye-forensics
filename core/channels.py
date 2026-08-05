import os
from PIL import Image

class ChannelScanner:
    def __init__(self, image_path):
        self.image_path = image_path

    def calculate_ahash(self):
        """Calculate Average Perceptual Hash (aHash) of the image."""
        try:
            # 1. Resize to 8x8
            img = Image.open(self.image_path).convert('L').resize((8, 8), Image.Resampling.LANCZOS)
            pixels = list(img.getdata())
            
            # 2. Find average pixel value
            avg = sum(pixels) / len(pixels)
            
            # 3. Create 64-bit hash
            bits = "".join(["1" if p > avg else "0" for p in pixels])
            
            # 4. Convert to Hex
            hex_hash = ""
            for i in range(0, 64, 4):
                nibble = bits[i:i+4]
                hex_hash += hex(int(nibble, 2))[2:]
                
            return hex_hash
        except Exception as e:
            return f"Hash Error: {str(e)}"

    def split_channels(self, output_dir=None):
        """Split image into Red, Green, and Blue channels for noise inspection."""
        if not os.path.exists(self.image_path):
            return {"error": "Image not found."}

        if not output_dir:
            output_dir = os.path.dirname(os.path.abspath(self.image_path))

        base = os.path.splitext(os.path.basename(self.image_path))[0]
        results = {}

        try:
            img = Image.open(self.image_path).convert('RGB')
            r, g, b = img.split()

            # Create individual channel images showing the channel values as grayscale
            r_path = os.path.join(output_dir, f"{base}_channel_red.png")
            g_path = os.path.join(output_dir, f"{base}_channel_green.png")
            b_path = os.path.join(output_dir, f"{base}_channel_blue.png")

            r.save(r_path)
            g.save(g_path)
            b.save(b_path)

            results = {
                "red": os.path.abspath(r_path),
                "green": os.path.abspath(g_path),
                "blue": os.path.abspath(b_path)
            }
            return {"success": True, "channels": results}
        except Exception as e:
            return {"success": False, "error": str(e)}
