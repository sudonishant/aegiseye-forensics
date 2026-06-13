import os
from PIL import Image, ImageChops

class ELAScanner:
    def __init__(self, image_path):
        self.image_path = image_path

    def analyze(self, quality=95, scale=10, output_path=None):
        """Perform Error Level Analysis (ELA) to detect image manipulation."""
        if not os.path.exists(self.image_path):
            return {"error": "Image file not found."}

        if not output_path:
            base, ext = os.path.splitext(self.image_path)
            output_path = f"{base}_ela_heatmap.png"

        temp_file = "temp_ela.jpg"

        try:
            # 1. Open original image
            original = Image.open(self.image_path).convert('RGB')

            # 2. Resave image at defined JPEG quality
            original.save(temp_file, 'JPEG', quality=quality)

            # 3. Open temporary compressed image
            compressed = Image.open(temp_file)

            # 4. Calculate absolute difference
            diff = ImageChops.difference(original, compressed)

            # 5. Calculate extreme values and scale the differences to make them visible
            extrema = diff.getextrema()
            max_diff = max([ex[1] for ex in extrema])
            if max_diff == 0:
                max_diff = 1

            # Enhancing/scaling the diff
            scale_factor = 255.0 / max_diff
            # Cap the scale to avoid extreme noise blowing up
            scale_factor = min(scale_factor, scale)

            # Apply scale factor using point transformation
            enhanced_diff = diff.point(lambda p: p * scale_factor)

            # 6. Save ELA Heatmap
            enhanced_diff.save(output_path)

            return {
                "success": True,
                "heatmap_path": os.path.abspath(output_path),
                "quality_tested": quality,
                "scale_factor_applied": scale_factor
            }

        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            # Clean up temp file
            if os.path.exists(temp_file):
                os.remove(temp_file)
