import os
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

class MetadataScanner:
    def __init__(self, image_path):
        self.image_path = image_path

    def get_decimal_from_dms(self, dms, ref):
        """Convert GPS coordinates in Degrees Minutes Seconds (DMS) to Decimal Degrees."""
        try:
            degrees = float(dms[0])
            minutes = float(dms[1])
            seconds = float(dms[2])
            
            decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)
            if ref in ['S', 'W']:
                decimal = -decimal
            return decimal
        except Exception:
            return None

    def scan(self):
        """Extract metadata and GPS coordinates from the image."""
        exif_data = {}
        gps_info = {}
        gps_coords = None
        
        if not os.path.exists(self.image_path):
            return {"error": "Image file not found."}

        try:
            image = Image.open(self.image_path)
            raw_exif = image._getexif()
            
            if not raw_exif:
                return {"message": "No EXIF metadata found in this image.", "exif": {}, "gps": None}

            # Extract human-readable tags
            for tag_id, value in raw_exif.items():
                tag_name = TAGS.get(tag_id, tag_id)
                if tag_name == "GPSInfo":
                    # Extract GPS tags
                    for gps_tag_id in value:
                        gps_tag_name = GPSTAGS.get(gps_tag_id, gps_tag_id)
                        gps_info[gps_tag_name] = value[gps_tag_id]
                else:
                    # Convert bytes to string if needed
                    if isinstance(value, bytes):
                        try:
                            value = value.decode('utf-8', errors='ignore')
                        except Exception:
                            value = str(value)
                    exif_data[tag_name] = str(value)

            # Process GPS Coordinates
            if gps_info:
                lat_dms = gps_info.get("GPSLatitude")
                lat_ref = gps_info.get("GPSLatitudeRef")
                lon_dms = gps_info.get("GPSLongitude")
                lon_ref = gps_info.get("GPSLongitudeRef")

                if lat_dms and lat_ref and lon_dms and lon_ref:
                    lat_dec = self.get_decimal_from_dms(lat_dms, lat_ref)
                    lon_dec = self.get_decimal_from_dms(lon_dms, lon_ref)
                    if lat_dec is not None and lon_dec is not None:
                        gps_coords = {
                            "latitude": lat_dec,
                            "longitude": lon_dec,
                            "map_link": f"https://www.google.com/maps/search/?api=1&query={lat_dec},{lon_dec}"
                        }

            return {
                "exif": exif_data,
                "gps": gps_coords,
                "format": image.format,
                "size": image.size,
                "mode": image.mode
            }

        except Exception as e:
            return {"error": f"Failed to extract metadata: {str(e)}"}

    def sanitize(self, output_path=None):
        """Remove all EXIF metadata from the image to protect privacy."""
        if not output_path:
            # Append _sanitized to filename
            base, ext = os.path.splitext(self.image_path)
            output_path = f"{base}_sanitized{ext}"

        try:
            image = Image.open(self.image_path)
            
            # Create a copy of the image without metadata
            data = list(image.getdata())
            clean_image = Image.new(image.mode, image.size)
            clean_image.putdata(data)
            
            clean_image.save(output_path, format=image.format)
            return {"success": True, "output_path": os.path.abspath(output_path)}
        except Exception as e:
            return {"success": False, "error": str(e)}
