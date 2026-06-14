import os
from PIL import Image, ImageDraw

def main():
    os.makedirs("/home/nishant/Desktop/antigravity/iit/aegiseye-forensics/evidence", exist_ok=True)
    
    # 1. Generate clean_evidence.jpg
    img_clean = Image.new('RGB', (400, 200), color=(255, 255, 255))
    d = ImageDraw.Draw(img_clean)
    
    # Draw config lines
    d.text((20, 20), "SYSTEM CONFIGURATION v1.0", fill=(0, 0, 0))
    d.text((20, 60), "DATABASE_PORT = 5432", fill=(0, 0, 0))
    d.text((20, 100), "DEBUG = False", fill=(0, 0, 0))
    d.text((20, 140), "ALLOWED_HOSTS = ['*']", fill=(0, 0, 0))
    
    clean_path = "/home/nishant/Desktop/antigravity/iit/aegiseye-forensics/evidence/clean_evidence.jpg"
    # Save as JPEG with high quality
    img_clean.save(clean_path, 'JPEG', quality=95)
    print(f"Generated clean evidence: {clean_path}")
    
    # 2. Generate tampered_evidence.jpg
    # Modify the text 'False' to 'True' with edited pixels and different compression quality
    img_tampered = Image.open(clean_path).convert('RGB')
    dt = ImageDraw.Draw(img_tampered)
    
    # Erase 'False'
    dt.rectangle([90, 95, 170, 120], fill=(255, 255, 255))
    
    # Write 'True'
    dt.text((90, 100), "True", fill=(200, 0, 0))
    
    tampered_path = "/home/nishant/Desktop/antigravity/iit/aegiseye-forensics/evidence/tampered_evidence.jpg"
    # Save with different quality to trigger ELA compression differences
    img_tampered.save(tampered_path, 'JPEG', quality=85)
    print(f"Generated tampered evidence: {tampered_path}")

if __name__ == "__main__":
    main()
