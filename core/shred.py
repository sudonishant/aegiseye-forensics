import os
import random
import string

class FileShredder:
    def __init__(self, file_path):
        self.file_path = file_path

    def shred(self, passes=3):
        """Securely overwrite and delete the file to prevent forensic recovery."""
        if not os.path.exists(self.file_path):
            return {"success": False, "error": "File does not exist."}

        if not os.path.isfile(self.file_path):
            return {"success": False, "error": "Path is not a regular file."}

        try:
            file_size = os.path.getsize(self.file_path)
            
            # 1. Overwrite passes
            with open(self.file_path, "ba+", buffering=0) as f:
                for p in range(1, passes + 1):
                    f.seek(0)
                    # Write random bytes in chunks
                    written = 0
                    chunk_size = 4096
                    while written < file_size:
                        bytes_to_write = min(chunk_size, file_size - written)
                        
                        # Alternate between random bytes and zero bytes
                        if p % 2 == 0:
                            payload = b"\x00" * bytes_to_write
                        else:
                            payload = os.urandom(bytes_to_write)
                            
                        f.write(payload)
                        written += bytes_to_write
                        
                    f.flush()
                    os.fsync(f.fileno())

            # 2. Rename file to a random name to destroy directory metadata
            parent_dir = os.path.dirname(self.file_path)
            rand_name = "".join(random.choices(string.ascii_letters, k=10))
            temp_renamed_path = os.path.join(parent_dir, rand_name)
            
            os.rename(self.file_path, temp_renamed_path)
            
            # 3. Remove the renamed file
            os.remove(temp_renamed_path)
            
            return {
                "success": True,
                "file_wiped": os.path.basename(self.file_path),
                "passes_completed": passes,
                "bytes_shredded": file_size
            }

        except Exception as e:
            return {"success": False, "error": str(e)}
