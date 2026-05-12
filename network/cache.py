import json
import time
import shutil
from pathlib import Path


class FileCache:
    # -- кэш для файлов
    def __init__(self, user_id):
        self.user_id = user_id
        from utils import DATA_PATH
        self.cache_dir = DATA_PATH / 'files_cache' / str(user_id)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_file = self.cache_dir / 'metadata.json'
        self.metadata = self.load_metadata()

    def load_metadata(self):
        if self.metadata_file.exists():
            with open(self.metadata_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {}

    def save_metadata(self):
        with open(self.metadata_file, 'w', encoding='utf-8') as f:
            json.dump(self.metadata, f, ensure_ascii=False, indent=2)

    def get_file_path(self, file_id, file_name):
        safe_name = "".join(c for c in file_name if c.isalnum() or c in '._- ')[:50]
        return self.cache_dir / f"{file_id}_{safe_name}"

    def has_file(self, file_id):
        return str(file_id) in self.metadata

    def save_file(self, file_id, file_name, file_type, file_size, file_data, thumbnail_data=None):
        file_path = self.get_file_path(file_id, file_name)
        with open(file_path, 'wb') as f:
            f.write(file_data)
        if thumbnail_data:
            thumb_path = self.cache_dir / f"thumb_{file_id}.jpg"
            with open(thumb_path, 'wb') as f:
                f.write(thumbnail_data)
        self.metadata[str(file_id)] = {
            'file_name': file_name,
            'file_type': file_type,
            'file_size': file_size,
            'file_path': str(file_path),
            'thumbnail_path': str(thumb_path) if thumbnail_data else None,
            'timestamp': time.time()
        }
        self.save_metadata()
        return file_path

    def get_file_info(self, file_id):
        return self.metadata.get(str(file_id))

    def get_file_data(self, file_id):
        info = self.get_file_info(file_id)
        if info and 'file_path' in info:
            with open(info['file_path'], 'rb') as f:
                return f.read()
        return None

    def get_thumbnail_data(self, file_id):
        info = self.get_file_info(file_id)
        if info and info.get('thumbnail_path'):
            with open(info['thumbnail_path'], 'rb') as f:
                return f.read()
        return None

    def clear_cache(self):
        shutil.rmtree(self.cache_dir, ignore_errors=True)