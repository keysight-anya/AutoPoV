"""
AutoPoV Source Handler Module
Handles ZIP uploads, file/folder uploads, and raw code paste
"""

import os
import shutil
import tempfile
import zipfile
import tarfile
import stat
from pathlib import Path, PurePosixPath
from typing import Optional, Tuple, List
import uuid

from app.config import settings


class SourceHandler:
    """Handles various source code input methods"""
    
    def __init__(self):
        self.temp_base = settings.TEMP_DIR
        os.makedirs(self.temp_base, exist_ok=True)
    
    def _get_scan_dir(self, scan_id: str) -> str:
        """Get or create scan directory"""
        scan_dir = os.path.join(self.temp_base, scan_id)
        os.makedirs(scan_dir, exist_ok=True)
        return scan_dir
    
    def _is_within_dir(self, base: Path, target: Path) -> bool:
        try:
            target.relative_to(base)
            return True
        except Exception:
            return False

    def _check_archive_limits(self, total_size: int, file_count: int):
        max_size = settings.MAX_ARCHIVE_UNCOMPRESSED_MB * 1024 * 1024
        if total_size > max_size:
            raise ValueError(f"Archive too large after decompression ({total_size / (1024*1024):.1f} MB)")
        if file_count > settings.MAX_ARCHIVE_FILES:
            raise ValueError(f"Archive contains too many files ({file_count})")

    def handle_zip_upload(
        self,
        zip_path: str,
        scan_id: str
    ) -> str:
        """
        Extract ZIP file to scan directory
        
        Args:
            zip_path: Path to uploaded ZIP file
            scan_id: Unique scan identifier
        
        Returns:
            Path to extracted directory
        """
        # Size limit on uploaded archive
        max_upload = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
        if os.path.getsize(zip_path) > max_upload:
            raise ValueError(f"ZIP upload too large (> {settings.MAX_UPLOAD_SIZE_MB} MB)")

        scan_dir = self._get_scan_dir(scan_id)
        extract_dir = os.path.join(scan_dir, "source")
        
        # Clean up if exists
        if os.path.exists(extract_dir):
            shutil.rmtree(extract_dir)
        
        os.makedirs(extract_dir)

        extract_base = Path(extract_dir).resolve()
        total_size = 0
        file_count = 0

        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            for info in zip_ref.infolist():
                name = info.filename
                # Skip directories
                if name.endswith('/'):
                    continue

                # Reject absolute paths or traversal
                p = PurePosixPath(name)
                if p.is_absolute() or '..' in p.parts:
                    raise ValueError(f"Path traversal detected in ZIP: {name}")

                # Reject symlinks
                is_symlink = stat.S_IFMT(info.external_attr >> 16) == stat.S_IFLNK
                if is_symlink:
                    raise ValueError(f"Symlink detected in ZIP: {name}")

                # Enforce compression ratio
                if info.compress_size and info.file_size:
                    ratio = info.file_size / max(info.compress_size, 1)
                    if ratio > settings.MAX_ARCHIVE_COMPRESSION_RATIO:
                        raise ValueError(f"Suspicious compression ratio in ZIP: {name}")

                # Enforce size limits
                total_size += info.file_size
                file_count += 1
                self._check_archive_limits(total_size, file_count)

                dest = (extract_base / name).resolve()
                if not self._is_within_dir(extract_base, dest):
                    raise ValueError(f"Path traversal detected in ZIP: {name}")

            zip_ref.extractall(extract_dir)

        # Handle single directory at root
        items = os.listdir(extract_dir)
        if len(items) == 1:
            single_path = os.path.join(extract_dir, items[0])
            if os.path.isdir(single_path):
                # Move contents up
                for item in os.listdir(single_path):
                    shutil.move(
                        os.path.join(single_path, item),
                        os.path.join(extract_dir, item)
                    )
                os.rmdir(single_path)
        
        return extract_dir
    
    def handle_tar_upload(
        self,
        tar_path: str,
        scan_id: str,
        compression: Optional[str] = None
    ) -> str:
        """
        Extract TAR file to scan directory
        
        Args:
            tar_path: Path to uploaded TAR file
            scan_id: Unique scan identifier
            compression: Compression type ('gz', 'bz2', 'xz', None)
        
        Returns:
            Path to extracted directory
        """
        max_upload = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
        if os.path.getsize(tar_path) > max_upload:
            raise ValueError(f"TAR upload too large (> {settings.MAX_UPLOAD_SIZE_MB} MB)")

        scan_dir = self._get_scan_dir(scan_id)
        extract_dir = os.path.join(scan_dir, "source")
        
        # Clean up if exists
        if os.path.exists(extract_dir):
            shutil.rmtree(extract_dir)
        
        os.makedirs(extract_dir)

        extract_base = Path(extract_dir).resolve()
        total_size = 0
        file_count = 0

        # Open TAR with appropriate compression
        mode = 'r'
        if compression == 'gz':
            mode = 'r:gz'
        elif compression == 'bz2':
            mode = 'r:bz2'
        elif compression == 'xz':
            mode = 'r:xz'
        
        with tarfile.open(tar_path, mode) as tar_ref:
            for member in tar_ref.getmembers():
                name = member.name
                p = PurePosixPath(name)
                if p.is_absolute() or '..' in p.parts:
                    raise ValueError(f"Path traversal detected in TAR: {name}")

                if member.issym() or member.islnk():
                    raise ValueError(f"Symlink detected in TAR: {name}")

                if member.isfile():
                    total_size += member.size
                    file_count += 1
                    self._check_archive_limits(total_size, file_count)

                dest = (extract_base / name).resolve()
                if not self._is_within_dir(extract_base, dest):
                    raise ValueError(f"Path traversal detected in TAR: {name}")

            tar_ref.extractall(extract_dir)
        
        return extract_dir
    
    def handle_file_upload(
        self,
        file_paths: List[str],
        scan_id: str,
        preserve_structure: bool = True
    ) -> str:
        """
        Handle file/folder uploads
        
        Args:
            file_paths: List of uploaded file paths
            scan_id: Unique scan identifier
            preserve_structure: Whether to preserve directory structure
        
        Returns:
            Path to source directory
        """
        scan_dir = self._get_scan_dir(scan_id)
        source_dir = os.path.join(scan_dir, "source")
        
        # Clean up if exists
        if os.path.exists(source_dir):
            shutil.rmtree(source_dir)
        
        os.makedirs(source_dir)

        base_dir = None
        abs_paths = [os.path.abspath(p) for p in file_paths]
        if abs_paths:
            try:
                base_dir = os.path.commonpath(abs_paths)
            except Exception:
                base_dir = None

        source_base = Path(source_dir).resolve()

        for file_path in file_paths:
            if os.path.isfile(file_path):
                abs_path = os.path.abspath(file_path)
                if preserve_structure and base_dir and abs_path.startswith(base_dir + os.sep):
                    rel = os.path.relpath(abs_path, base_dir)
                else:
                    rel = os.path.basename(abs_path)

                dest_path = (source_base / rel).resolve()
                if not self._is_within_dir(source_base, dest_path):
                    dest_path = (source_base / os.path.basename(abs_path)).resolve()

                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                shutil.copy2(abs_path, dest_path)
        
        return source_dir
    
    def handle_folder_upload(
        self,
        folder_path: str,
        scan_id: str
    ) -> str:
        """
        Handle folder upload by copying contents
        
        Args:
            folder_path: Path to uploaded folder
            scan_id: Unique scan identifier
        
        Returns:
            Path to source directory
        """
        scan_dir = self._get_scan_dir(scan_id)
        source_dir = os.path.join(scan_dir, "source")
        
        # Clean up if exists
        if os.path.exists(source_dir):
            shutil.rmtree(source_dir)
        
        # Copy entire folder
        shutil.copytree(folder_path, source_dir)
        
        return source_dir
    
    def handle_raw_code(
        self,
        code: str,
        scan_id: str,
        language: Optional[str] = None,
        filename: Optional[str] = None
    ) -> str:
        """
        Handle raw code paste
        
        Args:
            code: Raw source code
            scan_id: Unique scan identifier
            language: Programming language (for file extension)
            filename: Optional specific filename
        
        Returns:
            Path to source file
        """
        scan_dir = self._get_scan_dir(scan_id)
        source_dir = os.path.join(scan_dir, "source")
        
        # Clean up if exists
        if os.path.exists(source_dir):
            shutil.rmtree(source_dir)
        
        os.makedirs(source_dir)
        
        # Determine filename
        if not filename:
            ext = self._get_extension_from_language(language) or ".txt"
            filename = f"source{ext}"
        
        file_path = os.path.join(source_dir, filename)
        
        # Write code to file
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(code)
        
        return source_dir
    
    def _get_extension_from_language(self, language: Optional[str]) -> Optional[str]:
        """Get file extension from language name"""
        if not language:
            return None
        
        lang_map = {
            'python': '.py',
            'javascript': '.js',
            'typescript': '.ts',
            'java': '.java',
            'c': '.c',
            'cpp': '.cpp',
            'c++': '.cpp',
            'go': '.go',
            'rust': '.rs',
            'ruby': '.rb',
            'php': '.php',
            'csharp': '.cs',
            'c#': '.cs',
            'swift': '.swift',
            'kotlin': '.kt',
            'scala': '.scala',
            'r': '.r',
            'perl': '.pl',
            'shell': '.sh',
            'sql': '.sql',
            'html': '.html',
            'css': '.css',
            'xml': '.xml',
            'json': '.json',
            'yaml': '.yaml'
        }
        
        return lang_map.get(language.lower())
    
    def cleanup(self, scan_id: str):
        """Clean up scan directory"""
        scan_dir = os.path.join(self.temp_base, scan_id)
        if os.path.exists(scan_dir):
            shutil.rmtree(scan_dir)
    
    def get_source_info(self, source_dir: str) -> dict:
        """Get information about source directory"""
        info = {
            "total_files": 0,
            "total_lines": 0,
            "languages": {},
            "file_list": []
        }
        
        for root, dirs, files in os.walk(source_dir):
            # Skip hidden directories
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, source_dir)
                
                # Skip binary files
                if self._is_binary(file_path):
                    continue
                
                # Detect language
                ext = os.path.splitext(file)[1].lower()
                lang = self._get_language_from_ext(ext)
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = len(f.readlines())
                        info["total_files"] += 1
                        info["total_lines"] += lines
                        info["file_list"].append(rel_path)
                        
                        if lang:
                            info["languages"][lang] = info["languages"].get(lang, 0) + lines
                except Exception:
                    pass
        
        return info
    
    def _is_binary(self, file_path: str, chunk_size: int = 1024) -> bool:
        """Check if file is binary"""
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(chunk_size)
                return b'\0' in chunk
        except Exception:
            return True
    
    def _get_language_from_ext(self, ext: str) -> Optional[str]:
        """Get programming language from file extension"""
        lang_map = {
            '.py': 'Python',
            '.js': 'JavaScript',
            '.ts': 'TypeScript',
            '.jsx': 'JavaScript',
            '.tsx': 'TypeScript',
            '.java': 'Java',
            '.c': 'C',
            '.cpp': 'C++',
            '.cc': 'C++',
            '.h': 'C/C++',
            '.hpp': 'C++',
            '.go': 'Go',
            '.rs': 'Rust',
            '.rb': 'Ruby',
            '.php': 'PHP',
            '.cs': 'C#',
            '.swift': 'Swift',
            '.kt': 'Kotlin',
            '.scala': 'Scala',
            '.r': 'R',
            '.m': 'Objective-C',
            '.mm': 'Objective-C++',
            '.pl': 'Perl',
            '.sh': 'Shell',
            '.sql': 'SQL',
            '.html': 'HTML',
            '.css': 'CSS',
            '.xml': 'XML',
            '.json': 'JSON',
            '.yaml': 'YAML',
            '.yml': 'YAML'
        }
        return lang_map.get(ext)
    
    def detect_binary_files(self, source_dir: str) -> List[str]:
        """Detect binary files that might need Kaitai Struct parsing"""
        binary_extensions = {'.bin', '.hex', '.ksy', '.dat', '.raw'}
        binary_files = []
        
        for root, dirs, files in os.walk(source_dir):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in binary_extensions or self._is_binary(os.path.join(root, file)):
                    rel_path = os.path.relpath(os.path.join(root, file), source_dir)
                    binary_files.append(rel_path)
        
        return binary_files


# Global source handler instance
source_handler = SourceHandler()


def get_source_handler() -> SourceHandler:
    """Get the global source handler instance"""
    return source_handler
