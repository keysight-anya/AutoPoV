"""
AutoPoV Source Handler Module
Handles ZIP uploads, file/folder uploads, and raw code paste
"""

import os
import shutil
import tempfile
import zipfile
import tarfile
from pathlib import Path
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
        scan_dir = self._get_scan_dir(scan_id)
        extract_dir = os.path.join(scan_dir, "source")
        
        # Clean up if exists
        if os.path.exists(extract_dir):
            shutil.rmtree(extract_dir)
        
        os.makedirs(extract_dir)
        
        # Extract ZIP
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # Security: Check for path traversal
            for member in zip_ref.namelist():
                member_path = os.path.join(extract_dir, member)
                if not member_path.startswith(os.path.abspath(extract_dir)):
                    raise ValueError(f"Path traversal detected in ZIP: {member}")
            
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
        scan_dir = self._get_scan_dir(scan_id)
        extract_dir = os.path.join(scan_dir, "source")
        
        # Clean up if exists
        if os.path.exists(extract_dir):
            shutil.rmtree(extract_dir)
        
        os.makedirs(extract_dir)
        
        # Open TAR with appropriate compression
        mode = 'r'
        if compression == 'gz':
            mode = 'r:gz'
        elif compression == 'bz2':
            mode = 'r:bz2'
        elif compression == 'xz':
            mode = 'r:xz'
        
        with tarfile.open(tar_path, mode) as tar_ref:
            # Security: Check for path traversal
            for member in tar_ref.getmembers():
                member_path = os.path.join(extract_dir, member.name)
                if not member_path.startswith(os.path.abspath(extract_dir)):
                    raise ValueError(f"Path traversal detected in TAR: {member.name}")
            
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
        
        for file_path in file_paths:
            if os.path.isfile(file_path):
                if preserve_structure:
                    # Preserve relative path structure under source_dir
                    rel = os.path.relpath(file_path)
                    dest_path = os.path.join(source_dir, rel)
                    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                else:
                    dest_path = os.path.join(source_dir, os.path.basename(file_path))

                shutil.copy2(file_path, dest_path)
        
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
