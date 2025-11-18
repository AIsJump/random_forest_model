import pefile
import hashlib
import json
import math
import os
import re
import zipfile
import tempfile
from pathlib import Path
from features_config import FEATURE_KEYS


class MalwareFeatureExtractor:
    def __init__(self, zip_password=None, verbose=True):
        self.zip_password = zip_password
        self.verbose = verbose
        self.stats = {
            'processed_count': 0,
            'skipped_count': 0,
            'total_size': 0,
            'skipped_files': []
        }
    
    # ========== HELPER METHODS ==========
    
    @staticmethod
    def compute_sha256(data):
        """Compute SHA256 from bytes data."""
        h = hashlib.sha256()
        h.update(data)
        return h.hexdigest()

    @staticmethod
    def compute_entropy(data):
        """Compute Shannon entropy of binary data."""
        if not data:
            return 0.0
        occur = [0] * 256
        for byte in data:
            occur[byte] += 1
        ent = 0.0
        for count in occur:
            if count == 0:
                continue
            p = count / len(data)
            ent -= p * math.log2(p)
        return ent
    
    @staticmethod
    def sample_entropy_lightweight(data):
        """Compute entropy using aggressive sampling for low-memory systems."""
        if len(data) <= 2 * 1024 * 1024:  # If under 2MB, use full data
            return MalwareFeatureExtractor.compute_entropy(data)
        
        # sample first 1MB + last 1MB (skip middle for low-memory)
        samples = data[:1024*1024] + data[-1024*1024:]
        return MalwareFeatureExtractor.compute_entropy(samples)

    @staticmethod
    def extract_strings(data, min_len=4):
        """Extract strings from binary data, with size limit to avoid processing huge files."""
        # only scan first 10MB; avoid slow string extraction on large files
        max_scan = min(len(data), 10 * 1024 * 1024)
        pattern = rb"[ -~]{%d,}" % min_len
        return re.findall(pattern, data[:max_scan])

    @staticmethod
    def count_urls(strings):
        url_re = re.compile(br"(http|https|ftp)://", re.IGNORECASE)
        return sum(1 for s in strings if url_re.search(s))

    @staticmethod
    def count_paths(strings):
        path_re = re.compile(br"[A-Za-z]:\\\\")
        return sum(1 for s in strings if path_re.search(s))

    @staticmethod
    def has_suspicious_section_name(section_name):
        suspicious_names = [
            b'.upx', b'UPX', b'.aspack', b'.packed', b'.themida', b'.themi',
            b'.petite', b'.PEtite', b'.yoda', b'.Yoda', b'.npack', b'.mpress',
            b'.execryptor', b'.confuser', b'.dotnet', b'_CorExeMain',
            b'.code', b'.ctext', b'.rdata', b'.reloc', b'.rsrc', b'.data',
            b'CODE', b'DATA', b'INITKIND', b'.packed',b'!This', b'RichSignature'
        ]
        
        # section name is unusual
        if not section_name or len(section_name.strip(b'\x00')) == 0:
            return True
        
        name_lower = section_name.lower()
        for suspicious in suspicious_names:
            if suspicious.lower() in name_lower:
                return True
        
        return False

    @staticmethod
    def count_suspicious_keywords(strings):
        keywords = [
            b'execute', b'cmd', b'powershell', b'bypass', b'admin',
            b'inject', b'hook', b'virus', b'malware', b'trojan',
            b'ransomware', b'exploit', b'payload', b'shellcode',
            b'rootkit', b'backdoor', b'remote', b'command',
        ]
        count = 0
        for s in strings:
            s_lower = s.lower()
            for keyword in keywords:
                if keyword in s_lower:
                    count += 1
                    break  # count each string only once
        return count

    @staticmethod
    def count_registry_keys(strings):
        reg_re = re.compile(b'HKEY_', re.IGNORECASE)
        return sum(1 for s in strings if reg_re.search(s))
    
    # ========== FEATURE EXTRACTION ==========
    
    def extract_pe_features(self, path):
        features = {}
        raw = Path(path).read_bytes()
        features["file_size"] = len(raw)
        features["sha256"] = self.compute_sha256(raw)

        try:
            pe = pefile.PE(path, fast_load=True)
            features["is_pe"] = 1
        except Exception:
            # not valid PE file
            return None

        # ========== PE HEADER ==========
        features["num_sections"] = len(pe.sections)
        features["timestamp"] = pe.FILE_HEADER.TimeDateStamp
        features["characteristics"] = pe.FILE_HEADER.Characteristics
        features["machine"] = pe.FILE_HEADER.Machine

        try:
            features["subsystem"] = pe.OPTIONAL_HEADER.Subsystem
        except:
            features["subsystem"] = 0

        # Header and structure features
        try:
            # binary type flags
            is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)  # DLL flag
            is_executable = bool(pe.FILE_HEADER.Characteristics & 0x0002)  # EXECUTABLE_IMAGE flag
            features["is_dll"] = int(is_dll)
            features["is_executable"] = int(is_executable)
            
            # code and data sizes
            features["size_of_code"] = pe.OPTIONAL_HEADER.SizeOfCode
            features["size_of_initialized_data"] = pe.OPTIONAL_HEADER.SizeOfInitializedData
            
            # entry point address
            features["entry_point"] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            
            # header size (suspicious if too large or too small)
            features["size_of_headers"] = pe.OPTIONAL_HEADER.SizeOfHeaders
            
            # checksum
            features["checksum"] = pe.OPTIONAL_HEADER.CheckSum
        except:
            features["is_dll"] = 0
            features["is_executable"] = 0
            features["size_of_code"] = 0
            features["size_of_initialized_data"] = 0
            features["entry_point"] = 0
            features["size_of_headers"] = 0
            features["checksum"] = 0

        # ========== SECTION ENTROPY ==========
        entropies = []
        sec_lens = []
        num_writable_sections = 0
        has_rwx_section = 0
        num_exec_section = 0
        num_non_exec_section = 0
        has_suspicious_section_names = 0
        
        for sec in pe.sections:
            try:
                data = sec.get_data()
                data_len = len(data)
                sec_lens.append(data_len)
                # for large sections, use lightweight sampling (1MB + 1MB instead of 5MB+2.5MB+2.5MB)
                if data_len > 10 * 1024 * 1024:
                    entropies.append(self.sample_entropy_lightweight(data))
                else:
                    entropies.append(self.compute_entropy(data))
            except:
                continue
            
            # writable and executable flags
            try:
                sec_chars = sec.Characteristics
                # 0x80000000 = WRITABLE, 0x20000000 = EXECUTABLE
                is_writable = bool(sec_chars & 0x80000000)
                is_executable = bool(sec_chars & 0x20000000)
                
                if is_writable:
                    num_writable_sections += 1

                if is_executable:
                    num_exec_section += 1
                else:
                    num_non_exec_section += 1
                
                # check RWX
                if is_writable and is_executable:
                    has_rwx_section = 1
                
                # check section name
                if self.has_suspicious_section_name(sec.Name):
                    has_suspicious_section_names = 1
            except:
                continue
        
        features["num_writable_sections"] = num_writable_sections
        features["has_rwx_section"] = has_rwx_section
        features["has_suspicious_section_names"] = has_suspicious_section_names
        
        # entropy statistics
        if entropies:
            features["max_section_entropy"] = max(entropies)
            features["mean_section_entropy"] = sum(entropies) / len(entropies)
            features["min_section_entropy"] = min(entropies)
            features["std_section_entropy"] = (sum((e - features["mean_section_entropy"])**2 for e in entropies) / len(entropies))**0.5
        else:
            features["max_section_entropy"] = 0
            features["mean_section_entropy"] = 0
            features["min_section_entropy"] = 0
            features["std_section_entropy"] = 0
        
        # section size statistics
        if sec_lens:
            features["max_section_size"] = max(sec_lens)
            features["mean_section_size"] = sum(sec_lens) / len(sec_lens)
            features["min_section_size"] = min(sec_lens)
            features["std_section_size"] = (sum((s - features["mean_section_size"])**2 for s in sec_lens) / len(sec_lens))**0.5
            features["num_large_sections"] = sum(s > 500 * 1024 for s in sec_lens)  # > 500KB
        else:
            features["max_section_size"] = 0
            features["mean_section_size"] = 0
            features["min_section_size"] = 0
            features["std_section_size"] = 0
            features["num_large_sections"] = 0

        # ========== IMPORTS ==========
        imports = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode(errors="ignore").lower()
                for imp in entry.imports:
                    if imp.name:
                        imports.append(imp.name.decode(errors="ignore").lower())

        features["num_imported_dlls"] = len({imp.dll for imp in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])}) \
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT") else 0

        features["num_imported_functions"] = len(imports)

        # API presence flags
        def has_api(name):
            name = name.lower()
            return int(any(name in imp for imp in imports))

        # basic API flags; should remove common ones later
        features["uses_CreateProcess"] = has_api("createprocess")
        features["uses_VirtualAlloc"] = has_api("virtualalloc")
        features["uses_LoadLibrary"] = has_api("loadlibrary")
        features["uses_GetProcAddress"] = has_api("getprocaddress")
        features["uses_InternetConnect"] = has_api("internetconnect")
        features["uses_RegOpenKeyEx"] = has_api("regopenkeyex")
        
        features["uses_CreateRemoteThread"] = has_api("createremotethread")
        features["uses_WriteProcessMemory"] = has_api("writeprocessmemory")
        features["uses_ShellExecute"] = has_api("shellexecute")
        features["uses_WinExec"] = has_api("winexec")
        
        features["uses_SetWindowsHookEx"] = has_api("setwindowshookex")
        features["uses_RegSetValueEx"] = has_api("regsetvalueex")
        
        features["uses_CreateService"] = has_api("createservice")

        # ========== STRINGS ==========
        strs = self.extract_strings(raw)
        features["num_strings"] = len(strs)
        if strs:
            features["avg_string_length"] = sum(len(s) for s in strs) / len(strs)
            features["max_string_length"] = max(len(s) for s in strs)
        else:
            features["avg_string_length"] = 0
            features["max_string_length"] = 0

        features["num_urls"] = self.count_urls(strs)
        features["num_filepaths"] = self.count_paths(strs)
        features["num_suspicious_keywords"] = self.count_suspicious_keywords(strs)
        features["num_registry_keys"] = self.count_registry_keys(strs)

        # ========== RESOURCE FEATURES ==========
        has_resources = 0
        num_resources = 0
        has_version_info = 0
        has_manifest = 0
        
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                has_resources = 1

                def count_resources(res_dir):
                    count = 0
                    for res_type in res_dir.entries:
                        if hasattr(res_type, 'directory'):
                            for res_id in res_type.directory.entries:
                                if hasattr(res_id, 'directory'):
                                    for res_lang in res_id.directory.entries:
                                        count += 1
                        else:
                            count += 1
                    return count
                num_resources = count_resources(pe.DIRECTORY_ENTRY_RESOURCE)
                
                for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if res_type.struct.Id == 16:  # RT_VERSION
                        has_version_info = 1
                    elif res_type.struct.Id == 24:  # RT_MANIFEST
                        has_manifest = 1
        except:
            pass
        
        features["has_resources"] = has_resources
        features["num_resources"] = num_resources
        features["has_version_info"] = has_version_info
        features["has_manifest"] = has_manifest

        # ========== CODE QUALITY FEATURES ==========
        try:
            code_size = pe.OPTIONAL_HEADER.SizeOfCode
            data_size = pe.OPTIONAL_HEADER.SizeOfInitializedData
            
            if data_size > 0:
                features["code_to_data_ratio"] = code_size / data_size
            else:
                features["code_to_data_ratio"] = 0 if code_size == 0 else float('inf')
            
            # relocations
            has_relocations = 0
            if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
                has_relocations = 1
            features["has_relocations"] = has_relocations
            
            # ASLR flag (DLL characteristic 0x0040 = DYNAMIC_BASE)
            is_aslr = 0
            if pe.FILE_HEADER.Characteristics & 0x0040:
                is_aslr = 1
            features["is_aslr_enabled"] = is_aslr
        except:
            features["code_to_data_ratio"] = 0
            features["has_relocations"] = 0
            features["is_aslr_enabled"] = 0

        return features
    
    # ========== BATCH OPERATIONS ==========
    
    def extract_from_zip(self, zip_path, temp_dir=None):
        """Extract and process files from a zip archive. Returns list of feature dicts."""
        if temp_dir is None:
            temp_dir = tempfile.mkdtemp()
        
        features_list = []
        
        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                # zip is password protected
                if zf.namelist() and zf.getinfo(zf.namelist()[0]).flag_bits & 0x1:
                    if self.zip_password is None:
                        if self.verbose:
                            print(f"[WARN] {zip_path} is password protected. Skipping.")
                        return features_list
                    password_bytes = self.zip_password.encode('utf-8') if isinstance(self.zip_password, str) else self.zip_password
                else:
                    password_bytes = self.zip_password.encode('utf-8') if self.zip_password else None
                
                for file_info in zf.filelist:
                    if file_info.is_dir():
                        continue
                    
                    try:
                        # extract to temp directory with password if needed; unneeded in docker
                        extracted_path = zf.extract(file_info, temp_dir, pwd=password_bytes)
                        
                        try:
                            feat = self.extract_pe_features(extracted_path)
                            if feat is not None:  # only add if it's a valid PE file
                                features_list.append(feat)
                                self.stats['processed_count'] += 1
                                self.stats['total_size'] += feat["file_size"]
                                if self.verbose:
                                    print(f"[OK] {zip_path}:{file_info.filename}")
                            else:
                                self.stats['skipped_count'] += 1
                                self.stats['skipped_files'].append(f"{zip_path}:{file_info.filename}")
                        except Exception as e:
                            if self.verbose:
                                print(f"[FAIL] {zip_path}:{file_info.filename}: {e}")
                        finally:
                            # clean up extracted file; unneeded in docker
                            try:
                                os.remove(extracted_path)
                            except:
                                pass
                    except RuntimeError as e:
                        if "Bad password" in str(e) or "Bad CRC" in str(e):
                            if self.verbose:
                                print(f"[ERROR] {zip_path}: Incorrect password or corrupted file")
                        else:
                            if self.verbose:
                                print(f"[FAIL] {zip_path}:{file_info.filename}: {e}")
        except Exception as e:
            if self.verbose:
                print(f"[ERROR] Failed to read zip {zip_path}: {e}")
        
        return features_list

    def _print_progress_bar(self, iteration, total, prefix='Progress:', suffix='Complete', length=40):
        if total == 0:
            return
        percent = 100 * (iteration / float(total))
        filled = int(length * iteration // total)
        bar = '█' * filled + '░' * (length - filled)
        print(f'\r{prefix} |{bar}| {percent:.1f}% ({iteration}/{total}) {suffix}', end='', flush=True)
        if iteration == total:
            print()

    def extract_directory(self, dir_path):
        self.stats = {
            'processed_count': 0,
            'skipped_count': 0,
            'total_size': 0,
            'skipped_files': []
        }
        
        path_obj = Path(dir_path)
        features_list = []
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # zip
            if path_obj.is_file() and path_obj.suffix.lower() in ['.zip', '.zipx']:
                if self.verbose:
                    print(f"\nProcessing: {path_obj.name}")
                try:
                    zip_features = self.extract_from_zip(str(path_obj), temp_dir)
                    features_list.extend(zip_features)
                    if self.verbose:
                        print(f"{path_obj.name}: ✓ Complete")
                except Exception as e:
                    if self.verbose:
                        print(f"{path_obj.name}: ✗ Failed - {e}")
            
            # directory
            elif path_obj.is_dir():
                items = []
                for item in path_obj.iterdir():
                    items.append(item)
                
                # directory contains subdirs/zips or just files
                has_subdirs_or_zips = any(
                    item.is_dir() or item.suffix.lower() in ['.zip', '.zipx']
                    for item in items
                )
                
                if has_subdirs_or_zips:
                    # directory with subdirs/zips - stream processing
                    for item in items:
                        item_name = item.name
                        
                        if item.is_dir():
                            # process directory: stream files without loading all at once
                            files_in_dir = []
                            for f in item.iterdir():
                                if f.is_file():
                                    files_in_dir.append(f)
                            
                            total_files = len(files_in_dir)
                            
                            if self.verbose and total_files > 0:
                                print(f"\nProcessing: {item_name}")
                            
                            for idx, file_path in enumerate(files_in_dir, 1):
                                if self.verbose:
                                    self._print_progress_bar(idx, total_files, prefix=f'{item_name}:', suffix='files')
                                
                                try:
                                    feat = self.extract_pe_features(str(file_path))
                                    if feat is not None:
                                        features_list.append(feat)
                                        self.stats['processed_count'] += 1
                                        self.stats['total_size'] += feat["file_size"]
                                    else:
                                        self.stats['skipped_count'] += 1
                                        self.stats['skipped_files'].append(str(file_path))
                                except Exception as e:
                                    pass
                                finally:
                                    del feat # for low memory systems
                        
                        elif item.is_file() and item.suffix.lower() in ['.zip', '.zipx']:
                            if self.verbose:
                                print(f"\nProcessing: {item_name}")
                            
                            try:
                                zip_features = self.extract_from_zip(str(item), temp_dir)
                                features_list.extend(zip_features)
                                if self.verbose:
                                    print(f"{item_name}: ✓ Complete")
                            except Exception as e:
                                if self.verbose:
                                    print(f"{item_name}: ✗ Failed - {e}")
                            finally:
                                del zip_features
                
                else:
                    # directory with only files
                    files = []
                    for f in items:
                        if f.is_file():
                            files.append(f)
                    
                    total_files = len(files)
                    
                    if self.verbose and total_files > 0:
                        print(f"\nProcessing: {path_obj.name}")
                    
                    for idx, file_path in enumerate(files, 1):
                        if self.verbose:
                            self._print_progress_bar(idx, total_files, prefix=f'{path_obj.name}:', suffix='files')
                        
                        try:
                            feat = self.extract_pe_features(str(file_path))
                            if feat is not None:
                                features_list.append(feat)
                                self.stats['processed_count'] += 1
                                self.stats['total_size'] += feat["file_size"]
                            else:
                                self.stats['skipped_count'] += 1
                                self.stats['skipped_files'].append(str(file_path))
                        except Exception as e:
                            pass
                        finally:
                            del feat
        
        return features_list

    def extract_directory_to_file(self, dir_path, output_jsonl):
        features_list = self.extract_directory(dir_path)
        
        with open(output_jsonl, "a") as out:
            for feat in features_list:
                out.write(json.dumps(feat) + "\n")
        
        print(f"\n[SUMMARY] Features written to: {output_jsonl}")
        print(f"[SUMMARY] Files processed: {self.stats['processed_count']}")
        print(f"[SUMMARY] Total size of processed files: {self.stats['total_size']:,} bytes ({self.stats['total_size'] / (1024**3):.2f} GB)")
        print(f"[SUMMARY] Files skipped: {self.stats['skipped_count']}")
        
        if self.stats['skipped_count'] > 0:
            skip_log = output_jsonl.replace(".jsonl", "_skipped.log").replace(".json", "_skipped.log")
            with open(skip_log, "a") as log:
                for skipped_file in self.stats['skipped_files']:
                    log.write(f"{skipped_file}\n")
            print(f"[SUMMARY] Skipped files logged to: {skip_log}")


if __name__ == "__main__":
    import sys
    
    def get_top_level_items(dir_path):
        items = []
        try:
            for item in Path(dir_path).iterdir():
                if item.is_dir() or item.suffix.lower() in ['.zip', '.zipx']:
                    items.append(item.name)
        except FileNotFoundError:
            return []
        return sorted(items)
    
    def select_items_to_process():
        """Interactively select which directories/zips to process."""
        goodware_items = get_top_level_items("goodware")
        malware_items = get_top_level_items("malware")
        
        print("\n" + "="*60)
        print("MALWARE FEATURE EXTRACTION")
        print("="*60)
        
        print("\n[GOODWARE] Available items:")
        for i, item in enumerate(goodware_items, 1):
            print(f"  {i}. {item}")
        print(f"  {len(goodware_items) + 1}. Process all")
        print(f"  {len(goodware_items) + 2}. Skip goodware")
        
        goodware_selection = []
        goodware_process_all = False
        while True:
            try:
                choice = input(f"\nSelect goodware (1-{len(goodware_items) + 2}): ").strip()
                if not choice:
                    continue
                choice = int(choice)
                if 1 <= choice <= len(goodware_items):
                    goodware_selection = [goodware_items[choice - 1]]
                    print(f"Selected: {goodware_selection[0]}")
                    break
                elif choice == len(goodware_items) + 1:
                    goodware_selection = goodware_items
                    goodware_process_all = True
                    print(f"Selected all {len(goodware_selection)} goodware items")
                    break
                elif choice == len(goodware_items) + 2:
                    goodware_selection = []
                    print("Skipping goodware")
                    break
                else:
                    print(f"Invalid choice. Please enter 1-{len(goodware_items) + 2}")
            except ValueError:
                print("Invalid input, please enter a number.")
        
        print("\n[MALWARE] Available items:")
        for i, item in enumerate(malware_items, 1):
            print(f"  {i}. {item}")
        print(f"  {len(malware_items) + 1}. Process all")
        print(f"  {len(malware_items) + 2}. Skip malware")
        
        malware_selection = []
        malware_process_all = False
        while True:
            try:
                choice = input(f"\nSelect malware (1-{len(malware_items) + 2}): ").strip()
                if not choice:
                    continue
                choice = int(choice)
                if 1 <= choice <= len(malware_items):
                    malware_selection = [malware_items[choice - 1]]
                    print(f"Selected: {malware_selection[0]}")
                    break
                elif choice == len(malware_items) + 1:
                    malware_selection = malware_items
                    malware_process_all = True
                    print(f"Selected all {len(malware_selection)} malware items")
                    break
                elif choice == len(malware_items) + 2:
                    malware_selection = []
                    print("Skipping malware")
                    break
                else:
                    print(f"Invalid choice. Please enter 1-{len(malware_items) + 2}")
            except ValueError:
                print("Invalid input, please enter a number.")
        
        return goodware_selection, malware_selection, goodware_process_all, malware_process_all
    
    goodware_items, malware_items, goodware_all, malware_all = select_items_to_process()
    
    total_processed = 0
    total_skipped = 0
    total_size = 0
    goodware_processed = 0
    goodware_skipped = 0
    goodware_size = 0
    malware_processed = 0
    malware_skipped = 0
    malware_size = 0
    
    # process goodware
    if goodware_items:
        print("\n" + "="*60)
        print(f"Processing {len(goodware_items)} goodware item(s)...")
        print("="*60)
        extractor = MalwareFeatureExtractor(verbose=True)
        for item in goodware_items:
            item_path = f"goodware/{item}"

            # use goodware.jsonl if "Process all" was chosen
            output_file = "goodware_data/goodware.jsonl" if goodware_all else f"goodware_data/{item}.jsonl"
            print(f"\n>> Processing: {item} -> {output_file}")

            # clear output file
            if not goodware_all or item == goodware_items[0]:
                with open(output_file, "w") as f:
                    pass
            extractor.extract_directory_to_file(item_path, output_file)
            goodware_processed += extractor.stats['processed_count']
            goodware_skipped += extractor.stats['skipped_count']
            goodware_size += extractor.stats['total_size']
        total_processed += goodware_processed
        total_skipped += goodware_skipped
        total_size += goodware_size
    
    # process malware
    if malware_items:
        print("\n" + "="*60)
        print(f"Processing {len(malware_items)} malware item(s)...")
        print("="*60)
        extractor = MalwareFeatureExtractor(zip_password="infected", verbose=True)
        for item in malware_items:
            item_path = f"malware/{item}"

            # use malware.jsonl only if "Process all" was chosen
            if malware_all:
                output_file = "malware_data/malware.jsonl"
            else:
                item_base = item.replace('.zip', '').replace('.zipx', '')
                output_file = f"malware_data/{item_base}.jsonl"
            print(f"\n>> Processing: {item} -> {output_file}")

            # clear output file
            if not malware_all or item == malware_items[0]:
                with open(output_file, "w") as f:
                    pass
            extractor.extract_directory_to_file(item_path, output_file)
            malware_processed += extractor.stats['processed_count']
            malware_skipped += extractor.stats['skipped_count']
            malware_size += extractor.stats['total_size']
        total_processed += malware_processed
        total_skipped += malware_skipped
        total_size += malware_size
    
    if not goodware_items and not malware_items:
        print("\nNo items selected. Exiting.")
        sys.exit(0)
    
    # total summary
    print("\n" + "="*60)
    print("TOTAL SUMMARY")
    print("="*60)
    if goodware_items:
        print(f"Goodware:")
        print(f"  Files processed: {goodware_processed}")
        print(f"  Files skipped: {goodware_skipped}")
        print(f"  Total size: {goodware_size:,} bytes ({goodware_size / (1024**3):.2f} GB)")
    if malware_items:
        print(f"Malware:")
        print(f"  Files processed: {malware_processed}")
        print(f"  Files skipped: {malware_skipped}")
        print(f"  Total size: {malware_size:,} bytes ({malware_size / (1024**3):.2f} GB)")
    if goodware_items and malware_items:
        print("-" * 60)
    print(f"Grand total:")
    print(f"  Files processed: {total_processed}")
    print(f"  Files skipped: {total_skipped}")
    print(f"  Total size: {total_size:,} bytes ({total_size / (1024**3):.2f} GB)")
    print("="*60)
