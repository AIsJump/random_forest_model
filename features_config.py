# feature configuration for MalwareRandomForest and extract_features
FEATURE_KEYS = [
    "file_size",
    "sha256",
    "is_pe",

    # PE header
    "num_sections",
    "timestamp",
    "characteristics",
    "machine",
    "subsystem",
    "is_dll",
    "is_executable",
    "size_of_code",
    "size_of_initialized_data",
    "entry_point",
    "size_of_headers",
    "checksum",

    # section features
    "max_section_entropy",
    "mean_section_entropy",
    "min_section_entropy",
    "std_section_entropy",
    "max_section_size",
    "mean_section_size",
    "min_section_size",
    "std_section_size",
    "num_large_sections",
    "num_writable_sections",
    "has_rwx_section",
    "num_exec_sections",
    "num_non_exec_sections",
    "has_suspicious_section_names",

    # imports
    "num_imported_dlls",
    "num_imported_functions",
    "uses_CreateProcess",
    "uses_VirtualAlloc",
    "uses_LoadLibrary",
    "uses_GetProcAddress",
    "uses_InternetConnect",
    "uses_RegOpenKeyEx",
    "uses_CreateRemoteThread",
    "uses_WriteProcessMemory",
    "uses_ShellExecute",
    "uses_WinExec",
    "uses_SetWindowsHookEx",
    "uses_RegSetValueEx",
    "uses_CreateService",

    # string features
    "num_strings",
    "avg_string_length",
    "max_string_length",
    "num_urls",
    "num_filepaths",
    "num_suspicious_keywords",
    "num_registry_keys",

    # resource features
    "has_resources",
    "num_resources",
    "has_version_info",
    "has_manifest",

    # code quality features
    "code_to_data_ratio",
    "has_relocations",
    "is_aslr_enabled",
]
