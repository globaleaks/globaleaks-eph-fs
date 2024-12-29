# GLOBALEAKS-EPH-FS
An ephemeral ChaCha20-encrypted filesystem implementation using fusepy and cryptography suitable for privacy-sensitive applications, such as whistleblowing platforms.

[![Status](https://img.shields.io/static/v1?label=License&message=AGPLv3+%2B&color=%3CCOLOR%3E)](https://github.com/globaleaks/globaleaks-eph-fs/blob/main/LICENSE) [![build workflow](https://github.com/globaleaks/globaleaks-eph-fs/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/globaleaks/globaleaks-eph-fs/actions/workflows/test.yml?query=branch%3Amain) [![Codacy Badge](https://app.codacy.com/project/badge/Grade/16022819c993415e8c82c25fd7654926)](https://app.codacy.com/gh/globaleaks/globaleaks-eph-fs/dashboard) [![Codacy Badge](https://app.codacy.com/project/badge/Coverage/16022819c993415e8c82c25fd7654926)](https://app.codacy.com/gh/globaleaks/globaleaks-eph-fs/dashboard)

## Overview
`GLOBALEAKS-EPH-FS` provides an ephemeral, ChaCha20-encrypted filesystem implementation using Python, FUSE, and Cryptography. This filesystem is designed for temporary, secure storage with strong encryption, making it ideal for privacy-sensitive applications like whistleblowing platforms.

## Threat Model

### Assumptions
- The filesystem is designed to pass confidential files to antivirus scanners (e.g., [ClamAV](https://github.com/Cisco-Talos/clamav), [MAT2](https://0xacab.org/jvoisin/mat2)).
- The filesystem is ephemeral, meaning files are temporarily encrypted and erased after use.
- The filesystem operates in environments where privacy and confidentiality are crucial.
- The filesystem assumes that only authorized users, without root access or elevated privileges, interact with the system.

### Potential Threats & Mitigations

1. **Unauthorized File Access**:
   - **Threat**: Unauthorized users may attempt to access confidential files stored in the filesystem.
   - **Mitigation**: 
     - Data is primarily managed in RAM. The files are decrypted only temporarily in memory during processing and are never stored in plaintext on disk.
     - Filesystem permissions control access, allowing only authorized users to read files automatically decrypted on-access.

2. **Metadata Exposure**:
   - **Threat**: Sensitive metadata, such as filenames, directory structures, or file sizes, could be exposed to unauthorized users or stored in operating system caches.
   - **Mitigation**: UUID4 filenames are used, preventing any identifiable information from being exposed. This approach also mitigates risks from OS-level cache leaks, as filenames are randomized and non-meaningful.

3. **Data Tampering or Integrity Issues**:
   - **Threat**: An attacker could attempt to tamper with files by modifying their content or structure.
   - **Mitigation**: Filesystem permissions restrict write access to authorized users only, preventing unauthorized modifications to files.

### Conclusion
The ephemeral filesystem provides robust protection for confidential files through ChaCha20 encryption, randomized UUID4 filenames, and strict filesystem permissions that limit access and modification to authorized users. These features address the risks of unauthorized access, metadata exposure, and data tampering, ensuring the privacy and integrity of sensitive data during the scanning process.


## Installation

To install the package, use `pip`:

```bash
pip install globaleaks-eph-fs
```

## Usage

### Command-Line Interface (CLI)

To mount the filesystem from the command line:

```bash
globaleaks-eph-fs [--storage_directory <directory>] <mountpoint>
```

- `--storage_directory STORAGE_DIRECTORY` (optional): The directory used for storage. If not provided, a temporary directory will be used.
- `<mountpoint>`: The path where the filesystem will be mounted.

### Python API

You can also use `globaleaks-eph-fs` within your Python code. Here's an example:

```python
from globaleaks_eph_fs import mount_globaleaks_eph_fs

eph_fs_thread = mount_globaleaks_eph_fs("/mnt/globaleaks-eph-fs")

eph_fs_thread.join()
```

## Features

- **ChaCha20 Encryption**: All data stored in the filesystem is encrypted with ChaCha20.
- **FUSE Integration**: Mount the filesystem as a virtual disk using FUSE.
- **Temporary Storage**: The filesystem is ephemeral and can use a temporary directory for storage.
- **Metadata Free**: The filesystem preserves only files content enforcing random uuid4 files' names.

## Requirements

- Python 3.7+
- `fusepy` for FUSE support
- `cryptography` for encryption

## License

This project is licensed under the AGPLv3 License - see the [LICENSE](LICENSE) file for details.
