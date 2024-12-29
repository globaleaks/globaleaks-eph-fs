# globaleaks-eph-fs
An ephemeral ChaCha20-encrypted filesystem implementation using fusepy and cryptography suitable for privacy-sensitive applications, such as whistleblowing platforms.

[![Status](https://img.shields.io/static/v1?label=License&message=AGPLv3+%2B&color=%3CCOLOR%3E)](https://github.com/globaleaks/globaleaks-eph-fs/blob/main/LICENSE) [![build workflow](https://github.com/globaleaks/globaleaks-eph-fs/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/globaleaks/globaleaks-eph-fs/actions/workflows/test.yml?query=branch%3Amain) [![Codacy Badge](https://app.codacy.com/project/badge/Grade/16022819c993415e8c82c25fd7654926)](https://app.codacy.com/gh/globaleaks/globaleaks-eph-fs/dashboard) [![Codacy Badge](https://app.codacy.com/project/badge/Coverage/16022819c993415e8c82c25fd7654926)](https://app.codacy.com/gh/globaleaks/globaleaks-eph-fs/dashboard)

## Overview
`globaleaks-eph-fs` provides an ephemeral, ChaCha20-encrypted filesystem implementation using Python, FUSE, and Cryptography. This filesystem is designed for temporary, secure storage with strong encryption, making it ideal for privacy-sensitive applications like whistleblowing platforms.

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
