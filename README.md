# globaleaks-eph-fs
An ephemeral ChaCha20-encrypted filesystem implementation using fusepy and cryptography suitable for privacy-sensitive applications, such as whistleblowing platforms.

[![build workflow](https://github.com/globaleaks/globaleaks-eph-fs/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/globaleaks/globaleaks-eph-fs/actions/workflows/test.yml?query=branch%3Amain) [![Codacy Badge](https://app.codacy.com/project/badge/Grade/16022819c993415e8c82c25fd7654926)](https://app.codacy.com/gh/globaleaks/globaleaks-eph-fs/dashboard) [![Codacy Badge](https://app.codacy.com/project/badge/Coverage/16022819c993415e8c82c25fd7654926)](https://app.codacy.com/gh/globaleaks/globaleaks-eph-fs/dashboard)

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
globaleaks-eph-fs <mountpoint> [--storage_directory <directory>]
```

- `<mountpoint>`: The path where the filesystem will be mounted.
- `--storage_directory` (optional): The directory used for storage. If not provided, a temporary directory will be used.

### Python API

You can also use `globaleaks-eph-fs` within your Python code. Here's an example:

```python
import argparse
from globaleaks_eph_fs import EphemeralFS

def main():
    parser = argparse.ArgumentParser(description="GLOBALEAKS EPHEMERAL FS")
    parser.add_argument('mount_point', help="Path to mount the filesystem")
    parser.add_argument('--storage_directory', '-s', help="Optional storage directory. Defaults to a temporary directory.")
    args = parser.parse_args()

    EphemeralFS(args.mount_point, args.storage_directory, nothreads=True, foreground=True)


if __name__ == '__main__':
    main()
```

### Arguments

- `mount_point` (required): The directory where the encrypted filesystem will be mounted.
- `--storage_directory` (optional): Specify a custom storage directory for the filesystem. If not provided, a temporary directory will be used.

## Features

- **ChaCha20 Encryption**: All data stored in the filesystem is encrypted with ChaCha20.
- **FUSE Integration**: Mount the filesystem as a virtual disk using FUSE.
- **Temporary Storage**: The filesystem is ephemeral and can use a temporary directory for storage.

## Requirements

- Python 3.7+
- `fusepy` for FUSE support
- `cryptography` for encryption

## License

This project is licensed under the AGPLv3 License - see the [LICENSE](LICENSE) file for details.
