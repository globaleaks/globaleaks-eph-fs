import argparse
import errno
import os
import stat
import uuid
from fuse import FUSE, Operations
from tempfile import mkdtemp

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20


class EphemeralFile:
    def __init__(self, filesdir):
        """
        Initialize ChaCha20 encryption with a randomly generated key and nonce.
        """
        self.fd = None
        self.filename = str(uuid.uuid4())  # UUID as a string for the file name
        self.filepath = os.path.join(filesdir, self.filename)
        self.nonce = os.urandom(16) # 128-bit nonce
        self.key = os.urandom(32)   # 256-bit key
        self.cipher = Cipher(ChaCha20(self.key, self.nonce), mode=None)
        self.size = 0
        self.enc = self.cipher.encryptor()
        self.dec = None

    def open(self, mode):
        """
        Open the file for read or write operations.
        """
        if mode == 'w':
            self.fd = os.open(self.filepath, os.O_WRONLY | os.O_CREAT | os.O_APPEND)
            self.dec = None  # Reset decryption object on write mode
        else:
            self.fd = os.open(self.filepath, os.O_RDONLY)
            self.dec = self.cipher.decryptor()
        return self

    def write(self, data):
        """
        Write encrypted data to the file.
        """
        if isinstance(data, str):
            data = data.encode('utf-8')

        encrypted_data = self.enc.update(data)
        os.write(self.fd, encrypted_data)
        self.size += len(data)

    def read(self, c=4096):
        """
        Read and decrypt data from the file.
        """
        return self.dec.update(os.read(self.fd, c))

    def close(self):
        """
        Close the file descriptor.
        """
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __del__(self):
        """
        Ensure proper cleanup by closing and deleting the file.
        """
        self.close()
        try:
            os.remove(self.filepath)
        except FileNotFoundError:
            pass


class EphemeralOperations(Operations):
    def __init__(self, storage_directory=None):
        if storage_directory is None:
            storage_directory = mkdtemp()

        self.storage_directory = storage_directory
        self.files = {}  # Track open files and their secure temporary file handlers
        self.default_permissions = 0o660  # Default permissions for files (user read/write)
        self.uid = os.getuid()  # Current user's UID
        self.gid = os.getgid()  # Current user's GID
        self.use_ns = True  # Enable nanosecond precision for file times

    def getattr(self, path, fh=None):
        """Return the attributes of the file or directory."""
        if path == '/':
            # Return attributes for the root directory
            st = {
                'st_mode': (stat.S_IFDIR | 0o750),
                'st_nlink': 2,
            }
        else:
            # Check if the file exists
            file = self.files.get(path)

            if file is None or not os.path.exists(file.filepath):
                raise OSError(errno.ENOENT, "No such file or directory", path)

            # Get the file's metadata using os.stat()
            file_stat = os.stat(file.filepath)

            st = {
                'st_mode': (stat.S_IFREG | 0o660),
                'st_size': file.size,
                'st_nlink': 1,
                'st_uid': self.uid,    # User ID
                'st_gid': self.gid,    # Group ID
                'st_atime': file_stat.st_atime,
                'st_mtime': file_stat.st_mtime,
                'st_ctyme': file_stat.st_ctime
            }

        return st

    def readdir(self, path, fh):
        """Return the list of files in the directory."""
        return ['.', '..'] + [os.path.basename(f) for f in self.files]

    def create(self, path, mode):
        """Create a new encrypted file."""
        file = EphemeralFile(self.storage_directory)
        file.open('w')
        os.chmod(file.filepath, self.default_permissions)
        os.chown(file.filepath, self.uid, self.gid)
        self.files[path] = file

        return 0

    def open(self, path, flags):
        """Open an encrypted file."""
        file = self.files.get(path)
        if file is None:
            raise OSError(errno.ENOENT, "No such file or directory", path)
        mode = 'w' if (flags & os.O_RDWR or flags & os.O_WRONLY) else 'r'
        file.open(mode)
        return 0

    def write(self, path, data, offset, fh):
        """Write data to the encrypted file."""
        file = self.files.get(path)
        if file is None:
            raise OSError(errno.ENOENT, "No such file or directory", path)
        file.write(data)
        return len(data)

    def read(self, path, size, offset, fh):
        """Read data from the encrypted file."""
        file = self.files.get(path)
        if file is None:
            raise OSError(errno.ENOENT, "No such file or directory", path)
        os.lseek(file.fd, offset, os.SEEK_SET)  # Seek to the read offset
        return file.read(size)

    def release(self, path, fh):
        """Close the file."""
        file = self.files.get(path)
        if file:
            file.close()

    def unlink(self, path):
        """Remove a file."""
        file = self.files.pop(path, None)
        if file is None:
            raise OSError(errno.ENOENT, "No such file or directory", path)
        file.close()
        os.remove(file.filepath)


class EphemeralFS(FUSE):
    """
    A class that mounts an ephemeral filesystem at the given mount point.
    Inherits from FUSE to provide the filesystem mounting functionality.

    Args:
        mount_point (str): The path where the filesystem will be mounted.
        storage_directory (str, optional): The directory used for storage. If None, uses a temporary directory.
        **fuse_args: Additional arguments to pass to the FUSE constructor.
    """
    def __init__(self, mount_point, storage_directory=None, **fuse_args):
        self.mount_point = mount_point
        self.storage_directory = storage_directory

        # Create the mount point directory if it does not exist
        os.makedirs(self.mount_point, exist_ok=True)

        # If a storage directory is specified, create it as well
        if self.storage_directory:
            os.makedirs(self.storage_directory, exist_ok=True)
        else:
            self.storage_directory = None  # Default to None if not provided

        # Initialize the FUSE mount with the EphemeralFS
        super().__init__(EphemeralOperations(self.storage_directory), self.mount_point, **fuse_args)


def main():
    parser = argparse.ArgumentParser(description="GLOBALEAKS EPHEMERAL FS")
    parser.add_argument('mount_point', help="Path to mount the filesystem")
    parser.add_argument('--storage_directory', '-s', help="Optional storage directory. Defaults to a temporary directory.")
    args = parser.parse_args()

    EphemeralFS(args.mount_point, args.storage_directory, nothreads=True, foreground=True)


if __name__ == '__main__':
    main()
