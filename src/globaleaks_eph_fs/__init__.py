import argparse
import errno
import os
import stat
import uuid
import threading
from fuse import FUSE, FuseOSError, Operations
from tempfile import mkdtemp
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20

class EphemeralFile:
    def __init__(self, filesdir):
        """
        Initializes an ephemeral file with ChaCha20 encryption.
        Creates a new random file path and generates a unique encryption key and nonce.

        :param filesdir: The directory where the ephemeral file will be stored.
        """
        self.fd = None
        self.filename = str(uuid.uuid4())  # UUID as a string for the file name
        self.filepath = os.path.join(filesdir, self.filename)
        self.nonce = os.urandom(16)  # 128-bit nonce
        self.key = os.urandom(32)    # 256-bit key
        self.cipher = Cipher(ChaCha20(self.key, self.nonce), mode=None)
        self.size = 0
        self.position = 0
        self.enc = self.cipher.encryptor()
        self.dec = None
        self.creation_time = os.path.getctime(self.filepath) if os.path.exists(self.filepath) else None
        self.last_access_time = None
        self.last_mod_time = None
        self.mutex = threading.Lock()

    def open(self, mode):
        """
        Opens the ephemeral file for reading or writing.

        :param mode: 'w' for writing, 'r' for reading.
        :return: The file object.
        """
        with self.mutex:
            if mode == 'w':
                self.fd = os.open(self.filepath, os.O_RDWR | os.O_CREAT | os.O_APPEND)
                self.dec = None
            else:
                self.fd = os.open(self.filepath, os.O_RDONLY)
                self.dec = self.cipher.decryptor()
            self.last_access_time = os.path.getatime(self.filepath)
        return self

    def write(self, data):
        """
        Writes encrypted data to the file.

        :param data: Data to write to the file, can be a string or bytes.
        """
        with self.mutex:
            if isinstance(data, str):
                data = data.encode('utf-8')
            encrypted_data = self.enc.update(data)
            os.write(self.fd, encrypted_data)
            self.size += len(data)
            self.position += len(data)
            self.last_mod_time = os.path.getmtime(self.filepath)

    def read(self, size=None):
        """
        Reads data from the current position in the file.

        :param size: The number of bytes to read. If None, reads until the end of the file.
        :return: The decrypted data read from the file.
        """
        with self.mutex:
            data = b""
            bytes_read = 0

            while True:
                # Determine how much to read in this chunk
                chunk_size = min(4096, size - bytes_read) if size is not None else 4096

                chunk = os.read(self.fd, chunk_size)
                if not chunk:  # End of file
                    break

                data += self.dec.update(chunk)
                bytes_read += len(chunk)

                if size is not None and bytes_read >= size:
                    break

            # Update the last access time and position
            self.last_access_time = os.path.getatime(self.filepath)
            self.position += bytes_read  # Update position after read

        return data

    def seek(self, offset):
        """
        Sets the position for the next read operation.

        :param offset: The offset to seek to.
        """
        with self.mutex:
            if self.position != offset:
                if offset < self.position:
                    self.dec = self.cipher.decryptor()  # Reuse the existing cipher instance
                    os.lseek(self.fd, 0, os.SEEK_SET)
                    self.position = 0

                discard_size = offset - self.position
                chunk_size = 4096
                while discard_size > 0:
                    to_read = min(discard_size, chunk_size)
                    self.dec.update(os.read(self.fd, to_read))  # Discard the data
                    discard_size -= to_read

            self.position = offset  # Update position after seek

    def tell(self):
        with self.mutex:
            return self.position

    def close(self):
        """
        Closes the file descriptor.
        """
        with self.mutex:
            if self.fd is not None:
                os.close(self.fd)
                self.fd = None

    def __enter__(self):
        """
        Allows the use of the file in a 'with' statement.
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Ensures the file is closed when exiting a 'with' statement.
        """
        self.close()

    def __del__(self):
        """
        Ensures the file is cleaned up by closing it and removing the file.
        """
        self.close()
        try:
            os.remove(self.filepath)
        except FileNotFoundError:
            pass

class EphemeralOperations(Operations):
    def __init__(self, storage_directory=None):
        """
        Initializes the operations for the ephemeral filesystem.

        :param storage_directory: The directory to store the files. Defaults to a temporary directory.
        """
        if storage_directory is None:
            storage_directory = mkdtemp()
        self.storage_directory = storage_directory
        self.files = {}  # Track open files and their secure temporary file handlers
        self.default_permissions = 0o660  # Default permissions for files (user read/write)
        self.uid = os.getuid()  # Current user's UID
        self.gid = os.getgid()  # Current user's GID
        self.mutex = threading.Lock()

    def getattr(self, path, fh=None):
        """
        Retrieves file or directory attributes.

        :param path: The file or directory path.
        :param fh: File handle (not used here).
        :return: A dictionary of file attributes.
        """
        with self.mutex:
            if path == '/':
                st = {'st_mode': (stat.S_IFDIR | 0o750), 'st_nlink': 2}
            else:
                file = self.files.get(path)
                if file is None or not os.path.exists(file.filepath):
                    raise OSError(errno.ENOENT, "No such file or directory", path)
                st = {
                    'st_mode': (stat.S_IFREG | 0o660),
                    'st_size': file.size,
                    'st_nlink': 1,
                    'st_uid': self.uid,
                    'st_gid': self.gid,
                    'st_atime': file.last_access_time if file.last_access_time else os.path.getatime(file.filepath),
                    'st_mtime': file.last_mod_time if file.last_mod_time else os.path.getmtime(file.filepath),
                    'st_ctime': file.creation_time if file.creation_time else os.path.getctime(file.filepath),
                }
            return st

    def readdir(self, path, fh=None):
        """
        Lists the contents of a directory.

        :param path: The directory path.
        :param fh: File handle (not used here).
        :return: A list of directory contents.
        """
        with self.mutex:
            return ['.', '..'] + [os.path.basename(f) for f in self.files]

    def create(self, path, mode):
        """
        Creates a new file.

        :param path: The path where the file will be created.
        :param mode: The mode in which the file will be opened.
        :return: The file descriptor.
        """
        with self.mutex:
            file = EphemeralFile(self.storage_directory)
            file.open('w')
            os.chmod(file.filepath, self.default_permissions)
            os.chown(file.filepath, self.uid, self.gid)
            self.files[path] = file
            return file.fd

    def open(self, path, flags):
        """
        Opens an existing file.

        :param path: The file path.
        :param flags: The flags with which the file is opened.
        :return: The file descriptor.
        """
        with self.mutex:
            file = self.files.get(path)
            if path not in self.files:
                raise FuseOSError(errno.ENOENT)
            mode = 'w' if (flags & os.O_RDWR or flags & os.O_WRONLY) else 'r'
            file.open(mode)
            return file.fd

    def read(self, path, size, offset, fh=None):
        """
        Reads data from the file at a given offset.

        :param path: The file path.
        :param size: The number of bytes to read.
        :param offset: The offset from which to start reading.
        :param fh: File handle (not used here).
        :return: The data read from the file.
        """
        with self.mutex:
            file = self.files.get(path)
            if file is None:
                raise FuseOSError(errno.ENOENT)
            file.seek(offset)
            return file.read(size)

    def write(self, path, data, offset, fh=None):
        """
        Writes data to the file at a given offset.

        :param path: The file path.
        :param data: The data to write.
        :param offset: The offset to start writing from.
        :param fh: File handle (not used here).
        :return: The number of bytes written.
        """
        with self.mutex:
            file = self.files.get(path)
            file.write(data)
            return len(data)

    def unlink(self, path):
        """
        Removes a file.

        :param path: The file path to remove.
        """
        with self.mutex:
            file = self.files.pop(path, None)
            if file:
                file.close()
                os.remove(file.filepath)

    def release(self, path, fh=None):
        """
        Releases a file (closes it).

        :param path: The file path.
        :param fh: File handle (not used here).
        """
        with self.mutex:
            file = self.files.get(path)
            if file:
                file.close()

    def truncate(self, path, length, fh=None):
        """
        Truncates the file to a specified length. If the new size is smaller,
        the existing file is streamed into a new file up to `length`. If larger,
        the file is extended with encrypted `\0`. The file properties are swapped
        and the original file is unlinked.

        :param path: The file path to truncate.
        :param length: The new size of the file.
        """
        with self.mutex:
            original_file = self.files.get(path)
            if original_file is None:
                raise FuseOSError(errno.ENOENT)

            if length < original_file.size:
                original_file.open('r')

                truncated_file = EphemeralFile(self.storage_directory)
                truncated_file.open('w')
                os.chmod(truncated_file.filepath, self.default_permissions)
                os.chown(truncated_file.filepath, self.uid, self.gid)

                truncated_file.open('w')

                bytes_written = 0
                chunk_size = 4096
                while bytes_written < length:
                    remaining = length - bytes_written
                    to_read = min(chunk_size, remaining)
                    truncated_file.write(original_file.read(to_read))
                    bytes_written += to_read

                del original_file
                self.files[path] = truncated_file
            elif length > original_file.size:
                length = length - original_file.size
                original_file.open('w')
                bytes_written = 0
                chunk_size = 4096
                while bytes_written < length:
                    remaining = length - bytes_written
                    to_write = min(chunk_size, remaining)
                    original_file.write(b'\0' * to_write)
                    bytes_written += to_write

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
        """
        Initializes and mounts the ephemeral filesystem.

        :param mount_point: The path where the filesystem will be mounted.
        :param storage_directory: The directory to store the files (optional).
        """
        self.mount_point = mount_point
        self.storage_directory = storage_directory

        # Create the mount point directory if it does not exist
        os.makedirs(self.mount_point, exist_ok=True)

        # If a storage directory is specified, create it as well
        if self.storage_directory:
            os.makedirs(self.storage_directory, exist_ok=True)

        # Initialize the FUSE mount with the EphemeralFS
        super().__init__(EphemeralOperations(self.storage_directory), self.mount_point, **fuse_args)

def main():
    """
    The main function that parses arguments and starts the filesystem.
    """
    parser = argparse.ArgumentParser(description="GLOBALEAKS EPH FS")
    parser.add_argument('mount_point', help="Path to mount the filesystem")
    parser.add_argument('--storage_directory', '-s', help="Optional storage directory. Defaults to a temporary directory.")
    args = parser.parse_args()
    EphemeralFS(args.mount_point, args.storage_directory, foreground=True)

if __name__ == '__main__':
    main()
