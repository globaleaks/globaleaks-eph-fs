import argparse
import atexit
import errno
import os
import stat
import sys
import subprocess
import uuid
import threading
from fuse import FUSE, FuseOSError, Operations
from tempfile import gettempdir, mkdtemp
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.hashes import SHA512



CHUNK_SIZE = 64000


def hmac(key, string):
    """
    Calculate the hmac of a filename

    :param key: The key to be used to calculate the hmac
    :param string: The string on which calculate the hmac
    :return: The calculated hmac
    """
    h = HMAC(key, SHA512())
    h.update(string.encode('utf-8'))
    return h.finalize().hex()


def is_mount_point(path):
    """
    Checks if the given path is a mount point.

    A mount point is a directory where a filesystem is attached. This function checks
    if the provided path is currently being used as a mount point by querying the
    system's mount information.

    :param path: The directory path to check if it is a mount point.
    :return: True if the given path is a mount point, otherwise False.
    :raises Exception: If there is an error while running the 'mount' command or parsing the result.
    """
    result = subprocess.run(['mount'], capture_output=True, text=True)
    return any(os.path.abspath(path) in line for line in result.stdout.splitlines())


def unmount_if_mounted(path):
    """
    Checks if the given path is a mount point and attempts to unmount it.

    :param path: The path to check and unmount if it is a mount point.
    """
    if is_mount_point(path):
        subprocess.run(['fusermount', '-u', path])


class EphemeralFile:
    def __init__(self, directory=None):
        """
        Initializes an ephemeral file with ChaCha20 encryption.
        Creates a new random file path and generates a unique encryption key and nonce.

        :param dir: The directory where the ephemeral file will be stored.
        """
        self.fd = self.enc = self.dec = None
        self.position = 0
        directory = directory or gettempdir()
        filename = str(uuid.uuid4())  # If filenames is None, generate a random UUID as a string
        self.filepath = os.path.join(directory, filename)
        self.cipher = Cipher(ChaCha20(os.urandom(32), os.urandom(16)), mode=None)

    def __getattribute__(self, name):
        """
        Intercepts attribute access for the `EphemeralFile` class.

        If the attribute being accessed is 'size', it returns the size of the file
        by checking the file's attributes using os.stat. For all other attributes,
        it defers to the default behavior of `__getattribute__`, allowing normal
        attribute access.

        :param name: The name of the attribute being accessed.
        :return: The value of the requested attribute. If 'size' is requested,
                 the size of the file is returned. Otherwise, the default
                 behavior for attribute access is used.
        """
        if name == "size":
            return os.stat(self.filepath).st_size

        # For everything else, defer to the default behavior
        return super().__getattribute__(name)

    def open(self, mode='r'):
        """
        Opens the ephemeral file for reading or writing.

        :param mode: 'w' for writing, 'r' for reading.
        :return: The file object.
        """
        if self.fd is None:
            self.fd = os.open(self.filepath, os.O_RDWR | os.O_CREAT | os.O_APPEND)
        self.enc = self.cipher.encryptor()
        self.dec = self.cipher.decryptor()
        self.seek(0 if mode == 'r' else self.size)
        return self

    def seek(self, offset):
        """
        Sets the position for the next read operation.

        :param offset: The offset to seek to.
        """
        if offset < self.position:
            self.position = 0
            self.dec = self.cipher.decryptor()
            self.enc = self.cipher.encryptor()
            os.lseek(self.fd, 0, os.SEEK_SET)
            discard_size = offset
        else:
            discard_size = offset - self.position

        while discard_size > 0:
            to_read = min(CHUNK_SIZE, discard_size)
            data = self.dec.update(os.read(self.fd, to_read))
            data = self.enc.update(data)
            discard_size -= to_read

        self.position = offset

    def tell(self):
        """
        Returns the current position in the file.

        :return: The current position in the file.
        """
        return self.position

    def read(self, size=None):
        """
        Reads data from the current position in the file.

        :param size: The number of bytes to read. If None, reads until the end of the file.
        :return: The decrypted data read from the file.
        """
        result = bytearray()
        bytes_read = 0

        while True:
            chunk_size = min(CHUNK_SIZE, size - bytes_read) if size is not None else CHUNK_SIZE
            chunk = os.read(self.fd, chunk_size)
            if not chunk:
                break

            result.extend(self.dec.update(chunk))
            chunk_length = len(chunk)
            bytes_read += chunk_length
            self.position += chunk_length

            if size is not None and bytes_read >= size:
                break

        return bytes(result)

    def write(self, data):
        """
        Writes encrypted data to the file.

        :param data: Data to write to the file, can be a string or bytes.
        """
        os.write(self.fd, self.enc.update(data))
        self.position += len(data)

    def close(self):
        """
        Closes the file descriptor.
        """
        if self.fd:
            os.close(self.fd)
            self.fd = self.enc = self.dec = None

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
        try:
            self.close()
            os.unlink(self.filepath)
        except FileNotFoundError:
            pass


class EphemeralOperations(Operations):
    use_ns = True
    def __init__(self, storage_directory=None):
        """
        Initializes the operations for the ephemeral filesystem.

        :param storage_directory: The directory to store the files. Defaults to a temporary directory.
        """
        self.key = os.urandom(32)
        self.storage_directory = storage_directory if storage_directory is not None else mkdtemp()
        self.files = {}  # Track open files and their secure temporary file handlers
        self.vmap_files = {}
        self.directories = {'/': set()}
        self.vmap_directories = {}
        self.mutex = threading.Lock()

    def _split_path(self, path):
        """
        Splits a given path into its parent directory and final component.

        :param path: The full file or directory path.
        :return: A tuple (basedir, name), where basedir is the directory
                 and name is the last part of the path.
        """
        basedir, name = os.path.split(path)
        return ('/' + basedir.lstrip('/')) if basedir else '/', name

    def get_file(self, path):
        """
        Retrieves the file object associated with the specified path.

        :param path: The full path to the file.
        :return: The file object stored at the given path.
        :raises FuseOSError: If the file does not exist.
        """
        path = self.vmap_files.get(hmac(self.key, path), path)
        file = self.files.get(path)
        if file is None:
            raise FuseOSError(errno.ENOENT)
        return file

    def getattr(self, path, fh=None):
        """
        Retrieves file or directory attributes.

        :param path: The file or directory path.
        :param fh: File handle (not used here).
        :return: A dictionary of file attributes.
        """
        with self.mutex:
            path = self.vmap_directories.get(path, path)
            if path in self.directories:
                return {'st_mode': (stat.S_IFDIR | 0o750), 'st_nlink': 2}

            file = self.get_file(path)

            st = os.stat(file.filepath)
            return {
                'st_mode': (stat.S_IFREG | 0o600),
                'st_nlink': 1,
                'st_size': st.st_size,
            }

    def readdir(self, path, fh=None):
        """
        Lists the contents of a directory.

        :param path: The directory path.
        :param fh: File handle (not used here).
        :return: A list of directory contents.
        """
        with self.mutex:
            if path not in self.directories:
                raise FuseOSError(errno.ENOENT)
            return ['.', '..'] + list(self.directories.get(path))

    def mkdir(self, path, mode):
        """
        Creates a new directory at the specified path.

        :param path: The full path of the directory to create.
        :param mode: Permission mode for the new directory (not used in this implementation).
        :raises FuseOSError: If the parent directory does not exist.
        """
        with self.mutex:
            basedir, name = self._split_path(path)
            virtual_basedir = self.vmap_directories.get(basedir, basedir)
            virtual_name = str(uuid.uuid4())
            virtual_path = os.path.join(virtual_basedir, virtual_name)
            if virtual_basedir not in self.directories:
                raise FuseOSError(errno.ENOENT)
            self.directories[virtual_basedir].add(virtual_name)
            self.directories[virtual_path] = set()
            self.vmap_directories[path] = virtual_path

    def rmdir(self, path):
        """
        Removes an existing directory at the specified path.

        :param path: The full path of the directory to remove.
        :raises FuseOSError: If the directory does not exist or is not empty.
        """
        with self.mutex:
            path = self.vmap_directories.get(path, path)
            if path not in self.directories or self.directories[path]:
                raise FuseOSError(errno.ENOTEMPTY)
            basedir, name = self._split_path(path)
            self.directories[basedir].remove(name)
            self.directories.pop(path, None)
            self.vmap_directories.pop(path, None)

    def create(self, path, mode):
        """
        Creates a new file.

        :param path: The path where the file will be created.
        :param mode: The mode in which the file will be opened.
        :return: The file descriptor.
        """
        with self.mutex:
            basedir, name = self._split_path(path)
            virtual_basedir = self.vmap_directories.get(basedir, basedir)
            file = EphemeralFile(self.storage_directory)
            file.open('w')
            filename = os.path.basename(file.filepath)
            self.directories[virtual_basedir].add(filename)
            virtual_path = os.path.join(virtual_basedir, filename)
            self.files[virtual_path] = file
            self.vmap_files[hmac(self.key, path)] = virtual_path
            return file.fd

    def open(self, path, flags):
        """
        Opens an existing file.

        :param path: The file path.
        :param flags: The flags with which the file is opened.
        :return: The file descriptor.
        """
        with self.mutex:
            file = self.get_file(path)
            file.open('w' if (flags & os.O_RDWR or flags & os.O_WRONLY) else 'r')
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
            file = self.get_file(path)
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
            file = self.get_file(path)
            file.seek(offset)
            file.write(data)
            return len(data)

    def unlink(self, path):
        """
        Removes a file.

        :param path: The file path to remove.
        """
        with self.mutex:
            basedir, name1 = self._split_path(path)
            path = self.vmap_files.pop(hmac(self.key, path), path)
            basedir, name2 = self._split_path(path)
            file = self.files.pop(path, None)
            if not file:
                raise FuseOSError(errno.ENOENT)

            self.directories[basedir].discard(name1)
            self.directories[basedir].discard(name2)

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
            file = self.get_file(path)
            current_size = os.stat(file.filepath).st_size

            if length < current_size:
                file.close()  # Close and truncate externally
                os.truncate(file.filepath, length)
                file.open('w')  # Reopen to reset cipher state
            elif length > current_size:
                file.seek(current_size)
                pad_len = length - current_size
                while pad_len > 0:
                    to_write = min(CHUNK_SIZE, pad_len)
                    file.write(b'\0' * to_write)
                    pad_len -= to_write

    def release(self, path, fh=None):
        """
        Releases a file (closes it).

        :param path: The file path.
        :param fh: File handle (not used here).
        """
        with self.mutex:
            self.get_file(path).close()


def mount_globaleaks_eph_fs(mount_point, storage_directory=None, foreground=False):
    """
    Initializes and mounts the ephemeral filesystem.

    :param mount_point: The path where the filesystem will be mounted.
    :param storage_directory: The directory to store the files (optional).
    :return: A `FUSE` object that represents the mounted filesystem.
    """
    def _mount_globaleaks_eph_fs(mount_point, storage_directory=None, foreground=False):
        # Create the mount point directory if it does not exist
        os.makedirs(mount_point, exist_ok=True)

        # If a storage directory is specified, create it as well
        if storage_directory:
            os.makedirs(storage_directory, exist_ok=True)

        return FUSE(EphemeralOperations(storage_directory), mount_point, foreground=foreground)

    thread = threading.Thread(target=_mount_globaleaks_eph_fs, args=(mount_point, storage_directory, foreground))
    thread.start()

    atexit.register(unmount_if_mounted, mount_point)

    return thread


def main():
    """
    The main function that parses arguments and starts the filesystem.
    """
    parser = argparse.ArgumentParser(description="GLOBALEAKS EPH FS")
    parser.add_argument('mount_point', help="Path to mount the filesystem")
    parser.add_argument('--storage_directory', '-s', help="Optional storage directory. Defaults to a temporary directory.")
    args = parser.parse_args()

    unmount_if_mounted(args.mount_point)

    try:
       print(f"Mounting GLOBALEAKS EPH FS at {args.mount_point}")
       mount_globaleaks_eph_fs(args.mount_point, args.storage_directory, True).join()

    except KeyboardInterrupt:
        sys.exit(0)
    except:
        sys.exit(1)
