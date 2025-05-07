import errno
import os
import secrets
import shutil
import stat
import tempfile
import threading
import unittest
import uuid

from fuse import FuseOSError
from tempfile import mkdtemp
from unittest.mock import patch, MagicMock

from globaleaks_eph_fs import EphemeralFile, EphemeralOperations, mount_globaleaks_eph_fs, main, unmount_if_mounted

TEST_PATH = "/" + str(uuid.uuid4())
TEST_DATA = b"Hello, world! This is a test data for writing, seeking and reading operations."

ORIGINAL_SIZE = len(TEST_DATA)
EXTENDED_SIZE = ORIGINAL_SIZE*2
REDUCED_SIZE = ORIGINAL_SIZE//2

class TestEphemeralFile(unittest.TestCase):
    def setUp(self):
        self.storage_dir = mkdtemp()
        self.ephemeral_file = EphemeralFile(self.storage_dir)

    def tearDown(self):
        shutil.rmtree(self.storage_dir)

    def test_create_and_write_file(self):
        with self.ephemeral_file.open('w') as file:
            file.write(TEST_DATA)

        self.assertTrue(os.path.exists(self.ephemeral_file.filepath))

    def test_encryption_and_decryption(self):
        with self.ephemeral_file.open('w') as file:
            file.write(TEST_DATA)

        # Define test cases: each case is a tuple (seek_position, read_size, expected_data)
        seek_tests = [
            (0, 1, TEST_DATA[:1]),  # Seek at the start read 1 byte
            (5, 5, TEST_DATA[5:10]),  # Seek forward, read 5 bytes
            (10, 2, TEST_DATA[10:12]),  # Seek forward, read 2 bytes
            (0, 3, TEST_DATA[:3]),  # Seek backward, read 3 bytes
        ]

        # Test forward and backward seeking with different offsets
        with self.ephemeral_file.open('r') as file:
            for seek_pos, read_size, expected in seek_tests:
                file.seek(seek_pos)  # Seek to the given position
                self.assertEqual(file.tell(), seek_pos)  # Check position after seeking forward
                read_data = file.read(read_size)  # Read the specified number of bytes
                self.assertEqual(read_data, expected)  # Verify the data matches the expected value

    def test_file_cleanup(self):
        path_copy = self.ephemeral_file.filepath
        del self.ephemeral_file
        self.assertFalse(os.path.exists(path_copy))


class TestEphemeralOperations(unittest.TestCase):
    def setUp(self):
        self.storage_dir = mkdtemp()
        self.fs = EphemeralOperations(self.storage_dir)

        # Get current user's UID and GID
        self.current_uid = os.getuid()
        self.current_gid = os.getgid()

    def tearDown(self):
        for file in self.fs.files.values():
            os.remove(file.filepath)
        os.rmdir(self.storage_dir)

    def test_create_file(self):
        self.fs.create(TEST_PATH, 0o660)
        self.assertIn('st_mode', self.fs.getattr(TEST_PATH))

    def test_open_existing_file(self):
        self.fs.create(TEST_PATH, 0o660)
        self.fs.open(TEST_PATH, os.O_RDONLY)

    def test_write_and_read_file(self):
        self.fs.create(TEST_PATH, 0o660)

        self.fs.open(TEST_PATH, os.O_RDWR)
        self.fs.write(TEST_PATH, TEST_DATA, 0, None)

        self.fs.release(TEST_PATH, None)

        self.fs.open(TEST_PATH, os.O_RDONLY)

        read_data = self.fs.read(TEST_PATH, len(TEST_DATA), 0, None)

        self.assertEqual(read_data, TEST_DATA)

        self.fs.release(TEST_PATH, None)

    def test_unlink_file(self):
        self.fs.create(TEST_PATH, 0o660)
        self.assertIn('st_mode', self.fs.getattr(TEST_PATH))

        self.fs.unlink(TEST_PATH)

        with self.assertRaises(FuseOSError):
            self.fs.getattr(TEST_PATH)

    def test_file_not_found(self):
        with self.assertRaises(FuseOSError) as context:
            self.fs.open('/nonexistentfile', os.O_RDONLY)
        self.assertEqual(context.exception.errno, errno.ENOENT)

    def test_getattr_root(self):
        attr = self.fs.getattr('/')
        self.assertEqual(stat.S_IFMT(attr['st_mode']), stat.S_IFDIR)
        self.assertEqual(attr['st_mode'] & 0o777, 0o750)
        self.assertEqual(attr['st_nlink'], 2)

    def test_getattr_file(self):
        self.fs.create(TEST_PATH, mode=0o660)

        attr = self.fs.getattr(TEST_PATH)

        self.assertEqual(stat.S_IFMT(attr['st_mode']), stat.S_IFREG)
        self.assertEqual(attr['st_size'], 0)
        self.assertEqual(attr['st_nlink'], 1)

    def test_getattr_nonexistent(self):
        with self.assertRaises(OSError) as _:
            self.fs.getattr('/nonexistent')

    def test_truncate(self):
        self.fs.create(TEST_PATH, 0o660)
        self.fs.write(TEST_PATH, TEST_DATA, 0, None)

        self.fs.truncate(TEST_PATH, REDUCED_SIZE, None)
        file_content = self.fs.read(TEST_PATH, ORIGINAL_SIZE, 0, None)
        self.assertEqual(len(file_content), REDUCED_SIZE)
        self.assertEqual(file_content, TEST_DATA[:REDUCED_SIZE])

    def test_extend(self):
        self.fs.create(TEST_PATH, 0o660)
        self.fs.write(TEST_PATH, TEST_DATA, 0, None)

        self.fs.truncate(TEST_PATH, EXTENDED_SIZE, None)
        file_content = self.fs.read(TEST_PATH, EXTENDED_SIZE * 2, 0, None)
        self.assertEqual(file_content[:ORIGINAL_SIZE], TEST_DATA)
        self.assertEqual(len(file_content), EXTENDED_SIZE)
        self.assertTrue(all(byte == 0 for byte in file_content[ORIGINAL_SIZE:]))

    def test_readdir(self):
        self.assertEqual(self.fs.readdir('/', None), [".", ".."])

        for x in range(3):
            self.fs.create(str(uuid.uuid4()), 0o660)
            self.assertEqual(len(self.fs.readdir('/', None)), 3 + x)

    def test_mkdir_success(self):
        new_dir_path = "/dir1"
        self.fs.mkdir(new_dir_path, 0o755)

        attr = self.fs.getattr(new_dir_path)
        self.assertEqual(stat.S_IFMT(attr['st_mode']), stat.S_IFDIR)

    def test_mkdir_parent_not_exist(self):
        with self.assertRaises(FuseOSError) as context:
            self.fs.mkdir("/a/b", 0o755)
        self.assertEqual(context.exception.errno, errno.ENOENT)

    def test_rmdir_success(self):
        dir_path = "/dir2"
        self.fs.mkdir(dir_path, 0o755)
        self.fs.rmdir(dir_path)
        self.assertNotIn(dir_path, self.fs.directories)
        self.assertNotIn("dir2", self.fs.directories["/"])

    def test_rmdir_nonexistent(self):
        with self.assertRaises(FuseOSError) as context:
            self.fs.rmdir("/nonexistent")
        self.assertEqual(context.exception.errno, errno.ENOTEMPTY)

    def test_rmdir_not_empty(self):
        dir_path = "/dir3"
        file_path = "/dir3/testfile"
        self.fs.mkdir(dir_path, 0o755)
        self.fs.create(file_path, 0o660)
        with self.assertRaises(FuseOSError) as context:
            self.fs.rmdir(dir_path)
        self.assertEqual(context.exception.errno, errno.ENOTEMPTY)

    def test_concurrent_access(self):
        self.path = "/file"
        self.fs.create(self.path, 0o660)
        self.fs.open(self.path, os.O_RDWR)
        self.fs.write(self.path, TEST_DATA, 0, None)
        self.fs.release(self.path)  # finalize write

        self.fs.open(self.path, os.O_RDONLY)  # reopen for read

        thread_count = 100
        barrier = threading.Barrier(thread_count)

        def reader():
            barrier.wait()
            for _ in range(5):
                max_offset = len(TEST_DATA) - 1
                offset = secrets.randbelow(max_offset + 1)
                max_length = len(TEST_DATA) - offset
                length = 1 + secrets.randbelow(max_length)

                data = self.fs.read(self.path, length, offset, None)
                expected = TEST_DATA[offset:offset + length]
                self.assertEqual(data, expected, f"Mismatch at offset {offset} length {length}")

        threads = [threading.Thread(target=reader) for _ in range(thread_count)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

    @patch('atexit.register')
    @patch('argparse.ArgumentParser.parse_args')
    @patch('globaleaks_eph_fs.subprocess.run')
    @patch('globaleaks_eph_fs.mount_globaleaks_eph_fs')
    @patch('globaleaks_eph_fs.FUSE')
    @patch('builtins.print')
    def test_main_mount_with_unspecified_storage_directory(self, mock_print, mock_FUSE, mock_mount, mock_subprocess, mock_parse_args, mock_atexit_register):
        with tempfile.TemporaryDirectory() as mount_point:
            mock_parse_args.return_value = MagicMock(
                mount_point=mount_point,
                storage_directory=None,
                unmount=False
            )

            original_mount_function = mount_globaleaks_eph_fs

            def side_effect_func(mount_point, storage_directory, flag):
                return original_mount_function(mount_point, storage_directory, False)

            mock_mount.side_effect = side_effect_func

            main()

            mock_mount.assert_called_once_with(mount_point, None, True)

            mock_atexit_register.assert_called_once_with(unmount_if_mounted, mount_point)

            mock_subprocess.assert_called_once_with(['mount'], capture_output=True, text=True)

    @patch('atexit.register')
    @patch('argparse.ArgumentParser.parse_args')
    @patch('globaleaks_eph_fs.subprocess.run')
    @patch('globaleaks_eph_fs.mount_globaleaks_eph_fs')
    @patch('globaleaks_eph_fs.FUSE')
    @patch('builtins.print')
    def test_main_mount_with_specified_storage_directory(self, mock_print, mock_FUSE, mock_mount, mock_subprocess, mock_parse_args, mock_atexit_register):
        with tempfile.TemporaryDirectory() as mount_point, tempfile.TemporaryDirectory() as storage_directory:
            mock_parse_args.return_value = MagicMock(
                mount_point=mount_point,
                storage_directory=storage_directory
            )

            original_mount_function = mount_globaleaks_eph_fs

            def side_effect_func(mount_point, storage_directory, flag):
                return original_mount_function(mount_point, storage_directory, False)

            mock_mount.side_effect = side_effect_func

            main()

            mock_mount.assert_called_once_with(mount_point, storage_directory, True)

            mock_atexit_register.assert_called_once_with(unmount_if_mounted, mount_point)

            mock_subprocess.assert_called_once_with(['mount'], capture_output=True, text=True)

    @patch('atexit.register')
    @patch('argparse.ArgumentParser.parse_args')
    @patch('globaleaks_eph_fs.subprocess.run')
    @patch('globaleaks_eph_fs.mount_globaleaks_eph_fs')
    @patch('globaleaks_eph_fs.is_mount_point')
    @patch('globaleaks_eph_fs.FUSE')
    @patch('builtins.print')
    def test_main_with_mount_point_check(self, mock_print, mock_FUSE, mock_is_mount_point, mock_mount, mock_subprocess, mock_parse_args, mock_atexit_register):
        with tempfile.TemporaryDirectory() as mount_point:
            mock_parse_args.return_value = MagicMock(
                mount_point=mount_point,
                storage_directory=None
            )

            mock_is_mount_point.return_value = True

            original_mount_function = mount_globaleaks_eph_fs

            def side_effect_func(mount_point, storage_directory, flag):
                return original_mount_function(mount_point, storage_directory, False)

            mock_mount.side_effect = side_effect_func

            main()

            mock_mount.assert_called_once_with(mount_point, None, True)

            mock_atexit_register.assert_called_once_with(unmount_if_mounted, mount_point)

            mock_subprocess.assert_called_once_with(['fusermount', '-u', mount_point])

    @patch('atexit.register')
    @patch('argparse.ArgumentParser.parse_args')
    @patch('globaleaks_eph_fs.subprocess.run')
    @patch('globaleaks_eph_fs.mount_globaleaks_eph_fs')
    @patch('globaleaks_eph_fs.is_mount_point')
    @patch('globaleaks_eph_fs.FUSE')
    @patch('builtins.print')
    def test_main_keyboard_interrupt(self, mock_print, mock_FUSE, mock_is_mount_point, mock_mount, mock_subprocess, mock_parse_args, mock_atexit_register):
        with tempfile.TemporaryDirectory() as mount_point:
            mock_parse_args.return_value = MagicMock(
                mount_point=mount_point,
                storage_directory=None
            )

            mock_is_mount_point.return_value = False

            mock_mount.side_effect = KeyboardInterrupt

            with self.assertRaises(SystemExit):
                main()

            mock_mount.assert_called_once_with(mount_point, None, True)

            mock_subprocess.assert_not_called()

    @patch('atexit.register')
    @patch('argparse.ArgumentParser.parse_args')
    @patch('globaleaks_eph_fs.subprocess.run')
    @patch('globaleaks_eph_fs.mount_globaleaks_eph_fs')
    @patch('globaleaks_eph_fs.is_mount_point')
    @patch('globaleaks_eph_fs.FUSE')
    @patch('builtins.print')
    def test_main_other_exception(self, mock_print, mock_FUSE, mock_is_mount_point, mock_mount, mock_subprocess, mock_parse_args, mock_atexit_register):
        with tempfile.TemporaryDirectory() as mount_point:
            mock_parse_args.return_value = MagicMock(
                mount_point=mount_point,
                storage_directory=None
            )

            mock_is_mount_point.return_value = False

            mock_mount.side_effect = Exception("Some unexpected error")

            with self.assertRaises(SystemExit):
                main()

            mock_mount.assert_called_once_with(mount_point, None, True)

            mock_atexit_register.assert_not_called()

            mock_subprocess.assert_not_called()
