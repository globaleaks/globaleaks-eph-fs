import errno
import os
import shutil
import stat
import unittest
from tempfile import mkdtemp
from fuse import FuseOSError
from globaleaks_eph_fs import EphemeralFile, EphemeralOperations

TEST_PATH = 'TESTFILE.TXT'
TEST_DATA = b"Hello, world! This is a test data for writing, seeking and reading operations."


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
        TEST_PATH = self.ephemeral_file.filepath
        del self.ephemeral_file
        self.assertFalse(os.path.exists(TEST_PATH))

class TestEphemeralOperations(unittest.TestCase):
    def setUp(self):
        self.storage_dir = mkdtemp()
        self.operations = EphemeralOperations(self.storage_dir)

    def tearDown(self):
        for file in self.operations.files.values():
            os.remove(file.filepath)
        os.rmdir(self.storage_dir)

    def test_create_file(self):
        self.operations.create(TEST_PATH, 0o660)
        self.assertIn(TEST_PATH, self.operations.files)

    def test_open_existing_file(self):
        self.operations.create(TEST_PATH, 0o660)
        self.operations.open(TEST_PATH, os.O_RDONLY)

    def test_write_and_read_file(self):
        self.operations.create(TEST_PATH, 0o660)

        self.operations.open(TEST_PATH, os.O_RDWR)
        self.operations.write(TEST_PATH, TEST_DATA, 0, None)

        self.operations.release(TEST_PATH, None)

        self.operations.open(TEST_PATH, os.O_RDONLY)

        read_data = self.operations.read(TEST_PATH, len(TEST_DATA), 0, None)

        self.assertEqual(read_data, TEST_DATA)

        self.operations.release(TEST_PATH, None)

    def test_unlink_file(self):
        self.operations.create(TEST_PATH, 0o660)
        self.assertIn(TEST_PATH, self.operations.files)

        self.operations.unlink(TEST_PATH)
        self.assertNotIn(TEST_PATH, self.operations.files)

    def test_file_not_found(self):
        with self.assertRaises(FuseOSError) as context:
            self.operations.open('/nonexistentfile', os.O_RDONLY)
        self.assertEqual(context.exception.errno, errno.ENOENT)

    def test_getattr_root(self):
        attr = self.operations.getattr('/')
        self.assertEqual(attr['st_mode'], stat.S_IFDIR | 0o750)
        self.assertEqual(attr['st_nlink'], 2)

    def test_getattr_file(self):
        self.operations.create(TEST_PATH, mode=0o660)

        attr = self.operations.getattr(TEST_PATH)

        self.assertEqual(attr['st_mode'], stat.S_IFREG | 0o660)
        self.assertEqual(attr['st_size'], 0)
        self.assertEqual(attr['st_nlink'], 1)
        self.assertEqual(attr['st_uid'], os.getuid())
        self.assertEqual(attr['st_gid'], os.getgid())

        self.assertIn('st_atime', attr)
        self.assertIn('st_mtime', attr)
        self.assertIn('st_ctime', attr)

    def test_getattr_nonexistent(self):
        with self.assertRaises(OSError) as _:
            self.operations.getattr('/nonexistent')

    def test_truncate(self):
        ORIGINAL_SIZE =len(TEST_DATA)
        REDUCED_SIZE = len(TEST_DATA)//2

        self.operations.create(TEST_PATH, 0o660)
        self.operations.write(TEST_PATH, TEST_DATA, 0, None)

        self.operations.truncate(TEST_PATH, REDUCED_SIZE, None)
        file_content = self.operations.read(TEST_PATH, ORIGINAL_SIZE, 0, None)
        self.assertEqual(len(file_content), REDUCED_SIZE)
        self.assertEqual(file_content, TEST_DATA[:REDUCED_SIZE])

    def test_extend(self):
        ORIGINAL_SIZE =len(TEST_DATA)
        EXTENDED_SIZE = len(TEST_DATA)*2

        self.operations.create(TEST_PATH, 0o660)
        self.operations.write(TEST_PATH, TEST_DATA, 0, None)

        self.operations.truncate(TEST_PATH, EXTENDED_SIZE, None)
        file_content = self.operations.read(TEST_PATH, EXTENDED_SIZE * 2, 0, None)
        self.assertEqual(file_content[:ORIGINAL_SIZE], TEST_DATA)
        self.assertEqual(len(file_content), EXTENDED_SIZE)
        self.assertTrue(all(byte == 0 for byte in file_content[ORIGINAL_SIZE:]))

    def test_readdir(self):
        file_names = ['/file1', '/file2', '/file3']
        for file_name in file_names:
            self.operations.create(file_name, 0o660)

        directory_contents = self.operations.readdir('/', None)
        self.assertEqual(set(directory_contents), {'.', '..', 'file1', 'file2', 'file3'})

        self.operations.unlink('/file2')
        directory_contents = self.operations.readdir('/', None)
        self.assertEqual(set(directory_contents), {'.', '..', 'file1', 'file3'})

if __name__ == '__main__':
    unittest.main()
