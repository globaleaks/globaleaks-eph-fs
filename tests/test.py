import errno
import os
import shutil
import stat
import unittest
from tempfile import mkdtemp
from globaleaks_eph_fs import EphemeralFile, EphemeralOperations

TEST_PATH='TESTFILE.TXT'
TEST_DATA=b'TEST'


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
            for _ in range(10):
                file.write(TEST_DATA)

        with self.ephemeral_file.open('r') as file:
            decrypted_data = file.read()

        self.assertEqual(decrypted_data, TEST_DATA * 10)

    def test_file_cleanup(self):
        file_path = self.ephemeral_file.filepath
        del self.ephemeral_file
        self.assertFalse(os.path.exists(file_path))


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
        # Create the file first
        self.operations.create(TEST_PATH, 0o660)

        # Open the file for writing and write data
        self.operations.open(TEST_PATH, os.O_RDWR)
        self.operations.write(TEST_PATH, TEST_DATA, 0, None)

        # Release the file after writing (flushes any remaining changes)
        self.operations.release(TEST_PATH, None)

        # Open the file for reading
        self.operations.open(TEST_PATH, os.O_RDONLY)

        # Read the data from the file
        read_data = self.operations.read(TEST_PATH, len(TEST_DATA), 0, None)

        # Verify that the data read is the same as the written data
        self.assertEqual(read_data, TEST_DATA)

        # Release the file after reading
        self.operations.release(TEST_PATH, None)

    def test_unlink_file(self):
        self.operations.create(TEST_PATH, 0o660)
        self.assertIn(TEST_PATH, self.operations.files)

        self.operations.unlink(TEST_PATH)
        self.assertNotIn(TEST_PATH, self.operations.files)

    def test_file_not_found(self):
        with self.assertRaises(OSError) as context:
            self.operations.open('/nonexistentfile', os.O_RDONLY)
        self.assertEqual(context.exception.errno, errno.ENOENT)

    def test_getattr_root(self):
        """Test getattr on the root directory."""
        attr = self.operations.getattr('/')
        self.assertEqual(attr['st_mode'], stat.S_IFDIR | 0o750)
        self.assertEqual(attr['st_nlink'], 2)

    def test_getattr_file(self):
        """Test getattr on a file."""
        # Create a new file
        self.operations.create(TEST_PATH, mode=0o660)

        # Retrieve file attributes
        attr = self.operations.getattr(TEST_PATH)

        self.assertEqual(attr['st_mode'], stat.S_IFREG | 0o660)
        self.assertEqual(attr['st_size'], 0)
        self.assertEqual(attr['st_nlink'], 1)
        self.assertEqual(attr['st_uid'], os.getuid())
        self.assertEqual(attr['st_gid'], os.getgid())

        # Check times (just ensure they exist)
        self.assertIn('st_atime', attr)
        self.assertIn('st_mtime', attr)
        self.assertIn('st_ctyme', attr)

    def test_getattr_nonexistent(self):
        """Test getattr on a nonexistent path."""
        with self.assertRaises(OSError) as _:
            self.operations.getattr('/nonexistent')


if __name__ == '__main__':
    unittest.main()
