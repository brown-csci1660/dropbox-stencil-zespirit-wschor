##
## test_client.py: Dropbox @ CSCI1660 (Spring 2021)
##
## This is the file where all of your test cases for your Dropbox client
## implementation must go.
##

## WARNING: You MUST NOT change these default imports. If you change the default
##          import statements in the stencil code, your implementation will be
##          rejected by the autograder. (Our autograder actually enforces this
##          this correctly, as opposed to the Crewmate Academy's autograder
##          from the Handin project!)

import unittest
import string

import support.crypto as crypto
import support.util as util

from support.dataserver import dataserver, memloc
from support.keyserver import keyserver

from client import create_user, authenticate_user, User

import random

# DO NOT EDIT ABOVE THIS LINE ##################################################



###### helper functions #######
# sets are pairwise disjoint IFF the size of the union is equal to the count of the elements
def pairwise_disjoint(sets):
    union = set().union(*sets)
    n = sum(len(u) for u in sets)
    return n == len(union)
###############################

class ClientTests(unittest.TestCase):
    def setUp(self):
        """
        This function is automatically called before every test is run. It
        clears the dataserver and keyserver to a clean state for each test case.
        """
        dataserver.Clear()
        keyserver.Clear()

    def test_create_user(self):
        """
        Checks user creation.
        """
        u = create_user("usr", "pswd")
        u2 = authenticate_user("usr", "pswd")

        self.assertEqual(vars(u), vars(u2))

    def test_upload(self):
        """
        Tests if uploading a file throws any errors.
        """
        u = create_user("usr", "pswd")
        u.upload_file("file1", b'testing data')

    def test_download(self):
        """
        Tests if a downloaded file has the correct data in it.
        """
        u = create_user("usr", "pswd")

        data_to_be_uploaded = b'testing data'

        u.upload_file("file1", data_to_be_uploaded)
        downloaded_data = u.download_file("file1")

        self.assertEqual(downloaded_data, data_to_be_uploaded)

    def test_share_and_download(self):
        """
        Simple test of sharing and downloading a shared file.
        """
        u1 = create_user("usr1", "pswd")
        u2 = create_user("usr2", "pswd")

        u1.upload_file("shared_file", b'shared data')
        u1.share_file("shared_file", "usr2")

        u2.receive_file("shared_file", "usr1")
        down_data = u2.download_file("shared_file")

        self.assertEqual(down_data, b'shared data')

    def test_download_error(self):
        """
        Simple test that tests that downloading a file that doesn't exist
        raise an error.
        """
        u = create_user("usr", "pswd")

        # NOTE: When using `assertRaises`, the code that is expected to raise an
        #       error needs to be passed to `assertRaises` as a lambda function.
        self.assertRaises(util.DropboxError, lambda: u.download_file("file1"))

    def test_the_next_test(self):
        """
        Implement more tests by defining more functions like this one!

        Functions have to start with the word "test" to be recognized. Refer to
        the Python `unittest` API for more information on how to write test
        cases: https://docs.python.org/3/library/unittest.html
        """
        self.assertTrue(True)



class TestUserCreation(unittest.TestCase):
    """
    This class tests the functionality of user creation and authentication
    """
    def setUp(self):
        """
        This function is automatically called before every test is run. It
        clears the dataserver and keyserver to a clean state for each test case.
        """
        dataserver.Clear()
        keyserver.Clear()

    def test_bad_password(self):
        """Checks password authentication"""
        create_user("usr", "pswd")
        self.assertRaises(util.DropboxError, lambda: authenticate_user("usr", "BAD"))

    def test_bad_username(self):
        """Checks nonexistent username"""
        create_user("usr", "pswd")
        self.assertRaises(util.DropboxError, lambda: authenticate_user("rsu", "pswd"))

    def test_multi_user(self):
        """Creates many users"""
        names = string.ascii_lowercase
        passwords = map(str, range(len(names)))
        for n, p in zip(names, passwords):
            create_user(n, p)
            authenticate_user(n, p)



class TestFileFunctionality(unittest.TestCase):
    def setUp(self):
        """
        This function is automatically called before every test is run. It
        clears the dataserver and keyserver to a clean state for each test case.
        """
        dataserver.Clear()
        keyserver.Clear()

    def test_upload(self):
        """Tests if uploading a file creates a new entry"""
        create_user("usr", "pswd")
        u = authenticate_user("usr", "pswd")

        first_keys = list(dataserver.data.keys())
        u.upload_file("file1", b'testing data')
        second_keys = list(dataserver.data.keys())

        self.assertGreater(len(second_keys), len(first_keys))

    def test_download(self):
        """Tests if a downloaded file has the correct data in it"""
        create_user("usr", "pswd")
        u = authenticate_user("usr", "pswd")

        data_to_be_uploaded = b'testing data'

        u.upload_file("file1", data_to_be_uploaded)
        downloaded_data = u.download_file("file1")

        self.assertEqual(downloaded_data, data_to_be_uploaded)

    def test_append_correctness(self):
        """Tests appending correctness"""
        create_user("usr", "pswd")
        u = authenticate_user("usr", "pswd")
        u.upload_file("newfile", b'start data')
        u.append_file("newfile", b' appended data')
        down_data = u.download_file("newfile")
        self.assertEqual(down_data, b'start data appended data')

    def test_append_bandwidth(self):
        """Tests appending bandwidth"""
        create_user("usr", "pswd",)
        u = authenticate_user("usr", "pswd")
        byte_counts = []
        u.upload_file("newfile", b'start data')
        curr_count = dataserver.total_bytes_recv + dataserver.total_bytes_sent

        # preform some appends
        for _ in range(100):
            u.append_file("newfile", b'more data')
            byte_counts.append(dataserver.total_bytes_recv + dataserver.total_bytes_sent - curr_count)
            curr_count = dataserver.total_bytes_recv + dataserver.total_bytes_sent

        # if the bandwidth usage is monotically increasing, this is a sign that the
        # scheme scales with respect to something else as shares and append size are constant
        monotically_increasing = True
        c1 = byte_counts[0]
        for c2 in byte_counts[1:]:
            if c1 <= c2:
                monotically_increasing = False
                break
            c1 = c2
        # if the min is significantly smaller than the max, this is a sign that there is
        # something else by which the appending operation scales
        range_factor = (max(byte_counts) / min(byte_counts)) - 1

        self.assertFalse(monotically_increasing)
        self.assertLess(range_factor, 0.03)


    def test_overwrite(self):
        """Tests if a file can be overwritten"""
        create_user("usr", "pswd")
        u = authenticate_user("usr", "pswd")

        old_data_to_be_uploaded = b'testing data'
        new_data_to_be_uploaded = b'new data!'

        u.upload_file("file1", old_data_to_be_uploaded)
        old_downloaded_data = u.download_file("file1")
        u.upload_file("file1", new_data_to_be_uploaded)
        new_downloaded_data = u.download_file("file1")

        self.assertEqual(new_downloaded_data, new_data_to_be_uploaded)
        self.assertEqual(old_downloaded_data, old_data_to_be_uploaded)

    def test_one_client_many_files(self):
        """Tests uploading and downloading several random files"""
        NUM_FILES = 100
        create_user("usr", "pswd")
        u = authenticate_user("usr", "pswd")

        for i in range(NUM_FILES):
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10)).encode()
            name = str(i)

            u.upload_file(name, data)
            down_data = u.download_file(name)

            self.assertEqual(data, down_data)

    def test_many_clients_many_files(self):
        """Tests uploading and downloading several random files from several clients"""
        NUM_FILES = 100
        NUM_CLIENTS = 10

        for i in range(NUM_CLIENTS):
            create_user(str(i), str(i))
            u = authenticate_user(str(i), str(i))

            for i in range(NUM_FILES):
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10)).encode()
                name = str(i)

                u.upload_file(name, data)
                down_data = u.download_file(name)

                self.assertEqual(data, down_data)

    def test_download_nonexistent_file(self):
        """Tests downloading a file that does not exist"""
        create_user("usr", "pswd")
        u = authenticate_user("usr", "pswd")

        self.assertRaises(util.DropboxError, lambda: u.download_file("file"))

    def test_n_users_same_filename(self):
        """Tests that n users can have the same filename"""
        NUM_CLIENTS = 10
        clients = []
        for i in range(NUM_CLIENTS):
            create_user(str(i), str(i))
            u = authenticate_user(str(i), str(i))
            u.upload_file("samefile", b'usr data' + str(i).encode())
            clients.append(u)
        for i, u in enumerate(clients):
            self.assertEqual(b'usr data' + str(i).encode(), u.download_file('samefile'))

    def test_one_user_file_fuzz(self):
        """Fuzzes a file upload/download/replace/append sequence"""

        create_user("usr", "pswd")
        u = authenticate_user("usr", "pswd")

        data = b'Hello World!'

        NUM_ITERS = 200
        FILE_NAME = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=10))

        u.upload_file(FILE_NAME, data)

        def randData(maxLength):
            data_length = random.randint(1, maxLength)
            return ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=data_length)).encode()

        for _ in range(NUM_ITERS):

            choice = random.randint(1,3)

            if choice == 1: # Download
                downloaded_data = u.download_file(FILE_NAME)
                self.assertEqual(downloaded_data, data)

            elif choice == 2: # Append and download
                new_data = randData(50)
                data += new_data
                u.append_file(FILE_NAME, new_data)

                downloaded_data = u.download_file(FILE_NAME)
                self.assertEqual(downloaded_data, data)

            elif choice == 3: # Replace and download
                new_data = randData(50)
                data = new_data
                u.upload_file(FILE_NAME, data)

                downloaded_data = u.download_file(FILE_NAME)
                self.assertEqual(downloaded_data, data)


class TestSharingFunctionality(unittest.TestCase):
    """
    This class tests the functionality of the sharing implementation
    """
 
    def setUp(self):
        """
        This function is automatically called before every test is run. It
        clears the dataserver and keyserver to a clean state for each test case.
        """
        dataserver.Clear()
        keyserver.Clear()

    def test_share_and_download(self):
        """ Simple test of sharing and downloading a shared file"""

        create_user("usr1", "pswd")
        u1 = authenticate_user("usr1", "pswd")

        create_user("usr2", "pswd")
        u2 = authenticate_user("usr2", "pswd")

        u1.upload_file("shared_file", b'shared data')
        u1.share_file("shared_file", "usr2")

        u2.receive_file("shared_file", "usr1")
        down_data = u2.download_file("shared_file")

        self.assertEqual(down_data, b'shared data')

    def test_multi_share_and_download(self):
        """Test sharing and downloading a file with many users"""

        NUM_SHAREES = 15

        create_user("usr0", "pswd")
        u0 = authenticate_user("usr0", "pswd")
        u0.upload_file("shared_file", b'shared data')

        sharees = []
        for i in range(1, NUM_SHAREES + 1):
            create_user(f"usr{i}", "pswd")
            u = authenticate_user(f"usr{i}", "pswd")
            sharees.append(u)
            u0.share_file("shared_file", f"usr{i}")

            # check immediately
            u.receive_file("shared_file", "usr0")
            down_data = u.download_file("shared_file")

            self.assertEqual(down_data, b'shared data')


        # now check after all shares completed
        for u in sharees:
            down_data = u.download_file("shared_file")
            self.assertEqual(down_data, b'shared data')

    def test_revoke(self):
        """Test simple revoking logic (does not test attacks against revoking)"""
        create_user("usr0", "pswd")
        u0 = authenticate_user("usr0", "pswd")
        u0.upload_file("shared_file", b'shared data')

        create_user("usr1", "pswd")
        u1 = authenticate_user("usr1", "pswd")

        u0.share_file("shared_file", "usr1")

        u1.receive_file("shared_file", "usr0")
        u1.download_file("shared_file")

        u0.revoke_file("shared_file", "usr1")

        self.assertRaises(util.DropboxError, lambda: u1.download_file("shared_file"))

    def test_tree_revoke(self):
        """Test more complex revoking logic (does not test attacks against revoking)"""
        create_user("usr0", "pswd")
        u0 = authenticate_user("usr0", "pswd")
        u0.upload_file("shared_file", b'shared data')

        create_user("usr1", "pswd")
        u1 = authenticate_user("usr1", "pswd")

        u0.share_file("shared_file", "usr1")

        u1.receive_file("shared_file", "usr0")

        create_user("usr2", "pswd")
        u2 = authenticate_user("usr2", "pswd")

        u1.share_file("shared_file", "usr2")
        u2.receive_file("shared_file", "usr1")

        create_user("usr3", "pswd")
        u3 = authenticate_user("usr3", "pswd")

        u1.share_file("shared_file", "usr3")
        u3.receive_file("shared_file", "usr1")

        create_user("usr4", "pswd")
        u4 = authenticate_user("usr4", "pswd")

        u0.share_file("shared_file", "usr4")
        u4.receive_file("shared_file", "usr0")


        """
        sharing tree:
            u0
           /   \
          u4   u1
              /  \
             u2  u3
        """

        u1.download_file("shared_file")
        u2.download_file("shared_file")
        u3.download_file("shared_file")
        u4.download_file("shared_file")

        u0.revoke_file("shared_file", "usr1")

        self.assertRaises(util.DropboxError, lambda: u1.download_file("shared_file"))
        self.assertRaises(util.DropboxError, lambda: u2.download_file("shared_file"))
        self.assertRaises(util.DropboxError, lambda: u3.download_file("shared_file"))
        u4.download_file("shared_file")


    def test_share_nonexistent_file(self):
        """Test error handling of sharing nonexistent file"""
        create_user("usr0", "pswd")
        u0 = authenticate_user("usr0", "pswd")

        create_user("usr1", "pswd")
        authenticate_user("usr1", "pswd")

        self.assertRaises(util.DropboxError, lambda: u0.share_file("shared_file", "usr1"))

    def test_share_with_nonexistent_usr(self):
        """Test error handling of sharing nonexistent file"""

        create_user("usr0", "pswd")
        u0 = authenticate_user("usr0", "pswd")
        u0.upload_file("shared_file", b'shared data')

        self.assertRaises(util.DropboxError, lambda: u0.share_file("shared_file", "usr1"))

    def test_revoke_nonexistent_file(self):
        """Test error handling of sharing nonexistent file"""
        create_user("usr0", "pswd")
        u0 = authenticate_user("usr0", "pswd")

        create_user("usr1", "pswd")
        authenticate_user("usr1", "pswd")


        self.assertRaises(util.DropboxError, lambda: u0.revoke_file("shared_file", "usr1"))

class AttackIntegrity(unittest.TestCase):
    """
    This class preforms some simple attacks on Integrity
    """
    def setUp(self):
        """
        This function is automatically called before every test is run. It
        clears the dataserver and keyserver to a clean state for each test case.
        """
        dataserver.Clear()
        keyserver.Clear()

    def test_simple_byte_edit(self):
        create_user("user", "1234")
        user = authenticate_user("user", "1234")

        user.upload_file("file1", b'data')


        uploaded_data = bytearray(dataserver.data[dataserver.last_key])
        uploaded_data[0] = 0

        dataserver.data[dataserver.last_key] = bytes(uploaded_data)

        self.assertRaises(util.DropboxError, lambda: user.download_file("file1"))

    def test_appending_bytes(self):
        create_user("user", "1234")
        user = authenticate_user("user", "1234")

        ## append data
        user.upload_file("file1", b'data')

        uploaded_data = dataserver.data[dataserver.last_key]
        uploaded_data += b'\x00'

        dataserver.data[dataserver.last_key] = uploaded_data
        self.assertRaises(util.DropboxError, lambda: user.download_file("file1"))

    def test_prepending_bytes(self):
        user = create_user("user", "1234")
        ## preprend data
        user.upload_file("file1", b'data')

        uploaded_data = dataserver.data[dataserver.last_key]
        uploaded_data = b'\x00' + uploaded_data

        dataserver.data[dataserver.last_key] = uploaded_data
        self.assertRaises(util.DropboxError, lambda: user.download_file("file1"))

    def test_duplicating_bytes(self):
        user = create_user("user", "1234")
        ## duplicate data
        user.upload_file("file1", b'data')

        uploaded_data = dataserver.data[dataserver.last_key]
        uploaded_data += uploaded_data

        dataserver.data[dataserver.last_key] = uploaded_data
        self.assertRaises(util.DropboxError, lambda: user.download_file("file1"))

    def test_overwriting(self):


        create_user("user", "1234")
        user = authenticate_user("user", "1234")

        create_user("attacker", "1337")
        attacker = authenticate_user("attacker", "1337")

        user.upload_file("file1", b'data')

        user_key = dataserver.last_key

        attacker.upload_file("file2", b'data 2')
        attacker_key = dataserver.last_key

        ## overwrite the user's file with the attacker's containing the new data
        dataserver.data[user_key] = dataserver.data[attacker_key]


        self.assertRaises(util.DropboxError, lambda: user.download_file("file1"))


        attacker.upload_file("file3", b'data')
        attacker_key = dataserver.last_key

        ## overwrite the user's file with the attacker's containing the same data
        dataserver.data[user_key] = dataserver.data[attacker_key]

        self.assertRaises(util.DropboxError, lambda: user.download_file("file1"))


class AttackConfidentiality(unittest.TestCase):
    """
    This class preforms some simple attacks on confidentiality
    """

    def setUp(self):
        """
        This function is automatically called before every test is run. It
        clears the dataserver and keyserver to a clean state for each test case.
        """
        dataserver.Clear()
        keyserver.Clear()


    def test_crypto_nondeterminism(self):


        create_user("user1", "1234")
        user1 = authenticate_user("user1", "1234")

        create_user("user2", "2345")
        user2 = authenticate_user("user1", "1234")

        user1.upload_file("file1", b'data')
        user1_uploaded_data = bytearray(dataserver.data[dataserver.last_key])

        user2.upload_file("file1", b'data')
        user2_uploaded_data = bytearray(dataserver.data[dataserver.last_key])

        # two users with the same filename and data should result in different ciphertexts
        self.assertNotEqual(user1_uploaded_data, user2_uploaded_data)

        # a user that uploads two files with the same data should create two different ciphertexts
        user1.upload_file("file2", b'data')
        user1_second_uploaded_data = bytearray(dataserver.data[dataserver.last_key])
        self.assertNotEqual(user1_uploaded_data, user1_second_uploaded_data)


class CryptographicOrderingInvariants(unittest.TestCase):
    """
    This class preforms some simple attacks on confidentiality
    """

    def setUp(self):
        """
        This function is automatically called before every test is run. It
        clears the dataserver and keyserver to a clean state for each test case.
        """
        dataserver.Clear()
        keyserver.Clear()
        # clear the call log
        crypto.call_logger.log = []
    
    def test_one_key_one_purpose_create_user(self):
        create_user("user", "1234")
        sym_keyed_funcs = {"HMAC": set(), "HashKDF": set(), "SymmetricEncrypt": set()}
        
        for call in crypto.call_logger.log: 
            if call["name"] in sym_keyed_funcs:
                sym_keyed_funcs[call["name"]].add(call["args"]["key"])
        
        self.assertTrue(pairwise_disjoint(sym_keyed_funcs.values()))
    
    def test_one_key_one_purpose_fuzzing(self):
        create_user("usr", "pswd")
        u = authenticate_user("usr", "pswd")

        data = b'Hello World!'
        NUM_ITERS = 200
        FILE_NAME = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=10))

        u.upload_file(FILE_NAME, data)

        def randData(maxLength):
            data_length = random.randint(1, maxLength)
            return ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=data_length)).encode()

        for _ in range(NUM_ITERS):

            choice = random.randint(1,3)

            if choice == 1: # Download
                u.download_file(FILE_NAME)

            elif choice == 2: # Append and download
                new_data = randData(50)
                data += new_data
                u.append_file(FILE_NAME, new_data)
            elif choice == 3: # Replace and download
                new_data = randData(50)
                data = new_data
                u.upload_file(FILE_NAME, data)
       
    
        sym_keyed_funcs = {"HMAC": set(), "HashKDF": set(), "SymmetricEncrypt": set()}
        
        for call in crypto.call_logger.log: 
            if call["name"] in sym_keyed_funcs:
                sym_keyed_funcs[call["name"]].add(call["args"]["key"])
        
        self.assertTrue(pairwise_disjoint(sym_keyed_funcs.values()))
        

        

        



# DO NOT EDIT BELOW THIS LINE ##################################################

if __name__ == '__main__':
    unittest.main()
