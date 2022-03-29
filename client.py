##
## client.py: Dropbox @ CSCI1660 (Spring 2021)
##
## This is the file where all of your code for your Dropbox client
## implementation must go.
##

## WARNING: You MUST NOT change these default imports. If you change the default
##          import statements in the stencil code, your implementation will be
##          rejected by the autograder. (Our autograder actually enforces this
##          this correctly, as opposed to the Crewmate Academy's autograder
##          from the Handin project!)

# Optional library containing some helpful string constants; not required to use
# this in your implementation. See https://docs.python.org/3/library/string.html
# for usage and documentation.
import string

# Imports the `crypto` and `util` libraries. See the Dropbox Wiki for usage and
# documentation.
import support.crypto as crypto
import support.util as util

# Imports the `dataserver`, `keyserver`, and `memloc` instances. See the Dropbox
# Wiki for usage and documentation.
from support.dataserver import dataserver, memloc
from support.keyserver import keyserver

SYM_KEY_LEN = 16
SALT_LEN = 16
INTEGRITY_ERR_MSG = "Integrity Violation"
EMPTY_ERR_MSG = "Memloc Is Empty"
# DO NOT EDIT ABOVE THIS LINE ##################################################

def ensure_integrity(key, data, integrity_token): 
    if isinstance(key, bytes): 
        hmac_2 = crypto.HMAC(key, data)
        if not crypto.HMACEqual(integrity_token, hmac_2):
            raise util.DropboxError(INTEGRITY_ERR_MSG)

    elif isinstance(key, crypto.SignatureVerifyKey):
        if not crypto.SignatureVerify(key, data, integrity_token):
            raise util.DropboxError(INTEGRITY_ERR_MSG)
    else:
        # should never be raised
        raise util.DropboxError("type error")


def lock(key: bytes, data: bytes): 
    """
    Authenticated encryption using SymmetricEncrypt + HMAC
    """
    k1 = crypto.HashKDF(key, "encryption")
    k2 = crypto.HashKDF(key, "HMAC")

    ct = crypto.SymmetricEncrypt(k1, crypto.SecureRandom(16), data)
    hmac = crypto.HMAC(k2, ct)

    return [ct, hmac]

def unlock(key: bytes, ct_lst: list): 
    """
    Authenticated decryption using SymmetricEncrypt + HMAC
    """
    k1 = crypto.HashKDF(key, "encryption")
    k2 = crypto.HashKDF(key, "HMAC")

    ct, hmac = ct_lst
    ensure_integrity(k2, ct, hmac)

    return crypto.SymmetricDecrypt(k1, ct)

def auth_set(data, key, memloc, asm=False, recipient=None):
    if asm: 
        data_bytes = util.ObjectToBytes(data)
        try: 
            pub_key = keyserver.Get(f"enc@{recipient}")
        except ValueError:
            raise util.DropboxError("User does not exist")
        ciphertext = crypto.AsymmetricEncrypt(pub_key, data_bytes)
        signature = crypto.SignatureSign(key, ciphertext)
        dataserver.Set(memloc, util.ObjectToBytes([ciphertext, signature]))
    else: 
        data_bytes = util.ObjectToBytes(data)
        ciphertext = lock(key, data_bytes)
        ciphertext_bytes = util.ObjectToBytes(ciphertext)
        dataserver.Set(memloc, ciphertext_bytes)


def auth_get(key, memloc, asm=False, sender=None):
    try: 
        ciphertext_bytes = dataserver.Get(memloc)
    except ValueError: 
        raise util.DropboxError(EMPTY_ERR_MSG)
    
    if asm: 
        ciphertext, signature = util.BytesToObject(ciphertext_bytes)
        if not crypto.SignatureVerify(keyserver.Get(f"verify@{sender}"), ciphertext, signature):
            raise util.DropboxError(INTEGRITY_ERR_MSG)
        plaintext = crypto.AsymmetricDecrypt(key, ciphertext)
        plaintext = util.BytesToObject(plaintext)
        return plaintext
    else:
        try: 
            # json decoding MAY fail. If it does not, still have to 
            # formally check integrity
            ciphertext = util.BytesToObject(ciphertext_bytes)
        except Exception:
            raise util.DropboxError("Integrity Violation: JSON Error")

        data_bytes = unlock(key, ciphertext)
        ret = util.BytesToObject(data_bytes)
        return ret

def str_to_memloc(s):
    return memloc.MakeFromBytes(crypto.Hash(s.encode())[:16])


class User:
    def __init__(self, home_key, signing_key, priv_key, username, password) -> None:
        """
        Class constructor for the `User` class.

        You are free to add fields to the User class by changing the definition
        of this function.
        """
        self.home_key = home_key
        self.signing_key = signing_key
        self.priv_key = priv_key
        self.username = username
        self.password = password
        

    def upload_file(self, filename: str, data: bytes) -> None:
        """
        The specification for this function is at:
        http://dropbox.crewmate.academy/client-api/storage/upload-file.html
        """
        # test if file exists
        file_memloc = str_to_memloc(f"{filename}@{self.username}")
        exists = True
        # see if file exists; will raise exception if memloc is used or if it was used but
        # there is an integrity violation
        try: 
            indirection_key, key_loc, file_md_loc, _, _ = auth_get(self.home_key, file_memloc)
        except util.DropboxError as de:
            if str(de) == EMPTY_ERR_MSG:
                exists = False
            else: 
                raise de
       
        if exists:
            file_key = auth_get(indirection_key, key_loc)
            next_block_memloc, tail_block_memloc = auth_get(file_key, file_md_loc)
            auth_set([data, tail_block_memloc], file_key, next_block_memloc)
        
        else:
            indirection_key = crypto.SecureRandom(SYM_KEY_LEN)
            file_key = crypto.SecureRandom(SYM_KEY_LEN)
            key_loc = memloc.Make()
            file_md_loc = memloc.Make()
            # [indirection key, key_loc, file_md loc, owner?, shares = {}]
            personal_metadata = [indirection_key, key_loc, file_md_loc, True, {}]

            file_block_loc = memloc.Make()
            empty_tail_loc = memloc.Make()
            file_md = [file_block_loc, empty_tail_loc]

            file_memloc = str_to_memloc(f"{filename}@{self.username}")
            
            # store metadatas
            auth_set(personal_metadata, self.home_key, file_memloc)
            auth_set(file_md, file_key, file_md_loc)
            # store file
            auth_set([data, empty_tail_loc], file_key, file_block_loc)
            # store key
            auth_set(file_key, indirection_key, key_loc)

    def download_file(self, filename: str) -> bytes:
        """
        The specification for this function is at:
        http://dropbox.crewmate.academy/client-api/storage/download-file.html
        """
        file_memloc = str_to_memloc(f"{filename}@{self.username}")
        indirection_key, key_loc, file_md_loc, _, _ = auth_get(self.home_key, file_memloc)

        file_key = auth_get(indirection_key, key_loc)
        next_block_memloc, _ = auth_get(file_key, file_md_loc)
        
        collected_blocks = b''
        while True:
            try:
                data, tail_block_memloc = auth_get(file_key, next_block_memloc)
            except util.DropboxError as de:
                # found empty slot (EOF)
                if str(de) == EMPTY_ERR_MSG:
                    break
                else:
                    raise de

            collected_blocks += data
            next_block_memloc = tail_block_memloc
        
        return collected_blocks
        

    def append_file(self, filename: str, data: bytes) -> None:
        """
        The specification for this function is at:
        http://dropbox.crewmate.academy/client-api/storage/append-file.html
        """
        file_memloc = str_to_memloc(f"{filename}@{self.username}")
        indirection_key, key_loc, file_md_loc, _, _ = auth_get(self.home_key, file_memloc)

        file_key = auth_get(indirection_key, key_loc)
        first_slot, empty_slot = auth_get(file_key, file_md_loc)

        new_empty = memloc.Make()
        auth_set([data, new_empty], file_key, empty_slot)

        # update memloc
        metadata = [first_slot, new_empty]
        auth_set(metadata, file_key, file_md_loc)


    def share_file(self, filename: str, recipient: str) -> None:
        """
        The specification for this function is at:
        http://dropbox.crewmate.academy/client-api/sharing/share-file.html
        """
        # get file key
        file_memloc = str_to_memloc(f"{filename}@{self.username}")
        indirection_key, key_loc, file_md_loc, owner, sharees = auth_get(self.home_key, file_memloc)
        file_key = auth_get(indirection_key, key_loc)

        token_loc = str_to_memloc(f"{self.username}@{recipient}@{filename}")

        if owner:
            # generate new lockbox w/ file key
            lockbox_key = crypto.SecureRandom(SYM_KEY_LEN)
            lockbox_addr = memloc.Make()
            auth_set(file_key, lockbox_key, lockbox_addr)

            # sharing token
            sharing_token = [lockbox_addr, lockbox_key, file_md_loc]
            # log share
            sharees[recipient] = [lockbox_addr, lockbox_key]
            auth_set([indirection_key, key_loc, file_md_loc, owner, sharees], self.home_key, file_memloc)
        else:
            # share your own lockbox
            sharing_token = [key_loc, indirection_key, file_md_loc]
        
        # upload token
        auth_set(sharing_token, self.signing_key, token_loc, asm=True, recipient=recipient) 



    def receive_file(self, filename: str, sender: str) -> None:
        """
        The specification for this function is at:
        http://dropbox.crewmate.academy/client-api/sharing/receive-file.html
        """
        file_memloc = str_to_memloc(f"{filename}@{self.username}")

        # see if file exists; will raise exception if memloc is used or if it was used but
        # there is an integrity violation
        try: 
            auth_get(self.home_key, file_memloc)
        except util.DropboxError as de:
            if str(de) == INTEGRITY_ERR_MSG:
                raise de
            # otherwise it is empty and we can proceed

        token_loc = str_to_memloc(f"{sender}@{self.username}@{filename}")
        lockbox_addr, lockbox_key, file_md_loc = auth_get(self.priv_key, token_loc, asm=True, sender=sender)

        personal_metadata = [lockbox_key, lockbox_addr, file_md_loc, False, {}]
        auth_set(personal_metadata, self.home_key, file_memloc)

        


    def revoke_file(self, filename: str, old_recipient: str) -> None:
        """
        The specification for this function is at:
        http://dropbox.crewmate.academy/client-api/sharing/revoke-file.html
        """
        # implicitly checks if file exists
        filedata = self.download_file(filename)

        file_memloc = str_to_memloc(f"{filename}@{self.username}")
        indirection_key, key_loc, file_md_loc, owner, sharees = auth_get(self.home_key, file_memloc)

        if not owner:
            # if you don't own the file, just do nothing
            return 

        file_key = auth_get(indirection_key, key_loc)
        next_block_memloc, tail_block_memloc = auth_get(file_key, file_md_loc)

        # reupload w/ new file key
        new_file_key = crypto.SecureRandom(16)
        auth_set([next_block_memloc, tail_block_memloc], new_file_key, file_md_loc)
        auth_set([filedata, tail_block_memloc], new_file_key, next_block_memloc)

        # replace your own key
        auth_set(new_file_key, indirection_key, key_loc)

        # remove revoked user
        if old_recipient in sharees: 
            del sharees[old_recipient]
        
            # share new key
            for key_info in sharees.values():
                lockbox_addr, lockbox_key = key_info
                auth_set(new_file_key, lockbox_key, lockbox_addr)
            





def create_user(username: str, password: str) -> User:
    """
    The specification for this function is at:
    http://dropbox.crewmate.academy/client-api/authentication/create-user.html
    """
    verify_key, signing_key = crypto.SignatureKeyGen()
    try: 
        keyserver.Set(f"verify@{username}", verify_key)
    except ValueError: 
        raise util.DropboxError("Username already taken")
    
    pub_key, priv_key = crypto.AsymmetricKeyGen()
    keyserver.Set(f"enc@{username}", pub_key)

    salt = crypto.SecureRandom(SALT_LEN)
    salt_memloc = memloc.MakeFromBytes(crypto.Hash(f"salt@{username}".encode())[:16])
    salt_sign = crypto.SignatureSign(signing_key, salt)
    dataserver.Set(salt_memloc, util.ObjectToBytes([salt, salt_sign]))

    home_key = crypto.PasswordKDF(password, salt, SYM_KEY_LEN)


    home_memloc = memloc.MakeFromBytes(crypto.Hash(f"home@{username}".encode())[:16])
    auth_set([bytes(signing_key), bytes(priv_key)], home_key, home_memloc)

    return authenticate_user(username, password)

def authenticate_user(username: str, password: str) -> User:
    """
    The specification for this function is at:
    http://dropbox.crewmate.academy/client-api/authentication/authenticate-user.html
    """
    try:
        verify_key = keyserver.Get(f"verify@{username}")
    except ValueError:
        raise util.DropboxError("Username does not exist") 


    salt_memloc = memloc.MakeFromBytes(crypto.Hash(f"salt@{username}".encode())[:16])
    salt, salt_sign = util.BytesToObject(dataserver.Get(salt_memloc))
    ensure_integrity(verify_key, salt, salt_sign)
    
    home_key = crypto.PasswordKDF(password, salt, SYM_KEY_LEN)
    home_memloc = memloc.MakeFromBytes(crypto.Hash(f"home@{username}".encode())[:16])
    
    signing_key, priv_key = auth_get(home_key, home_memloc)
    signing_key = crypto.SignatureSignKey.from_bytes(signing_key)
    priv_key = crypto.AsymmetricDecryptKey.from_bytes(priv_key)

    return User(home_key, signing_key, priv_key, username, password)



if __name__ == "__main__":
    w = create_user("will", "iam")
    z = create_user("zach", "ary")
    b = create_user("bern", "ardo")
    r = create_user("rob", "erto")

    w.upload_file("file1", b'data')
    print(w.download_file("file1"))

    w.append_file("file1", b' more data')
    print(w.download_file("file1"))

    w.share_file("file1", "zach")
    z.receive_file("file1", "will")
    print(z.download_file("file1"))

    z.append_file("file1", b' zach\'s data')
    print(w.download_file("file1"))

    z.share_file("file1", "bern")
    b.receive_file("file1", "zach")
    print(b.download_file("file1"))

    w.share_file("file1", "rob")
    r.receive_file("file1", "will")
    print(r.download_file("file1"))

    w.revoke_file("file1", "zach")

    # success
    print(w.download_file("file1"))
    print(r.download_file("file1"))

    # fail
    try:
        z.download_file("file1")
    except util.DropboxError:
        print("SUCCESS")

    try:
        b.download_file("file1")
    except util.DropboxError:
        print("SUCCESS")






