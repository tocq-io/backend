import base58, hashlib, base64

# inspired by https://gist.github.com/dschuetz/2ff54d738041fc888613f925a7708a06

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import requests

cont_headers = {'content-type': 'application/octet-stream'}
url_prefix = 'http://127.0.0.1:8787/'

def init_key_pair(backend=None):
    return ec.generate_private_key(ec.SECP256R1(), backend)

def verify_personal_info(shared_info):
    try:
        public_bytes = load_der_public_key(base64.b64decode(shared_info["pub_key"]))
        public_bytes.verify(base64.b64decode(shared_info["sig"]), shared_info["topic"].encode(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        print ("Verification of %s failed" % topic)
        return False
    else:
        return True

#First create Alice's key pair and folder for her first topic
def init_personal_info(private_key, topic = "TestTopic"):
    sig = private_key.sign(topic.encode(), ec.ECDSA(hashes.SHA256()))
    pub_key = private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return {"pub_key": base64.b64encode(pub_key), "topic": topic, "sig": base64.b64encode(sig)}


def init_shared_folder(shared_info, private_key):
    #verify that the shared topic is from the sharing persona
    if not verify_personal_info(shared_info):
        return

    # Create a shared folder based on both keys
    #
    shared_key = private_key.exchange(ec.ECDH(), load_der_public_key(base64.b64decode(shared_info["pub_key"])))

    shared_sign_key = Ed25519PrivateKey.from_private_bytes(shared_key)
    shared_sig = shared_sign_key.sign(shared_info["topic"].encode())
    shared_short_sig = hashlib.new('ripemd160', shared_sig)

    topic_folder = base58.b58encode(shared_short_sig.digest())

    return topic_folder

#Send message
def send_to(msg: str, folder: bytes, receiver_signing_key_str):
    #Create 1 time private key pair to send to Alice
    ephemeral_private_key = init_key_pair()
    ephemeral_pub_bytes = ephemeral_private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    receiver_signing_key = load_der_public_key(base64.b64decode(receiver_signing_key_str))
    shared_key = ephemeral_private_key.exchange(ec.ECDH(), receiver_signing_key)

    ckdf = ConcatKDFHash(
        algorithm=hashes.SHA256(),
        length=48,
        otherinfo=ephemeral_pub_bytes[-65:]
    )
    kdf_out = ckdf.derive(shared_key)
    key_enc = kdf_out[0:32]
    iv = kdf_out[16:]

    C = AESGCM(key_enc)
    ct = C.encrypt(iv, msg.encode(), None)
    #well, it works
    crypt_msg = ephemeral_pub_bytes + ct

    topic_folder = folder.decode()
    #print(crypt_msg)
    url = url_prefix + topic_folder

    r = requests.put(url, data=crypt_msg, headers=cont_headers)

#Read message
def read_from(sent, signing_key):
    r = requests.get(url_prefix + sent)
    crypt_msg = r.content
    print(len(crypt_msg))

    ephemeral_public_key = crypt_msg[:91]
    ephemeral_public_bytes = load_der_public_key(ephemeral_public_key)

    cr_msg = crypt_msg[91:]
    shared_key = signing_key.exchange(ec.ECDH(), ephemeral_public_bytes)

    ckdf = ConcatKDFHash(
        algorithm=hashes.SHA256(),
        length=48,
        otherinfo=ephemeral_public_key[-65:]
    )
    kdf_out = ckdf.derive(shared_key)
    key_enc = kdf_out[0:32]
    iv = kdf_out[16:]

    C = AESGCM(key_enc)
    msg = C.decrypt(iv, cr_msg, None)

    r = requests.delete(url_prefix + sent)

    return msg.decode()

#Initialie a key for each person
#assuming public keys are exchanged over adequate means
alice_signing_key = init_key_pair()

alice_shared_info = init_personal_info(alice_signing_key)

bob_signing_key = init_key_pair()

bob_shared_info = init_personal_info(bob_signing_key, alice_shared_info['topic'])

#the 'folder' name can be generated locally based on exchanged public key and does not have to be shared
alice_bob_folder_info = init_shared_folder(bob_shared_info, alice_signing_key)
print(alice_bob_folder_info)
#Alice can send a message or other data to the shared topic
send_to("Hello Bob, how are you?", alice_bob_folder_info, bob_shared_info['pub_key'])
# bob reads data
print(read_from(alice_bob_folder_info.decode(), bob_signing_key))

#Bob sends more data back
send_to("Supergood.", alice_bob_folder_info, alice_shared_info['pub_key'])
#alice reads data
print(read_from(alice_bob_folder_info.decode(), alice_signing_key))

# another persona joining the topic
jane_signing_key = init_key_pair()

jane_shared_info = init_personal_info(jane_signing_key, alice_shared_info['topic'])
jane_alice_folder_info = init_shared_folder(alice_shared_info, jane_signing_key)
print(jane_alice_folder_info)

jane_bob_folder_info = init_shared_folder(bob_shared_info, jane_signing_key)
print(jane_bob_folder_info)

#Jane sends message to alice
send_to("Hi alice, hi bob, joining!.", jane_alice_folder_info, alice_shared_info['pub_key'])
#also sending it to bob
send_to("Hi alice, hi bob, joining!.", jane_bob_folder_info, bob_shared_info['pub_key'])
#alice reads data
print(read_from(jane_alice_folder_info.decode(), alice_signing_key))
# bob reads data
print(read_from(jane_bob_folder_info.decode(), bob_signing_key))

#ALice answers
send_to("Hi Jane!", jane_alice_folder_info, jane_shared_info['pub_key'])
#also sending it to bob
send_to("Hi Jane!", alice_bob_folder_info, bob_shared_info['pub_key'])
#alice reads data
print(read_from(jane_alice_folder_info.decode(), jane_signing_key))
# bob reads data
print(read_from(alice_bob_folder_info.decode(), bob_signing_key))

#Bob answers
send_to("Hi hi!!", jane_bob_folder_info, jane_shared_info['pub_key'])
#also sending it to Alice
send_to("Hi hi!!", alice_bob_folder_info, alice_shared_info['pub_key'])
#alice reads data
print(read_from(jane_bob_folder_info.decode(), jane_signing_key))
# bob reads data
print(read_from(alice_bob_folder_info.decode(), alice_signing_key))
