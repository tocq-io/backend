import os, base58, hashlib, base64

# inspired by https://gist.github.com/dschuetz/2ff54d738041fc888613f925a7708a06

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import requests
#runs in memory, if set to True it uses a local wrangler REST API
with_http = True
cont_headers = {'content-type': 'text/plain'}
url_prefix = 'http://127.0.0.1:8787/'

def init_key_pair(backend=None):
    return ec.generate_private_key(ec.SECP256R1(), backend)

def get_personal_topic(topic: str, private_key):
    sig = private_key.sign(topic.encode(), ec.ECDSA(hashes.SHA256()))
    short_sig = hashlib.new('ripemd160', sig)
    topic_folder = base58.b58encode(short_sig.digest())
    pub_key = private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    #create_personal_topic(topic_folder)
    return {"pub_key": base64.b64encode(pub_key), "topic_folder": topic_folder, "topic": topic, "sig": base64.b64encode(sig)}

def verify_personal_topic_receiver(signature: str, topic: str, public_key):
    try:
        public_bytes = load_der_public_key(base64.b64decode(public_key))
        public_bytes.verify(base64.b64decode(signature), topic.encode(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        print ("Verification of %s failed" % topic)
        return False
    else:
        return True

def create_personal_topic(topic_folder: str):
    try:
        os.mkdir(topic_folder)
    except OSError:
        print ("Creation of user directory %s failed" % topic_folder)
    else:
        print ("Successfully created user directory %s " % topic_folder)


def delete_personal_topic(topic_folder: str):
    try:
        os.rmdir(topic_folder)
    except OSError:
        print ("Deletion of user directory %s failed" % topic_folder)
    else:
        print ("Successfully deleted user directory %s " % topic_folder)

#First create Alice's key pair and folder for her first topic
def init_personal_topic(private_key, topic = "TestTopic"):
    return get_personal_topic(topic, private_key)


def init_received_personal_topic(shared_info, private_key):
    #verify that the shared topic is from the sharing persona
    if not verify_personal_topic_receiver(shared_info['sig'], shared_info["topic"], shared_info["pub_key"]):
        return

    # Option to create a shared folder based on both keys
    # but that would prevent sharing with more than 2 persons
    # shared_key = bob_private_key.exchange(ec.ECDH(), alice_shared_info["pub_key"])
    #
    # sign_alic_msgs = ed25519.Ed25519PrivateKey.from_private_bytes(shared_key)
    # bob_to_alice_sig = sign_alic_msgs.sign(alice_shared_info["topic"])
    # bob_to_alice_short_sig = hashlib.new('ripemd160', bob_to_alice_sig).digest()
    #
    # not having a shared folder means that each persona has their own folder for a specific topic, containing
    # received and sent objects.

    return get_personal_topic(shared_info["topic"], private_key)

#Send message
def send_to(msg: str, receiver_info, sender_info=None):
    #verify that the folder is the folder of the receiver
    if not verify_personal_topic_receiver(receiver_info['sig'], receiver_info["topic"], receiver_info["pub_key"]):
        return
    #Create 1 time private key pair to send to Alice
    ephemeral_private_key = init_key_pair()
    ephemeral_pub_bytes = ephemeral_private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    receiver_signing_key = load_der_public_key(base64.b64decode(receiver_info["pub_key"]))
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
    final_ct = ephemeral_pub_bytes + ct
    crypt_msg = base64.b64encode(final_ct)

    if with_http:
        topic_folder = receiver_info["topic_folder"].decode()
        print(crypt_msg)
        url = url_prefix + topic_folder
        if sender_info:
             url += '/' + sender_info["topic_folder"].decode()

        r = requests.put(url, data=crypt_msg, headers=cont_headers)
        print(r)
        return topic_folder
    else:
        ret_msg = {"to": receiver_info["topic_folder"], "obj":crypt_msg}
        if sender_info:
            ret_msg["from"] = sender_info["topic_folder"]
            ret_msg["sig"] = sender_info["sig"]

        return ret_msg

#Read message
def read_from(sent, signing_key):
    if with_http:
        r = requests.get(url_prefix + sent)
        sent_obj = r.text
    else:
        sent_obj = sent['obj']
    crypt_msg = base64.b64decode(sent_obj)
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
    return msg.decode()

#Initialie a key for each topic
alice_signing_key = init_key_pair()
#alice creates a folder to receive data on and creates an object containing all necessary info for this topic
#the object could be shared eg. over a QR code or by sharing it over a ledger.
#The object is shared either with one person or many and represents an invitation to share data with the sharing persona.
alice_shared_info = init_personal_topic(alice_signing_key)
#data can be sent anonymously and safely based on Alice's public information
bob_sent_to_topic = send_to("Just some shared data", alice_shared_info)
read_from(bob_sent_to_topic, alice_signing_key)

#Bob also wants to receive messages and creates a key pair specific for this topic
bob_signing_key = init_key_pair()
#and creates a folder to receive data on, having the same topic, the created object would have to be shared
#with Alice to be writable. This also implies that Alice would have to accept that she wants to share with Bob.
#Consent (or not) to share with another persona is private. It does not need backend systems to consent to an invitation.
bob_sharable_info = init_received_personal_topic(alice_shared_info, bob_signing_key)

#Alice can send a response to the shared data and share some other data back, on the same topic
sent_obj_from_alice = send_to("Thanks for the data, how are you?", bob_sharable_info, alice_shared_info)
print(sent_obj_from_alice)
print(read_from(sent_obj_from_alice, bob_signing_key))

#Bob sends more data back
sent_obj_from_bob = send_to("Supergood.", alice_shared_info, bob_sharable_info)
print(sent_obj_from_bob)
print(read_from(sent_obj_from_bob, alice_signing_key))
