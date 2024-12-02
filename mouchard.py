import paho.mqtt.client as mqtt
import paho.mqtt
import sys, json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as pad
import sys,os,json
import base64

mqtt_broker_address = "194.57.103.203"
mqtt_broker_port = 1883
mqtt_client_id = "mouchard_julien_hugo"
topic = "vehicule/JH/mouchard"
topic_ca = "vehicule/JH/ca"

USE_VERSION2_CALLBACKS = not paho.mqtt.__version__.startswith("1.")

if USE_VERSION2_CALLBACKS:
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, mqtt_client_id)
else:
    client = mqtt.Client(mqtt_client_id)

if client.connect(mqtt_broker_address,mqtt_broker_port,60) != 0:
    print("Problème de connexion avec le broker")

def generate_key():
    #creation des clés publique et privé du vendeur
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Écrire les clés dans des fichiers, on part du principe que la caait accès à la clé puyblique du mouchard
    with open(f'key/private_key_mouchard.pem', 'wb') as f:
        f.write(private_pem)

    with open(f'key/public_key_mouchard.pem', 'wb') as f:
        f.write(public_pem)

def generate_key_aes():
    #générer clé AES pour la Ca
    AES_key_mouchard_ca = os.urandom(32)
    AES_iv_mouchard_ca = os.urandom(16) 

    with open(f'key/AES_key_mouchard_ca.bin',"wb") as f:
        f.write(AES_key_mouchard_ca)

    with open(f'key/AES_iv_mouchard_ca.bin','wb') as f:
        f.write(AES_iv_mouchard_ca)

def load_private_key():
    #charger la clé privée
    with open(f'key/private_key_mouchard.pem', 'rb') as f:
        private_key_pem = f.read()

    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    return private_key

def generate_csr():

    key = load_private_key()

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    # info csr
    x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Laon"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Hirson"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "URCA"),
    x509.NameAttribute(NameOID.COMMON_NAME, "urca.fr"),
    ])).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("urca.fr"),
            x509.DNSName("www.urca.fr"),
            x509.DNSName("subdomain.urca.fr"),
    ]),
    critical=False,
    # 
    ).sign(key, hashes.SHA256())
    # Write our CSR out to disk.
    with open("csr/csr_mouchard.pem", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

def chiffre_message_AES(message):
    #le message doit être en byte pour âtre chiffré
    #ne fonctionne pas avec les strings
    if not isinstance(message,bytes):
        message = message.encode('utf-8')

    with open('key/AES_key_mouchard_ca.bin', 'rb') as f:
        AES_key_file = f.read()

    with open('key/AES_iv_mouchard_ca.bin', 'rb') as f:
        AES_iv_file = f.read()

    cipher = Cipher(algorithms.AES(AES_key_file), modes.CBC(AES_iv_file))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_contenu = padder.update(message) + padder.finalize()
    ct = encryptor.update(padded_contenu) + encryptor.finalize()

    message_chiffre_base64 = base64.b64encode(ct).decode('utf-8')
    return message_chiffre_base64

def dechiffre_message_AES(message):
    with open('key/AES_key_mouchard_ca.bin', 'rb') as f:
        AES_key_file = f.read()

    with open('key/AES_iv_mouchard_ca.bin', 'rb') as f:
        AES_iv_file = f.read()

    cipher = Cipher(algorithms.AES(AES_key_file), modes.CBC(AES_iv_file))

    decryptor = cipher.decryptor()
    message_dechiffre = decryptor.update(message) + decryptor.finalize()

    message_dechiffre_str = message_dechiffre.decode('utf-8')

    return message_dechiffre_str

def on_message(client, userdata, msg):
    json_data = msg.payload.decode('utf-8')
    message = json.loads(json_data)

    if message['type'] == 'envoi_certificat':

        print("certificat recu de la part de la CA \n")
        cert = dechiffre_message_AES(message['certificat'])
        cert = eval(cert.encode('utf-8'))
        with open("certificat/cert_mouchard.pem", "wb") as f:
            f.write(cert)

def test_csr():
    print("génération du csr et envoie du csr à la CA")
    generate_csr()

    with open("csr/csr_mouchard.pem", "rb") as f:
        contenu = str(f.read())

    #chiffrer le csr avec AES
    contenu_chiffre = chiffre_message_AES(contenu.encode('utf-8'))

    message = {
        'type': 'demande_certificat',
        'id': 'mouchard',
        'csr': contenu_chiffre
    }

    json_data = json.dumps(message)
    client.publish(topic_ca,json_data)

#générer clé publique et privée et les clés aes du mouchard
generate_key()
generate_key_aes()

print("démarrage du mouchard \n")
print("test csr")
test_csr()
