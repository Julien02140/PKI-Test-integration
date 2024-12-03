import paho.mqtt.client as mqtt
import paho.mqtt
import json, os, base64, time
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timezone
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding as pad

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
    with open('key/private_key_mouchard.pem', 'wb') as f:
        f.write(private_pem)

    with open('key/public_key_mouchard.pem', 'wb') as f:
        f.write(public_pem)

def generate_key_aes():
    #générer clé AES pour la Ca
    AES_key_mouchard_ca = os.urandom(32)
    AES_iv_mouchard_ca = os.urandom(16) 

    with open('key/AES_key_mouchard_ca.bin',"wb") as f:
        f.write(AES_key_mouchard_ca)

    with open('key/AES_iv_mouchard_ca.bin','wb') as f:
        f.write(AES_iv_mouchard_ca)

def load_private_key():
    #charger la clé privée
    with open('key/private_key_mouchard.pem', 'rb') as f:
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

def on_connect(client, userdata, flags, reason_code, properties):
    print("Connecté au broker MQTT avec le code de retour:", reason_code)
    client.subscribe(topic)

def on_message(client, userdata, msg):
    json_data = msg.payload.decode('utf-8')
    message = json.loads(json_data)
    if message['type'] == 'erreur':
        print(message['erreur'])
    elif message['type'] == 'envoi_certificat':

        print("certificat recu de la part de la CA \n")
        cert = dechiffre_message_AES(message['certificat'])
        cert = eval(cert.encode('utf-8'))
        with open("certificat/cert_mouchard.pem", "wb") as f:
            f.write(cert)

client.on_message = on_message
client.on_connect = on_connect

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
    time.sleep(3)

    print('Premier test')
    # Teste le fait d'enlever des données
    contenu_chiffre_modifie = contenu_chiffre[:-10]
    message['csr'] = contenu_chiffre_modifie
    json_data = json.dumps(message)
    client.publish(topic_ca,json_data)
    time.sleep(3)

    print('Deuxième test')
    # Teste le fait de modifier les données
    contenu_chiffre_modifie = contenu_chiffre.replace('E','5')
    message['csr'] = contenu_chiffre_modifie
    json_data = json.dumps(message)
    client.publish(topic_ca,json_data)

def test_certificat():

    with open('certificat/cert_mouchard.pem', 'rb') as f:
        cert_byte = f.read()

    cert = x509.load_pem_x509_certificate(cert_byte, default_backend())
    # Vérifier si le certificat est encore valide
    now = datetime.now(timezone.utc)

    if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
        return False, "Le certificat n'est pas dans sa période de validité."
    
    print("date du certificat valide")

    with open("key/public_key_ca.pem", "rb") as f:
        ca_public_key = f.read()
        
    ca_public_key = serialization.load_pem_public_key(ca_public_key, backend=default_backend())

    #On verifie la signature du certificat en utilisant la clé publique de la CA
    try:
        # Vérifiez la signature du certificat
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            pad.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        print("signature valide")
        return True
    except Exception as e:
        print(f"Erreur lors de la vérification de la signature : {e}")
        return False  # La signature est invalide 

#générer clé publique et privée et les clés aes du mouchard
generate_key()
generate_key_aes()

print("démarrage du mouchard \n")
test_csr()
test_certificat()

# client.loop_forever()



