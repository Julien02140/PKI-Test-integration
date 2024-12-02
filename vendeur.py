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
import time

numero_vendeur = sys.argv[1]
mqtt_broker_address = "194.57.103.203"
mqtt_broker_port = 1883
mqtt_client_id = "veudeur_client_julien_hugo"
topic = f"vehicule/JH/vendeur{numero_vendeur}" # ajouter le numéro de client en argument
topic_ca = "vehicule/JH/ca"
topic_client = "vehicule/JH/client"

USE_VERSION2_CALLBACKS = not paho.mqtt.__version__.startswith("1.")

if USE_VERSION2_CALLBACKS:
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, mqtt_client_id)
else:
    client = mqtt.Client(mqtt_client_id)

if client.connect(mqtt_broker_address,mqtt_broker_port,60) != 0:
    print("Problème de connexion avec le broker")

def on_message(client, userdata, msg):
    json_data = msg.payload.decode('utf-8')
    message = json.loads(json_data)
    if message['type'] == 'connexion_acceptee':

        #La CA a accepté la connexion et a recu la clé AES
        #Le vendeur peut donc commencé à générer son csr

        print("génération du csr et envoie du csr à la CA")
        generate_csr()
        
        with open(f"csr_vendeur{numero_vendeur}.pem", "rb") as f:
            contenu = str(f.read())

        #chiffrer le csr avec AES
        contenu_chiffre = chiffre_message_AES(message['id'],contenu.encode('utf-8'))

        reponse = {
            'type': 'demande_certificat',
            'id': f'vendeur{numero_vendeur}',
            'csr': contenu_chiffre
        }

        json_data = json.dumps(reponse)
        client.publish(topic_ca,json_data)

    if message['type'] == 'envoi_certificat':

        print("certificat recu de la part de la CA \n")
        cert = dechiffre_message_AES(message['id'],message['certificat'])
        cert = eval(cert.encode('utf-8'))
        with open(f"cert_vendeur{numero_vendeur}.pem", "wb") as f:
            f.write(cert)
        
    if message['type'] == 'envoie_cle_AES_client':
        #Le vendeur recoit la clé AES du client
        #déchiffrer en utilisant la cle privée du vendeur

        id = message['id']
        AES_key = dechiffre_message(message['AES_key'])
        AES_iv = dechiffre_message(message['AES_iv'])

        with open(f'key/AES_key_vendeur{numero_vendeur}_{id}','rb') as AES_key_file:
            AES_key_file.write(AES_key)

        with open(f'key/AES_iv_vendeur{numero_vendeur}_{id}','rb') as AES_iv_file:
            AES_iv_file.write(AES_iv)

        print(f'cle AES recu de la part du {id}')

        #envoyer le certificat au client  
        print(f"demande de certificat recu de la part du {message['id']}")

        with open(f'cert_vendeur{numero_vendeur}.pem', 'rb') as f:
            cert_bytes = f.read()

        print(f"message id = {message['id']}")

        certificate = x509.load_pem_x509_certificate(cert_bytes)

        certificate = certificate.public_bytes(encoding=serialization.Encoding.PEM)

        certificat_chiffre = chiffre_message_AES(message['id'],certificate)

        reponse = {
            'type': 'retour_demande_de_certificat',
            'id': f'vendeur{numero_vendeur}',
            'certificat': certificat_chiffre
        }

        json_data = json.dumps(reponse)
        print("envoie du certificat au client \n")
        client.publish(f"vehicule/JH/{message['id']}",json_data)

    # received_data = msg.payload.decode().split(',')
    # type_demande = received_data[0]
    # contenu = received_data[1]

    # if type_demande == 'retour_certificat':
    #     print("Message reçu sur le sujet/topic "+msg.topic)
    #     with open(f'cert_vendeur{numero_vendeur}.crt', 'wb') as c:
    #         c.write(contenu)
    # elif type_demande == 'demande_certificat':
    #     with open(f'cert_vendeur{numero_vendeur}.crt', 'r') as f:
    #         certificat = f.read()
    #         client.publish(topic_client+contenu, ','.join(map(str, ['retour_certificat',certificat])))

def on_connect(client, userdata, flags, reason_code, properties):
    print("Connecté au broker MQTT avec le code de retour:", reason_code)
    client.subscribe(topic)

def generate_csr():
    
    #charger la clé privée
    with open(f'key/private_key_vendeur{numero_vendeur}.pem', 'rb') as f:
        private_key_pem = f.read()

    private_key = serialization.load_pem_private_key(private_key_pem, password=None)

    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"vendeur{numero_vendeur}"),
    ])

    csr = x509.CertificateSigningRequestBuilder().subject_name(
        name
    ).sign(private_key, hashes.SHA256())

    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    with open(f"csr_vendeur{numero_vendeur}.pem", "wb") as f:
        f.write(csr_pem)

    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(f"private_key_vendeur{numero_vendeur}.pem", "wb") as f:
        f.write(private_key_pem)

    with open(f"public_key_vendeur{numero_vendeur}.pem", "wb") as f:
        f.write(public_key_pem)

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

    # Écrire les clés dans des fichiers
    with open(f'key/private_key_vendeur{numero_vendeur}.pem', 'wb') as f:
        f.write(private_pem)

    with open(f'key/public_key_vendeur{numero_vendeur}.pem', 'wb') as f:
        f.write(public_pem)

    #On part du postula que le client a déja la clé publique du vendeur
    with open(f'../client/key/public_key_vendeur{numero_vendeur}.pem', 'wb') as f:
        f.write(public_pem)

def chiffre_message(id_receveur,message):

    with open(f'key/public_key_{id_receveur}.pem', 'rb') as f:
        public_key_pem = f.read()

    print(f"utilisation de clé publique key/public_key_{id_receveur}.pem\n")

    public_key = serialization.load_pem_public_key(
        public_key_pem,
    )

    #chiffrer le message
    message_chiffre = public_key.encrypt(
            message,
            pad.OAEP(
            mgf=pad.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    message_chiffre_base_64 = base64.b64encode(message_chiffre).decode('utf-8')

    return message_chiffre_base_64

def dechiffre_message(message):
    with open(f'key/private_key_vendeur_{numero_vendeur}', 'rb') as f:
        public_key_pem = f.read()

    
    private_key = serialization.load_pem_public_key(
        public_key_pem,
        password=None,
    )

    #dechiffrer le message
    message_dechiffrer = private_key.decrypt(
            message,
            padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return message_dechiffrer

def chiffre_message_AES(id_receveur,message):
    #le message doit être en byte pour âtre chiffré
    #ne fonctionne pas avec les strings
    if not isinstance(message,bytes):
        message = message.encode('utf-8')

    with open(f'key/AES_key_vendeur{numero_vendeur}_{id_receveur}.bin', 'rb') as f:
        AES_key_file = f.read()

    with open(f'key/AES_iv_vendeur{numero_vendeur}_{id_receveur}.bin', 'rb') as f:
        AES_iv_file = f.read()

    cipher = Cipher(algorithms.AES(AES_key_file), modes.CBC(AES_iv_file))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_contenu = padder.update(message) + padder.finalize()
    ct = encryptor.update(padded_contenu) + encryptor.finalize()

    message_chiffre_base64 = base64.b64encode(ct).decode('utf-8')


    return message_chiffre_base64

def dechiffre_message_AES(id_envoyeur,message):
    with open(f'key/AES_key_vendeur{numero_vendeur}_{id_envoyeur}.bin', 'rb') as AES_key_file:
        AES_key_file.read()

    with open(f'key/AES_iv_vendeur{numero_vendeur}{id_envoyeur}.bin', 'rb') as AES_iv_file:
        AES_iv_file.read()

    cipher = Cipher(algorithms.AES(AES_key_file), modes.CBC(AES_iv_file))

    decryptor = cipher.decryptor()
    message_dechiffre = decryptor.update(message) + decryptor.finalize()

    return message_dechiffre

client.on_message = on_message
client.on_connect = on_connect

#générer clé publique et privée
generate_key()

#générer clé AES pour la Ca
AES_key_vendeur_ca = os.urandom(32)
AES_iv_vendeur_ca = os.urandom(16) 

with open(f'key/AES_key_vendeur{numero_vendeur}_ca.bin',"wb") as f:
    f.write(AES_key_vendeur_ca)

with open(f'key/AES_iv_vendeur{numero_vendeur}_ca.bin','wb') as f:
    f.write(AES_iv_vendeur_ca)

with open(f'key/AES_key_vendeur{numero_vendeur}_ca.bin',"rb") as f:
    AES_key_vendeur_ca = f.read()

with open(f'key/AES_key_vendeur{numero_vendeur}_ca.bin',"rb") as f:
    AES_iv_vendeur_ca = f.read()

#chiffre la clé AES avec la clé publique de la CA
AES_key_vendeur_ca_chiffre = chiffre_message('ca',AES_key_vendeur_ca)
AES_iv_vendeur_ca_chiffre = chiffre_message('ca',AES_iv_vendeur_ca)

#envoyer une demande de connexion à la Ca et lui donner la clé AES
message = {
    'type': 'demande_connexion',
    'id': f'vendeur{numero_vendeur}',
    'AES_key_vendeur': AES_key_vendeur_ca_chiffre,
    'AES_iv_vendeur' : AES_iv_vendeur_ca_chiffre
}

json_data = json.dumps(message)
client.publish(topic_ca,json_data)

print(f"démarrage vendeur {numero_vendeur}")

client.loop_forever()