import paho.mqtt.client as mqtt
import paho.mqtt
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import sys,os,json
import base64
import time

# Paramètres MQTT
numero_client = sys.argv[1]
mqtt_broker_address = "194.57.103.203"
mqtt_broker_port = 1883
mqtt_client_id = "ca_client_julien_hugo"
topic = f"vehicule/JH/client{numero_client}"
#le client1 va communiqué avec le vendeur1
#c'est pour les différent scénarios
#scénario 1 : client1, vendeur1 : vérification du certificat (signature et date)
#scénario 2 : client2, vendeur2 : vérifier le certificat + vérifier si il est non révoqué (certificat non révoqué)
#scénario 3 : client3, vendeur3 : pareil que scénario 2 mais le certificat est révoqué
topic_vendeur = f"vehicule/JH/vendeur{numero_client}"
topic_ca = "vehicule/JH/ca"

USE_VERSION2_CALLBACKS = not paho.mqtt.__version__.startswith("1.")

if USE_VERSION2_CALLBACKS:
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, mqtt_client_id)
else:
    client = mqtt.Client(mqtt_client_id)

if client.connect("194.57.103.203",1883,60) != 0:
    print("Problème de connexion avec le broker")

def on_message(client, userdata, msg):
    json_data = msg.payload.decode('utf-8')
    message = json.loads(json_data)

    if message['type'] == 'envoie_crl':
        #seul le client 1 et 2 arrive dans cet boucle
        #crl de la CA reu
        print("j'ai recu la crl \n")

        id = message['id']

        crl = dechiffre_message_AES(id,message['crl'])

        if crl != None:
        
            crl = crl.encode('utf-8')

            with open("crl.pem", "wb") as f:
                f.write(crl)
        
            #charger le certificat
            with open(f"cert_vendeur{numero_client}.pem", "rb") as f:
                cert_vendeur = f.read()

            cert_vendeur = x509.load_pem_x509_certificate(cert_vendeur, default_backend())

            #Le client vérifie si le certificat n'est pas dans la crl
            verifier_crl(cert_vendeur)
        
        else:
            #la crl est vide, aucun certificat n'a été révoqué par la CA pour le moment
            print("CRL vide \n")
            print("Certificat non révoqué \n")

    if message['type'] == 'retour_cle_AES_ca':

        #La CA a bien recu la clé AES

        #On peut commencé les échanges avec le vendeur
        #Le client va demandé le certificat au vendeur
        message_vendeur = {
            'type': 'demande_certificat_client',
            'id': f'client{numero_client}',
        }

        json_data_vendeur = json.dumps(message_vendeur)
        client.publish(topic_vendeur,json_data_vendeur)

    if message['type'] == 'retour_demande_de_certificat':
        #le client a recu le certificat
        print(f"certificat reçu de la part du {message['id']}")
        cert_str = message.get('certificat',None)
        cert_encode = cert_str.encode('utf-8')

        with open(f'cert_{message["id"]}.pem', 'wb') as c:
            c.write(cert_encode)
        
        cert = x509.load_pem_x509_certificate(cert_encode, default_backend())

        bool = verify_certificate(cert)

        if bool == True:
            print("certificat valide")

            #si le certificat est valide alors le client va extraire la clé publique du certificat
            
            public_key_vendeur = cert.public_key()
            public_key_pem = public_key_vendeur.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            with open(f"key/public_key_{message['id']}.pem", 'wb') as f:
                f.write(public_key_pem)

            #maintenant on peut envoyer la clé AES chiffré avec la clé publique du vendeur

            with open(f"key/AES_key_client{numero_client}_{message['id']}.bin",'rb') as f:
                AES_key = f.read()

            with open(f"key/AES_iv_client{numero_client}_{message['id']}.bin",'rb') as f:
                AES_iv = f.read()

            AES_key_chiffre = chiffre_message(message['id'],AES_key)
            AES_iv_chiffre = chiffre_message(message['id'],AES_iv)

            message_vendeur = {
                    'type': 'envoie_cle_AES_client',
                    'id': f'client{numero_client}',
                    'AES_key': AES_key_chiffre,
                    'AES_iv': AES_iv_chiffre
            }

            print("Cle AES envoyé au vendeur \n")

        json_data_vendeur = json.dumps(message_vendeur)
        client.publish(topic_vendeur,json_data_vendeur)

        else:
            print("certificat non valide")

    if message['type'] == 'AES_recu_vendeur':
        #le vendeur a bien recu la clé AES

        if(numero_client == "1"):
            print("fin du scénario 1")

        else:
            #le scénario 2 et 3 continue
            #le client demande la crl à la CA

            message_crl = {
                'type': 'demande_crl',
                'id': f'client{numero_client}'
            }

                json_data = json.dumps(message_crl)
                client.publish(topic_ca, json_data)

        else:
            print("certificat non valide")

        
def on_connect(client, userdata, flags, reason_code, properties):
    print("Connecté au broker MQTT avec le code de retour:", reason_code)
    client.subscribe(topic)

def verify_certificate(cert):
    # Vérifier si le certificat est encore valide
    now = datetime.now(timezone.utc)

    if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
        return False, "Le certificat n'est pas dans sa période de validité."
    
    print("date du certificat valide")

    with open("public_key_ca.pem", "rb") as f:
        ca_public_key = f.read()
        
    ca_public_key = serialization.load_pem_public_key(ca_public_key, backend=default_backend())

    #On verifie la signature du certificat en utilisant la clé publique de la CA
    try:
        # Vérifiez la signature du certificat
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        print("signature valide")
        return True
    except Exception as e:
        print(f"Erreur lors de la vérification de la signature : {e}")
        return False  # La signature est invalide 

client.on_connect = on_connect
client.on_message = on_message

#création d'un dossier confiance, cela stocke les certificats de confiance.
if not os.path.exists("trusted"):
    os.makedirs("trusted")

#création d'un dossier pour les certificats rejetés.
if not os.path.exists("rejected"):
    os.makedirs("rejected")

#consulte la crl et regarde si le certificat est révoqué
def verifier_crl(cert):
    #charger la clé publique de la CA
    with open("public_key_ca.pem", "rb") as f:
        ca_public_key = f.read()
    
    ca_public_key = serialization.load_pem_public_key(ca_public_key, backend=default_backend())

    #charge le fichier crl
    with open("crl.pem", "rb") as f:
        crl = f.read()

    crl = x509.load_pem_x509_crl(crl, default_backend())

    # Vérifier la signature de la CRL
    try:
        ca_public_key.verify(
            crl.signature,
            crl.tbs_certlist_bytes,
            padding.PKCS1v15(),
            crl.signature_hash_algorithm,
        )
        print("Signature de la CRL valide.")
    except Exception as e:
        print(f"Erreur lors de la vérification de la signature de la CRL : {e}")

    # Vérifier la validité de la CRL
    # now = datetime.now()
    # if now < crl.next_update or now > crl.last_update:
    #     print("La CRL est valide.")
    # else:
    #     print("La CRL a expiré ou n'est pas encore valide.")

    for revoked_cert in crl:
        if revoked_cert.serial_number == cert.serial_number:
            print("Le certificat est révoqué.")
            return True
    print("Le certificat n'est pas révoqué.")
    return False

def generate_key():
    #creation des clés publique et privé du client
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
    with open(f'key/private_key_client{numero_client}.pem', 'wb') as f:
        f.write(private_pem)

    with open(f'key/public_key_client{numero_client}.pem', 'wb') as f:
        f.write(public_pem)

    #On part du postula que le vendeur a deja la clé publique du client
    with open(f'../vendeur/key/public_key_client{numero_client}.pem', 'wb') as f:
        f.write(public_pem)


def chiffre_message(id_receveur,message):
    with open(f'key/public_key_{id_receveur}.pem', 'rb') as f:
        public_key_pem = f.read()

    public_key = serialization.load_pem_public_key(
        public_key_pem,
        password=None,
    )

    #chiffrer le message
    message_chiffre = public_key.encrypt(
            message,
            padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return message_chiffre

def dechiffre_message(message64):
    with open(f'key/private_key_client{numero_client}.pem', 'rb') as f:
        public_key_pem = f.read()
    
    private_key = serialization.load_pem_public_key(
        public_key_pem,
        password=None,
    )

    message = base64.b64decode(message64)

    #dechiffrer le message
    message_dechiffre = private_key.decrypt(
            message,
            pad.OAEP(
            mgf=pad.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return message_dechiffre

def chiffre_message_AES(id_receveur,message):
    #le message doit être en byte pour âtre chiffré
    #ne fonctionne pas avec les strings
    with open(f'key/AES_key_client{numero_client}_{id_receveur}.bin', 'rb') as AES_key_file:
        AES_key_file.read()

    with open(f'key/AES_iv_client{numero_client}_{id_receveur}.bin', 'rb') as AES_iv_file:
        AES_iv_file.read()

    cipher = Cipher(algorithms.AES(AES_key_file), modes.CBC(AES_iv_file))
    encryptor = cipher.encryptor()
    ct = encryptor.update(message) + encryptor.finalize()

    return ct

def dechiffre_message_AES(id_envoyeur,message):
    with open(f'key/AES_key_client{numero_client}_{id_envoyeur}.bin', 'rb') as AES_key_file:
        AES_key_file.read()

    with open(f'key/AES_iv_client{numero_client}_{id_envoyeur}.bin', 'rb') as AES_iv_file:
        AES_iv_file.read()

    cipher = Cipher(algorithms.AES(AES_key_file), modes.CBC(AES_iv_file))

    decryptor = cipher.decryptor()
    message_dechiffre = decryptor.update(message) + decryptor.finalize()

    return message_dechiffre

    
#demande de la clé publique de la CA, le client en a besoin poour vérfifier la signature des certificats
# message_ca = {
#     'type': 'demande_cle_publique_ca',
#     'id': f'client{numero_client}' 
# }

# json_data = json.dumps(message_ca)
# client.publish(topic_ca,json_data)

print(f"client numero : {numero_client} démarre")

generate_key()

# client.loop_start()


#le client n'a pas besoin de clés asymétrique
#il va envoyer sa clé asymétrique chiffré avec la clé publique de la CA 

#générer la clé AES pour communiquer avec la CA
AES_key_client_ca = os.urandom(32)
AES_iv_client_ca = os.urandom(16) 

with open(f'key/AES_key_client{numero_client}_ca') as f:
    f.write(AES_key_client_ca)

with open(f'key/AES_iv_client{numero_client}_ca') as f:
    f.write(AES_iv_client_ca)

#génerer la clé AES pour communiquer avec le vendeur
AES_key_client_vendeur = os.urandom(32)
AES_iv_client_vendeur = os.urandom(16) 

with open(f'key/AES_key_client{numero_client}_vendeur{numero_client}') as f:
    f.write(AES_key_client_vendeur)

with open(f'key/AES_iv_client{numero_client}_vendeur{numero_client}') as f:
    f.write(AES_iv_client_vendeur)


AES_key_chiffre = chiffre_message('ca',AES_key_client_ca)
AES_iv_chiffre = chiffre_message('ca',AES_iv_client_ca)

message_ca = {
    'type': 'envoie_cle_AES_client',
    'id': f'client{numero_client}',
    'AES_key_client': AES_key_chiffre,
    'AES_iv_client' : AES_iv_chiffre
}

json_data_crl = json.dumps(message_ca)
client.publish(topic_ca, json_data_crl)

#envoyer_messages()

# client.loop_stop()
# client.publish(topic_vendeur1,json_data_vendeur)
client.loop_forever()