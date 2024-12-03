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
from datetime import datetime, timezone, timedelta

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
    try:
        # Décode le message chiffré en base64 en bytes
        try:
            message_chiffre = base64.b64decode(message)
        except base64.binascii.Error:
            return "Erreur : Le message n'est pas un encodage Base64 valide."

        # Charger la clé AES
        try:
            with open('key/AES_key_mouchard_ca.bin', 'rb') as f:
                AES_key_file = f.read()
            with open('key/AES_iv_mouchard_ca.bin', 'rb') as f:
                AES_iv_file = f.read()
        except FileNotFoundError as e:
            return f"Erreur : Fichier clé ou IV introuvable ({str(e)})."

        # Vérification des tailles de clé et IV
        if len(AES_key_file) not in {16, 24, 32}:
            return "Erreur : La clé AES a une taille invalide."
        if len(AES_iv_file) != 16:
            return "Erreur : L'IV AES doit être de 16 octets."

        # Configurer le chiffrement AES en mode CBC
        cipher = Cipher(algorithms.AES(AES_key_file), modes.CBC(AES_iv_file))
        decryptor = cipher.decryptor()

        # Déchiffrer le message
        try:
            message_dechiffre = decryptor.update(message_chiffre) + decryptor.finalize()
        except ValueError:
            return "Erreur : Déchiffrement impossible. Données corrompues ou clé/IV incorrects."

        # Supprimer le padding
        try:
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            unpadded_message = unpadder.update(message_dechiffre) + unpadder.finalize()
        except ValueError:
            return "Erreur : Padding invalide après le déchiffrement."

        # Décoder le message déchiffré en utf-8
        try:
            message_dechiffre_str = unpadded_message.decode('utf-8')
        except UnicodeDecodeError:
            return "Erreur : Le message déchiffré ne peut pas être décodé en UTF-8."

        return message_dechiffre_str

    except Exception as e:
        return f"Erreur inattendue : {str(e)}"

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

    elif message['type'] == 'reponse_verif_certificat':
        print("réponse de la ca pour la vérification du certificat")
        reponse = dechiffre_message_AES(message['reponse'])
        print(reponse)
        #verification de la crl, on regarde si le faux certificat a bien été ajouté à la crl
        test_crl()


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
    
#consulte la crl et regarde si le certificat est révoqué
def test_crl():
    print("test crl")
    with open('certificat/cert_mouchard_false.pem', 'rb') as f:
        cert_byte = f.read()

    cert = x509.load_pem_x509_certificate(cert_byte, default_backend())
    #charger la clé publique de la CA
    with open("key/public_key_ca.pem", "rb") as f:
        ca_public_key = f.read()
    
    ca_public_key = serialization.load_pem_public_key(ca_public_key, backend=default_backend())

    #charge le fichier crl
    try:
        with open("crl/crl.pem", "rb") as f:
            crl = f.read()
    except FileNotFoundError:
        print("Erreur : il n'y pas de CRL pour le moment")
        return

    crl = x509.load_pem_x509_crl(crl, default_backend())

    # Vérifier la signature de la CRL
    try:
        ca_public_key.verify(
            crl.signature,
            crl.tbs_certlist_bytes,
            pad.PKCS1v15(),
            crl.signature_hash_algorithm,
        )
        print("Signature de la CRL valide.")
    except Exception as e:
        print(f"Erreur lors de la vérification de la signature de la CRL : {e}")

    for revoked_cert in crl:
        if revoked_cert.serial_number == cert.serial_number:
            print("Le certificat est révoqué.")
            return True
    print("Le certificat n'est pas révoqué.")
    return False

def generate_false_certificat():
    with open("key/private_key_mouchard.pem", "rb") as f:
        key = f.read()
    
    false_key = serialization.load_pem_private_key(key, password=None)

    with open("csr/csr_mouchard.pem", "rb") as f:
        csr_bytes = f.read()

    csr = x509.load_pem_x509_csr(csr_bytes, default_backend())

    alt_names = [x509.DNSName("mouchard_server")]
    basic_contraints = x509.BasicConstraints(ca=True, path_length=None)
    now = datetime.now(timezone.utc)
    # Signer le CSR avec la clé privée du mouchard pour émettre le certificat falsifié
    print(csr.subject)
    cert_build = (
        x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(
                    x509.Name([
                        x509.NameAttribute(NameOID.COMMON_NAME, "mouchard")
                    ])
                )
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .add_extension(basic_contraints,True)
            .add_extension(x509.SubjectAlternativeName(alt_names), False)
    )

    cert = cert_build.sign(false_key, hashes.SHA256(), default_backend())

    # Sauvegarder le certificat falsifié dans un fichier PEM
    with open('certificat/cert_mouchard_false.pem', 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def envoi_false_certitficat():
    with open('certificat/cert_mouchard_false.pem', 'rb') as f:
        cert_bytes = f.read()

        cert_chiffre = chiffre_message_AES(cert_bytes)
        message = {
            'type': 'verif_certificat',
            'id': 'mouchard',
            'certificat': cert_chiffre
        }
        json_data = json.dumps(message)
        print("envoie du certificat falsifié")
        client.publish(topic_ca,json_data)

def envoi_good_certificat():
        with open('certificat/cert_mouchard.pem', 'rb') as f:
            cert_bytes = f.read()

        cert_chiffre = chiffre_message_AES(cert_bytes)
        message = {
            'type': 'verif_certificat',
            'id': 'mouchard',
            'certificat': cert_chiffre
        }
        json_data = json.dumps(message)
        print("envoie du bon certificat")
        client.publish(topic_ca,json_data)

#générer clé publique et privée et les clés aes du mouchard
generate_key()
generate_key_aes()

print("démarrage du mouchard \n")
test_csr() #demande de certificat de la part du mouchard

test_certificat() #on verifie que le certificat émit par la ca est valide

#Le mouchard va simuler un client et va demandé à la ca si le certificat du mouchard est valide
envoi_good_certificat()

#le mouchard va créer son propre certificat auto signé, un "mauvais" certificat pour tester la réacion de la ca
generate_false_certificat()

#le mouchard va simuler un client et va demandé si le certificat falsifié qu'il vient de creer est valide
envoi_false_certitficat()

client.loop_forever()



