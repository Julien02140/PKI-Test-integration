import paho.mqtt.client as mqtt
import paho.mqtt
import os, json, base64
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import load_pem_x509_certificate
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as pad

# Paramètres MQTT
mqtt_broker_address = "194.57.103.203"
mqtt_broker_port = 1883
mqtt_client_id = "ca_server_julien_hugo"
topic = "vehicule/JH/ca"
topic_mouchard = "vehicule/JH/mouchard"
server_name = 'ca_server_julien_hugo'

# nb_message_recu = 0
def generate_certif_ca():

    #générer les clé privés et publique, chiffrement asymétrique
    key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend,
    )

    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'ca')
    ])

    alt_names = [x509.DNSName(server_name)]
    #alt_names.append(x509.DNSName(server_IP))

    #elle peut émettre des certificats, si on met path_length=0, elle ne peut pas
    #emettre de certificat, il faut laisser à None
    basic_contraints = x509.BasicConstraints(ca=True, path_length=None)
    now = datetime.now(timezone.utc)

    cert = (
        x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(1000)
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .add_extension(basic_contraints,True)
            .add_extension(x509.SubjectAlternativeName(alt_names), False)
            .sign(key, hashes.SHA256(), default_backend)    
    )

    my_cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)

    #Transformer en format pem la clé privée
    my_key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    #transformer en fomat pem la clé publique
    public_key = key.public_key()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    if not os.path.exists("certificat"):
        os.makedirs("certificat")
    if not os.path.exists("key"):
        os.makedirs("key")
    if not os.path.exists("pem"):
        os.makedirs("pem")

    with open('certificat/cert_ca.crt', 'wb') as c:
        c.write(my_cert_pem)

    with open('key/key_ca.key', 'wb') as c:
        c.write(my_key_pem)

    with open('key/public_key_ca.pem', 'wb') as f:
        f.write(public_pem)

    #on doit aussi creer un fichier pem
    #ce fichier contient le certificat et la clé privée
    with open('pem/cert_ca.pem','wb') as c:
        c.write(my_cert_pem)
        c.write(my_key_pem) 

def verify_signature(csr_file):
    csr = x509.load_pem_x509_csr(csr_file, default_backend())
    # Obtenir la signature et les informations de la demande de certificat
    signature = csr.signature
    tbs_certificate_bytes = csr.tbs_certrequest_bytes

    # Vérifier la signature
    try:
        csr.public_key().verify(
            signature,
            tbs_certificate_bytes,
            pad.PKCS1v15(),  # Utiliser le même padding que lors de la signature
            csr.signature_hash_algorithm,
        )
        return True  # La signature est valide
    except InvalidSignature:
        return False  # La signature est invalide

def add_certificat_crl(name):
    if not os.path.exists("crl"):
        os.makedirs("crl")

    crl = None

    if os.path.exists("crl/crl.pem"):
        with open("crl/crl.pem", "rb") as f:
            crl_bytes = f.read()
        crl = x509.load_pem_x509_crl(crl_bytes)
        # revoked_certificate = builder.revoked_certificate
        # print("certificat revoqué " + revoked_certificate + "\n")
        #builder = x509.CertificateRevocationListBuilder(builder)

    with open(f"pem/cert_{name}.pem", "rb") as f:
        cert_bytes = f.read()

    cert = x509.load_pem_x509_certificate(cert_bytes)
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, 'JulienHugo CA CRL'),
    ]))
    now = datetime.now(timezone.utc)
    builder = builder.last_update(now)
    builder = builder.next_update(now + timedelta(days=1))

    builder_re = x509.RevokedCertificateBuilder()
    builder_re = builder_re.revocation_date(datetime.today())
    builder_re = builder_re.serial_number(cert.serial_number)
    revoked_certificate = builder_re.build()
    builder = builder.add_revoked_certificate(revoked_certificate)

    if crl != None:
        for r in crl:
            if r.serial_number != cert.serial_number:
                builder_re = x509.RevokedCertificateBuilder()
                builder_re = builder_re.revocation_date(datetime.today())
                builder_re = builder_re.serial_number(r.serial_number)
                revoked_certificate = builder_re.build()
                builder = builder.add_revoked_certificate(revoked_certificate)
    
    with open("key/key_ca.key", "rb") as f:
        ca_key_pem = f.read()
    
    ca_private_key = serialization.load_pem_private_key(
        ca_key_pem,
        password=None,
        backend=default_backend()
    )

    crl = builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256(), backend=default_backend())

    crl_serialize = crl.public_bytes(serialization.Encoding.PEM)

    with open("crl/crl.pem", "wb") as f:
        f.write(crl_serialize)

def emit_certificate(csr_bytes):
    # Charger la clé privée de la CA
    with open("pem/cert_ca.pem", "rb") as f:
        ca_cert_pem = f.read()

    # Générer une nouvelle clé RSA, pour simuler une signature falsifié pour le test
    false_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Sérialiser la clé privée au format PEM
    false_key_pem = false_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Enregistrer la clé privée dans un fichier
    with open("private_key_false.pem", "wb") as f:
        f.write(false_key_pem)
    
    with open("private_key_false.pem", "rb") as f:
        false_key = f.read()

    false_key = serialization.load_pem_private_key(false_key, password=None)


    with open("key/key_ca.key", "rb") as f:
        ca_key = f.read()

    private_key = serialization.load_pem_private_key(ca_key, password=None)


    # Charger le CSR
    csr = x509.load_pem_x509_csr(csr_bytes, default_backend())

    # Charger le certificat de la CA
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem, default_backend())
    alt_names = [x509.DNSName(server_name)]
    basic_contraints = x509.BasicConstraints(ca=True, path_length=None)
    now = datetime.now(timezone.utc)
    # Signer le CSR avec la clé privée de la CA pour émettre le certificat
    cert_build = (
        x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .add_extension(basic_contraints,True)
            .add_extension(x509.SubjectAlternativeName(alt_names), False)
            #.sign(private_key, hashes.SHA256(), default_backend())
    )

    cert = cert_build.sign(private_key, hashes.SHA256(), default_backend())

      
    # with open("key/key_ca.key", "rb") as f:
    #     ca_key = f.read()

    # private_key = serialization.load_pem_private_key(ca_key, password=None)
    # signature = private_key.sign(
    #     cert.encode('utf-8'),
    #     padding.PSS(
    #         mgf=padding.MGF1(hashes.SHA256()),
    #         salt_length=padding.PSS.MAX_LENGTH
    #     ),
    #     hashes.SHA256()
    # )


    # Retourner le certificat émis
    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
    with open('certificat/cert_mouchard.pem', 'wb') as c:
        c.write(cert_bytes)
    return cert_bytes

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

    if message['type'] == 'demande_certificat':

        print(f"demande de certificat de la part du mouchard \n")
        csr = message.get('csr', None)
        #déchiffrer avec AES
        csr = dechiffre_message_AES(csr)
        if csr.startswith("Erreur : "):
            print(csr)
            reponse = {
                    'type': 'erreur',
                    'id': 'ca',
                    'erreur': csr
                }
            json_data = json.dumps(reponse)
            client.publish(topic_mouchard,json_data)
        else:
            csr = eval(csr.encode('utf-8'))
            print("verification de la signature du csr")
            if verify_signature(csr):
                cert = str(emit_certificate(csr))
                cert_bytes = cert.encode('utf-8')
                cert_chiffre = chiffre_message_AES(cert_bytes)
                reponse = {
                    'type': 'envoi_certificat',
                    'id': 'ca',
                    'certificat': cert_chiffre
                }
                json_data = json.dumps(reponse)
                print("signature du csr correct")
                client.publish(topic_mouchard,json_data)

                # Pour créer le scénario où le client trouve que le certificat est révoqué dans la CRL
                #c'est le vendeur 3 qui a un certificat révoqué
                if message['id'] == 'vendeur3':
                    add_certificat_crl(message['id'])
            else: 
                print('Erreur avec la signature')

    elif message['type'] == 'demande_crl':

        id = message['id']

        print(f"demande de crl de la part du {message['id']} \n")

        try:
            with open("crl/crl.pem", "rb") as f:
                crl_data = f.read()
                crl_data = crl_data.decode('utf-8')
        except FileNotFoundError:
            print("Le fichier n'existe pas, crl vide")
            crl_data = None

        #chiffre la crl
        crl_data_chiffre = chiffre_message_AES(id,crl_data)

        reponse = {
            'type': 'envoie_crl',
            'crl': crl_data_chiffre
        }

        json_data = json.dumps(reponse)
        client.publish(f"vehicule/JH/{message['id']}",json_data)

def on_connect(client, userdata, flags, reason_code, properties):
    print("Connecté au broker MQTT avec le code de retour:", reason_code)
    client.subscribe(topic)

def dechiffre_message(message64):
    with open('key/key_ca.key','rb') as f:
        private_key_pem = f.read()

    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None
    )

    message = base64.b64decode(message64)

    #dechiffrer le message
    message_dechiffre = private_key.decrypt(
            message,
            padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return message_dechiffre

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

generate_certif_ca()

#generer un dossier crl et un fichier vide pour la crl
if not os.path.exists("crl"):
    os.makedirs("crl")

client.on_message = on_message
client.on_connect = on_connect

print("démarrage CA")

def get_crl(numero_vendeur):
    # with open("pem/cert_vendeur1.key", "rb") as f:
    #     cert_vendeur = f.read()

    # cert = load_pem_x509_certificate(cert_vendeur, default_backend())

    # add_certificat_crl(cert)

    #creer un fichier pour la clé publique:
    with open("pem/cert_ca.pem", "rb") as f:
        ca_cert = f.read()

    cert = x509.load_pem_x509_certificate(ca_cert, default_backend())
    public_key = cert.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open("key/public_key_ca.pem", "wb") as f:
        f.write(public_key_pem)
 
    return public_key_pem


client.loop_forever()


# with open("crl/crl.pem", "rb") as f:
#     crl_data = f.read()

# reponse = {
#     'type': 'envoie_crl',
#     'crl': crl_data.decode('utf-8') #convertir en str 
# }

# json_data = json.dumps(reponse)
# client.publish("vehicule/JH/client1",json_data)