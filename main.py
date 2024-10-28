from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
#Part 2 Imports
import sqlite3
from cryptography.hazmat.primitives.serialization import load_pem_private_key


#Database setup
conn = sqlite3.connect('totally_not_my_privateKeys.db')
#Create a cursor
c = conn.cursor()
#Create the database if it doesn't exist
c.execute("""CREATE TABLE IF NOT EXISTS keys(
          kid INTEGER PRIMARY KEY AUTOINCREMENT,
          key BLOB NOT NULL,
          exp INTEGER NOT NULL)""")
#Server setup
hostName = "localhost"
serverPort = 8080

#Create keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)


#Create serialization of key. This can be stored in a SQLITE database
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
#Apparently RSA keys don't have an expiration date, so I've chosen to indicate "expired" keys with a -1, and "unexpired" keys with a 1
c.execute("INSERT INTO keys (key, exp) VALUES (?, ?) ", (pem, 1) )#Store the private key in the database
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
c.execute("INSERT INTO keys (key, exp) VALUES (?,?) ", (expired_pem, -1))#Store the expired private key in the database
numbers = private_key.private_numbers()
#REMOVE THE FOLLOWING


    

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            headers = {

                "kid": "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            c.execute("Select * FROM keys WHERE exp > 0") #Grab the unexpired key
            items = c.fetchone()
            if 'expired' in params: #If the token is supposed to be created having already expired

                
                c.execute("SELECT * FROM keys WHERE exp < '0'")#Grab the expired key from the database
                items = c.fetchone() #THe location of the key is items[2]
                
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1) #set the expiration date to an hour ago
            db_pem = items[1]



            encoded_jwt = jwt.encode(token_payload, db_pem, algorithm="RS256", headers=headers) #create a token
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8")) #Send the token to our user
            return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            keys = {
                "keys": [
                    {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "goodKID",
                        "n": int_to_base64(numbers.public_numbers.n),
                        "e": int_to_base64(numbers.public_numbers.e),
                    }
                ]
            }
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

###run the web server###
if __name__ == "__main__":
    #Part 1: Setup the database
    
    #Part 2: Start the web server
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
