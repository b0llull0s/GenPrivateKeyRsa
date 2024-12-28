#!/usr/bin/python3

def print_banner():
    banner = """
      .. ..',..''''','',,,,,,,,,,',,,,'.,,',,,,,,;,,,,,,,,,,,,'.',,'.  ...
       .   ..'...'.,'''''',,;;;,,,,;,,''.',';,,,;;;;;,,,,,,'......,'.    ..
            .'..'..'',,;,;;;;;;;,;;;,,.';;;',;;;;:;;;;;;;,,...''';,.   .
             .....'''''''''''''''''''..''''.'''''''''''''''''.....'.
            .,;;:;;::::;,,,'''.'',;;::;;;;::::;,,'',;;;;:::::;;;;;'.    ....
           .',,,''',,,,','.. .......',''',,,''''.....''',,,,,'',,,'.    ....
           ....''.....            . .',,','..... .   ........'',,,''.     .
            ... .                   ..';;;.....                .'''..
            .                         .........                    .
         .'.                          ..'......                    ...
         ',.           ...     ..    .;,,,'.'..              ..     ''
         .'            ...         .'','''.','.                     ...
        .',.    ........'.  .    .,;,. ..  .:;,'.       ....        .,'
        ..''.   ...'.......... ..','.       .''''.   .........      ....
       .....,,.....'......'....,,,;.         .''',,............    .',..
      .';,. ..''''''..',;,;,,.'',,'          .......''','........''''..'
   ....,,''..   ......',''..   .'.             ..........''...'.......''.
   ...',;,,...      ..,,;;'.. .;.              .....,,,'.'.. ......';;;:,....
       .....          ....,,....                .'.','''..      ...''''.. ..
        ...   . ..       .,,..''                .'.,;,'..    ...  ...,.
               ............;,.,,.       ..      ''',,....  ...'.....'..
                    .........'''.      .'.     ..''.... ........   ..
                     ...''.';:;;;;'...;:;,'....;':;,','  .;,..                

##############################################################################
#                                 by b0llull0s                               #
##############################################################################
    """
    print(banner)

if __name__ == "__main__":
    print_banner()

from Crypto.PublicKey import RSA
from pwn import *
import requests
from bs4 import BeautifulSoup

def get_n_from_pubkey(file_path):

   # Extracts the modulus 'n' from an RSA public key file.

    with open(file_path, 'r') as f:
        key = RSA.importKey(f.read())
    return key.n, key.e

def query_factordb(n):

   # Queries FactorDB with the modulus 'n'.

    factordb_url = f"http://factordb.com/index.php?query={n}"
    response = requests.get(factordb_url)
    if response.status_code == 200:
        return response.text
    else:
        raise Exception("Failed to connect to FactorDB.")

def extract_factors(factordb_html):

   # Extracts the prime factors 'p' and 'q' from FactorDB.
    
    soup = BeautifulSoup(factordb_html, 'html.parser')
    factor_links = soup.find_all('a', href=True)
    factors = []
    
    for link in factor_links:
        if "index.php?id=" in link['href']:
            factor_id = link.text.strip()
            if factor_id.isdigit():
                factors.append(int(factor_id))
    
    if len(factors) < 2:
        raise Exception("Could not extract both p and q from FactorDB.")
    
    return factors[0], factors[1]

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:    
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)
    
def modinv(a, n):
    g, x, y = egcd(a, n)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % n

if __name__ == "__main__":
    try:
        # Load the public key and extract n and e

        public_key_file = "id_rsa.pub"
        n, e = get_n_from_pubkey(public_key_file)
        log.info(f"Modulus (n): {n}")
        log.info(f"Public Exponent (e): {e}")
        
        # Query FactorDB to retrieve the prime factors

        factordb_html = query_factordb(n)
        p, q = extract_factors(factordb_html)
        log.info(f"Prime factors retrieved: p = {p}, q = {q}")
        
        # Calculate m (phi(n)) and d (private exponent)

        m = (p - 1) * (q - 1)
        d = modinv(e, m)
        log.info(f"Calculated private exponent (d): {d}")
        
        # Construct the private key

        finalKey = RSA.construct((n, e, d, p, q))
        private_key_pem = finalKey.export_key()
        
        # Save the private key to a file
        
        with open("id_rsa", "wb") as f:
            f.write(private_key_pem)
        log.success("Private key successfully generated and saved as 'id_rsa'")
    
    except Exception as e:
        log.error(f"An error occurred: {e}")

