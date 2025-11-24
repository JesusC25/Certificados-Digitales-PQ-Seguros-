"""
Simulador de Dilithium3 (CRYSTALS-Dilithium / FIPS 204 ML-DSA)

Tamaños según FIPS 204:
- Clave pública: 1952 bytes
- Clave privada: 4000 bytes
- Firma: 3293 bytes
"""

import hashlib
import secrets
from typing import Tuple


class DilithiumSimulator:

    @staticmethod
    def generate_keypair() -> Tuple[bytes, bytes]:
        """
        Genera un par de claves Dilithium3
        
        La semilla se almacena en ambas claves para que el simulador
        pueda verificar firmas correctamente.
        """
        # Generar semilla maestra
        seed = secrets.token_bytes(32)
        
        # Clave pública: semilla (primeros 32 bytes) + datos derivados
        public_key_data = hashlib.sha3_512(seed + b"PUBLIC").digest() * 31
        public_key = seed + public_key_data[:1920]  # Total: 1952 bytes
        
        # Clave privada: semilla (primeros 32 bytes) + datos derivados  
        private_key_data = hashlib.sha3_512(seed + b"PRIVATE").digest() * 63
        private_key = seed + private_key_data[:3968]  # Total: 4000 bytes
        
        return public_key, private_key
    
    @staticmethod
    def sign(message: bytes, private_key: bytes) -> bytes:
        """
        Firma un mensaje usando la clave privada
        """
        # Extraer semilla (primeros 32 bytes de la clave privada)
        seed = private_key[:32]
        
        # Generar firma usando semilla + mensaje
        signature_data = hashlib.sha3_512(seed + message + b"SIGNATURE").digest() * 52
        return signature_data[:3293]
    
    @staticmethod
    def verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verifica la firma de un mensaje
        """
        if len(signature) != 3293:
            return False
            
        if len(public_key) < 32:
            return False
        
        # Extraer semilla (primeros 32 bytes de la clave pública)
        seed = public_key[:32]
        
        # Regenerar la firma esperada
        expected_signature = hashlib.sha3_512(seed + message + b"SIGNATURE").digest() * 52
        expected_signature = expected_signature[:3293]
        
        # Comparar firmas
        return signature == expected_signature