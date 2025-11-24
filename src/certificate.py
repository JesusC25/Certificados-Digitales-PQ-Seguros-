"""
Certificado Digital en formato JSON
"""

import json
import base64
import hashlib
from datetime import datetime
from typing import Dict, List, Optional
import uuid


class Certificate:
    """
    Certificado Digital
    
    Extensiones mínimas:
    - basicConstraints
    - keyUsage
    - subjectKeyIdentifier
    """
    
    def __init__(self):
        self.version = 3
        self.serial_number = str(uuid.uuid4())
        self.signature_algorithm = "dilithium3"
        self.issuer = {}
        self.validity = {}
        self.subject = {}
        self.subject_public_key_info = {}
        self.extensions = {}
        self.signature_value = None
    
    def set_issuer(self, cn: str, o: str, c: str):
        self.issuer = {"CN": cn, "O": o, "C": c}
    
    def set_subject(self, cn: str, o: str, c: str):
        self.subject = {"CN": cn, "O": o, "C": c}
    
    def set_validity(self, not_before: datetime, not_after: datetime):
        self.validity = {
            "notBefore": not_before.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "notAfter": not_after.strftime("%Y-%m-%dT%H:%M:%SZ")
        }
    
    def set_public_key(self, public_key: bytes):
        self.subject_public_key_info = {
            "algorithm": "dilithium3",
            "publicKey": base64.b64encode(public_key).decode('utf-8')
        }
    
    def set_extensions(self, is_ca: bool, key_usage: List[str], path_len: Optional[int] = None):
        basic_constraints = {"cA": is_ca}
        if path_len is not None:
            basic_constraints["pathLen"] = path_len
        
        pk_bytes = base64.b64decode(self.subject_public_key_info["publicKey"])
        ski = hashlib.sha256(pk_bytes).hexdigest()[:40]
        
        self.extensions = {
            "basicConstraints": basic_constraints,
            "keyUsage": key_usage,
            "subjectKeyIdentifier": ski
        }
    
    def add_authority_key_identifier(self, ca_ski: str):
        self.extensions["authorityKeyIdentifier"] = ca_ski
    
    def get_tbs_certificate(self) -> str:
        """Serializa como JSON canónico (To Be Signed)"""
        tbs = {
            "version": self.version,
            "serialNumber": self.serial_number,
            "signatureAlgorithm": self.signature_algorithm,
            "issuer": self.issuer,
            "validity": self.validity,
            "subject": self.subject,
            "subjectPublicKeyInfo": self.subject_public_key_info,
            "extensions": self.extensions
        }
        return json.dumps(tbs, sort_keys=True, separators=(',', ':'))
    
    def sign(self, ca_private_key: bytes):
        """
        Proceso de firma:
        1. El certificado se serializa como cadena (JSON canonical)
        2. La CA aplica Dilithium.Sign sobre esa cadena
        3. El resultado se almacena en signatureValue
        """
        from src.dilithium import DilithiumSimulator
        
        tbs_json = self.get_tbs_certificate()
        tbs_bytes = tbs_json.encode('utf-8')
        signature = DilithiumSimulator.sign(tbs_bytes, ca_private_key)
        self.signature_value = base64.b64encode(signature).decode('utf-8')
    
    def to_dict(self) -> Dict:
        return {
            "version": self.version,
            "serialNumber": self.serial_number,
            "signatureAlgorithm": self.signature_algorithm,
            "issuer": self.issuer,
            "validity": self.validity,
            "subject": self.subject,
            "subjectPublicKeyInfo": self.subject_public_key_info,
            "extensions": self.extensions,
            "signatureValue": self.signature_value
        }
    
    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Certificate':
        cert = cls()
        cert.version = data["version"]
        cert.serial_number = data["serialNumber"]
        cert.signature_algorithm = data["signatureAlgorithm"]
        cert.issuer = data["issuer"]
        cert.validity = data["validity"]
        cert.subject = data["subject"]
        cert.subject_public_key_info = data["subjectPublicKeyInfo"]
        cert.extensions = data["extensions"]
        cert.signature_value = data.get("signatureValue")
        return cert