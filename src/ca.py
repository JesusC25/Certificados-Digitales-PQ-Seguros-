"""
Autoridad Certificadora
"""

from datetime import datetime, timedelta
from src.dilithium import DilithiumSimulator
from src.certificate import Certificate


class CertificateAuthority:
    
    def __init__(self, cn: str = "Root CA PQ", o: str = "Proyecto PKI", c: str = "CO"):
        self.cn = cn
        self.o = o
        self.c = c
        self.public_key, self.private_key = DilithiumSimulator.generate_keypair()
        self.root_certificate = None
    
    def create_root_certificate(self, validity_years: int = 10) -> Certificate:
        """Crea certificado raíz autofirmado"""
        cert = Certificate()
        cert.set_issuer(self.cn, self.o, self.c)
        cert.set_subject(self.cn, self.o, self.c)
        
        not_before = datetime.utcnow()
        not_after = not_before + timedelta(days=validity_years * 365)
        cert.set_validity(not_before, not_after)
        
        cert.set_public_key(self.public_key)
        cert.set_extensions(is_ca=True, key_usage=["keyCertSign", "cRLSign"], path_len=0)
        cert.sign(self.private_key)
        
        self.root_certificate = cert
        return cert
    
    def issue_end_entity_certificate(self, subject_cn: str, subject_public_key: bytes,
                                     validity_days: int = 365) -> Certificate:
        """Emite certificado de entidad final"""
        if self.root_certificate is None:
            raise Exception("CA debe tener certificado raíz primero")
        
        cert = Certificate()
        cert.set_issuer(self.cn, self.o, self.c)
        cert.set_subject(subject_cn, self.o, self.c)
        
        not_before = datetime.utcnow()
        not_after = not_before + timedelta(days=validity_days)
        cert.set_validity(not_before, not_after)
        
        cert.set_public_key(subject_public_key)
        cert.set_extensions(is_ca=False, key_usage=["digitalSignature"])
        
        ca_ski = self.root_certificate.extensions["subjectKeyIdentifier"]
        cert.add_authority_key_identifier(ca_ski)
        cert.sign(self.private_key)
        
        return cert