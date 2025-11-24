"""
Validador de Certificados
"""

from datetime import datetime
from typing import List, Tuple
import base64
from src.certificate import Certificate
from src.dilithium import DilithiumSimulator


class CertificateValidator:
    """
    Validador de certificados
    
    Campos que revisa:
    1. Fechas (notBefore, notAfter)
    2. Emisor en trust store
    3. Firma Dilithium
    4. Extensiones
    """
    
    def __init__(self, trusted_roots: List[Certificate]):
        self.trusted_roots = trusted_roots
    
    def validate(self, cert: Certificate) -> Tuple[bool, str]:
        """Valida certificado"""
        
        # Verificar fechas
        try:
            now = datetime.utcnow()
            not_before = datetime.strptime(cert.validity["notBefore"], "%Y-%m-%dT%H:%M:%SZ")
            not_after = datetime.strptime(cert.validity["notAfter"], "%Y-%m-%dT%H:%M:%SZ")
            
            if now < not_before:
                return False, "Certificado aún no válido"
            if now > not_after:
                return False, "Certificado expirado"
        except Exception as e:
            return False, f"Error en fechas: {e}"
        
        # Buscar emisor
        issuer_cert = None
        for root in self.trusted_roots:
            if root.subject == cert.issuer:
                issuer_cert = root
                break
        
        if issuer_cert is None:
            return False, "CA no confiada"
        
        # Verificar firma
        try:
            tbs_json = cert.get_tbs_certificate()
            tbs_bytes = tbs_json.encode('utf-8')
            signature = base64.b64decode(cert.signature_value)
            issuer_pk = base64.b64decode(issuer_cert.subject_public_key_info["publicKey"])
            
            if not DilithiumSimulator.verify(tbs_bytes, signature, issuer_pk):
                return False, "Firma inválida"
        except Exception as e:
            return False, f"Error verificando firma: {e}"
        
        # Verificar extensiones
        ext = cert.extensions
        is_ca = ext.get("basicConstraints", {}).get("cA", False)
        key_usage = ext.get("keyUsage", [])
        
        if not is_ca and "keyCertSign" in key_usage:
            return False, "Extensiones violadas"
        
        if "authorityKeyIdentifier" in ext:
            expected_aki = issuer_cert.extensions["subjectKeyIdentifier"]
            if ext["authorityKeyIdentifier"] != expected_aki:
                return False, "Authority Key Identifier no coincide"
        
        return True, "Certificado válido"