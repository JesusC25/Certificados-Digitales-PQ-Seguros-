"""
Ejemplos de uso del sistema PKI post-cuántico
"""

import json
from datetime import datetime, timedelta
from src.ca import CertificateAuthority
from src.validator import CertificateValidator
from src.dilithium import DilithiumSimulator
from src.certificate import Certificate


def ejemplo_simple_verificacion():

    print("EJEMPLO SIMPLE DE VERIFICACIÓN")
    print("=" * 60)
    
    # Crear CA
    ca = CertificateAuthority(cn="Test CA", o="Test", c="CO")
    root = ca.create_root_certificate()
    
    # Generar claves para servidor
    pk, sk = DilithiumSimulator.generate_keypair()
    cert = ca.issue_end_entity_certificate("test.com", pk)
    
    # Mostrar certificado (valores abreviados)
    print("\n1. Certificado JSON:")
    cert_dict = cert.to_dict()
    cert_dict["subjectPublicKeyInfo"]["publicKey"] = cert_dict["subjectPublicKeyInfo"]["publicKey"][:20] + "..."
    cert_dict["signatureValue"] = cert_dict["signatureValue"][:20] + "..."
    print(json.dumps(cert_dict, indent=2))
    
    # Campos que revisa el cliente
    print("\n2. Campos que revisa el validador:")
    print(f"   - Fechas: {cert.validity['notBefore']} a {cert.validity['notAfter']}")
    print(f"   - Emisor: {cert.issuer['CN']}")
    print(f"   - Sujeto: {cert.subject['CN']}")
    print(f"   - CA: {cert.extensions['basicConstraints']['cA']}")
    print(f"   - Key Usage: {cert.extensions['keyUsage']}")
    
    # Verificación
    print("\n3. Verificación Dilithium:")
    validator = CertificateValidator([root])
    is_valid, msg = validator.validate(cert)
    print(f"   Resultado: {is_valid} - {msg}")
    
    # Modificación
    print("\n4. Si se modifica algún campo:")
    tampered = Certificate.from_dict(cert.to_dict())
    tampered.subject["CN"] = "hacker.com"
    is_valid, msg = validator.validate(tampered)
    print(f"   Certificado modificado: {tampered.subject['CN']}")
    print(f"   Resultado: {is_valid} - {msg}")
    print()


def caso_valido():
    """
    CASO VÁLIDO
    Certificado correcto que pasa todas las verificaciones
    """
    print("\nCASO VÁLIDO")
    print("=" * 60)
    
    # Crear CA y certificado
    ca = CertificateAuthority()
    root = ca.create_root_certificate()
    
    pk, sk = DilithiumSimulator.generate_keypair()
    cert = ca.issue_end_entity_certificate("server.ejemplo.com", pk)
    
    # Validar
    validator = CertificateValidator([root])
    is_valid, msg = validator.validate(cert)
    
    print(f"Certificado: {cert.subject['CN']}")
    print(f"Emisor: {cert.issuer['CN']}")
    print(f"Validez: {cert.validity['notBefore']} a {cert.validity['notAfter']}")
    print(f"Resultado: {is_valid} - {msg}")
    
    return root, cert


def caso_invalido_1_fecha_expirada(root):
    """
    CASO INVÁLIDO 1: Fecha inválida (expirado)
    """
    print("\nCASO INVÁLIDO 1: Certificado expirado")
    print("=" * 60)
    
    # Crear certificado con fechas en el pasado
    pk, sk = DilithiumSimulator.generate_keypair()
    
    cert = Certificate()
    cert.set_issuer("Root CA PQ", "Proyecto PKI", "CO")
    cert.set_subject("expired.ejemplo.com", "Proyecto PKI", "CO")
    
    # Fechas expiradas
    past = datetime.utcnow() - timedelta(days=400)
    cert.set_validity(past - timedelta(days=365), past)
    
    cert.set_public_key(pk)
    cert.set_extensions(False, ["digitalSignature"])
    cert.add_authority_key_identifier(root.extensions["subjectKeyIdentifier"])
    
    # Firmar con clave privada de CA real
    from src.ca import CertificateAuthority
    temp_ca = CertificateAuthority()
    temp_ca.root_certificate = root
    cert.sign(temp_ca.private_key)
    
    # Validar
    validator = CertificateValidator([root])
    is_valid, msg = validator.validate(cert)
    
    print(f"Certificado: {cert.subject['CN']}")
    print(f"Expiró: {cert.validity['notAfter']}")
    print(f"Resultado: {is_valid}")
    print(f"Mensaje: {msg}")


def caso_invalido_2_issuer_no_coincide(root):
    """
    CASO INVÁLIDO 2: Issuer no coincide con subject de CA
    """
    print("\nCASO INVÁLIDO 2: Issuer no coincide")
    print("=" * 60)
    
    pk, sk = DilithiumSimulator.generate_keypair()
    
    cert = Certificate()
    # Issuer incorrecto (no es "Root CA PQ")
    cert.set_issuer("Fake Issuer", "Bad Org", "XX")
    cert.set_subject("bad.ejemplo.com", "Proyecto PKI", "CO")
    
    not_before = datetime.utcnow()
    not_after = not_before + timedelta(days=365)
    cert.set_validity(not_before, not_after)
    
    cert.set_public_key(pk)
    cert.set_extensions(False, ["digitalSignature"])
    
    # Firmar con alguna clave (no importa, fallará por issuer)
    temp_ca = CertificateAuthority()
    cert.sign(temp_ca.private_key)
    
    # Validar
    validator = CertificateValidator([root])
    is_valid, msg = validator.validate(cert)
    
    print(f"Certificado: {cert.subject['CN']}")
    print(f"Issuer del certificado: {cert.issuer['CN']}")
    print(f"Subject de la CA: {root.subject['CN']}")
    print(f"Resultado: {is_valid}")
    print(f"Mensaje: {msg}")


def caso_invalido_3_firma_invalida(root, cert_original):
    """
    CASO INVÁLIDO 3: Firma inválida (Dilithium.Verify retorna falso)
    """
    print("\nCASO INVÁLIDO 3: Firma inválida (certificado modificado)")
    print("=" * 60)
    
    # Modificar un campo del certificado
    tampered = Certificate.from_dict(cert_original.to_dict())
    tampered.subject["CN"] = "attacker.malicious.com"
    
    # Validar (la firma ya no coincide con el contenido modificado)
    validator = CertificateValidator([root])
    is_valid, msg = validator.validate(tampered)
    
    print(f"Certificado original: {cert_original.subject['CN']}")
    print(f"Certificado modificado: {tampered.subject['CN']}")
    print(f"Firma: {tampered.signature_value[:40]}...")
    print(f"Resultado: {is_valid}")
    print(f"Mensaje: {msg}")


def caso_invalido_4_ca_no_confiada():
    """
    CASO INVÁLIDO 4: CA no confiada (no presente en trust store)
    """
    print("\nCASO INVÁLIDO 4: CA no confiada")
    print("=" * 60)
    
    # CA legítima en el trust store
    ca_legitima = CertificateAuthority(cn="CA Legitima", o="Good Org", c="CO")
    root_legitima = ca_legitima.create_root_certificate()
    
    # CA falsa (no está en el trust store)
    ca_falsa = CertificateAuthority(cn="Fake CA", o="Bad Org", c="XX")
    root_falsa = ca_falsa.create_root_certificate()
    
    # Certificado firmado por CA falsa
    pk, sk = DilithiumSimulator.generate_keypair()
    cert_falso = ca_falsa.issue_end_entity_certificate("fake.com", pk)
    
    # Validar con trust store que solo tiene CA legítima
    validator = CertificateValidator([root_legitima])
    is_valid, msg = validator.validate(cert_falso)
    
    print(f"Certificado: {cert_falso.subject['CN']}")
    print(f"Emisor del certificado: {cert_falso.issuer['CN']}")
    print(f"CA en trust store: {root_legitima.subject['CN']}")
    print(f"Resultado: {is_valid}")
    print(f"Mensaje: {msg}")


def caso_invalido_5_extensiones_violadas(root):
    """
    CASO INVÁLIDO 5: Extensiones violadas
    Certificado de entidad final con keyUsage=keyCertSign
    """
    print("\nCASO INVÁLIDO 5: Extensiones violadas")
    print("=" * 60)
    
    pk, sk = DilithiumSimulator.generate_keypair()
    
    cert = Certificate()
    cert.set_issuer("Root CA PQ", "Proyecto PKI", "CO")
    cert.set_subject("bad-extensions.com", "Proyecto PKI", "CO")
    
    not_before = datetime.utcnow()
    not_after = not_before + timedelta(days=365)
    cert.set_validity(not_before, not_after)
    
    cert.set_public_key(pk)
    
    # ERROR: Entidad final (CA=FALSE) con keyCertSign
    # Solo las CAs pueden tener keyCertSign
    cert.set_extensions(False, ["digitalSignature", "keyCertSign"])
    cert.add_authority_key_identifier(root.extensions["subjectKeyIdentifier"])
    
    # Firmar
    temp_ca = CertificateAuthority()
    temp_ca.root_certificate = root
    cert.sign(temp_ca.private_key)
    
    # Validar
    validator = CertificateValidator([root])
    is_valid, msg = validator.validate(cert)
    
    print(f"Certificado: {cert.subject['CN']}")
    print(f"CA: {cert.extensions['basicConstraints']['cA']}")
    print(f"Key Usage: {cert.extensions['keyUsage']}")
    print(f"Problema: Entidad final (CA=FALSE) no puede tener keyCertSign")
    print(f"Resultado: {is_valid}")
    print(f"Mensaje: {msg}")


def caso_invalido_6_formato_corrupto(root):
    """
    CASO INVÁLIDO 6: Formato de certificado inválido o corrupto
    """
    print("\nCASO INVÁLIDO 6: Formato corrupto")
    print("=" * 60)
    
    # Crear certificado con firma corrupta
    pk, sk = DilithiumSimulator.generate_keypair()
    
    cert = Certificate()
    cert.set_issuer("Root CA PQ", "Proyecto PKI", "CO")
    cert.set_subject("corrupto.com", "Proyecto PKI", "CO")
    
    not_before = datetime.utcnow()
    not_after = not_before + timedelta(days=365)
    cert.set_validity(not_before, not_after)
    
    cert.set_public_key(pk)
    cert.set_extensions(False, ["digitalSignature"])
    cert.add_authority_key_identifier(root.extensions["subjectKeyIdentifier"])
    
    # Firma corrupta (bytes inválidos)
    cert.signature_value = "FIRMA_CORRUPTA_INVALIDA"
    
    # Validar
    validator = CertificateValidator([root])
    is_valid, msg = validator.validate(cert)
    
    print(f"Certificado: {cert.subject['CN']}")
    print(f"Firma: {cert.signature_value}")
    print(f"Problema: Firma no es Base64 válido")
    print(f"Resultado: {is_valid}")
    print(f"Mensaje: {msg}")


def ejecutar_todos_los_casos():
    print("\n" + "=" * 60)
    print("CASOS DE PRUEBA - CERTIFICADOS DIGITALES PQ")
    print("=" * 60)
    
    # Ejemplo simple
    ejemplo_simple_verificacion()
    
    # Caso válido
    root, cert = caso_valido()
    
    # 6 casos inválidos
    caso_invalido_1_fecha_expirada(root)
    caso_invalido_2_issuer_no_coincide(root)
    caso_invalido_3_firma_invalida(root, cert)
    caso_invalido_4_ca_no_confiada()
    caso_invalido_5_extensiones_violadas(root)
    caso_invalido_6_formato_corrupto(root)
    
    # Resumen
    print("\n" + "=" * 60)
    print("RESUMEN DE CASOS")
    print("=" * 60)
    print(" Caso válido: Certificado correcto")
    print(" Caso inválido 1: Fecha expirada")
    print(" Caso inválido 2: Issuer no coincide")
    print(" Caso inválido 3: Firma inválida")
    print(" Caso inválido 4: CA no confiada")
    print(" Caso inválido 5: Extensiones violadas")
    print(" Caso inválido 6: Formato corrupto")
    print()
    
    return root, cert