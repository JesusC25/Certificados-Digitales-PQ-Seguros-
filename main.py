"""
Programa principal del sistema PKI post-cuántico con Dilithium
"""

import os
from src.examples import ejecutar_todos_los_casos
from src.threat_model import modelo_amenazas


def main():
    print("\n" + "=" * 60)
    print("CERTIFICADOS DIGITALES POST-CUÁNTICOS CON DILITHIUM")
    print("=" * 60)
    
    # Ejecutar todos los casos de prueba
    root, cert = ejecutar_todos_los_casos()
    
    # Modelo de amenazas
    modelo_amenazas()
    
    # Guardar certificados
    os.makedirs("output", exist_ok=True)
    
    with open("output/root_ca_cert.json", "w") as f:
        f.write(root.to_json())
    
    with open("output/server_cert.json", "w") as f:
        f.write(cert.to_json())
    
    print("\n" + "=" * 60)
    print("CERTIFICADOS GENERADOS")
    print("=" * 60)
    print("output/root_ca_cert.json")
    print("output/server_cert.json")
    print()
    print("El prototipo ha demostrado exitosamente:")
    print("   Emisión de certificados con Dilithium3")
    print("   Verificación de certificados")
    print("   Cadena de confianza Root CA → Entidad Final")
    print("   1 caso válido + 6 casos inválidos")
    print("   Modelo de amenazas documentado")
    print("=" * 60)
    print()


if __name__ == "__main__":
    main()