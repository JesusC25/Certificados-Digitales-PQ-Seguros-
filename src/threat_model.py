"""
Modelo de Amenazas
"""


def modelo_amenazas():
    """
    Amenazas:
    1. Modificación del JSON por un tercero
    2. Certificados falsos sin firma válida
    3. Problemas por expiración o timestamps
    """
    
    print("\n\nMODELO DE AMENAZAS")
    print("=" * 60)
    
    amenazas = [
        ("Modificación del JSON", "Firma Dilithium detecta cambios"),
        ("Certificados falsos", "Validador verifica firma con clave pública CA"),
        ("Expiración/timestamps", "Validador verifica notBefore y notAfter")
    ]
    
    for i, (amenaza, mitigacion) in enumerate(amenazas, 1):
        print(f"\n{i}. {amenaza}")
        print(f"   Mitigación: {mitigacion}")