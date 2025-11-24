"""
Sistema PKI Post-Cuántico con Dilithium3
"""

import os
from src.examples import (
    ejemplo_simple_verificacion,
    caso_valido,
    caso_invalido_1_fecha_expirada,
    caso_invalido_2_issuer_no_coincide,
    caso_invalido_3_firma_invalida,
    caso_invalido_4_ca_no_confiada,
    caso_invalido_5_extensiones_violadas,
    caso_invalido_6_formato_corrupto
)


def limpiar_pantalla():
    """Limpia la pantalla según el sistema operativo"""
    os.system('cls' if os.name == 'nt' else 'clear')


def mostrar_menu():
    print("\n" + "=" * 70)
    print("CERTIFICADOS DIGITALES POST-CUÁNTICOS CON DILITHIUM")
    print("=" * 70)
    print("\nMENÚ DE PRUEBAS:")
    print("-" * 70)
    print("  0. Ejemplo simple de verificación")
    print("  1. Caso válido - Certificado correcto")
    print("  2. Caso inválido 1 - Certificado expirado")
    print("  3. Caso inválido 2 - Issuer no coincide")
    print("  4. Caso inválido 3 - Firma inválida (certificado modificado)")
    print("  5. Caso inválido 4 - CA no confiada")
    print("  6. Caso inválido 5 - Extensiones violadas")
    print("  7. Caso inválido 6 - Formato corrupto")
    print("  8. Ejecutar TODOS los casos")
    print("-" * 70)
    print("  9. Salir")
    print("=" * 70)


def esperar_enter():
    """Espera a que el usuario presione Enter"""
    input("\nPresiona Enter para volver al menú...")


def guardar_certificados(root, cert, nombre_caso=""):
    """Guarda los certificados en archivos JSON"""
    os.makedirs("output", exist_ok=True)
    
    if nombre_caso:
        root_file = f"output/root_ca_{nombre_caso}.json"
        cert_file = f"output/cert_{nombre_caso}.json"
    else:
        root_file = "output/root_ca_cert.json"
        cert_file = "output/server_cert.json"
    
    with open(root_file, "w", encoding='utf-8') as f:
        f.write(root.to_json())
    
    with open(cert_file, "w", encoding='utf-8') as f:
        f.write(cert.to_json())
    
    print("\n" + "=" * 70)
    print("CERTIFICADOS GUARDADOS EN:")
    print("=" * 70)
    print(f"  • {root_file}")
    print(f"  • {cert_file}")
    print("=" * 70)


def ejecutar_prueba(opcion):
    """Ejecuta la prueba seleccionada"""
    limpiar_pantalla()
    
    if opcion == 0:
        ejemplo_simple_verificacion()
        esperar_enter()
        
    elif opcion == 1:
        print("Ejecutando caso válido...\n")
        root, cert = caso_valido()
        guardar_certificados(root, cert, "01_caso_valido")
        esperar_enter()
        
    elif opcion == 2:
        print("Ejecutando caso inválido 1...\n")
        root, cert = caso_invalido_1_fecha_expirada()
        guardar_certificados(root, cert, "02_expirado")
        esperar_enter()
        
    elif opcion == 3:
        print("Ejecutando caso inválido 2...\n")
        root, cert = caso_invalido_2_issuer_no_coincide()
        guardar_certificados(root, cert, "03_issuer_no_coincide")
        esperar_enter()
        
    elif opcion == 4:
        print("Ejecutando caso inválido 3...\n")
        root, cert = caso_invalido_3_firma_invalida()
        guardar_certificados(root, cert, "04_firma_invalida")
        esperar_enter()
        
    elif opcion == 5:
        print("Ejecutando caso inválido 4...\n")
        root, cert = caso_invalido_4_ca_no_confiada()
        guardar_certificados(root, cert, "05_ca_no_confiada")
        esperar_enter()
        
    elif opcion == 6:
        print("Ejecutando caso inválido 5...\n")
        root, cert = caso_invalido_5_extensiones_violadas()
        guardar_certificados(root, cert, "06_extensiones_violadas")
        esperar_enter()
        
    elif opcion == 7:
        print("Ejecutando caso inválido 6...\n")
        root, cert = caso_invalido_6_formato_corrupto()
        guardar_certificados(root, cert, "07_formato_corrupto")
        esperar_enter()
        
    elif opcion == 8:
        print("Ejecutando TODOS los casos...\n")
        from src.examples import ejecutar_todos_los_casos
        
        # Ejecutar todos y guardar cada uno
        print("\n>>> Guardando certificados de todos los casos...\n")
        
        # Caso válido
        root, cert = caso_valido()
        guardar_certificados(root, cert, "01_caso_valido")
        
        # Casos inválidos
        root, cert = caso_invalido_1_fecha_expirada()
        guardar_certificados(root, cert, "02_expirado")
        
        root, cert = caso_invalido_2_issuer_no_coincide()
        guardar_certificados(root, cert, "03_issuer_no_coincide")
        
        root, cert = caso_invalido_3_firma_invalida()
        guardar_certificados(root, cert, "04_firma_invalida")
        
        root, cert = caso_invalido_4_ca_no_confiada()
        guardar_certificados(root, cert, "05_ca_no_confiada")
        
        root, cert = caso_invalido_5_extensiones_violadas()
        guardar_certificados(root, cert, "06_extensiones_violadas")
        
        root, cert = caso_invalido_6_formato_corrupto()
        guardar_certificados(root, cert, "07_formato_corrupto")
        
        print("\n" + "=" * 70)
        print("TODOS LOS CERTIFICADOS HAN SIDO GUARDADOS")
        print("=" * 70)
        
        esperar_enter()


def main():
    
    while True:
        limpiar_pantalla()
        mostrar_menu()
        
        try:
            opcion = input("\nSelecciona una opción (0-9): ").strip()
            
            if opcion == "9":
                limpiar_pantalla()
                print("\n" + "=" * 70)
                print("GRACIAS POR USAR EL SISTEMA PKI POST-CUÁNTICO")
                print("=" * 70)
                print("\nSaliendo del programa...")
                print("=" * 70)
                break
            
            opcion = int(opcion)
            
            if opcion < 0 or opcion > 9:
                print("\n⚠ Opción inválida. Por favor selecciona un número entre 0 y 9.")
                esperar_enter()
                continue
            
            # Ejecutar prueba seleccionada
            ejecutar_prueba(opcion)
        
        except ValueError:
            print("\n Por favor ingresa un número válido (0-9).")
            esperar_enter()
        except KeyboardInterrupt:
            limpiar_pantalla()
            print("\n\n" + "=" * 70)
            print("Programa interrumpido por el usuario.")
            print("=" * 70)
            break
        except Exception as e:
            print(f"\n Error inesperado: {e}")
            print("\nDetalles del error:")
            import traceback
            traceback.print_exc()
            esperar_enter()


if __name__ == "__main__":
    main()