# PKI Post-Cuántica con Dilithium

Sistema de Infraestructura de Clave Pública (PKI) educativo que implementa certificados digitales usando criptografía post-cuántica (Dilithium3/FIPS 204 ML-DSA).

## ¿Qué hace este programa?

Este proyecto simula una PKI completa con certificados digitales resistentes a ataques de computadoras cuánticas:

- **Autoridad Certificadora (CA)**: Genera certificados raíz autofirmados y emite certificados para entidades finales
- **Certificados Digitales**: Formato JSON con extensiones (basicConstraints, keyUsage, subjectKeyIdentifier)
- **Firma Digital Post-Cuántica**: Utiliza Dilithium3 para firmar y verificar certificados
- **Validador de Certificados**: Verifica fechas, emisores, firmas criptográficas y extensiones
- **Casos de Prueba**: Incluye 7 casos (1 válido + 6 inválidos) que demuestran diferentes escenarios

## Características

Generación de pares de claves Dilithium3  
Creación de certificados raíz (autofirmados)  
Emisión de certificados de entidad final  
Validación completa de certificados  
Detección de certificados manipulados  
Verificación de fechas de validez  
Trust store configurable  

## Requisitos

- Python 3.7 o superior
- No requiere dependencias externas (simulador educativo)

## Instalación

1. Clonar el repositorio:
```bash
git clone https://github.com/JesusC25/Certificados-Digitales-PQ-Seguros-.git
cd Certificados-Digitales-PQ-Seguros-
```

2. Ejecutar el programa:
```bash
python main.py
```

## Estructura del Proyecto

```
src/
├── __init__.py           # Módulo raíz
├── dilithium.py          # Simulador de Dilithium3
├── certificate.py        # Clase Certificate (formato JSON)
├── ca.py                 # Autoridad Certificadora
├── validator.py          # Validador de certificados
├── examples.py           # Casos de prueba
└── threat_model.py       # Modelo de amenazas
```

Podrá elegir los casos de prueba:
- Ejemplo simple de verificación
- Caso válido (certificado correcto)
- 6 casos inválidos (fecha expirada, issuer incorrecto, firma inválida, CA no confiada, extensiones violadas, formato corrupto)



