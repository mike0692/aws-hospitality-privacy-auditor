# AWS Hospitality & TravelTech Privacy Auditor

Herramienta de auditoría automatizada (*Compliance-as-Code*) para evaluar la postura de seguridad, privacidad y cumplimiento normativo en infraestructuras AWS para el sector hotelero, agencias de viaje y plataformas de reservas (PMS/OTA).

## Marcos Normativos Evaluados
- **Ley 1581 de 2012 (Colombia):** Principios de Seguridad y Confidencialidad en datos personales de huéspedes (Arts. 4 y 17).
- **GDPR (Reglamento General de Protección de Datos - UE):** Artículos 25 (*Privacy by Design and by Default*) y 32 (*Seguridad del Tratamiento*).
- **PCI-DSS v4.0:** Requisitos 1.2, 1.3, 3.4 y 7.1 aplicables a entornos que almacenan, procesan o transmiten datos de titulares de tarjetas (CHD).

## Arquitectura y Controles Implementados
- **AWS S3 (Almacenamiento):** Detección de cifrado en reposo (SSE) y bloqueo estricto de acceso público (*Public Access Block* de 4 candados).
- **AWS RDS (Bases de Datos PMS):** Verificación de aislamiento de red (sin IP pública) y cifrado de hardware mediante AWS KMS.
- **AWS IAM (Gestión de Identidades):** Detección de políticas permisivas con privilegios de superadministrador comodín (`*:*`).
- **Reportes Ejecutivos:** Generación dinámica de reportes de auditoría en formato Markdown (`AUDIT_REPORT.md`).

## Suite de Pruebas Automatizadas
Pruebas unitarias deterministas desacopladas de la red mediante `pytest` y emulación de llamadas con `botocore.stub.Stubber` (costo cero y ejecución en milisegundos):

```bash
pytest