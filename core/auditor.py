import boto3
import json
import logging
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("HospitalityAuditor")

class HospitalityComplianceAuditor:
    def __init__(self, region_name="us-east-1"):
        """Inicializa los clientes de AWS para interactuar con la API."""
        self.region = region_name
        self.s3_client = boto3.client("s3", region_name=self.region)
        self.findings = []

    def check_encryption(self, bucket_name: str) -> dict:
        """
        Evalúa si el almacenamiento de datos de huéspedes tiene cifrado por defecto.
        Mapeo: Ley 1581 Art. 17 | GDPR Art. 32 | PCI-DSS v4.0 Req. 3.4
        """
        try:
            enc = self.s3_client.get_bucket_encryption(Bucket=bucket_name)
            return {"compliant": True, "details": "Cifrado SSE activo."}
        except ClientError as e:
            if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                return {
                    "compliant": False,
                    "violation": "Bucket sin cifrado en reposo.",
                    "frameworks": ["Ley 1581 (Art. 17)", "GDPR (Art. 32)", "PCI-DSS v4.0 (Req. 3.4)"]
                }
            return {"compliant": False, "violation": f"Error al consultar: {str(e)}", "frameworks": []}

    def check_public_access_block(self, bucket_name: str) -> dict:
        """
        Verifica si el bucket tiene activo el bloqueo total de acceso público.
        Mapeo: Ley 1581 (Seguridad) | GDPR Art. 25 | PCI-DSS v4.0 Req. 1.2
        """
        try:
            pab = self.s3_client.get_public_access_block(Bucket=bucket_name)
            config = pab.get("PublicAccessBlockConfiguration", {})

            is_secure = (
                config.get("BlockPublicAcls", False) and
                config.get("IgnorePublicAcls", False) and
                config.get("BlockPublicPolicy", False) and
                config.get("RestrictPublicBuckets", False)
            )

            if is_secure:
                return {"compliant": True, "details": "Bloqueo de acceso público 100% activo."}
            else:
                return {
                    "compliant": False,
                    "violation": "Configuración de acceso público permisiva o incompleta.",
                    "frameworks": ["Ley 1581", "GDPR Art. 25", "PCI-DSS Req. 1.2"]
                }
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                return {
                    "compliant": False,
                    "violation": "El bucket no tiene ninguna configuración de bloqueo público.",
                    "frameworks": ["Ley 1581", "GDPR Art. 25", "PCI-DSS Req. 1.2"]
                }
            return {"compliant": False, "violation": f"Error al consultar: {str(e)}", "frameworks": []}

    def audit_bucket(self, bucket_name: str) -> dict:
        """Ejecuta todos los controles sobre un bucket y consolida el veredicto."""
        enc_result = self.check_encryption(bucket_name)
        pab_result = self.check_public_access_block(bucket_name)

        is_overall_compliant = enc_result["compliant"] and pab_result["compliant"]
        
        audit_entry = {
            "resource": bucket_name,
            "compliant": is_overall_compliant,
            "controls": {
                "encryption_at_rest": enc_result,
                "public_access_block": pab_result
            }
        }
        self.findings.append(audit_entry)
        return audit_entry

    def generate_markdown_report(self) -> str:
        """Genera un reporte ejecutivo en Markdown mapeado a marcos regulatorios."""
        lines = [
            "# Hospitality & TravelTech Security Audit Report",
            "**Frameworks Evaluated:** Ley 1581 | GDPR (Art. 25/32) | PCI-DSS v4.0 (Req. 1.2/3.4)",
            "",
            "| Recurso (S3) | Estado | Hallazgos / Violaciones |",
            "| :--- | :--- | :--- |"
        ]

        for entry in self.findings:
            status = "COMPLIANT" if entry["compliant"] else "NON-COMPLIANT"
            violations = []
            
            for control_name, detail in entry["controls"].items():
                if not detail.get("compliant"):
                    violations.append(f"{control_name}: {detail.get('violation')}")
            
            violation_str = "<br>".join(violations) if violations else "Todos los controles superados."
            lines.append(f"| `{entry['resource']}` | **{status}** | {violation_str} |")

        return "\n".join(lines)

if __name__ == "__main__":
    print("Módulo de Auditoría cargado e inicializado correctamente.")