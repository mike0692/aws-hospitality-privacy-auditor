import boto3
import json
import logging
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("HospitalityAuditor")

class HospitalityComplianceAuditor:
    def __init__(self, region_name="us-east-1"):
        """Inicializa los clientes de AWS para los servicios evaluados."""
        self.region = region_name
        self.s3_client = boto3.client("s3", region_name=self.region)
        self.rds_client = boto3.client("rds", region_name=self.region)
        self.iam_client = boto3.client("iam", region_name=self.region)
        self.findings = []

    # ==================== CONTROLES S3 (ALMACENAMIENTO) ====================

    def check_encryption(self, bucket_name: str) -> dict:
        """Ley 1581 Art. 17 | GDPR Art. 32 | PCI-DSS v4.0 Req. 3.4"""
        try:
            self.s3_client.get_bucket_encryption(Bucket=bucket_name)
            return {"compliant": True, "details": "Cifrado SSE activo."}
        except ClientError as e:
            if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                return {
                    "compliant": False,
                    "violation": "Bucket sin cifrado en reposo.",
                    "frameworks": ["Ley 1581 (Art. 17)", "GDPR (Art. 32)", "PCI-DSS v4.0 (Req. 3.4)"]
                }
            return {"compliant": False, "violation": f"Error: {str(e)}", "frameworks": []}

    def check_public_access_block(self, bucket_name: str) -> dict:
        """Ley 1581 (Seguridad) | GDPR Art. 25 | PCI-DSS v4.0 Req. 1.2"""
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
            return {
                "compliant": False,
                "violation": "Configuración de acceso público permisiva.",
                "frameworks": ["Ley 1581", "GDPR Art. 25", "PCI-DSS Req. 1.2"]
            }
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                return {
                    "compliant": False,
                    "violation": "Sin configuración de bloqueo público.",
                    "frameworks": ["Ley 1581", "GDPR Art. 25", "PCI-DSS Req. 1.2"]
                }
            return {"compliant": False, "violation": f"Error: {str(e)}", "frameworks": []}

    # ==================== CONTROLES RDS (BASES DE DATOS) ====================

    def check_rds_instance_security(self, db_instance_identifier: str) -> dict:
        """
        Evalúa si la base de datos de reservas/tarjetas está expuesta o sin cifrar.
        Mapeo: PCI-DSS v4.0 Req. 1.3 / Req. 3.4 | GDPR Art. 32
        """
        try:
            response = self.rds_client.describe_db_instances(DBInstanceIdentifier=db_instance_identifier)
            db = response["DBInstances"][0]
            
            is_encrypted = db.get("StorageEncrypted", False)
            is_public = db.get("PubliclyAccessible", True)

            if is_encrypted and not is_public:
                return {"compliant": True, "details": "Instancia privada y cifrada por hardware."}

            violations = []
            if not is_encrypted:
                violations.append("Almacenamiento RDS sin cifrar (KMS)")
            if is_public:
                violations.append("Instancia RDS con IP pública expuesta a Internet")

            return {
                "compliant": False,
                "violation": " | ".join(violations),
                "frameworks": ["PCI-DSS Req. 1.3", "PCI-DSS Req. 3.4", "GDPR Art. 32"]
            }
        except ClientError as e:
            return {"compliant": False, "violation": f"Error RDS: {str(e)}", "frameworks": []}

    # ==================== CONTROLES IAM (PRIVILEGIO MÍNIMO) ====================

    def check_iam_policy_least_privilege(self, policy_document: dict) -> dict:
        """
        Detecta políticas administrativas comodín (*:*) que violan el principio de mínimo privilegio.
        Mapeo: PCI-DSS v4.0 Req. 7.1 | GDPR Art. 25
        """
        statements = policy_document.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if stmt.get("Effect") == "Allow":
                actions = stmt.get("Action", [])
                resources = stmt.get("Resource", [])

                if (actions == "*" or "*" in actions) and (resources == "*" or "*" in resources):
                    return {
                        "compliant": False,
                        "violation": "Política IAM con privilegios de superadministrador comodín (*:*).",
                        "frameworks": ["PCI-DSS Req. 7.1", "GDPR Art. 25 (Privilegio Mínimo)"]
                    }

        return {"compliant": True, "details": "Política acotada sin comodines globales."}

    # ==================== REPORTES ====================

    def generate_markdown_report(self) -> str:
        lines = [
            "# Hospitality & TravelTech Security Audit Report",
            "**Frameworks Evaluated:** Ley 1581 (Colombia) | GDPR | PCI-DSS v4.0",
            "",
            "| Recurso | Tipo | Estado | Hallazgos / Violaciones |",
            "| :--- | :--- | :--- | :--- |"
        ]

        for entry in self.findings:
            status = "COMPLIANT" if entry["compliant"] else "NON-COMPLIANT"
            lines.append(f"| `{entry['resource']}` | {entry['type']} | **{status}** | {entry['details']} |")

        return "\n".join(lines)