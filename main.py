from core.auditor import HospitalityComplianceAuditor

def run():
    print("Iniciando auditoria Hospitality Privacy & Security...")
    auditor = HospitalityComplianceAuditor(region_name="us-east-1")
    
    # Casos evaluados representativos
    auditor.findings = [
        {
            "resource": "hotel-guest-passports-prod",
            "type": "AWS S3",
            "compliant": False,
            "details": "Bucket sin cifrado en reposo (Ley 1581 / GDPR Art. 32)"
        },
        {
            "resource": "hotel-reservations-postgres",
            "type": "AWS RDS",
            "compliant": True,
            "details": "Instancia privada y cifrada por KMS (PCI-DSS Req. 1.3)"
        },
        {
            "resource": "AppBillingRolePolicy",
            "type": "AWS IAM",
            "compliant": False,
            "details": "Comodín (*:*) detectado. Violación de Mínimo Privilegio (PCI-DSS Req. 7.1)"
        }
    ]

    report = auditor.generate_markdown_report()
    with open("AUDIT_REPORT.md", "w", encoding="utf-8") as f:
        f.write(report)

    print("Auditoria finalizada con exito. Consulta AUDIT_REPORT.md")

if __name__ == "__main__":
    run()