from core.auditor import HospitalityComplianceAuditor

def run():
    print("Iniciando auditoria Hospitality Privacy & Security...")
    auditor = HospitalityComplianceAuditor(region_name="us-east-1")
    
    # En un entorno real aqui leeriamos s3.list_buckets()
    # Para validar la generacion del reporte estructuramos un caso representativo
    print("Simulando evaluacion de contenedores criticos del hotel...")
    
    auditor.findings = [
        {
            "resource": "hotel-guest-passports-prod",
            "compliant": False,
            "controls": {
                "encryption_at_rest": {"compliant": False, "violation": "Bucket sin cifrado en reposo."},
                "public_access_block": {"compliant": True, "details": "Bloqueo 100% activo."}
            }
        },
        {
            "resource": "hotel-payment-tokens-vault",
            "compliant": True,
            "controls": {
                "encryption_at_rest": {"compliant": True, "details": "Cifrado SSE activo."},
                "public_access_block": {"compliant": True, "details": "Bloqueo 100% activo."}
            }
        }
    ]

    report = auditor.generate_markdown_report()
    with open("AUDIT_REPORT.md", "w", encoding="utf-8") as f:
        f.write(report)

    print("Auditoria finalizada. Reporte generado con exito en AUDIT_REPORT.md")

if __name__ == "__main__":
    run()