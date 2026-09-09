# Hospitality & TravelTech Security Audit Report
**Frameworks Evaluated:** Ley 1581 (Colombia) | GDPR | PCI-DSS v4.0

| Recurso | Tipo | Estado | Hallazgos / Violaciones |
| :--- | :--- | :--- | :--- |
| `hotel-guest-passports-prod` | AWS S3 | **NON-COMPLIANT** | Bucket sin cifrado en reposo (Ley 1581 / GDPR Art. 32) |
| `hotel-reservations-postgres` | AWS RDS | **COMPLIANT** | Instancia privada y cifrada por KMS (PCI-DSS Req. 1.3) |
| `AppBillingRolePolicy` | AWS IAM | **NON-COMPLIANT** | Comodín (*:*) detectado. Violación de Mínimo Privilegio (PCI-DSS Req. 7.1) |