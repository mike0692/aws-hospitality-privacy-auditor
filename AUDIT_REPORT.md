# Hospitality & TravelTech Security Audit Report
**Frameworks Evaluated:** Ley 1581 | GDPR (Art. 25/32) | PCI-DSS v4.0 (Req. 1.2/3.4)

| Recurso (S3) | Estado | Hallazgos / Violaciones |
| :--- | :--- | :--- |
| `hotel-guest-passports-prod` | **NON-COMPLIANT** | encryption_at_rest: Bucket sin cifrado en reposo. |
| `hotel-payment-tokens-vault` | **COMPLIANT** | Todos los controles superados. |