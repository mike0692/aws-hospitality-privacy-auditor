import pytest
from botocore.stub import Stubber
from botocore.exceptions import ClientError
from core.auditor import HospitalityComplianceAuditor

def test_check_encryption_compliant():
    """Valida que el auditor reporte 'compliant: True' cuando el bucket tiene cifrado activo."""
    auditor = HospitalityComplianceAuditor(region_name="us-east-1")
    
    with Stubber(auditor.s3_client) as stubber:
        expected_response = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        }
        stubber.add_response("get_bucket_encryption", expected_response, {"Bucket": "hotel-secure-bucket"})
        
        result = auditor.check_encryption("hotel-secure-bucket")
        
        assert result["compliant"] is True
        assert "Cifrado SSE activo" in result["details"]

def test_check_encryption_non_compliant():
    """Valida que el auditor detecte la violación y cite las leyes cuando no hay cifrado."""
    auditor = HospitalityComplianceAuditor(region_name="us-east-1")
    
    with Stubber(auditor.s3_client) as stubber:
        stubber.add_client_error(
            "get_bucket_encryption",
            service_error_code="ServerSideEncryptionConfigurationNotFoundError",
            service_message="The server side encryption configuration was not found"
        )
        
        result = auditor.check_encryption("hotel-unencrypted-bucket")
        
        assert result["compliant"] is False
        assert "Ley 1581 (Art. 17)" in result["frameworks"]
        assert "PCI-DSS v4.0 (Req. 3.4)" in result["frameworks"]

def test_check_public_access_block_compliant():
    """Valida que reporte compliant: True cuando los 4 candados públicos están en True."""
    auditor = HospitalityComplianceAuditor(region_name="us-east-1")
    
    with Stubber(auditor.s3_client) as stubber:
        expected_response = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            }
        }
        stubber.add_response("get_public_access_block", expected_response, {"Bucket": "hotel-secure-bucket"})
        
        result = auditor.check_public_access_block("hotel-secure-bucket")
        
        assert result["compliant"] is True
        assert "100% activo" in result["details"]

def test_check_public_access_block_non_compliant():
    """Valida que reporte violación cuando falta al menos un candado público."""
    auditor = HospitalityComplianceAuditor(region_name="us-east-1")
    
    with Stubber(auditor.s3_client) as stubber:
        expected_response = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": True
            }
        }
        stubber.add_response("get_public_access_block", expected_response, {"Bucket": "hotel-exposed-bucket"})
        
        result = auditor.check_public_access_block("hotel-exposed-bucket")
        
        assert result["compliant"] is False
        assert "Ley 1581" in result["frameworks"]
        assert "PCI-DSS Req. 1.2" in result["frameworks"]