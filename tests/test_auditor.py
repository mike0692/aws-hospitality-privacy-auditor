import pytest
from botocore.stub import Stubber
from core.auditor import HospitalityComplianceAuditor

# --- PRUEBAS S3 ---

def test_s3_encryption_compliant():
    auditor = HospitalityComplianceAuditor()
    with Stubber(auditor.s3_client) as stub:
        stub.add_response("get_bucket_encryption", {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        }, {"Bucket": "b1"})
        res = auditor.check_encryption("b1")
        assert res["compliant"] is True

def test_s3_encryption_non_compliant():
    auditor = HospitalityComplianceAuditor()
    with Stubber(auditor.s3_client) as stub:
        stub.add_client_error("get_bucket_encryption", "ServerSideEncryptionConfigurationNotFoundError")
        res = auditor.check_encryption("b1")
        assert res["compliant"] is False
        assert "Ley 1581 (Art. 17)" in res["frameworks"]

def test_s3_pab_compliant():
    auditor = HospitalityComplianceAuditor()
    with Stubber(auditor.s3_client) as stub:
        stub.add_response("get_public_access_block", {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True
            }
        }, {"Bucket": "b1"})
        res = auditor.check_public_access_block("b1")
        assert res["compliant"] is True

def test_s3_pab_non_compliant():
    auditor = HospitalityComplianceAuditor()
    with Stubber(auditor.s3_client) as stub:
        stub.add_response("get_public_access_block", {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": False, "RestrictPublicBuckets": True
            }
        }, {"Bucket": "b1"})
        res = auditor.check_public_access_block("b1")
        assert res["compliant"] is False

# --- PRUEBAS RDS ---

def test_rds_instance_compliant():
    auditor = HospitalityComplianceAuditor()
    with Stubber(auditor.rds_client) as stub:
        stub.add_response("describe_db_instances", {
            "DBInstances": [{"StorageEncrypted": True, "PubliclyAccessible": False}]
        }, {"DBInstanceIdentifier": "hotel-pms-db"})
        res = auditor.check_rds_instance_security("hotel-pms-db")
        assert res["compliant"] is True

def test_rds_instance_exposed_and_unencrypted():
    auditor = HospitalityComplianceAuditor()
    with Stubber(auditor.rds_client) as stub:
        stub.add_response("describe_db_instances", {
            "DBInstances": [{"StorageEncrypted": False, "PubliclyAccessible": True}]
        }, {"DBInstanceIdentifier": "hotel-exposed-db"})
        res = auditor.check_rds_instance_security("hotel-exposed-db")
        assert res["compliant"] is False
        assert "PCI-DSS Req. 1.3" in res["frameworks"]

# --- PRUEBAS IAM ---

def test_iam_policy_wildcard_violation():
    auditor = HospitalityComplianceAuditor()
    policy = {
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
    }
    res = auditor.check_iam_policy_least_privilege(policy)
    assert res["compliant"] is False
    assert "PCI-DSS Req. 7.1" in res["frameworks"]

def test_iam_policy_restricted_compliant():
    auditor = HospitalityComplianceAuditor()
    policy = {
        "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::hotel-docs/*"}]
    }
    res = auditor.check_iam_policy_least_privilege(policy)
    assert res["compliant"] is True