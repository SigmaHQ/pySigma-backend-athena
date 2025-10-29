import pytest
from sigma.collection import SigmaCollection

from sigma.backends.athena import athenaBackend
from sigma.pipelines.athena import athena_pipeline_security_lake_table_name


@pytest.fixture
def athena_backend():
    pipeline = athena_pipeline_security_lake_table_name()
    return athenaBackend(
        processing_pipeline=pipeline,
        aws_table_region="eu-west-2",
    )


def test_table_name_cloudtrail(athena_backend):

    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                product: aws
                service: cloudtrail
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """
            )
        )
        == [
            """SELECT * FROM amazon_security_lake_table_eu_west_2_cloud_trail_mgmt_2_0 WHERE LOWER(fieldA) = 'valuea' AND LOWER(fieldB) = 'valueb'"""
        ]
    )


def test_table_name_cloudtrail_s3(athena_backend):

    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                product: aws
                service: cloudtrail_s3
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """
            )
        )
        == [
            """SELECT * FROM amazon_security_lake_table_eu_west_2_s3_data_2_0 WHERE LOWER(fieldA) = 'valuea' AND LOWER(fieldB) = 'valueb'"""
        ]
    )


def test_table_name_cloudtrail_lambda(athena_backend):

    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                product: aws
                service: cloudtrail_lambda
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """
            )
        )
        == [
            """SELECT * FROM amazon_security_lake_table_eu_west_2_lambda_execution_2_0 WHERE LOWER(fieldA) = 'valuea' AND LOWER(fieldB) = 'valueb'"""
        ]
    )


def test_table_name_route53(athena_backend):

    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                product: aws
                service: route53
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """
            )
        )
        == [
            """SELECT * FROM amazon_security_lake_table_eu_west_2_route53_2_0 WHERE LOWER(fieldA) = 'valuea' AND LOWER(fieldB) = 'valueb'"""
        ]
    )


def test_table_name_security_hub(athena_backend):

    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                product: aws
                service: security_hub
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """
            )
        )
        == [
            """SELECT * FROM amazon_security_lake_table_eu_west_2_sh_findings_2_0 WHERE LOWER(fieldA) = 'valuea' AND LOWER(fieldB) = 'valueb'"""
        ]
    )


def test_table_name_vpc_flow_logs(athena_backend):

    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                product: aws
                service: vpc_flow_logs
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """
            )
        )
        == [
            """SELECT * FROM amazon_security_lake_table_eu_west_2_vpc_flow_2_0 WHERE LOWER(fieldA) = 'valuea' AND LOWER(fieldB) = 'valueb'"""
        ]
    )


def test_table_name_waf(athena_backend):

    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                product: aws
                service: waf
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """
            )
        )
        == [
            """SELECT * FROM amazon_security_lake_table_eu_west_2_waf_2_0 WHERE LOWER(fieldA) = 'valuea' AND LOWER(fieldB) = 'valueb'"""
        ]
    )


def test_table_name_eks_audit(athena_backend):

    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                product: aws
                service: eks_audit
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """
            )
        )
        == [
            """SELECT * FROM amazon_security_lake_table_eu_west_2_eks_audit_2_0 WHERE LOWER(fieldA) = 'valuea' AND LOWER(fieldB) = 'valueb'"""
        ]
    )


def test_table_name_no_region_set():
    pipeline = athena_pipeline_security_lake_table_name()
    athena_backend = athenaBackend(
        processing_pipeline=pipeline,
        # aws_table_region="eu-west-2", # We've unset this to trigger the error.
    )

    with pytest.raises(KeyError) as exc_info:
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                product: aws
                service: cloudtrail
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """
            )
        )

        # Check that the expected missing key is in the error message
        assert "aws_table_region" in str(exc_info.value)
