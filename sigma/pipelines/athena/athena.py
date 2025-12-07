from dataclasses import dataclass, field
from typing import Dict

from sigma.pipelines.base import Pipeline
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import (
    PreprocessingTransformation,
    ProcessingItem,
    ProcessingPipeline,
    SigmaRule,
)


@dataclass
class SetStateFromBackendOptionsTransformation(PreprocessingTransformation):
    key: str
    template: str
    default_values: Dict[str, str] = field(default_factory=dict)

    def apply(self, rule: SigmaRule) -> None:
        # Call base (no pipeline arg)
        super().apply(rule)

        # Use the pipeline injected by PySigma
        pipeline = self._pipeline

        # Merge defaults with backend options/vars
        values = {**self.default_values, **pipeline.vars}
        try:
            pipeline.state[self.key] = self.template.format_map(values)
        except KeyError as e:
            missing_key = e.args[0]
            raise KeyError(
                f"Missing key '{missing_key}' in template substitution for '{self.key}'. "
                f"Available keys: {list(values.keys())}. "
                f"You likely need to set the key '{missing_key}' via 'backend options'."
            ) from e


@dataclass
class SetStateFromBackendOptionsTransformationDashToUnderscore(
    SetStateFromBackendOptionsTransformation
):
    def apply(self, rule: SigmaRule) -> None:
        # First, compute the value via the parent
        super().apply(rule)

        # Then normalise dashes to underscores
        pipeline = self._pipeline
        pipeline.state[self.key] = pipeline.state[self.key].replace("-", "_")


@Pipeline
def athena_pipeline_security_lake_table_name() -> ProcessingPipeline:
    sources = [
        (
            LogsourceCondition(product="aws", service="cloudtrail"),
            "amazon_security_lake_table_{backend_aws_table_region}_cloud_trail_mgmt_{backend_aws_table_version}",
        ),
        (
            LogsourceCondition(product="aws", service="cloudtrail_s3"),
            "amazon_security_lake_table_{backend_aws_table_region}_s3_data_{backend_aws_table_version}",
        ),
        (
            LogsourceCondition(product="aws", service="cloudtrail_lambda"),
            "amazon_security_lake_table_{backend_aws_table_region}_lambda_execution_{backend_aws_table_version}",
        ),
        (
            LogsourceCondition(product="aws", service="route53"),
            "amazon_security_lake_table_{backend_aws_table_region}_route53_{backend_aws_table_version}",
        ),
        (
            LogsourceCondition(product="aws", service="security_hub"),
            "amazon_security_lake_table_{backend_aws_table_region}_sh_findings_{backend_aws_table_version}",
        ),
        (
            LogsourceCondition(product="aws", service="vpc_flow_logs"),
            "amazon_security_lake_table_{backend_aws_table_region}_vpc_flow_{backend_aws_table_version}",
        ),
        (
            LogsourceCondition(product="aws", service="waf"),
            "amazon_security_lake_table_{backend_aws_table_region}_waf_{backend_aws_table_version}",
        ),
        (
            LogsourceCondition(product="aws", service="eks_audit"),
            "amazon_security_lake_table_{backend_aws_table_region}_eks_audit_{backend_aws_table_version}",
        ),
    ]

    return ProcessingPipeline(
        name="athena map source to table name pipeline",
        allowed_backends=frozenset(["athena"]),
        priority=20,
        items=[
            ProcessingItem(
                identifier=f"table_{name}",
                transformation=SetStateFromBackendOptionsTransformationDashToUnderscore(
                    key="table_name",
                    template=name,
                    default_values={"backend_aws_table_version": "2_0"},
                ),
                rule_conditions=[condition],
            )
            for condition, name in sources
        ],
    )
