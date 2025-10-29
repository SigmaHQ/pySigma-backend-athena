import pytest
from sigma.collection import SigmaCollection

from sigma.backends.athena import athenaBackend


def test_setting_table_directly():
    athena_backend = athenaBackend(table="table_set_directly_on_backend")
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """
            )
        )
        == [
            """SELECT * FROM table_set_directly_on_backend WHERE LOWER(fieldA) = 'valuea' AND LOWER(fieldB) = 'valueb'"""
        ]
    )
