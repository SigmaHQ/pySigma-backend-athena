import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaValueError

from sigma.backends.athena import athenaBackend


@pytest.fixture
def athena_backend():
    return athenaBackend(element_at_fields=["unmapped"])


# -----------------------------------------------------------------------------
# 1) Case sensitivity × string match shape
# -----------------------------------------------------------------------------


def test_athena_cased_contains(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Cased + Contains
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                  fieldA|cased|contains: SubString
                condition: sel
        """
            )
        )
        == [r"SELECT * FROM <TABLE> WHERE fieldA LIKE '%SubString%' ESCAPE '\'"]
    )


def test_athena_cased_startswith(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Cased + StartsWith
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                  fieldA|cased|startswith: Prefix
                condition: sel
        """
            )
        )
        == [r"SELECT * FROM <TABLE> WHERE fieldA LIKE 'Prefix%' ESCAPE '\'"]
    )


def test_athena_cased_endswith(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Cased + EndsWith
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                  fieldA|cased|endswith: Suffix
                condition: sel
        """
            )
        )
        == [r"SELECT * FROM <TABLE> WHERE fieldA LIKE '%Suffix' ESCAPE '\'"]
    )


# -----------------------------------------------------------------------------
# 5) Field vs field comparisons with case options
# -----------------------------------------------------------------------------


def test_athena_cased_fieldref(athena_backend: athenaBackend):

    with pytest.raises(
        NotImplementedError,
        match="cased is not support with fieldref for this backend at present",
    ):
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Cased + Fieldref
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                  fieldA|cased|fieldref: fieldB
                condition: sel
                """
            )
        )


def test_athena_not_fieldref_case_insensitive(athena_backend: athenaBackend):
    # Ensure NOT places correctly around the comparison and still uses LOWER(...) for non-cased
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: NOT Fieldref (non-cased)
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                  fieldA|fieldref: fieldB
                condition: not sel
        """
            )
        )
        == ["SELECT * FROM <TABLE> WHERE NOT LOWER(fieldA) = LOWER(fieldB)"]
    )


# -----------------------------------------------------------------------------
# 7) element_at fields × string modifiers
# -----------------------------------------------------------------------------


def test_athena_element_at_contains(athena_backend: athenaBackend):
    # Non-cased path should use LOWER(element_at(...)) and lowercase literal wrapped in %...%
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: element_at + contains (non-cased)
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                  unmapped.serviceEventDetails.account_id|contains: "123"
                condition: sel
        """
            )
        )
        == [
            r"SELECT * FROM <TABLE> WHERE LOWER(element_at(unmapped, 'serviceEventDetails.account_id')) LIKE '%123%' ESCAPE '\'"
        ]
    )


def test_athena_element_at_cased_startswith(athena_backend: athenaBackend):
    # Cased path should remove LOWER and preserve literal casing
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: element_at + cased + startswith
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                  unmapped.serviceEventDetails.account_id|cased|startswith: AWS
                condition: sel
        """
            )
        )
        == [
            r"SELECT * FROM <TABLE> WHERE element_at(unmapped, 'serviceEventDetails.account_id') LIKE 'AWS%' ESCAPE '\'"
        ]
    )


# -----------------------------------------------------------------------------
# 8) Regex + case choice parity
# -----------------------------------------------------------------------------


def test_athena_cased_regex_same_as_default(athena_backend: athenaBackend):
    # Combining |cased and |re should raise an error.
    with pytest.raises(
        SigmaValueError,
        match="Regular expression modifier only applicable to unmodified values",
    ):
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
                title: Cased + Regex parity
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                      fieldA|cased|re: Foo.*bar
                    condition: sel
                """
            )
        )


# -----------------------------------------------------------------------------
# 11) Lists with wildcards under substring modifiers
# -----------------------------------------------------------------------------


def test_athena_contains_list_with_literal_star_and_question(
    athena_backend: athenaBackend,
):
    # Backend behaviour:
    # - In "contains", we wrap the value in %...% for LIKE.
    # - '?' should be translated to '_' (SQL single-char wildcard).
    # - '*' is treated as a literal (NOT a wildcard) within contains.
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: contains list with * and ?
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                  fieldA|contains:
                    - val*a
                    - val?b
                    - val_c
                condition: sel
        """
            )
        )
        == [
            r"SELECT * FROM <TABLE> WHERE LOWER(fieldA) LIKE '%val%a%' ESCAPE '\' OR LOWER(fieldA) LIKE '%val_b%' ESCAPE '\' OR LOWER(fieldA) LIKE '%val\_c%' ESCAPE '\'"
        ]
    )


# -----------------------------------------------------------------------------
# 12) Dotted/special field names × modifiers
# -----------------------------------------------------------------------------


def test_athena_special_field_name_with_endswith(athena_backend: athenaBackend):
    # Non-cased path with quoted identifier and lowercase literal for LIKE
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: EndsWith on quoted field name
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                  field name|endswith: S
                condition: sel
        """
            )
        )
        == [r"""SELECT * FROM <TABLE> WHERE LOWER("field name") LIKE '%s' ESCAPE '\'"""]
    )


def test_athena_escaped_dot_with_contains(athena_backend: athenaBackend):
    # actor.user\\.uid must be treated as actor."user.uid"
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Contains on escaped dotted field
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                  actor.user\\.uid|contains: "123"
                condition: sel
        """
            )
        )
        == [
            r"""SELECT * FROM <TABLE> WHERE LOWER(actor."user.uid") LIKE '%123%' ESCAPE '\'"""
        ]
    )
