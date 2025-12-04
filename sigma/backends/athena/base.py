import re
from typing import Any, ClassVar, Dict, Optional, Pattern, Tuple, Union

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionItem,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.modifiers import SigmaCaseSensitiveModifier
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaCasedString,
    SigmaCompareExpression,
    SigmaFieldReference,
    SigmaNumber,
    SigmaString,
    SpecialChars,
)


class athenaBaseBackend(TextQueryBackend):
    """
    Athena backend for converting Sigma rules into Athena-compatible SQL queries.

    This backend transforms Sigma rules into queries suitable for AWS Athena, handling field
    and value conversions, correlation rules, and query formatting. It supports case-insensitive
    matching, wildcards, and specific correlation types like event_count and value_count.

    See the pySigma documentation for further details:
    https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html
    """

    def __init__(
        self,
        processing_pipeline: Optional[ProcessingPipeline] = None,
        collect_errors: bool = False,
        **backend_options: Dict,
    ):
        """
        Initialize the Athena backend.

        Args:
            processing_pipeline: Optional processing pipeline to apply transformations to Sigma rules.
            collect_errors: If True, collect errors during conversion instead of raising them.
            table: Optional, the name of the table to include in the SQL statement.
            fields: Optional, the name of the fields to select in the SQL statement. Defaults to *.
            **backend_options: Additional backend-specific options.
        """
        super().__init__(processing_pipeline, collect_errors, **backend_options)

        self._default_table_name: str = backend_options.get("table") or "<TABLE>"

        self._element_at_fields: list[str] = (
            backend_options.get("element_at_fields") or []
        )
        if isinstance(self._element_at_fields, str):
            self._element_at_fields = [
                e.strip() for e in self._element_at_fields.split(",")
            ]

    # ----------------------------------------------------------------------------------------------------------
    # General Setup

    name: ClassVar[str] = "athena backend"
    formats: ClassVar[Dict[str, str]] = {
        "default": "Plain athena queries",
    }
    requires_pipeline: ClassVar[bool] = (
        False  # Backend does not require a processing pipeline.
    )

    # Operator precedence for boolean conditions
    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (
        ConditionNOT,
        ConditionAND,
        ConditionOR,
    )
    group_expression: ClassVar[str] = "({expr})"  # Grouping for precedence override

    # Query tokens
    token_separator: str = " "  # Separator between boolean operators
    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "NOT"
    eq_token: ClassVar[str] = " = "  # Token for field-value equality
    eq_expression: ClassVar[str] = "LOWER({field}){backend.eq_token}{value}"

    # Field quoting and escaping
    field_quote: ClassVar[str] = '"'  # Character to quote field names
    field_quote_pattern: ClassVar[Pattern] = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
    field_quote_pattern_negation: ClassVar[bool] = (
        True  # Quote fields that don't match the pattern
    )

    # String value handling
    str_quote: ClassVar[str] = "'"  # String quoting character
    escape_char: ClassVar[str] = "\\"  # Escaping character for strings
    wildcard_multi: ClassVar[str] = "%"  # Multi-character wildcard
    wildcard_single: ClassVar[str] = "_"  # Single-character wildcard
    add_escaped: ClassVar[str] = "\\"  # Additional characters to escape
    filter_chars: ClassVar[str] = ""  # Characters to filter out
    bool_values: ClassVar[Dict[bool, str]] = {True: "true", False: "false"}

    # String matching expressions
    startswith_expression: ClassVar[str] = r"LOWER({field}) LIKE '{value}%' ESCAPE '\'"
    endswith_expression: ClassVar[str] = r"LOWER({field}) LIKE '%{value}' ESCAPE '\'"
    contains_expression: ClassVar[str] = r"LOWER({field}) LIKE '%{value}%' ESCAPE '\'"
    wildcard_match_expression: ClassVar[str] = r"LOWER({field}) LIKE {value} ESCAPE '\'"

    # Regular expression handling
    re_expression: ClassVar[str] = "REGEXP_LIKE({field}, '{regex}')"
    re_escape_char: ClassVar[str] = "\\"
    re_escape: ClassVar[Tuple[str]] = ()
    re_escape_escape_char: bool = True
    re_flag_prefix: bool = False

    # Case-sensitive string matching
    case_sensitive_match_expression: ClassVar[str] = "{field} = {value}"
    case_sensitive_startswith_expression: ClassVar[str] = (
        r"{field} LIKE '{value}%' ESCAPE '\'"
    )
    case_sensitive_endswith_expression: ClassVar[str] = (
        r"{field} LIKE '%{value}' ESCAPE '\'"
    )
    case_sensitive_contains_expression: ClassVar[str] = (
        r"{field} LIKE '%{value}%' ESCAPE '\'"
    )

    # Numeric comparison operators
    compare_op_expression: ClassVar[str] = "{field} {operator} {value}"
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    # Field-to-field comparison
    field_equals_field_expression: ClassVar[Optional[str]] = (
        "LOWER({field1}) = LOWER({field2})"
    )
    field_equals_field_escaping_quoting: Tuple[bool, bool] = (True, True)

    # Null and existence checks
    field_null_expression: ClassVar[str] = "{field} IS NULL"
    field_exists_expression: ClassVar[str] = "{field} IS NOT NULL"
    field_not_exists_expression: ClassVar[str] = "{field} IS NULL"

    # IN expressions
    convert_or_as_in: ClassVar[bool] = True
    convert_and_as_in: ClassVar[bool] = False
    in_expressions_allow_wildcards: ClassVar[bool] = False
    field_in_list_expression: ClassVar[str] = "{field} {op} ({list})"
    or_in_operator: ClassVar[str] = "IN"
    list_separator: ClassVar[str] = ", "

    # Unbound value expressions
    unbound_value_str_expression: ClassVar[str] = "'{value}'"
    unbound_value_num_expression: ClassVar[str] = "{value}"
    unbound_value_re_expression: ClassVar[str] = "_=~{value}"

    # Deferred query handling
    deferred_start: ClassVar[str] = ""
    deferred_separator: ClassVar[str] = ""
    deferred_only_query: ClassVar[str] = ""

    # ----------------------------------------------------------------------------------------------------------

    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        result = super().convert_condition_field_eq_val_str(cond, state)
        return self.fix_wildcard_quotes(cond, result)

    def convert_condition_field_eq_val_str_case_sensitive(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        result = super().convert_condition_field_eq_val_str_case_sensitive(cond, state)
        return self.fix_wildcard_quotes(cond, result)

    def fix_wildcard_quotes(
        self, cond: ConditionFieldEqualsValueExpression, value: str
    ):
        # We need to deal with the issue that wildcarded values come pre-quoted.
        if cond.value.startswith(SpecialChars.WILDCARD_MULTI) and cond.value.endswith(
            SpecialChars.WILDCARD_MULTI
        ):
            # Tidy up: '%'valueB'%'
            return re.sub(r"'%'(.+)'%'", r"'%\1%'", value)
        elif cond.value.startswith(SpecialChars.WILDCARD_MULTI):
            # Tidy up: '%'valueD''
            return value.replace("''", "'").replace("%'", "%")
        elif cond.value.endswith(SpecialChars.WILDCARD_MULTI):
            # Tidy up: ''valueC'%'
            return value.replace("''", "'").replace("'%", "%")

        return value

    def escape_and_quote_field(self, field_name: str) -> str:
        """
        Escape and quote field names, handling hierarchical fields with dots.

        Args:
            field_name: The field name to escape and quote.

        Returns:
            The escaped and quoted field name.
        """

        # Split on unescaped dots: matches a literal dot (.) only if it is not preceded by a backslash (i.e., not escaped).
        # We need to treat a dot (.) in a field name as an indicator of hierarchy, thus we should escape around each part.
        # e.g actor.us@er.uid -> actor."us@er".uid
        parts = [p.replace(r"\.", ".") for p in re.split(r"(?<!\\)\.", field_name)]

        # We need to support accessing map<string,string> fields (although we'll only support them at the top level).
        if parts[0] in self._element_at_fields:
            return f"""element_at({parts[0]}, '{".".join(parts[1:])}')"""

        escaped_and_quoted_parts: list[str] = []

        for s in parts:
            escaped_and_quoted_parts.append(super().escape_and_quote_field(s))

        return ".".join(escaped_and_quoted_parts)

    def convert_value_str(self, s: SigmaString, state: ConversionState) -> str:
        """
        Convert a string value, applying case-insensitive conversion if needed.

        Args:
            s: The Sigma string to convert.
            state: Current conversion state.

        Returns:
            The converted string value.
        """
        converted = super().convert_value_str(s, state)
        if not isinstance(s, SigmaCasedString):
            converted = converted.casefold()
        return converted

    def convert_condition_as_in_expression(
        self, cond: Union[ConditionOR, ConditionAND], state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """
        Convert a field-in-value-list condition.

        Args:
            cond: The OR or AND condition to convert.
            state: Current conversion state.

        Returns:
            The converted query string or deferred expression.
        """
        field = self.escape_and_quote_field(cond.args[0].field)
        if not isinstance(cond.args[0].value, SigmaCasedString):
            field = f"LOWER({field})"

        return self.field_in_list_expression.format(
            field=field,
            op=(
                self.or_in_operator
                if isinstance(cond, ConditionOR)
                else self.and_in_operator
            ),
            list=self.list_separator.join(
                [
                    (
                        self.convert_value_str(arg.value, state)
                        if isinstance(arg.value, SigmaString)
                        else str(arg.value)
                    )
                    for arg in cond.args
                ]
            ),
        )

    def convert_condition_field_eq_field(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of comparision of two fields."""
        cond_value = cond.value
        if not isinstance(cond_value, SigmaFieldReference):
            raise TypeError(
                "Expected SigmaFieldReference for cond.value, got {type(cond_value)}"
            )

        if SigmaCaseSensitiveModifier in cond.parent.modifiers:
            raise NotImplementedError(
                "cased is not support with fieldref for this backend at present"
            )

        return super().convert_condition_field_eq_field(cond, state)

    def athena_finalize_query_default(
        self, rule: SigmaRule, query: str, state: ConversionState
    ) -> Any:
        """
        Finalize the query by adding SELECT and aggregation clauses.

        Args:
            rule: The Sigma rule being converted.
            query: The query string to finalize.
            index: Index of the query (for multi-query rules).
            state: Current conversion state.

        Returns:
            The finalized Athena query string.
        """

        table_name = (
            state.processing_state.get("table_name") or self._default_table_name
        )

        # ---

        select_fields = rule.fields or ["*"]

        formatted_select_fields: str = ", ".join(
            [self._format_select_field(s) for s in select_fields]
        )

        # ---

        athena_query = (
            f"SELECT {formatted_select_fields} FROM {table_name} WHERE {query}"
        )
        return athena_query

    def finalize_query_default(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> Any:
        return self.athena_finalize_query_default(rule, query, state)

    # ----------------------------------------------------------------------------------------------------------

    def _format_select_field(self, field: str) -> str:
        if field == "*":
            return field

        # If it looks like a function, we leave it alone.
        if "(" in field and ")" in field:
            return field

        match = re.search(r"\s(as)\s", field, flags=re.IGNORECASE)
        if match:
            start, end = match.span()
            field_name = self.escape_and_quote_field(field[:start])
            seperator = field[start:end]
            field_as = self.escape_and_quote_field(field[end:])
            return field_name + seperator + field_as

        return self.escape_and_quote_field(field)

    # ----------------------------------------------------------------------------------------------------------

    def convert_condition_val_str(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        raise NotImplementedError(
            "Value-only string expressions (i.e Full Text Search or 'keywords' search) are not supported by the backend."
        )

    def convert_condition_val_num(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        raise NotImplementedError(
            "Value-only number expressions (i.e Full Text Search or 'keywords' search) are not supported by the backend."
        )
