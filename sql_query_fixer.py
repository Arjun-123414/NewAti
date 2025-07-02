# sql_query_fixer.py
import re
from typing import Dict, List, Tuple


def extract_schema_info(schema_text: str) -> Dict[str, Dict[str, str]]:
    """
    Parse schema text to extract table and column information with data types.
    Returns: {table_name: {column_name: data_type}}
    """
    schema_dict = {}
    current_table = None

    lines = schema_text.strip().split('\n')
    for line in lines:
        line = line.strip()
        if line.startswith('Table:'):
            current_table = line.replace('Table:', '').strip()
            schema_dict[current_table] = {}
        elif line.startswith('- ') and current_table:
            # Parse column info: "- column_name (Data Type: type)"
            match = re.match(r'- (\w+)\s*\(Data Type:\s*([^)]+)\)', line)
            if match:
                column_name = match.group(1)
                data_type = match.group(2).strip()
                schema_dict[current_table][column_name] = data_type

    return schema_dict


def is_string_type(data_type: str) -> bool:
    """Check if a data type is string-based."""
    string_types = ['VARCHAR', 'STRING', 'TEXT', 'CHAR', 'NVARCHAR', 'NCHAR']
    return any(st in data_type.upper() for st in string_types)


def fix_count_distinct(query: str) -> str:
    """
    Fix COUNT() to COUNT(DISTINCT) where appropriate.
    Handles cases like COUNT(column) -> COUNT(DISTINCT column)
    """
    # Pattern to find COUNT(column) but not COUNT(DISTINCT column) or COUNT(*)
    pattern = r'COUNT\s*\(\s*(?!DISTINCT\s+)(?!\*\s*)(\w+)\s*\)'

    def replace_with_distinct(match):
        column = match.group(1)
        return f'COUNT(DISTINCT {column})'

    fixed_query = re.sub(pattern, replace_with_distinct, query, flags=re.IGNORECASE)
    return fixed_query


def fix_string_comparisons(query: str, schema_dict: Dict[str, Dict[str, str]]) -> str:
    """
    Fix string column comparisons to use ILIKE instead of =
    """
    # Extract table names from query
    tables = []
    table_pattern = r'FROM\s+(\w+)|JOIN\s+(\w+)'
    for match in re.finditer(table_pattern, query, re.IGNORECASE):
        table = match.group(1) or match.group(2)
        if table:
            tables.append(table.upper())

    if not tables:
        return query

    # Find all string columns from the tables in the query
    string_columns = set()
    for table in tables:
        # Check both uppercase and original case
        for table_case in [table, table.lower(), table.upper()]:
            if table_case in schema_dict:
                for col, dtype in schema_dict[table_case].items():
                    if is_string_type(dtype):
                        string_columns.add(col.upper())
                break

    # Pattern to find column = 'value' comparisons
    # This handles both quoted and unquoted column names
    pattern = r'(?:")?(\w+)(?:")?\s*=\s*[\'"]([^\'\"]+)[\'"]'

    def replace_with_ilike(match):
        column = match.group(1)
        value = match.group(2)

        # Check if this column is a string column
        if column.upper() in string_columns:
            # Handle quoted column names
            if '"' in match.group(0):
                return f'"{column}" ILIKE \'%{value}%\''
            else:
                return f'{column} ILIKE \'%{value}%\''
        else:
            # Keep original if not a string column
            return match.group(0)

    fixed_query = re.sub(pattern, replace_with_ilike, query)

    return fixed_query


def auto_fix_sql_query(query: str, schema_text: str) -> Tuple[str, List[str]]:
    """
    Main function to automatically fix common SQL query issues.

    Args:
        query: Original SQL query
        schema_text: Schema information in text format

    Returns:
        Tuple of (fixed_query, list_of_fixes_applied)
    """
    fixes_applied = []
    original_query = query

    # Parse schema
    schema_dict = extract_schema_info(schema_text)

    # Fix 1: COUNT -> COUNT(DISTINCT)
    query_after_count_fix = fix_count_distinct(query)
    if query_after_count_fix != query:
        fixes_applied.append("Added DISTINCT to COUNT functions")
        query = query_after_count_fix

    # Fix 2: String comparisons = -> ILIKE '%value%'
    query_after_string_fix = fix_string_comparisons(query, schema_dict)
    if query_after_string_fix != query:
        fixes_applied.append("Changed string column comparisons from = to ILIKE with wildcards")
        query = query_after_string_fix

    return query, fixes_applied


# Simple function to integrate into your main.py
def fix_generated_sql(sql_query: str, schema_text: str) -> str:
    """
    Simple integration function that returns the fixed SQL query.
    Use this in your main.py after LLM generates the SQL.
    """
    fixed_query, fixes = auto_fix_sql_query(sql_query, schema_text)

    # Optionally log what was fixed
    if fixes:
        print(f"SQL Auto-fixes applied: {', '.join(fixes)}")

    return fixed_query
