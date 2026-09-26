# SPDX-License-Identifier: Apache-2.0
"""`.env` parsing and in-place editing (guardrails/dotenv.py), with a golden file for edits."""

from pathlib import Path

import pytest

from dockhand_mcp.guardrails.compose import MASKED
from dockhand_mcp.guardrails.dotenv import DotenvEditError, edit_dotenv, parse_dotenv

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "env"


def golden(name: str) -> str:
    return (FIXTURES / name).read_bytes().decode("utf-8")


def test_modify_preserves_comments_blank_lines_and_order() -> None:
    result = edit_dotenv(
        golden("modify-input.env"),
        set_vars={"TZ": "Europe/Paris", "APP_PORT": "9090", "GREETING": "hello world"},
        rename={"OLD_NAME": "NEW_NAME"},
        delete=["REMOVE_ME"],
    )
    assert result.text == golden("modify-expected.env")
    assert result.diff() == {
        "added": ["GREETING"],
        "changed": ["TZ", "APP_PORT"],
        "unchanged": [],
        "renamed": [{"from": "OLD_NAME", "to": "NEW_NAME"}],
        "deleted": ["REMOVE_ME"],
    }


def test_parse_values() -> None:
    text = (
        "# comment\n"
        "A=plain # inline comment\n"
        "export B = spaced\n"
        "C='single $A # kept'\n"
        'D="double \\"q\\" $A"\n'
        "E=${A}/x\n"
        "F=\n"
        "not an assignment\n"
        "A=later\n"
    )
    assert parse_dotenv(text) == {
        "A": "later",
        "B": "spaced",
        "C": "single $A # kept",
        "D": 'double "q" plain',
        "E": "plain/x",
        "F": "",
    }


def test_parse_multiline_quoted_values_and_masked_base() -> None:
    assert parse_dotenv('KEY="line one\nline two"\nNEXT=1\n') == {
        "KEY": "line one\nline two",
        "NEXT": "1",
    }
    values = parse_dotenv("PATHS=${SECRET}/x\n", base={"SECRET": MASKED})
    assert values["PATHS"].endswith("/x") and "SECRET" in values["PATHS"]


def test_unterminated_quotes_are_refused() -> None:
    with pytest.raises(DotenvEditError, match="unterminated"):
        parse_dotenv("KEY='never closed\nOTHER=1\n")


def test_crlf_files_keep_crlf() -> None:
    result = edit_dotenv("A=1\r\nB=2\r\n", set_vars={"B": "3", "C": "4"})
    assert result.text == "A=1\r\nB=3\r\nC=4\r\n"


def test_missing_final_newline_and_empty_file() -> None:
    assert edit_dotenv("A=1", set_vars={"B": "2"}).text == "A=1\nB=2\n"
    assert edit_dotenv("", set_vars={"A": "x y"}).text == "A='x y'\n"


def test_values_are_quoted_so_they_are_read_back_literally() -> None:
    text = edit_dotenv("", set_vars={"A": "p$ss #1", "B": "a=b:c/d", "C": ""}).text
    assert text == "A='p$ss #1'\nB=a=b:c/d\nC=\n"
    assert parse_dotenv(text) == {"A": "p$ss #1", "B": "a=b:c/d", "C": ""}


def test_value_needing_quotes_with_a_single_quote_is_refused() -> None:
    with pytest.raises(DotenvEditError, match="single quote"):
        edit_dotenv("", set_vars={"A": "it's here"})


def test_duplicate_definitions_are_all_updated() -> None:
    assert edit_dotenv("A=1\nB=2\nA=3\n", set_vars={"A": "9"}).text == "A=9\nB=2\nA=9\n"
    assert edit_dotenv("A=1\nA=3\n", delete=["A"]).text == ""


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"delete": ["NOPE"]}, "not defined"),
        ({"rename": {"NOPE": "X"}}, "not defined"),
        ({"rename": {"A": "B"}}, "already defined"),
        ({"rename": {"A": "X", "B": "X"}}, "repeated"),
        ({"delete": ["A"], "set_vars": {"A": "1"}}, "deleted and also"),
        ({"rename": {"A": "X"}, "set_vars": {"A": "1"}}, "renamed away"),
    ],
)
def test_edit_errors(kwargs: dict[str, object], message: str) -> None:
    with pytest.raises(DotenvEditError, match=message):
        edit_dotenv("A=1\nB=2\n", **kwargs)  # type: ignore[arg-type]


def test_multiline_values_cannot_be_edited_in_place() -> None:
    with pytest.raises(DotenvEditError, match="multi-line"):
        edit_dotenv('KEY="a\nb"\n', set_vars={"KEY": "c"})
    # Other keys in the same file can.
    assert edit_dotenv('KEY="a\nb"\nX=1\n', set_vars={"X": "2"}).text == 'KEY="a\nb"\nX=2\n'


def test_rename_then_set_the_new_name() -> None:
    result = edit_dotenv("OLD=1\n", rename={"OLD": "NEW"}, set_vars={"NEW": "2"})
    assert result.text == "NEW=2\n"
    assert result.changed == ["NEW"]
