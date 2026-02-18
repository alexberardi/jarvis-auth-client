"""Tests for header utilities."""

import os

import pytest

from jarvis_auth_client.headers import (
    HEADER_APP_ID,
    HEADER_APP_KEY,
    HEADER_CONTEXT_HOUSEHOLD_ID,
    HEADER_CONTEXT_HOUSEHOLD_MEMBER_IDS,
    HEADER_CONTEXT_NODE_ID,
    HEADER_CONTEXT_USER_ID,
    build_context_headers,
    get_app_headers,
    parse_household_member_ids,
)


class TestGetAppHeaders:
    def test_returns_headers_when_env_set(self, monkeypatch):
        monkeypatch.setenv("JARVIS_APP_ID", "my-app")
        monkeypatch.setenv("JARVIS_APP_KEY", "my-secret")

        headers = get_app_headers()

        assert headers == {
            HEADER_APP_ID: "my-app",
            HEADER_APP_KEY: "my-secret",
        }

    def test_raises_when_app_id_missing(self, monkeypatch):
        monkeypatch.delenv("JARVIS_APP_ID", raising=False)
        monkeypatch.setenv("JARVIS_APP_KEY", "my-secret")

        with pytest.raises(ValueError, match="JARVIS_APP_ID"):
            get_app_headers()

    def test_raises_when_app_key_missing(self, monkeypatch):
        monkeypatch.setenv("JARVIS_APP_ID", "my-app")
        monkeypatch.delenv("JARVIS_APP_KEY", raising=False)

        with pytest.raises(ValueError, match="JARVIS_APP_ID"):
            get_app_headers()

    def test_raises_when_both_missing(self, monkeypatch):
        monkeypatch.delenv("JARVIS_APP_ID", raising=False)
        monkeypatch.delenv("JARVIS_APP_KEY", raising=False)

        with pytest.raises(ValueError):
            get_app_headers()


class TestBuildContextHeaders:
    def test_all_fields(self):
        headers = build_context_headers(
            household_id="hh123",
            node_id="node456",
            user_id=789,
            household_member_ids=[1, 2, 3],
        )

        assert headers == {
            HEADER_CONTEXT_HOUSEHOLD_ID: "hh123",
            HEADER_CONTEXT_NODE_ID: "node456",
            HEADER_CONTEXT_USER_ID: "789",
            HEADER_CONTEXT_HOUSEHOLD_MEMBER_IDS: "1,2,3",
        }

    def test_no_fields(self):
        headers = build_context_headers()
        assert headers == {}

    def test_only_household_id(self):
        headers = build_context_headers(household_id="hh1")
        assert headers == {HEADER_CONTEXT_HOUSEHOLD_ID: "hh1"}

    def test_only_user_id(self):
        headers = build_context_headers(user_id=42)
        assert headers == {HEADER_CONTEXT_USER_ID: "42"}

    def test_user_id_zero(self):
        headers = build_context_headers(user_id=0)
        assert headers == {HEADER_CONTEXT_USER_ID: "0"}

    def test_empty_member_ids_excluded(self):
        headers = build_context_headers(household_member_ids=[])
        assert HEADER_CONTEXT_HOUSEHOLD_MEMBER_IDS not in headers

    def test_single_member_id(self):
        headers = build_context_headers(household_member_ids=[5])
        assert headers[HEADER_CONTEXT_HOUSEHOLD_MEMBER_IDS] == "5"


class TestParseHouseholdMemberIds:
    def test_valid_ids(self):
        assert parse_household_member_ids("1,2,3") == [1, 2, 3]

    def test_single_id(self):
        assert parse_household_member_ids("42") == [42]

    def test_none_returns_empty(self):
        assert parse_household_member_ids(None) == []

    def test_empty_string_returns_empty(self):
        assert parse_household_member_ids("") == []

    def test_whitespace_handling(self):
        assert parse_household_member_ids(" 1 , 2 , 3 ") == [1, 2, 3]

    def test_invalid_value_returns_empty(self):
        assert parse_household_member_ids("a,b,c") == []

    def test_mixed_valid_invalid_returns_empty(self):
        # The implementation catches ValueError for the whole list
        assert parse_household_member_ids("1,abc,3") == []
