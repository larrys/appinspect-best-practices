import unittest
from unittest.mock import Mock
from unittest.mock import call

import os
import sys
import json
from splunk_appinspect.app import App
from splunk_appinspect.python_analyzer.trustedlibs.trusted_libs_manager import TrustedLibsManager

test_path = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(test_path, ".."))


class BaseTest(unittest.TestCase):
    """
    Base Class for all tests, so we can inherit some utility methods and common setup.
    """

    def setUp(self):
        self.maxDiff = None
        self.reporter = Mock()

    def get_app(self, location):
        return App(location=os.path.join(test_path, location), trusted_libs_manager=TrustedLibsManager())

    def assert_clean(self):
        self.reporter.warn.assert_not_called()
        self.reporter.fail.assert_not_called()

    def assert_mocked_calls(self, location):
        expected_file = os.path.join(test_path, location, "expected.json")
        if os.path.exists(expected_file):
            with open(expected_file, "r") as fh:
                expected_json = json.load(fh)
                expected_json.sort()
                calls = json.loads(json.dumps(self.reporter.mock_calls))
                calls.sort()
                self.assertListEqual(expected_json, calls)
        else:
            self.fail(f"Unable to load file {expected_file}")


class TestCheckRegularExpressions(BaseTest):
    """
    Tests for check_regular_expression checks.
    """

    # Some of these tests need more test cases

    def test_clean(self):
        """
        This test checks things in test_data/check_regular_expressions_clean,
        all the props.conf and transforms.conf settings are clean for all the
        checks in check_regular_expressions
        """
        from checks import check_regular_expressions
        app = self.get_app("test_data/check_regular_expressions_clean")
        for check_name in [c for c in dir(check_regular_expressions) if c.startswith("check_")]:
            getattr(check_regular_expressions, check_name)(app, self.reporter)
        self.assert_clean()

    def test_empty(self):
        """
        This check empty is just checking an empty app does not throw any
        failures or errors.
        """
        from checks import check_regular_expressions
        app = self.get_app("test_data/check_regular_expressions_empty")
        for check_name in [c for c in dir(check_regular_expressions) if c.startswith("check_")]:
            getattr(check_regular_expressions, check_name)(app, self.reporter)
        self.assert_clean()

    def test_check_dynamic_field_names(self):
        """
        Tests both props.conf and transforms.conf for checking of dynamic field
        names.
        """
        from checks.check_regular_expressions import check_dynamic_field_names_transforms
        from checks.check_regular_expressions import check_dynamic_field_names_props
        test_app = "test_data/check_regular_expressions_dynamic_field_names"
        app = self.get_app(test_app)
        check_dynamic_field_names_transforms(app, self.reporter)
        check_dynamic_field_names_props(app, self.reporter)
        self.assert_mocked_calls(test_app)

    def test_check_valid_sedcmd(self):
        """
        Tests that SEDCMD is valid
        """
        from checks.check_regular_expressions import check_valid_regex_sedcmd
        test_app = "test_data/check_regular_expressions_valid_sedcmd"
        app = self.get_app(test_app)
        check_valid_regex_sedcmd(app, self.reporter)
        self.assert_mocked_calls(test_app)

    def test_check_valid_regex(self):
        """
        Checks if regexes in EXTRACT in props.conf and transforms.conf are valid.
        """
        from checks.check_regular_expressions import check_valid_regex_for_extract
        from checks.check_regular_expressions import check_valid_regex_for_transforms
        test_app = "test_data/check_regular_expressions_valid_regex"
        app = self.get_app(test_app)
        check_valid_regex_for_extract(app, self.reporter)
        check_valid_regex_for_transforms(app, self.reporter)
        self.assert_mocked_calls(test_app)

    def test_transforms_duplicates(self):
        """
        Tests for duplicates in transforms.conf, props.conf, and between them.
        """
        from checks.check_regular_expressions import check_duplicate_transforms_regex
        from checks.check_regular_expressions import check_duplicate_extract
        from checks.check_regular_expressions import check_extract_duplicates_transforms
        test_app = "test_data/check_regular_expressions_duplicates"
        app = self.get_app(test_app)
        check_duplicate_transforms_regex(app, self.reporter)
        check_extract_duplicates_transforms(app, self.reporter)
        check_duplicate_extract(app, self.reporter)
        self.assert_mocked_calls(test_app)


class TestCheckMagicEight(BaseTest):
    """
    Tests for the Magic Eight checks.
    """

    def test_clean(self):
        """
        This test checks things in test_data/check_magic_eight_clean, all the
        props.conf settings are clean for all the checks in check_magic_eight
        """
        from checks import check_magic_eight
        app = self.get_app("test_data/check_magic_eight_clean")
        for check_name in [c for c in dir(check_magic_eight) if c.startswith("check_")]:
            getattr(check_magic_eight, check_name)(app, self.reporter)
        self.assert_clean()

    def test_dirty(self):
        """
        Test for bad config for the magic 8
        """
        from checks import check_magic_eight
        app = self.get_app("test_data/check_magic_eight_dirty")
        for check_name in [c for c in dir(check_magic_eight) if c.startswith("check_")]:
            getattr(check_magic_eight, check_name)(app, self.reporter)
        self.assert_mocked_calls("test_data/check_magic_eight_dirty")

    def test_dirty_truncate(self):
        """
        Checks for TRUNCATE checks
        """
        from checks.check_magic_eight import check_truncate
        app = self.get_app("test_data/check_magic_eight_truncate")
        check_truncate(app, self.reporter)
        self.assert_mocked_calls("test_data/check_magic_eight_truncate")

    def test_max_timestamp_lookahead(self):
        """
        Test for MAX_TIMESTAMP_LOOKAHEAD
        """
        from checks.check_magic_eight import check_max_timestamp_lookahead
        test_app = "test_data/check_magic_eight_max_timestamp_lookahead"
        app = self.get_app(test_app)
        check_max_timestamp_lookahead(app, self.reporter)
        self.assert_mocked_calls(test_app)


if __name__ == '__main__':
    unittest.main()
