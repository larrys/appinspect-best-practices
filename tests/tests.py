import unittest
from unittest.mock import Mock
from unittest.mock import call

import os
import sys
from splunk_appinspect.app import App
from splunk_appinspect.python_analyzer.trustedlibs.trusted_libs_manager import TrustedLibsManager

test_path = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(test_path, ".."))

# Some of these tests need more test cases


class TestCheckRegularExpressions(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None

    def get_app(self, location):
        return App(location=os.path.join(test_path, location), trusted_libs_manager=TrustedLibsManager())

    def test_clean(self):
        """
        This test checks things in test_data/check_regular_expressions_clean,
        all the props.conf and transforms.conf settings are clean for all the
        checks in check_regular_expressions
        """
        from checks import check_regular_expressions
        app = self.get_app("test_data/check_regular_expressions_clean")
        reporter = Mock()
        for check_name in [c for c in dir(check_regular_expressions) if c.startswith("check_")]:
            getattr(check_regular_expressions, check_name)(app, reporter)
        reporter.warn.assert_not_called()
        reporter.fail.assert_not_called()

    def test_empty(self):
        """
        """
        from checks import check_regular_expressions
        app = self.get_app("test_data/check_regular_expressions_empty")
        reporter = Mock()
        for check_name in [c for c in dir(check_regular_expressions) if c.startswith("check_")]:
            getattr(check_regular_expressions, check_name)(app, reporter)
        reporter.warn.assert_not_called()
        reporter.fail.assert_not_called()

    def test_check_dynamic_field_names(self):
        """
        Tests both props.conf and transforms.conf for checking of dynamic field
        names.
        """
        from checks.check_regular_expressions import check_dynamic_field_names_transforms
        from checks.check_regular_expressions import check_dynamic_field_names_props
        app = self.get_app(
            "test_data/check_regular_expressions_dynamic_field_names")
        reporter = Mock()
        check_dynamic_field_names_transforms(app, reporter)
        check_dynamic_field_names_props(app, reporter)
        expected = [call.fail('Have _KEY_1, could not find _VAL_1', 'default/props.conf', 2),
                    call.fail('Have _KEY_1, could not find _VAL_1',
                              'default/transforms.conf', 2),
                    call.fail('Have _KEY_2, could not find _VAL_2',
                              'default/props.conf', 4),
                    call.fail('Have _KEY_2, could not find _VAL_2',
                              'default/props.conf', 5),
                    call.fail('Have _KEY_2, could not find _VAL_2',
                              'default/props.conf', 6),
                    call.fail('Have _KEY_2, could not find _VAL_2',
                              'default/transforms.conf', 8),
                    call.fail('Have _KEY_2, could not find _VAL_2',
                              'default/transforms.conf', 11),
                    call.fail('Have _KEY_2, could not find _VAL_2',
                              'default/transforms.conf', 14),
                    call.fail('Have _VAL_1, could not find _KEY_1',
                              'default/props.conf', 3),
                    call.fail('Have _VAL_1, could not find _KEY_1',
                              'default/props.conf', 4),
                    call.fail('Have _VAL_1, could not find _KEY_1',
                              'default/props.conf', 5),
                    call.fail('Have _VAL_1, could not find _KEY_1',
                              'default/props.conf', 6),
                    call.fail('Have _VAL_1, could not find _KEY_1',
                              'default/transforms.conf', 5),
                    call.fail('Have _VAL_1, could not find _KEY_1',
                              'default/transforms.conf', 8),
                    call.fail('Have _VAL_1, could not find _KEY_1',
                              'default/transforms.conf', 11),
                    call.fail('Have _VAL_1, could not find _KEY_1',
                              'default/transforms.conf', 14),
                    call.warn(
                        'Extra named capture group defined in regex with _KEY_ and _VAL_', 'default/props.conf', 7),
                    call.warn('Extra named capture group defined in regex with _KEY_ and _VAL_', 'default/transforms.conf', 17)]
        expected.sort()
        calls = reporter.mock_calls
        calls.sort()
        self.assertListEqual(expected, calls)

    def test_check_valid_sedcmd(self):
        """
        Tests that SEDCMD is valid
        """
        from checks.check_regular_expressions import check_valid_regex_sedcmd
        app = self.get_app("test_data/check_regular_expressions_valid_sedcmd")
        reporter = Mock()
        check_valid_regex_sedcmd(app, reporter)
        expected = [call.fail('Invalid [bad]:SEDCMD-1 of s/regex/replacement', 'default/props.conf', 2),
                    call.fail('No flags allowed for y/// in SEDCMD',
                              'default/props.conf', 3),
                    call.fail(
                        'For y///, both sides should be the same length', 'default/props.conf', 4),
                    call.fail('Regex (regex is invalid in SEDCMD-4', 'default/props.conf', 5)]
        expected.sort()
        calls = reporter.mock_calls
        calls.sort()
        self.assertListEqual(expected, calls)

    def test_check_valid_regex(self):
        """
        Checks if regexes in EXTRACT in props.conf and transforms.conf are valid.
        """
        from checks.check_regular_expressions import check_valid_regex_for_extract
        from checks.check_regular_expressions import check_valid_regex_for_transforms
        app = self.get_app("test_data/check_regular_expressions_valid_regex")
        reporter = Mock()
        check_valid_regex_for_extract(app, reporter)
        check_valid_regex_for_transforms(app, reporter)
        expected = [call.fail('Regex (.* is invalid in EXTRACT-1', 'default/props.conf', 2),
                    call.fail('Regex .*) is invalid in EXTRACT-2',
                              'default/props.conf', 3),
                    call.fail(
                        'Duplicate named groups in (?P<name>.*)(?P<name>.*)', 'default/props.conf', 4),
                    call.fail(
                        'Duplicate named groups in (?<name>.*)(?P<name>.*)', 'default/props.conf', 5),
                    call.fail(
                        'Duplicate named groups in (?<name>.*)(?<name>.*)', 'default/props.conf', 6),
                    call.fail('Regex .*) is invalid in REGEX',
                              'default/transforms.conf', 5),
                    call.fail(
                        'Duplicate named groups in (?P<name>.*)(?P<name>.*)', 'default/transforms.conf', 8),
                    call.fail('Regex (.* is invalid in REGEX',
                              'default/transforms.conf', 2),
                    call.fail('Duplicate named groups in (?<name>.*)(?<name>.*)',
                              'default/transforms.conf', 14),
                    call.fail('Duplicate named groups in (?<name>.*)(?P<name>.*)', 'default/transforms.conf', 11)]
        expected.sort()
        calls = reporter.mock_calls
        calls.sort()
        self.assertListEqual(expected, calls)

    def test_props_duplicates(self):
        from checks.check_regular_expressions import check_duplicate_extract
        app = self.get_app("test_data/check_regular_expressions_duplicates")
        reporter = Mock()
        check_duplicate_extract(app, reporter)
        expected = [call.warn('Regular expression tA:(?P<_KEY_1>\\w+)\\s*:\\s*(?P<_VAL_1>\\w+) duplicates another extract', 'default/props.conf', 2),
                    call.warn(
                        'Regular expression tA:(?P<_KEY_1>\\w+)\\s*:\\s*(?P<_VAL_1>\\w+) duplicates another extract', 'default/props.conf', 3),
                    call.warn(
                        'Regular expression tB:(?<_KEY_2>\\w+)\\s*:\\s*(?<_VAL_2>\\w+) duplicates another extract', 'default/props.conf', 5),
                    call.warn(
                        'Regular expression tB:(?P<_KEY_2>\\w+)\\s*:\\s*(?P<_VAL_2>\\w+) duplicates another extract', 'default/props.conf', 4),
                    call.warn(
                        'Regular expression tC:(?<_KEY_A>\\w+)\\s*:\\s*(?<_VAL_A>\\w+) duplicates another extract', 'default/props.conf', 6),
                    call.warn('Regular expression tC:(?<_KEY_B>\\w+)\\s*:\\s*(?<_VAL_B>\\w+) duplicates another extract', 'default/props.conf', 7)]
        expected.sort()
        calls = reporter.mock_calls
        calls.sort()
        self.assertListEqual(expected, calls)

    def test_transforms_duplicates(self):
        from checks.check_regular_expressions import check_duplicate_transforms_regex
        app = self.get_app("test_data/check_regular_expressions_duplicates")
        reporter = Mock()
        check_duplicate_transforms_regex(app, reporter)
        expected = [call.warn('Regular expression ([^\\s\\=]+)="([^"]+)" duplicates another REGEX', 'default/transforms.conf', 20),
                    call.warn(
                        'Regular expression ([^\\s\\=]+)="([^"]+)" duplicates another REGEX', 'default/transforms.conf', 25),
                    call.warn(
                        'Regular expression A:(?P<_KEY_1>\\w+)\\s*:\\s*(?P<_VAL_1>\\w+) duplicates another REGEX', 'default/transforms.conf', 2),
                    call.warn(
                        'Regular expression A:(?P<_KEY_1>\\w+)\\s*:\\s*(?P<_VAL_1>\\w+) duplicates another REGEX', 'default/transforms.conf', 5),
                    call.warn('Regular expression B:(?<_KEY_2>\\w+)\\s*:\\s*(?<_VAL_2>\\w+) duplicates another REGEX',
                              'default/transforms.conf', 11),
                    call.warn(
                        'Regular expression B:(?P<_KEY_2>\\w+)\\s*:\\s*(?P<_VAL_2>\\w+) duplicates another REGEX', 'default/transforms.conf', 8),
                    call.warn('Regular expression C:(?<_KEY_A>\\w+)\\s*:\\s*(?<_VAL_A>\\w+) duplicates another REGEX',
                              'default/transforms.conf', 14),
                    call.warn('Regular expression C:(?<_KEY_B>\\w+)\\s*:\\s*(?<_VAL_B>\\w+) duplicates another REGEX', 'default/transforms.conf', 17)]
        expected.sort()
        calls = reporter.mock_calls
        calls.sort()
        self.assertListEqual(expected, calls)

    def test_transforms_and_props_duplicates(self):
        from checks.check_regular_expressions import check_extract_duplicates_transforms
        app = self.get_app("test_data/check_regular_expressions_duplicates")
        reporter = Mock()
        check_extract_duplicates_transforms(app, reporter)
        expected = [call.warn('[bad]:EXTRACT-7 duplicates transforms seven', 'default/props.conf', 8),
                    call.warn(
                        '[bad]:EXTRACT-7 duplicates transforms seven', 'default/props.conf', 8),
                    call.warn(
                        '[bad]:EXTRACT-7 duplicates transforms seven', 'default/props.conf', 8),
                    call.warn(
                        '[bad]:EXTRACT-7 duplicates transforms seven', 'default/props.conf', 8),
                    call.warn(
                        '[bad]:EXTRACT-7 duplicates transforms seven', 'default/props.conf', 8),
                    call.warn(
                        '[bad]:EXTRACT-7 duplicates transforms seven', 'default/props.conf', 8),
                    call.warn('[bad]:EXTRACT-7 duplicates transforms seven', 'default/props.conf', 8)]
        expected.sort()
        calls = reporter.mock_calls
        calls.sort()
        self.assertListEqual(expected, calls)


if __name__ == '__main__':
    unittest.main()
