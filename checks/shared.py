import os
from splunk_appinspect.configuration_file import ConfigurationFile
import regex as re


def _regex_valid_for_property(app, reporter, property_pattern):
    """
    Checks the regex for props.conf property that is expecting valid a valid
    regular expression.
    """
    config_file_paths = app.get_config_file_paths("props.conf")
    if config_file_paths:
        for directory, filename in iter(config_file_paths.items()):
            file_path = os.path.join(directory, filename)
            config: ConfigurationFile = app.props_conf(directory)
            for stanza in set(config.sections_with_setting_key_pattern(property_pattern)):
                for setting in stanza.settings_with_key_pattern(property_pattern):
                    _regex_valid(setting, reporter, file_path)


def _regex_valid(setting, reporter, file_path, regex=None):
    """
    Checks that the regex is valid, at least according to the regex library.
    Splunk's regex engine might have a different opinion. Try to capture those
    differences here, and check for them, if possible.
    """
    if regex is None:
        regex = setting.value
    try:
        pattern = re.compile(regex)
    except re.error:
        output = f"Regex {regex} is invalid in {setting.name}"
        reporter.fail(output, file_path, setting.lineno)
        return
    # Named capture groups checks
    if len(pattern.groupindex.keys()) > 0:
        # find duplicate named capture groups
        named_capture_pattern = re.compile(
            r"""
            \(              # Start of capture group
            (?<!(?<!\\)\\)  # So long as it is  not preceded by a \ (but \\ is okay)
            \?P?<           # Named capture group flag ?<... or ?P<...
            ([^>]+)         # Name of capture group
            >               # End of capture group name
            """, re.VERBOSE)
        groups = named_capture_pattern.findall(regex)
        if len(groups) != len(set(groups)):
            output = f"Duplicate named groups in {regex}"
            reporter.fail(output, file_path, setting.lineno)


def _dynamic_field_names(setting, reporter, file_path):
    """
    Checks that for each _KEY_x we have a _VAL_x, and vice-versa, and fails if
    that is the case. This also checks if there is an extra named capture group,
    which could be unintended, this issues a warning, since it might be valid in
    some scenarios. TODO, this is valid in props.conf EXTRACT settings, but not
    sure about transforms REGEX setting.
    """
    pattern = re.compile(setting.value)
    key_val_pattern = re.compile(r"_(?<type>(?:KEY|VAL))_(?<id>.*)")
    groups = list(filter(key_val_pattern.match, pattern.groupindex))
    if len(groups) == 0:
        # Can't call not_applicable, since it will flag that for all of them as that
        pass
    elif len(groups) != len(pattern.groupindex.keys()):
        if not ignorable(setting, "extra_capture_group"):
            output = "Extra named capture group defined in regex with _KEY_ and _VAL_"
            reporter.warn(output, file_path, setting.lineno)
    else:
        for group in groups:
            m = key_val_pattern.match(group)
            type = m.group('type')
            id = m.group('id')
            if type == "KEY":
                if len(list(filter(lambda i: i == f"_VAL_{id}", groups))) != 1:
                    output = f"Have _KEY_{id}, could not find _VAL_{id}"
                    reporter.fail(output, file_path, setting.lineno)
            else:
                if len(list(filter(lambda i: i == f"_KEY_{id}", groups))) != 1:
                    output = f"Have _VAL_{id}, could not find _KEY_{id}"
                    reporter.fail(output, file_path, setting.lineno)


def _cleanup_regex(input):
    """
    Clean up (?P<name>...) to (?<name>...), since they are in effect, the same
    regular expression. We also renumber _KEY_x and _VAL_x, so we can find
    duplicates easier that are in effect, the same regular expression.
    """
    pattern = re.compile(r"(?<!(?<!\\)\\)\(\?(P)<")
    regex = re.sub(pattern, "(?<", input)
    # These two regular expressions are effectively the same:
    #
    # (?<_KEY_1>.*):(?<_VAL_1_>.*)
    # (?<_KEY_2>.*):(?<_VAL_2_>.*)
    #
    # This cleans them up
    key_pattern = re.compile(r"_KEY_(?<id>.*)")
    for (idx, key) in enumerate(list(filter(key_pattern.match, re.compile(regex).groupindex))):
        id = key_pattern.match(key)['id']
        regex = re.sub(r"<_VAL_" + re.escape(id) + r">",
                       f"<_VAL_{str(idx)}>", regex)
        regex = re.sub(r"<_KEY_" + re.escape(id) + r">",
                       f"<_KEY_{str(idx)}>", regex)
    return regex


def ignorable(setting, rule_name):
    """
    Is this item ignorable? Not all checks are ignorable. Currently only
    warnings.

    Add a comment like this before the setting.

    # ignore <RULE_NAME>

    Replace <RULE_NAME> with the rule name in question. If you need to ignore
    multiple rules, add multiple comments.

    # ignore <RULE_NAME_1> # ignore <RULE_NAME_2>

    The rule name might not be the check methond, since some methods call a
    shared method between multiple rules. TODO how to make this discoverable
    without saying it for each check warn/fail?

    Current rule_names that are ignorable:

    extra_capture_group
    duplicate_regex

    These only apply to THESE app inspect checks. Not the ones provided by
    Splunk.
    """
    return False
    # TODO, for some reason if props.conf in test has extra newline, it fails.
    # Bug in the configuration file parsing?
    # for header in setting.header:
    #     if header == f"# ignore {rule_name}":
    #         return True
    # return False


def _is_numeric(property_value):
    try:
        int(property_value)
        return True
    except ValueError:
        return False
