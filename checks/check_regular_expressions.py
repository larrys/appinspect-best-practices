"""
Best practice checks for regular expressions found in props.conf and
transforms.conf.

https://docs.splunk.com/Documentation/Splunk/latest/Admin/Propsconf
https://docs.splunk.com/Documentation/Splunk/latest/Admin/Transformsconf
"""
import splunk_appinspect
import os
import regex as re
from splunk_appinspect.configuration_file import ConfigurationFile
from .shared import ignorable, _cleanup_regex, _dynamic_field_names, _regex_valid, _regex_valid_for_property


@splunk_appinspect.tags("best_practices", "best_practices_regex", "best_practices_transforms")
@splunk_appinspect.cert_version(min="2.14.1")
def check_dynamic_field_names_transforms(app, reporter):
    """
    Checks that _KEY_1 also has _VAL_1 for REGEX in transforms.conf
    """
    key_regex = "^REGEX$"
    config_file_paths = app.get_config_file_paths("transforms.conf")
    if config_file_paths:
        for directory, filename in iter(config_file_paths.items()):
            file_path = os.path.join(directory, filename)
            config: ConfigurationFile = app.transforms_conf(directory)
            for stanza in set(config.sections_with_setting_key_pattern(key_regex)):
                for setting in stanza.settings_with_key_pattern(key_regex):
                    _dynamic_field_names(setting, reporter, file_path)


@splunk_appinspect.tags("best_practices", "best_practices_regex", "best_practices_props")
@splunk_appinspect.cert_version(min="2.14.1")
def check_dynamic_field_names_props(app, reporter):
    """
    Checks that _KEY_x also has just one _VAL_x for props.conf
    """
    key_regex = "EXTRACT-"
    config_file_paths = app.get_config_file_paths("props.conf")
    if config_file_paths:
        for directory, filename in iter(config_file_paths.items()):
            file_path = os.path.join(directory, filename)
            config: ConfigurationFile = app.props_conf(directory)
            for stanza in set(config.sections_with_setting_key_pattern(key_regex)):
                for setting in stanza.settings_with_key_pattern(key_regex):
                    _dynamic_field_names(setting, reporter, file_path)


@splunk_appinspect.tags("best_practices", "best_practices_props")
@splunk_appinspect.cert_version(min="2.14.1")
def check_duplicate_extract(app, reporter):
    """
    Checks for duplicate EXTRACT regexes. These could be moved to a
    transforms.conf REGEX entry.
    """
    key_regex = "EXTRACT-"
    config_file_paths = app.get_config_file_paths("props.conf")
    if config_file_paths:
        for directory, filename in iter(config_file_paths.items()):
            file_path = os.path.join(directory, filename)
            config: ConfigurationFile = app.props_conf(directory)
            regexes = {}
            for stanza in set(config.sections_with_setting_key_pattern(key_regex)):
                for setting in stanza.settings_with_key_pattern(key_regex):
                    # Clean up regex to find effectively the same regex.
                    regex = _cleanup_regex(setting.value)
                    if regex in regexes:
                        regexes[regex].append(setting)
                    else:
                        regexes[regex] = [setting]
            for regex in regexes.keys():
                if len(regexes[regex]) > 1:
                    for dupe in regexes[regex]:
                        if not ignorable(setting, "duplicate_regex"):
                            output = f"Regular expression {dupe.value} duplicates another extract"
                            reporter.warn(output, file_path, dupe.lineno)


@splunk_appinspect.tags("best_practices", "best_practices_transforms")
@splunk_appinspect.cert_version(min="2.14.1")
def check_duplicate_transforms_regex(app, reporter):
    """
    Checks for duplicate REGEX in transforms.
    """
    key_regex = "REGEX"
    config_file_paths = app.get_config_file_paths("transforms.conf")
    if config_file_paths:
        for directory, filename in iter(config_file_paths.items()):
            file_path = os.path.join(directory, filename)
            config: ConfigurationFile = app.transforms_conf(directory)
            regexes = {}
            for stanza in set(config.sections_with_setting_key_pattern(key_regex)):
                for setting in stanza.settings_with_key_pattern(key_regex):
                    # Clean up regex to find effectively the same regex.
                    regex = _cleanup_regex(setting.value)
                    if regex in regexes:
                        regexes[regex].append(stanza)
                    else:
                        regexes[regex] = [stanza]
            for regex in regexes.keys():
                if len(regexes[regex]) > 1:
                    # If one has MV_ADD and the other does not, let it pass (but
                    # only if there are two duplicates based off regular
                    # expression)
                    # TODO, should also compare values of MV_ADD if one is True
                    # and other False (and/or null)
                    if len(regexes[regex]) == 2 and len(set([s.has_option("MV_ADD") for s in regexes[regex]])) == 2:
                        pass
                    else:
                        for dupe in regexes[regex]:
                            if not ignorable(setting, "duplicate_regex"):
                                output = f"Regular expression {dupe.get_option('REGEX').value} duplicates another REGEX"
                                reporter.warn(output, file_path,
                                              dupe.get_option("REGEX").lineno)


@splunk_appinspect.tags("best_practices", "best_practices_transforms", "best_practices_props")
@splunk_appinspect.cert_version(min="2.14.1")
def check_extract_duplicates_transforms(app, reporter):
    """
    Checks for EXTRACT regular expressions that duplicate REGEX in
    transforms.conf
    """
    props_key_regex_pattern = "EXTRACT-"
    transforms_key_regex_pattern = "^REGEX$"
    props_file_paths = app.get_config_file_paths("props.conf")
    transforms_file_paths = app.get_config_file_paths("transforms.conf")
    transforms_regexes = {}
    if props_file_paths and transforms_file_paths:
        for directory, filename in iter(transforms_file_paths.items()):
            transforms_config: ConfigurationFile = app.transforms_conf(
                directory)
            transforms_extract_sections = set(
                transforms_config.sections_with_setting_key_pattern(transforms_key_regex_pattern))
            for stanza in transforms_extract_sections:
                regex = _cleanup_regex(stanza.get_option("REGEX").value)
                # there can be duplicates, but we check for those elsewhere
                transforms_regexes[regex] = stanza
        for directory, filename in iter(props_file_paths.items()):
            file_path = os.path.join(directory, filename)
            props_config: ConfigurationFile = app.props_conf(directory)
            props_extract_sections = list(
                props_config.sections_with_setting_key_pattern(props_key_regex_pattern))
            for stanza in props_extract_sections:
                for setting in stanza.settings_with_key_pattern(props_key_regex_pattern):
                    regex = _cleanup_regex(setting.value)
                    if regex in transforms_regexes:
                        if not ignorable(setting, "duplicate_regex"):
                            output = f"[{stanza.name}]:{setting.name} duplicates transforms {transforms_regexes[regex].name}"
                            reporter.warn(output,
                                          file_path, setting.lineno)


@splunk_appinspect.tags("best_practices", "best_practices_regex", "best_practices_props")
@splunk_appinspect.cert_version(min="2.14.1")
def check_valid_regex_sedcmd(app, reporter):
    """
    Checks that the regex in s/// is valid. Checks that only s/// and y/// are
    used. Makes sure for y/// that same length of input and replacement part,
    and no flags for y///
    """
    key_regex = "^SEDCMD-"
    config_file_paths = app.get_config_file_paths("props.conf")
    if config_file_paths:
        for directory, filename in iter(config_file_paths.items()):
            file_path = os.path.join(directory, filename)
            config: ConfigurationFile = app.props_conf(directory)
            pattern = re.compile(
                r"""
                (?<type>[sy])   # Start with s or y
                \/              # followed by a /
                (?<search>.*?)  # Capture everything as the named group search
                (?<!(?<!\\)\\)  # Don't let escaped / stop too early
                \/              # The middle /
                (?<replace>.*?) # Everything in the replace part.
                (?<!(?<!\\)\\)  # Don't let escaped / stop too early
                \/              # Closing /
                (?<flags>.*)    # Flags at the end
                """,
                re.VERBOSE
            )
            for stanza in set(config.sections_with_setting_key_pattern(key_regex)):
                for setting in stanza.settings_with_key_pattern(key_regex):
                    m = pattern.match(setting.value)
                    if not m:
                        output = f"Invalid [{stanza.name}]:{setting.name} of {setting.value}"
                        reporter.fail(output, file_path, setting.lineno)
                    else:
                        type = m["type"]
                        search = m["search"]
                        replace = m["replace"]
                        flags = m["flags"]
                        if type == "y":
                            if len(flags) > 0:
                                output = "No flags allowed for y/// in SEDCMD"
                                reporter.fail(
                                    output, file_path, setting.lineno)
                            if len(search) != len(replace):
                                output = "For y///, both sides should be the same length"
                                reporter.fail(output, file_path,
                                              setting.lineno)
                        else:
                            # TODO Check flags here are valid for s///
                            # g, \d+, iI, mM
                            # what about e and p?
                            # w is for a file, so not supported
                            _regex_valid(setting, reporter,
                                         file_path, regex=search)


@splunk_appinspect.tags("best_practices", "best_practices_regex", "best_practices_transforms")
@splunk_appinspect.cert_version(min="2.14.1")
def check_valid_regex_for_transforms(app, reporter):
    """
    Checks that REGEX is valid in transforms.conf.
    """
    key_regex = "^REGEX$"
    config_file_paths = app.get_config_file_paths("transforms.conf")
    if config_file_paths:
        for directory, filename in iter(config_file_paths.items()):
            file_path = os.path.join(directory, filename)
            config: ConfigurationFile = app.transforms_conf(directory)
            for stanza in set(config.sections_with_setting_key_pattern(key_regex)):
                _regex_valid(stanza.get_option("REGEX"), reporter, file_path)


@splunk_appinspect.tags("best_practices", "best_practices_regex", "best_practices_props")
@splunk_appinspect.cert_version(min="2.14.1")
def check_valid_regex_for_extract(app, reporter):
    """
    Checks that EXTRACT regex is valid in props.conf.
    """
    # TODO, add check that there needs to be at least one named extract here
    # (improved one over appinspect slightly broken one)
    _regex_valid_for_property(app, reporter, "^EXTRACT-")


@splunk_appinspect.tags("best_practices", "best_practices_regex", "best_practices_props")
@splunk_appinspect.cert_version(min="2.14.1")
def check_valid_regex_for_break_only_before(app, reporter):
    """
    Checks that BREAK_ONLY_BEFORE in props.conf is a valid regular expression.
    """
    _regex_valid_for_property(app, reporter, "^BREAK_ONLY_BEFORE$")


@splunk_appinspect.tags("best_practices", "best_practices_regex", "best_practices_props")
@splunk_appinspect.cert_version(min="2.14.1")
def check_valid_regex_for_event_breaker(app, reporter):
    """
    Checks that EVENT_BREAKER in props.conf is a valid regular expression.
    """
    # TODO, there needs to be a check there is an unnamed capture group
    _regex_valid_for_property(app, reporter, "^EVENT_BREAKER$")


@splunk_appinspect.tags("best_practices", "best_practices_regex", "best_practices_props")
@splunk_appinspect.cert_version(min="2.14.1")
def check_valid_regex_for_field_header_regex(app, reporter):
    """
    Checks that FIELD_HEADER_REGEX in props.conf is a valid regular expression.
    """
    _regex_valid_for_property(app, reporter, "^FIELD_HEADER_REGEX$")


@splunk_appinspect.tags("best_practices", "best_practices_regex", "best_practices_props")
@splunk_appinspect.cert_version(min="2.14.1")
def check_valid_regex_for_lb_chunk_breaker(app, reporter):
    """
    Checks that LB_CHUNK_BREAKER in props.conf is a valid regular expression.
    """
    _regex_valid_for_property(app, reporter, "^LB_CHUNK_BREAKER$")


@splunk_appinspect.tags("best_practices", "best_practices_regex", "best_practices_props")
@splunk_appinspect.cert_version(min="2.14.1")
def check_valid_regex_for_line_breaker(app, reporter):
    """
    Checks that LINE_BREAKER in props.conf is a valid regular expression.
    """
    _regex_valid_for_property(app, reporter, "^LINE_BREAKER$")


@splunk_appinspect.tags("best_practices", "best_practices_regex", "best_practices_props")
@splunk_appinspect.cert_version(min="2.14.1")
def check_valid_regex_for_must_break_after(app, reporter):
    """
    Checks that MUST_BREAK_AFTER in props.conf is a valid regular expression.
    """
    _regex_valid_for_property(app, reporter, "^MUST_BREAK_AFTER$")


@splunk_appinspect.tags("best_practices", "best_practices_regex", "best_practices_props")
@splunk_appinspect.cert_version(min="2.14.1")
def check_valid_regex_for_must_not_break_after(app, reporter):
    """
    Checks that MUST_NOT_BREAK_AFTER in props.conf is a valid regular expression.
    """
    _regex_valid_for_property(app, reporter, "^MUST_NOT_BREAK_AFTER$")


@splunk_appinspect.tags("best_practices", "best_practices_regex", "best_practices_props")
@splunk_appinspect.cert_version(min="2.14.1")
def check_valid_regex_for_must_not_break_before(app, reporter):
    """
    Checks that MUST_NOT_BREAK_BEFORE in props.conf is a valid regular expression.
    """
    _regex_valid_for_property(app, reporter, "^MUST_NOT_BREAK_BEFORE$")


@splunk_appinspect.tags("best_practices", "best_practices_regex", "best_practices_props")
@splunk_appinspect.cert_version(min="2.14.1")
def check_valid_regex_for_preamble_regex(app, reporter):
    """
    Checks that PREAMBLE_REGEX in props.conf is a valid regular expression.
    """
    _regex_valid_for_property(app, reporter, "^PREAMBLE_REGEX$")


@splunk_appinspect.tags("best_practices", "best_practices_regex", "best_practices_props")
@splunk_appinspect.cert_version(min="2.14.1")
def check_valid_regex_for_time_prefix(app, reporter):
    """
    Checks that TIME_PREFIX in props.conf is a valid regular expression.
    """
    _regex_valid_for_property(app, reporter, "^TIME_PREFIX$")


@splunk_appinspect.tags("best_practices", "best_practices_regex", "best_practices_props")
@splunk_appinspect.cert_version(min="2.14.1")
def check_valid_regex_for_more_than(app, reporter):
    """
    Checks that MORE_THAN in props.conf is a valid regular expression.
    """
    _regex_valid_for_property(app, reporter, "^MORE_THAN")


@splunk_appinspect.tags("best_practices", "best_practices_regex", "best_practices_props")
@splunk_appinspect.cert_version(min="2.14.1")
def check_valid_regex_for_less_than(app, reporter):
    """
    Checks that LESS_THAN in props.conf is a valid regular expression.
    """
    _regex_valid_for_property(app, reporter, "^LESS_THAN")
