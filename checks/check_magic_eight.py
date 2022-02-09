import splunk_appinspect
import os
import regex as re
from splunk_appinspect.configuration_file import ConfigurationFile
from splunk_appinspect.splunk import normalizeBoolean
from .shared import _is_numeric


@splunk_appinspect.tags("best_practices", "best_practices_magic_eight")
@splunk_appinspect.cert_version(min="2.14.1")
def check_should_linemerge(app, reporter):
    """Check that SHOULD_LINEMERGE is set to false"""
    property = "SHOULD_LINEMERGE"
    config_file_paths = app.get_config_file_paths("props.conf")
    for directory, filename in iter(config_file_paths.items()):
        file_path = os.path.join(directory, filename)
        props_config: ConfigurationFile = app.props_conf(directory)
        for stanza in props_config.sections():
            if not stanza.has_option(property):
                output = f"{property} is not set for [{stanza.name}]"
                reporter.warn(output, file_path, stanza.lineno)
            elif normalizeBoolean(stanza.get_option(property).value):
                output = f"{property} is true, when it should be false for [{stanza.name}]"
                reporter.warn(output, file_path, stanza.lineno)


@splunk_appinspect.tags("best_practices", "best_practices_magic_eight")
@splunk_appinspect.cert_version(min="2.14.1")
def check_line_breaker(app, reporter):
    """Check that LINE_BREAKER is set"""
    property = "LINE_BREAKER"
    config_file_paths = app.get_config_file_paths("props.conf")
    for directory, filename in iter(config_file_paths.items()):
        file_path = os.path.join(directory, filename)
        props_config: ConfigurationFile = app.props_conf(directory)
        for stanza in props_config.sections():
            if not stanza.has_option(property):
                output = f"{property} is not set for [{stanza.name}]"
                reporter.warn(output, file_path, stanza.lineno)


@splunk_appinspect.tags("best_practices", "best_practices_magic_eight")
@splunk_appinspect.cert_version(min="2.14.1")
def check_time_prefix(app, reporter):
    """Check that TIME_PREFIX is set"""
    property = "TIME_PREFIX"
    config_file_paths = app.get_config_file_paths("props.conf")
    for directory, filename in iter(config_file_paths.items()):
        file_path = os.path.join(directory, filename)
        props_config: ConfigurationFile = app.props_conf(directory)
        for stanza in props_config.sections():
            if not stanza.has_option(property):
                output = f"{property} is not set for [{stanza.name}]"
                reporter.warn(output, file_path, stanza.lineno)


@splunk_appinspect.tags("best_practices", "best_practices_magic_eight")
@splunk_appinspect.cert_version(min="2.14.1")
def check_max_timestamp_lookahead(app, reporter):
    """Check that MAX_TIMESTAMP_LOOKAHEAD is set, numeric and >= 0"""
    property = "MAX_TIMESTAMP_LOOKAHEAD"
    config_file_paths = app.get_config_file_paths("props.conf")
    for directory, filename in iter(config_file_paths.items()):
        file_path = os.path.join(directory, filename)
        props_config: ConfigurationFile = app.props_conf(directory)
        for stanza in props_config.sections():
            if not stanza.has_option(property):
                output = f"{property} is not set for [{stanza.name}]"
                reporter.warn(output, file_path, stanza.lineno)
            else:
                setting = stanza.get_option(property)
                if not _is_numeric(setting.value):
                    output = f"{property} is not numeric for [{stanza.name}] ({setting.value})"
                    reporter.warn(output, file_path, setting.lineno)
                elif not int(setting.value) >= 0:
                    output = f"{property} is not >= 0 [{stanza.name}] ({setting.value})"
                    reporter.warn(output, file_path, setting.lineno)


@splunk_appinspect.tags("best_practices", "best_practices_magic_eight")
@splunk_appinspect.cert_version(min="2.14.1")
def check_time_format(app, reporter):
    """Check that TIME_FORMAT is set"""
    property = "TIME_FORMAT"
    config_file_paths = app.get_config_file_paths("props.conf")
    for directory, filename in iter(config_file_paths.items()):
        file_path = os.path.join(directory, filename)
        props_config: ConfigurationFile = app.props_conf(directory)
        for stanza in props_config.sections():
            if not stanza.has_option(property):
                output = f"{property} is not set for [{stanza.name}]"
                reporter.warn(output, file_path, stanza.lineno)


@splunk_appinspect.tags("best_practices", "best_practices_magic_eight")
@splunk_appinspect.cert_version(min="2.14.1")
def check_truncate(app, reporter):
    """Check that TRUNCATE is set"""
    property = "TRUNCATE"
    config_file_paths = app.get_config_file_paths("props.conf")
    for directory, filename in iter(config_file_paths.items()):
        file_path = os.path.join(directory, filename)
        props_config: ConfigurationFile = app.props_conf(directory)
        for stanza in props_config.sections():
            if not stanza.has_option(property):
                output = f"{property} is not set for [{stanza.name}]"
                reporter.warn(output, file_path, stanza.lineno)
            else:
                setting = stanza.get_option(property)
                if not _is_numeric(setting.value):
                    output = f"{property} is not numeric for [{stanza.name}] ({setting.value})"
                    reporter.warn(output, file_path, setting.lineno)
                elif not int(setting.value) > 0:
                    output = f"{property} is not > 0 [{stanza.name}] ({setting.value})"
                    reporter.warn(output, file_path, setting.lineno)


@splunk_appinspect.tags("best_practices", "best_practices_magic_eight")
@splunk_appinspect.cert_version(min="2.14.1")
def check_event_breaker_enable(app, reporter):
    """Check that EVENT_BREAKER_ENABLE is set to true"""
    property = "EVENT_BREAKER_ENABLE"
    config_file_paths = app.get_config_file_paths("props.conf")
    for directory, filename in iter(config_file_paths.items()):
        file_path = os.path.join(directory, filename)
        props_config: ConfigurationFile = app.props_conf(directory)
        for stanza in props_config.sections():
            if not stanza.has_option(property):
                output = f"{property} is not set for [{stanza.name}]"
                reporter.warn(output, file_path, stanza.lineno)
            elif not normalizeBoolean(stanza.get_option(property).value):
                output = f"{property} is false, when it should be true for [{stanza.name}]"
                reporter.warn(output, file_path, stanza.lineno)


@splunk_appinspect.tags("best_practices", "best_practices_magic_eight")
@splunk_appinspect.cert_version(min="2.14.1")
def check_event_breaker(app, reporter):
    """Check that EVENT_BREAKER is set"""
    property = "EVENT_BREAKER"
    config_file_paths = app.get_config_file_paths("props.conf")
    for directory, filename in iter(config_file_paths.items()):
        file_path = os.path.join(directory, filename)
        props_config: ConfigurationFile = app.props_conf(directory)
        for stanza in props_config.sections():
            if not stanza.has_option(property):
                output = f"{property} is not set for [{stanza.name}]"
                reporter.warn(output, file_path, stanza.lineno)
