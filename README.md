# App Inspect Best Practices

This is a set of app inspect custom checks to make sure certain best practices are followed.

## Using

You will need to follow [these directions](https://dev.splunk.com/enterprise/docs/developapps/testvalidate/appinspect/createaicustchecks/). If you have existing custom checks, you will need to copy the python files from the checks directory into your existing directory.

Then when you run `splunk_appinspect` CLI you will need to specify `--custom-checks-dir` and pass in the directory containing the custom checks. You will also want to include `--included-tags best_practices` to include these checks.

You can also run `./check_best_practices.sh <path_to_archive_or_app_folder>` to run _just_ the best practices checks, and output the results.

## Checks

The doc strings for each check should give you an idea of what it checks. _TODO_ flesh this out from doc strings.

### Regular Expression Checks

_TODO_ Enumerate them here

### Magic Eight Checks

These check that the magic eight `props.conf` settings are configured. See [Magic 8](https://kinneygroup.com/blog/splunk-magic-8-props-conf/) for more details.

### Future Checks

- transforms.conf checks
  - Checking REGEX and FORMAT map together appropriately
    - Check where unnamed capture group count matches format $var count.
    - Unnamed capture group mixed in with named capture groups
    - Is it valid to have FORMAT when your REGEX is just named capture groups?
    - There might be lots of edge cases...

## App Inspect Tags

_TODO_ List them here.

## Contributing

Pull requests are welcome!

## License

The code in this repository is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.
