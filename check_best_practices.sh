#!/usr/bin/env bash

if [ $# -eq 0 ]; then
    echo "$0 <path_to_directory_or_archive>"
    exit
fi

if [ ! -e $1 ]; then
    echo "$1 is not a file or directory!"
    exit
fi

SCRIPT_HOME=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )

# Run app inspect for just best_practices
splunk-appinspect inspect \
    --mode precert \
    --custom-checks-dir ${SCRIPT_HOME}/checks \
    --included-tags best_practices \
    --excluded-tags splunk_appinspect \
    --excluded-tags appapproval \
    --excluded-tags packaging_standards \
    $1