#!/bin/sh
# Depends on coverage installed
coverage run --branch --source=../checks -m unittest
coverage html
