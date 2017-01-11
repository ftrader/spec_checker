#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Program entry point"""

from __future__ import print_function

import argparse
import os
import sys

from spec_checker import metadata, runtime, default_config


def main(argv):
    """Program entry point.

    :param argv: command-line arguments
    :type argv: :class:`list`
    """
    # initialize these since otherwise PEP8 checker complains
    # about F821 undefined name
    PROJECT_ID = REQUIREMENT_PREFIX = USER_REQ_TAG = SYS_REQ_TAG = \
        SW_REQ_TAG = REQUIREMENT_PATTERN = REQUIREMENT_TRACEABILITY_START = \
        REQUIREMENT_TRACEABILITY_CONT = DESIGN_ELEMENT_INTRODUCTION = \
        REQ_TO_DES_SECTION_START = REQ_TO_DES_TABLE_START = \
        REQ_TO_DES_ENTRY = DESIGN_PREFIX = DES_TO_REQ_SECTION_START = \
        DES_TO_REQ_TABLE_START = DES_TO_REQ_ENTRY = None

    author_strings = []
    for name, email in zip(metadata.authors, metadata.emails):
        author_strings.append('Author: {0} <{1}>'.format(name, email))

    epilog = '''{project} v{version}
Copyright (c) {copyright} {email}
This program is licensed under the AGPLv3.
'''.format(
        project=metadata.project,
        version=metadata.version,
        copyright=metadata.copyright,
        email=author_strings[0].split()[2])

    argparser = argparse.ArgumentParser(
        prog=os.path.basename(argv[0]),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=metadata.description)
    argparser.add_argument(
        '-V', '--version',
        action='version',
        version='{0} {1}'.format(metadata.project, metadata.version))
    argparser.add_argument("--config", nargs='?',
                           help="path to a custom configuration file")
    argparser.add_argument("requirements_doc", nargs='?',
                           help="path to a requirements document")
    argparser.add_argument("design_doc", nargs='?',
                           help="path to a design document")
    argparser.add_argument("code_path_or_URL", nargs='?', default=None,
                           help="URL or path to source code directory")
    args = argparser.parse_args(args=argv[1:])

    print(epilog)
    if not args.requirements_doc:
        argparser.print_help()
        return 1

    try:
        if args.config:
            if not os.path.exists(args.config):
                print("Error: configuration file '%s' not found" % args.config)
                sys.exit(1)
            print("loading configuration from '%s'" % args.config)
            with open(args.config) as f:
                code = compile(f.read(), args.config, 'exec')
                exec(code)
                config = {
                    "PROJECT_ID": PROJECT_ID,
                    "REQUIREMENT_PREFIX": REQUIREMENT_PREFIX,
                    "USER_REQ_TAG": USER_REQ_TAG,
                    "SYS_REQ_TAG": SYS_REQ_TAG,
                    "SW_REQ_TAG": SW_REQ_TAG,
                    "REQUIREMENT_PATTERN": REQUIREMENT_PATTERN,
                    "REQUIREMENT_TRACEABILITY_START":
                    REQUIREMENT_TRACEABILITY_START,
                    "REQUIREMENT_TRACEABILITY_CONT":
                    REQUIREMENT_TRACEABILITY_CONT,
                    "DESIGN_ELEMENT_INTRODUCTION":
                    DESIGN_ELEMENT_INTRODUCTION,
                    "REQ_TO_DES_SECTION_START": REQ_TO_DES_SECTION_START,
                    "REQ_TO_DES_TABLE_START": REQ_TO_DES_TABLE_START,
                    "REQ_TO_DES_ENTRY": REQ_TO_DES_ENTRY,
                    "DESIGN_PREFIX": DESIGN_PREFIX,
                    "DES_TO_REQ_SECTION_START": DES_TO_REQ_SECTION_START,
                    "DES_TO_REQ_TABLE_START": DES_TO_REQ_TABLE_START,
                    "DES_TO_REQ_ENTRY": DES_TO_REQ_ENTRY
                }
        else:
            # try to load the standard settings
            print(
                "loading configuration from %s/check_traceability_project.py"
                % os.getcwd())
            config = default_config.__dict__
    except Exception:
        raise

    tc = runtime.TraceabilityChecker(
        config, args.requirements_doc, args.design_doc, args.code_path_or_URL)
    errors = tc.check()
    if errors:
        for err in errors:
            print("Error: %s" % err)
        return 1
    else:
        return 0


def entry_point():
    """Zero-argument entry point for use with setuptools/distribute."""
    raise SystemExit(main(sys.argv))


if __name__ == '__main__':
    entry_point()
