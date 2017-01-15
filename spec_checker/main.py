#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Program entry point"""

from __future__ import print_function

import argparse
import os
import sys

from spec_checker import metadata, runtime, default_config


def load_config_from_file(filepath):
    ''' load a configuration from a file '''
    try:
        with open(filepath) as f:
            code = compile(f.read(), filepath, 'exec')
            exec(code)
            config = {
                "PROJECT_ID": locals()["PROJECT_ID"],
                "REQUIREMENT_PREFIX": locals()["REQUIREMENT_PREFIX"],
                "USER_REQ_TAG": locals()["USER_REQ_TAG"],
                "SYS_REQ_TAG": locals()["SYS_REQ_TAG"],
                "SW_REQ_TAG": locals()["SW_REQ_TAG"],
                "REQUIREMENT_PATTERN": locals()["REQUIREMENT_PATTERN"],
                "REQUIREMENT_TRACEABILITY_START":
                locals()["REQUIREMENT_TRACEABILITY_START"],
                "REQUIREMENT_TRACEABILITY_CONT":
                locals()["REQUIREMENT_TRACEABILITY_CONT"],
                "DESIGN_ELEMENT_INTRODUCTION":
                locals()["DESIGN_ELEMENT_INTRODUCTION"],
                "REQ_TO_DES_SECTION_START":
                locals()["REQ_TO_DES_SECTION_START"],
                "REQ_TO_DES_TABLE_START": locals()["REQ_TO_DES_TABLE_START"],
                "REQ_TO_DES_ENTRY": locals()["REQ_TO_DES_ENTRY"],
                "DESIGN_PREFIX": locals()["DESIGN_PREFIX"],
                "DES_TO_REQ_SECTION_START":
                locals()["DES_TO_REQ_SECTION_START"],
                "DES_TO_REQ_TABLE_START": locals()["DES_TO_REQ_TABLE_START"],
                "DES_TO_REQ_ENTRY": locals()["DES_TO_REQ_ENTRY"]
            }
    except Exception:
        raise
    return config


def main(argv):
    """Program entry point.

    :param argv: command-line arguments
    :type argv: :class:`list`
    """
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
            config = load_config_from_file(args.config)
        else:
            # try to load the standard settings
            default_cfg_file = "%s/spec-checker.conf" % os.getcwd()
            if os.path.exists(default_cfg_file):
                print("loading configuration from %s"
                      % default_cfg_file)
                config = load_config_from_file(default_cfg_file)
            else:
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
