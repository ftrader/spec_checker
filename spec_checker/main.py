#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Program entry point"""

from __future__ import print_function

import argparse
import os
import sys

from spec_checker import metadata, runtime


def main(argv):
    """Program entry point.

    :param argv: command-line arguments
    :type argv: :class:`list`
    """
    author_strings = []
    for name, email in zip(metadata.authors, metadata.emails):
        author_strings.append('Author: {0} <{1}>'.format(name, email))

    epilog = '''
{project} {version}

{authors}
URL: <{url}>
'''.format(
        project=metadata.project,
        version=metadata.version,
        authors='\n'.join(author_strings),
        url=metadata.url)

    #argparser = argparse.ArgumentParser(prog='Traceability Checker')
    argparser = argparse.ArgumentParser(
        prog=os.path.basename(argv[0]),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=metadata.description,
        epilog=epilog)
    #argparser.add_argument('--version', action='version', version="%(prog)s " + PROGRAM_VERSION)
    argparser.add_argument(
        '-V', '--version',
        action='version',
        version='{0} {1}'.format(metadata.project, metadata.version))
    #argparser.add_argument('--doctest', action='store_true')
    argparser.add_argument("--config", nargs='?', help="path to a custom configuration file")
    argparser.add_argument("requirements_doc", nargs='?', help="path to a requirements document")
    argparser.add_argument("design_doc", nargs='?', help="path to a design document")
    argparser.add_argument("code_path_or_URL", nargs='?', default=None,
                           help="URL or path to source code directory")
    #args = argparser.parse_args()
    args = argparser.parse_args(args=argv[1:])
    #print(epilog)

    try:
        if args.config:
            if not os.path.exists(args.config):
                print("Error: configuration file '%s' not found" % args.config)
                sys.exit(1)
            print("Info: loading configuration from '%s'" % args.config)
            with open(args.config) as f:
                code = compile(f.read(), args.config, 'exec')
                #exec(code, global_vars, local_vars)
                exec(code)
        else:
            # try to load the standard settings
            print("Info: loading configuration from %s/check_traceability_project.py" % os.getcwd())
            from spec_checker.default_config import *

    finally:
        # stuff into a config dictionary to pass to the checker
        config = {
                "PROJECT_ID" : PROJECT_ID,
                "REQUIREMENT_PREFIX" : REQUIREMENT_PREFIX,
                "USER_REQ_TAG" : USER_REQ_TAG,
                "SYS_REQ_TAG" : SYS_REQ_TAG,
                "SW_REQ_TAG" : SW_REQ_TAG,
                "REQUIREMENT_PATTERN" : REQUIREMENT_PATTERN,
                "REQUIREMENT_TRACEABILITY_START" : REQUIREMENT_TRACEABILITY_START,
                "REQUIREMENT_TRACEABILITY_CONT" : REQUIREMENT_TRACEABILITY_CONT,
                "DESIGN_ELEMENT_INTRODUCTION" : DESIGN_ELEMENT_INTRODUCTION,
                "REQ_TO_DES_SECTION_START" : REQ_TO_DES_SECTION_START,
                "REQ_TO_DES_TABLE_START" : REQ_TO_DES_TABLE_START,
                "REQ_TO_DES_ENTRY" : REQ_TO_DES_ENTRY,
                "DESIGN_PREFIX" : DESIGN_PREFIX,
                "DES_TO_REQ_SECTION_START" : DES_TO_REQ_SECTION_START,
                "DES_TO_REQ_TABLE_START" : DES_TO_REQ_TABLE_START,
                "DES_TO_REQ_ENTRY" : DES_TO_REQ_ENTRY
                }

    if not args.requirements_doc:
        argparser.print_help()
        return 1

    tc = runtime.TraceabilityChecker(config, args.requirements_doc, args.design_doc, args.code_path_or_URL)
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
