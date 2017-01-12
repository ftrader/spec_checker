#!/usr/bin/env python
'''
utility functions
'''

import re

from spec_checker.default_config import REQUIREMENT_PREFIX, USER_REQ_TAG, \
    SYS_REQ_TAG, SW_REQ_TAG, DESIGN_PREFIX


# helper function which return True depending on type of requirement
# according to its name
def is_user_req(req_name, prefix=REQUIREMENT_PREFIX + USER_REQ_TAG):
    '''
    >>> is_user_req('THE-SPEC_CHECKER-USER-REQ-1', 'THE-SPEC_CHECKER-USER')
    True
    >>> is_user_req('THE-SPEC_CHECKER-SYS-REQ-1', 'THE-SPEC_CHECKER-USER')
    False
    >>> is_user_req('THE-SPEC_CHECKER-SW-REQ-1-1', 'THE-SPEC_CHECKER-USER')
    False
    '''
    return req_name.startswith(prefix)


def is_sys_req(req_name, prefix=REQUIREMENT_PREFIX + SYS_REQ_TAG):
    '''
    >>> is_sys_req('THE-SPEC_CHECKER-USER-REQ-1', 'THE-SPEC_CHECKER-SYS')
    False
    >>> is_sys_req('THE-SPEC_CHECKER-SYS-REQ-1', 'THE-SPEC_CHECKER-SYS')
    True
    >>> is_sys_req('THE-SPEC_CHECKER-SW-REQ-1-1', 'THE-SPEC_CHECKER-SYS')
    False
    '''
    return req_name.startswith(prefix)


def is_sw_req(req_name, prefix=REQUIREMENT_PREFIX + SW_REQ_TAG):
    '''
    >>> is_sw_req('THE-SPEC_CHECKER-USER-REQ-1', 'THE-SPEC_CHECKER-SW')
    False
    >>> is_sw_req('THE-SPEC_CHECKER-SYS-REQ-1', 'THE-SPEC_CHECKER-SW')
    False
    >>> is_sw_req('THE-SPEC_CHECKER-SW-REQ-1-1', 'THE-SPEC_CHECKER-SW')
    True
    '''
    return req_name.startswith(prefix)


# helper functions to determine upstream/downstream relations
# purely according to naming conventions


def is_upstream(r1, r2, user_prefix, sys_prefix, sw_prefix):
    ''' return True if r1 is potential upstream of r2, else False

    >>> is_upstream('THE-SPEC_CHECKER-USER-REQ-1',\
                    'THE-SPEC_CHECKER-SYS-REQ-1',\
                    'THE-SPEC_CHECKER-USER',\
                    'THE-SPEC_CHECKER-SYS',\
                    'THE-SPEC_CHECKER-SW')
    True
    >>> is_upstream('THE-SPEC_CHECKER-SYS-REQ-1',\
                    'THE-SPEC_CHECKER-SW-REQ-1-1',\
                    'THE-SPEC_CHECKER-USER',\
                    'THE-SPEC_CHECKER-SYS',\
                    'THE-SPEC_CHECKER-SW')
    True
    >>> is_upstream('THE-SPEC_CHECKER-USER-REQ-1',\
                    'THE-SPEC_CHECKER-SW-REQ-1',\
                    'THE-SPEC_CHECKER-USER',\
                    'THE-SPEC_CHECKER-SYS',\
                    'THE-SPEC_CHECKER-SW')
    False
    >>> is_upstream('THE-SPEC_CHECKER-SYS-REQ-1',\
                    'THE-SPEC_CHECKER-USER-REQ-1',\
                    'THE-SPEC_CHECKER-USER',\
                    'THE-SPEC_CHECKER-SYS',\
                    'THE-SPEC_CHECKER-SW')
    False
    >>> is_upstream('THE-SPEC_CHECKER-SW-REQ-1',\
                    'THE-SPEC_CHECKER-SYS-REQ-1',\
                    'THE-SPEC_CHECKER-USER',\
                    'THE-SPEC_CHECKER-SYS',\
                    'THE-SPEC_CHECKER-SW')
    False
    >>> is_upstream('THE-SPEC_CHECKER-SW-REQ-1',\
                    'THE-SPEC_CHECKER-USER-REQ-1',\
                    'THE-SPEC_CHECKER-USER',\
                    'THE-SPEC_CHECKER-SYS',\
                    'THE-SPEC_CHECKER-SW')
    False
    '''
    if is_user_req(r1, user_prefix) and is_sys_req(r2, sys_prefix):
        return True
    if is_sys_req(r1, sys_prefix) and is_sw_req(r2, sw_prefix):
        return True
    return False


def is_downstream(r1, r2, user_prefix, sys_prefix, sw_prefix):
    ''' return True if r1 is potential downstream of r2, else False

    >>> is_downstream('THE-SPEC_CHECKER-USER-REQ-1',\
                      'THE-SPEC_CHECKER-SYS-REQ-1',\
                      'THE-SPEC_CHECKER-USER',\
                      'THE-SPEC_CHECKER-SYS',\
                      'THE-SPEC_CHECKER-SW')
    False
    >>> is_downstream('THE-SPEC_CHECKER-SYS-REQ-1',\
                      'THE-SPEC_CHECKER-SW-REQ-1-1',\
                      'THE-SPEC_CHECKER-USER',\
                      'THE-SPEC_CHECKER-SYS',\
                      'THE-SPEC_CHECKER-SW')
    False
    >>> is_downstream('THE-SPEC_CHECKER-USER-REQ-1',\
                      'THE-SPEC_CHECKER-SW-REQ-1',\
                      'THE-SPEC_CHECKER-USER',\
                      'THE-SPEC_CHECKER-SYS',\
                      'THE-SPEC_CHECKER-SW')
    False
    >>> is_downstream('THE-SPEC_CHECKER-SYS-REQ-1',\
                      'THE-SPEC_CHECKER-USER-REQ-1',\
                      'THE-SPEC_CHECKER-USER',\
                      'THE-SPEC_CHECKER-SYS',\
                      'THE-SPEC_CHECKER-SW')
    True
    >>> is_downstream('THE-SPEC_CHECKER-SW-REQ-1',\
                      'THE-SPEC_CHECKER-SYS-REQ-1',\
                      'THE-SPEC_CHECKER-USER',\
                      'THE-SPEC_CHECKER-SYS',\
                      'THE-SPEC_CHECKER-SW')
    True
    >>> is_downstream('THE-SPEC_CHECKER-SW-REQ-1',\
                      'THE-SPEC_CHECKER-USER-REQ-1',\
                      'THE-SPEC_CHECKER-USER',\
                      'THE-SPEC_CHECKER-SYS',\
                      'THE-SPEC_CHECKER-SW')
    False
    '''
    if is_sys_req(r1, sys_prefix) and is_user_req(r2, user_prefix):
        return True
    if is_sw_req(r1, sw_prefix) and is_sys_req(r2, sys_prefix):
        return True
    return False


def group_split(group,
                req_prefix=REQUIREMENT_PREFIX,
                des_prefix=DESIGN_PREFIX):
    ''' return a list of requirement or design element names in group
    separated by commas, semi-colons and/or tab/space.
    Returns a list (possibly empty) of req/des identifiers.

    >>> group_split("THE-SPEC_CHECKER-SW-REQ-1-1", "THE-SPEC_CHECKER",\
        "THE-SPEC_CHECKER")
    ['THE-SPEC_CHECKER-SW-REQ-1-1']
    >>> group_split("THE-SPEC_CHECKER-SW-REQ-1-1,"\
        "THE-SPEC_CHECKER-SW-REQ-1-2", "THE-SPEC_CHECKER", "THE-SPEC_CHECKER")
    ['THE-SPEC_CHECKER-SW-REQ-1-1', 'THE-SPEC_CHECKER-SW-REQ-1-2']
    >>> group_split("THE-SPEC_CHECKER-SW-REQ-2-1;"\
        "THE-SPEC_CHECKER-SW-REQ-2-2", "THE-SPEC_CHECKER", "THE-SPEC_CHECKER")
    ['THE-SPEC_CHECKER-SW-REQ-2-1', 'THE-SPEC_CHECKER-SW-REQ-2-2']
    >>> group_split("THE-SPEC_CHECKER-SW-REQ-3-1,"\
        " THE-SPEC_CHECKER-SW-REQ-3-2", "THE-SPEC_CHECKER", "THE-SPEC_CHECKER")
    ['THE-SPEC_CHECKER-SW-REQ-3-1', 'THE-SPEC_CHECKER-SW-REQ-3-2']
    >>> group_split("THE-SPEC_CHECKER-SW-REQ-4-1, "\
        "foo, THE-SPEC_CHECKER-SW-REQ-4-2", "THE-SPEC_CHECKER",\
        "THE-SPEC_CHECKER")
    ['THE-SPEC_CHECKER-SW-REQ-4-1', 'THE-SPEC_CHECKER-SW-REQ-4-2']
    >>> group_split("TODO: complete this list")
    []
    '''
    split_group = re.split(',|;| |\t', group.strip())
    result = [r.strip() for r in split_group
              if (r.startswith(req_prefix) or r.startswith(des_prefix))]
    return result

if __name__ == "__main__":
    import doctest
    doctest.testmod()
