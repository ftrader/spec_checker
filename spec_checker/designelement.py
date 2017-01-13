'''
Class for design elements
'''

import sys


class DesignElement(object):
    ''' class modeling a textual design element. Not everything
    is captured, currently only the name and specified traceability to
    SW reqs. '''

    def __init__(self, name):
        self.name = name
        self.linked_reqs = []

    def is_linked_to_req(self, req_name):
        return req_name in self.linked_reqs

    def add_reqs(self, input_str_or_list):
        ''' add design element(s) '''
        if type(input_str_or_list) == list:
            for req in input_str_or_list:
                self.linked_reqs.append(req)
        elif type(input_str_or_list) == str:
            self.linked_reqs.append(input_str_or_list)
        else:
            print("Unrecognized type - not list or string: %s" %
                  input_str_or_list)
            sys.exit(1)
