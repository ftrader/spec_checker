'''
Class for requirements
'''

import sys


class Requirement(object):
    ''' requirement class modeling a textual requirement. Not everything
    is captured, currently only the name and traceability. '''

    def __init__(self, name):
        self.name = name
        self.upstream_reqs = []
        self.downstream_reqs = []
        self.raw_trace_reqs = []
        self.linked_design_elems = []

    def add_raw_trace_req(self, input_str_or_list):
        ''' add a raw trace requirement - raw means we do not yet know
        if it is up or downstream '''
        if type(input_str_or_list) == list:
            for derived_req in input_str_or_list:
                self.raw_trace_reqs.append(derived_req)
        elif type(input_str_or_list) == str:
            self.raw_trace_reqs.append(input_str_or_list)
        else:
            print("Unrecognized type - not list or string: %s" %
                  input_str_or_list)
            sys.exit(1)

    def add_design_elem(self, input_str):
        self.linked_design_elems.append(input_str)

    def set_upstream_req(self, upstream_req):
        ''' add to upstream (parent) requirements '''
        self.upstream_reqs.append(upstream_req)

    def are_ups_and_downs_consistent_with_raw_reqs(self):
        if self.raw_trace_reqs:
            # up and down must also be empty
            return (not self.upstream_reqs and not self.downstream_reqs)
        for rr in self.raw_trace_reqs:
            if rr not in self.upstream_reqs and rr not in self.downstream_reqs:
                return False
        return True
