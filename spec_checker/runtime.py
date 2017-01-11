#!/usr/bin/env python
"""Classes for requirements, design elements and the checker itself"""

# TODO: ensure doctests are executed

import sys
import re


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


class TraceabilityChecker(object):

    def __init__(self, cfg_dict, reqfile, desfile, code_path_or_url=None):
        self.cfg = cfg_dict
        # assert that all the necessary config bits are there
        assert(self.cfg['REQUIREMENT_PREFIX'])
        assert(self.cfg['USER_REQ_TAG'])
        assert(self.cfg['SYS_REQ_TAG'])
        assert(self.cfg['SW_REQ_TAG'])
        assert(self.cfg['REQUIREMENT_PATTERN'])
        assert(self.cfg['REQUIREMENT_TRACEABILITY_START'])
        assert(self.cfg['REQUIREMENT_TRACEABILITY_CONT'])
        assert(self.cfg['DESIGN_ELEMENT_INTRODUCTION'])
        assert(self.cfg['REQ_TO_DES_SECTION_START'])
        assert(self.cfg['REQ_TO_DES_TABLE_START'])
        assert(self.cfg['REQ_TO_DES_ENTRY'])
        assert(self.cfg['DESIGN_PREFIX'])
        assert(self.cfg['DES_TO_REQ_SECTION_START'])
        assert(self.cfg['DES_TO_REQ_TABLE_START'])
        assert(self.cfg['DES_TO_REQ_ENTRY'])
        self.req_pattern = re.compile(self.cfg['REQUIREMENT_PATTERN'])
        self.req_trace_pattern = re.compile(
            self.cfg['REQUIREMENT_TRACEABILITY_START'])
        self.req_trace_cont_pattern = re.compile(
            self.cfg['REQUIREMENT_TRACEABILITY_CONT'])
        self.des_elem_intro_pattern = re.compile(
            self.cfg['DESIGN_ELEMENT_INTRODUCTION'])
        self.req_to_des_start_pattern = re.compile(
            self.cfg['REQ_TO_DES_SECTION_START'])
        self.req_to_des_cont_pattern = re.compile(self.cfg['REQ_TO_DES_ENTRY'])
        self.des_to_req_start_pattern = re.compile(
            self.cfg['DES_TO_REQ_SECTION_START'])
        self.des_to_req_cont_pattern = re.compile(self.cfg['DES_TO_REQ_ENTRY'])

        self.reqfile = reqfile
        self.desfile = desfile
        self.srcpath = code_path_or_url
        self.requirements = set()
        self.design_elements = set()

        if not reqfile:
            raise Exception("No requirements file specified. Cannot continue.")
        self.read_requirements()
        if self.desfile:
            self.read_design()
        print("source code : %s (not implemented yet)" % self.srcpath)
        # self.read_source()

    # helper function which return True depending on type of requirement
    # according to its name
    def is_user_req(self, req_name):
        '''
        >>> TraceabilityChecker.is_user_req('THE-SPEC_CHECKER-USER-REQ-1')
        True
        >>> TraceabilityChecker.is_user_req('THE-SPEC_CHECKER-SYS-REQ-1')
        False
        >>> TraceabilityChecker.is_user_req('THE-SPEC_CHECKER-SW-REQ-1-1')
        False
        '''
        return req_name.startswith(self.cfg['REQUIREMENT_PREFIX']
                                   + self.cfg['USER_REQ_TAG'])

    def is_sys_req(self, req_name):
        '''
        >>> TraceabilityChecker.is_sys_req('THE-SPEC_CHECKER-USER-REQ-1')
        False
        >>> TraceabilityChecker.is_sys_req('THE-SPEC_CHECKER-SYS-REQ-1')
        True
        >>> TraceabilityChecker.is_sys_req('THE-SPEC_CHECKER-SW-REQ-1-1')
        False
        '''
        return req_name.startswith(self.cfg['REQUIREMENT_PREFIX']
                                   + self.cfg['SYS_REQ_TAG'])

    def is_sw_req(self, req_name):
        '''
        >>> TraceabilityChecker.is_sw_req('THE-SPEC_CHECKER-USER-REQ-1')
        False
        >>> TraceabilityChecker.is_sw_req('THE-SPEC_CHECKER-SYS-REQ-1')
        False
        >>> TraceabilityChecker.is_sw_req('THE-SPEC_CHECKER-SW-REQ-1-1')
        True
        '''
        return req_name.startswith(self.cfg['REQUIREMENT_PREFIX']
                                   + self.cfg['SW_REQ_TAG'])

    # helper functions to determine upstream/downstream relations
    # purely according to naming conventions
    def is_upstream(self, r1, r2):
        ''' return True if r1 is potential upstream of r2, else False

        >>> TraceabilityChecker.is_upstream('THE-SPEC_CHECKER-USER-REQ-1',\
            'THE-SPEC_CHECKER-SYS-REQ-1')
        True
        >>> TraceabilityChecker.is_upstream('THE-SPEC_CHECKER-SYS-REQ-1',\
            'THE-SPEC_CHECKER-SW-REQ-1-1')
        True
        >>> TraceabilityChecker.is_upstream('THE-SPEC_CHECKER-USER-REQ-1',\
            'THE-SPEC_CHECKER-SW-REQ-1')
        False
        >>> TraceabilityChecker.is_upstream('THE-SPEC_CHECKER-SYS-REQ-1',\
            'THE-SPEC_CHECKER-USER-REQ-1')
        False
        >>> TraceabilityChecker.is_upstream('THE-SPEC_CHECKER-SW-REQ-1',\
            'THE-SPEC_CHECKER-SYS-REQ-1')
        False
        >>> TraceabilityChecker.is_upstream('THE-SPEC_CHECKER-SW-REQ-1',\
            'THE-SPEC_CHECKER-USER-REQ-1')
        False
        '''
        if self.is_user_req(r1) and self.is_sys_req(r2):
            return True
        if self.is_sys_req(r1) and self.is_sw_req(r2):
            return True
        return False

    def is_downstream(self, r1, r2):
        ''' return True if r1 is potential downstream of r2, else False

        >>> TraceabilityChecker.is_downstream('THE-SPEC_CHECKER-USER-REQ-1',\
            'THE-SPEC_CHECKER-SYS-REQ-1')
        False
        >>> TraceabilityChecker.is_downstream('THE-SPEC_CHECKER-SYS-REQ-1',\
            'THE-SPEC_CHECKER-SW-REQ-1-1')
        False
        >>> TraceabilityChecker.is_downstream('THE-SPEC_CHECKER-USER-REQ-1',\
            'THE-SPEC_CHECKER-SW-REQ-1')
        False
        >>> TraceabilityChecker.is_downstream('THE-SPEC_CHECKER-SYS-REQ-1',\
            'THE-SPEC_CHECKER-USER-REQ-1')
        True
        >>> TraceabilityChecker.is_downstream('THE-SPEC_CHECKER-SW-REQ-1',\
            'THE-SPEC_CHECKER-SYS-REQ-1')
        True
        >>> TraceabilityChecker.is_downstream('THE-SPEC_CHECKER-SW-REQ-1',\
            'THE-SPEC_CHECKER-USER-REQ-1')
        False
        '''
        if self.is_sys_req(r1) and self.is_user_req(r2):
            return True
        if self.is_sw_req(r1) and self.is_sys_req(r2):
            return True
        return False

    def group_split(self, group):
        ''' return a list of requirement or design element names in group
        separated by commas, semi-colons and/or tab/space.
        Returns a list (possibly empty) of req/des identifiers.

        >>> TraceabilityChecker.group_split("THE-SPEC_CHECKER-SW-REQ-1-1")
        ['THE-SPEC_CHECKER-SW-REQ-1-1']
        >>> TraceabilityChecker.group_split("THE-SPEC_CHECKER-SW-REQ-1-1,"\
            "THE-SPEC_CHECKER-SW-REQ-1-2")
        ['THE-SPEC_CHECKER-SW-REQ-1-1', 'THE-SPEC_CHECKER-SW-REQ-1-2']
        >>> TraceabilityChecker.group_split("THE-SPEC_CHECKER-SW-REQ-2-1;"\
            "THE-SPEC_CHECKER-SW-REQ-2-2")
        ['THE-SPEC_CHECKER-SW-REQ-2-1', 'THE-SPEC_CHECKER-SW-REQ-2-2']
        >>> TraceabilityChecker.group_split("THE-SPEC_CHECKER-SW-REQ-3-1,"\
            " THE-SPEC_CHECKER-SW-REQ-3-2")
        ['THE-SPEC_CHECKER-SW-REQ-3-1', 'THE-SPEC_CHECKER-SW-REQ-3-2']
        >>> TraceabilityChecker.group_split("THE-SPEC_CHECKER-SW-REQ-4-1, "\
            "foo, THE-SPEC_CHECKER-SW-REQ-4-2")
        ['THE-SPEC_CHECKER-SW-REQ-4-1', 'THE-SPEC_CHECKER-SW-REQ-4-2']
        >>> TraceabilityChecker.group_split("TODO: complete this list")
        []
        '''
        split_group = re.split(',|;| |\t', group.strip())
        result = [r.strip() for r in split_group
                  if (r.startswith(self.cfg['REQUIREMENT_PREFIX'])
                      or r.startswith(self.cfg['DESIGN_PREFIX']))]
        return result

    def find_requirement(self, name):
        ''' return the requirement object for <name>, if it exists '''
        for r in self.requirements:
            if r.name == name:
                return r
        return None

    def find_design_elem(self, name):
        ''' return the design element object for <name>, if it exists '''
        for d in self.design_elements:
            if d.name == name:
                return d
        return None

    def _rebuild_ups_and_downs(self):
        ''' build the upstream / downstream requirement lists from the
        raw traceability lists.
        Assumes that all requirements mentioned in the traceability lists
        have been also been read in from file - any requirement which does
        not resolve in self.requirements raises an error. Errors are
        collected and returned in a non-empty list, otherwise an empty list
        is returned. '''
        self.req_names = [r.name for r in self.requirements]
        result = []  # collect errors in here, return empty list if all ok
        assert(self.req_names)
        for r in self.requirements:
            for rr in r.raw_trace_reqs:
                if rr not in self.req_names:
                    result.append(
                        "'%s' : traceability to unknown requirement '%s'"
                        % (r.name, rr))
                else:
                    # determine if upstream or downstream
                    # then add if not already in
                    if self.is_upstream(rr, r.name):
                        # rr considered upstream of r.name
                        if rr not in r.upstream_reqs:
                            r.upstream_reqs.append(rr)
                            # appended rr to upstream reqs of r.name
                    elif self.is_downstream(rr, r.name):
                        # rr is considered downstream of r.name
                        if rr not in r.downstream_reqs:
                            r.downstream_reqs.append(rr)
                            # appended rr to downstream reqs of r.name
                    else:
                        result.append(
                            "'%s' : traceability on same level: '%s'"
                            % (r.name, rr))
        return result

    def check(self):
        ''' check traceability '''
        print("checking requirements file: %s" % self.reqfile)
        errors = self.check_requirements_consistency()
        if self.desfile:
            print("checking design file: %s" % self.desfile)
            errors += self.check_design_consistency()
        return errors

    def check_design_consistency(self):
        ''' check consistency for design elements '''
        errors = []
        # we definitely expect requirements for cross-reference purposes
        assert(self.requirements)
        if not self.design_elements:
            errors.append("No design elements found.")
        else:
            # check #1. check that each SW-req has associated design elem(s)
            for r in self.requirements:
                if self.is_sw_req(r.name):
                    referencing_elems = []
                    for d in self.design_elements:
                        if d.is_linked_to_req(r.name):
                            referencing_elems.append(d)
                    if not referencing_elems:
                        errors.append(
                            "software requirement '%s' has no associated "
                            "design element" % r.name)
            # check #2. check that all design element(s) have linked SW-REQs
            # and that only SW reqs are linked
            for d in self.design_elements:
                if not d.linked_reqs:
                    errors.append(
                        "design element '%s' is not linked to software "
                        "requirement(s)" % d.name)
                else:
                    for lr in d.linked_reqs:
                        if not self.is_sw_req(lr):
                            errors.append(
                                "%s: linked requirement '%s' is not a "
                                "software requirement" % (d.name, lr))
                        if not self.find_requirement(lr):
                            errors.append(
                                "%s: linked requirement '%s' was not found"
                                % (d.name, lr))
            # check #3. TODO: consistency and completeness check between
            # req->des and des->req tables

            # check #4. TODO: well-formedness of all design element ids

        return errors

    def check_requirements_consistency(self):
        ''' check consistency for requirements '''
        errors = []
        if not self.requirements:
            errors.append("no valid requirements found.")

        for r in self.requirements:
            # print "Checking ", r.name, ':', r.raw_trace_reqs
            # go through the raw trace reqs and build upstream/downstream reqs
            if ((not r.upstream_reqs and not r.downstream_reqs) or
                    not r.are_ups_and_downs_consistent_with_raw_reqs()):
                error_list = self._rebuild_ups_and_downs()
                if error_list:
                    for e in error_list:
                        errors.append(e)

            if not r.name.startswith(self.cfg['REQUIREMENT_PREFIX']):
                errors.append("invalid requirement prefix: %s" % r.name)

            if self.cfg['USER_REQ_TAG'] in r.name:
                assert(not r.upstream_reqs)  # should not be possible at all
                if not r.downstream_reqs:
                    errors.append(
                        "no system requirements for user requirement %s"
                        % r.name)
                else:
                    for dr_name in r.downstream_reqs:
                        if not self.is_sys_req(dr_name):
                            errors.append(
                                "%s: bad downstream requirement %s (must be "
                                "system requirement)" % (r.name, dr_name))
            elif self.cfg['SYS_REQ_TAG'] in r.name:
                if not r.upstream_reqs:
                    errors.append(
                        "no user requirements for system requirement %s"
                        % r.name)
                else:
                    for ur_name in r.upstream_reqs:
                        if not self.is_user_req(ur_name):
                            errors.append(
                                "%s: bad upstream requirement %s (must be "
                                "user requirement)" % (r.name, ur_name))
                if not r.downstream_reqs:
                    errors.append(
                        "no software requirements for system requirement %s"
                        % r.name)
                else:
                    for dr_name in r.downstream_reqs:
                        if not self.is_sw_req(dr_name):
                            errors.append(
                                "%s: bad downstream requirement %s (must be "
                                "software requirement)" % (r.name, dr_name))
            elif self.cfg['SW_REQ_TAG'] in r.name:
                assert(not r.downstream_reqs)  # nope out
                if not r.upstream_reqs:
                    errors.append(
                        "No system requirements for software requirement %s"
                        % r.name)
                else:
                    for ur_name in r.upstream_reqs:
                        if not self.is_sys_req(ur_name):
                            errors.append(
                                "%s: bad upstream requirement %s (must be "
                                "system requirement)" % (r.name, ur_name))
            else:
                errors.append(
                    "not recognized as a user, system or software "
                    "requirement name: %s" % r.name)

        return errors

    def read_requirements(self):
        ''' read a requirements file and construct set of
        Requirement objects for later checking '''
        try:
            rf = open(self.reqfile, 'rt')
        except Exception, e:
            raise
            print("Error: unable to open requirements at '%s'" % self.reqfile)
            print(e)
            sys.exit(1)
        content = rf.readlines()
        in_traceability = False
        last_req = None
        last_req_obj = None
        traceability = []
        for line in content:
            line = line.strip()
            if in_traceability:
                # in traceability continuation mode...
                assert(last_req)
                match_trace_cont = self.req_trace_cont_pattern.match(line)
                if match_trace_cont:
                    trace_group = match_trace_cont.group()
                    if trace_group:
                        for e in self.group_split(trace_group):
                            traceability.append(e)
                else:
                    # exit traceability collection mode
                    for derived_req in traceability:
                        assert(last_req_obj)
                        last_req_obj.add_raw_trace_req(derived_req)
                    in_traceability = False

            else:
                # not in a specific state
                # Requirement: ...
                match_req_pat = self.req_pattern.match(line)
                # Traceability: ...
                match_req_trace_pat = self.req_trace_pattern.match(line)
                if match_req_pat:
                    last_req = match_req_pat.group(1)
                    # requirement found
                    if not last_req.startswith(self.cfg['REQUIREMENT_PREFIX']):
                        print("Error: invalid requirement prefix for '%s' "
                              "(should begin with '%s')" % (
                                  last_req, self.cfg['REQUIREMENT_PREFIX']))
                        sys.exit(1)

                    if not self.find_requirement(last_req):
                        last_req_obj = Requirement(last_req)
                        self.requirements.add(last_req_obj)
                        traceability = []
                    else:
                        print("Error parsing requirements file: duplicate "
                              "requirement definition")
                        sys.exit(1)
                elif match_req_trace_pat:
                    ''' enter traceability collection mode '''
                    if not last_req:
                        print("Error: found traceability without requirement "
                              "while parsing requirements file")
                        sys.exit(1)
                    in_traceability = True
                    trace_group = match_req_trace_pat.group(1)
                    for e in self.group_split(trace_group):
                        traceability.append(e)

    def read_design(self):
        ''' read a design file and construct set of DesignElement objects
        for later checking.
        In the input file, all design elements must precede the tables
        that cross-reference requirements and design. '''
        try:
            df = open(self.desfile, 'rt')
        except Exception, e:
            raise
            print("Error: unable to open design at '%s'" % self.desfile)
            print(e)
            sys.exit(1)
        content = df.readlines()
        in_req_to_des = False
        in_des_to_req = False
        for line in content:
            line = line.strip()
            if in_req_to_des:
                match_req_to_des_cont = self.req_to_des_cont_pattern.match(
                    line)
                if match_req_to_des_cont:
                    req_group_split = self.group_split(
                        match_req_to_des_cont.group(1))
                    des_group_split = self.group_split(
                        match_req_to_des_cont.group(2))
                    if req_group_split:
                        pass
                    else:
                        print("Error: no requirement(s) found in requirement"
                              "->design table entry: '%s'" % line)
                        sys.exit(1)

                    if des_group_split:
                        pass
                    else:
                        print("Error: no design element(s) found in "
                              "requirement->design table entry: '%s'" % line)
                        sys.exit(1)
                    # add req->des links
                    for r in req_group_split:
                        if not r in [req.name for req in self.requirements]:
                            print("Error: unknown requirement '%s' found in "
                                  "requirement->design table" % r)
                        else:
                            r_obj = self.find_requirement(r)
                            for d in des_group_split:
                                if d not in r_obj.linked_design_elems:
                                    r_obj.add_design_elem(d)
                else:
                    ''' exit req->des collection mode, finalize data '''
                    if line.startswith("#") or line == '---':
                        # exiting...
                        in_req_to_des = False
            elif in_des_to_req:
                # in des_to_req continuation mode...
                match_des_to_req_cont = self.des_to_req_cont_pattern.match(
                    line)
                if match_des_to_req_cont:
                    des_group_split = self.group_split(
                        match_des_to_req_cont.group(1))
                    req_group_split = self.group_split(
                        match_des_to_req_cont.group(2))
                    if des_group_split:
                        pass
                    else:
                        print("Error: no design element(s) found in design->"
                              "requirement table entry: '%s'" % line)
                        sys.exit(1)

                    if req_group_split:
                        pass
                    else:
                        print("Error: no requirement(s) found in design->"
                              "requirement table entry: '%s'" % line)
                        sys.exit(1)

                    # add des->req links
                    for d in des_group_split:
                        if not d in [des.name for des in self.design_elements]:
                            print("Error: unknown design element '%s' "
                                  "found in design->requirement table" % d)
                        else:
                            d_obj = self.find_design_elem(d)
                            for r in req_group_split:
                                if r not in d_obj.linked_reqs:
                                    d_obj.add_reqs(r)
                else:
                    ''' exit des->req collection mode, finalize data '''
                    if line.startswith("#") or line == '---':
                        # exiting...
                        in_des_to_req = False

            # not in a specific state
            match_des_elem_intro_pat = self.des_elem_intro_pattern.match(
                line)  # Design element reference
            match_req_to_des_start_pat = self.req_to_des_start_pattern.match(
                line)
            match_des_to_req_start_pat = self.des_to_req_start_pattern.match(
                line)
            if match_des_elem_intro_pat:
                des_elem = match_des_elem_intro_pat.group(1)
                # design element reference found
                if not self.find_design_elem(des_elem):
                    des_elem_obj = DesignElement(des_elem)
                    self.design_elements.add(des_elem_obj)
                else:
                    print("Error in design file: duplicate design element "
                          "definition '%s'" % des_elem)
                    sys.exit(1)
            elif match_req_to_des_start_pat:
                ''' enter requirements->design start mode '''
                # entering requirements -> design section
                in_req_to_des = True
            elif match_des_to_req_start_pat:
                ''' enter design->requirements start mode '''
                # entering design -> requirements section
                in_des_to_req = True


if __name__ == "__main__":
    import doctest
    doctest.testmod()
