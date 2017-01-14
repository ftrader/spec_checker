#!/usr/bin/env python
"""Classes for requirements, design elements and the checker itself"""

# TODO: ensure doctests are executed

import sys
import re

from spec_checker import util, requirement, designelement


class ErrorList(object):
    def __init__(self):
        self._err_list = []

    def append(self, item):
        if not item in self._err_list:
            self._err_list.append(item)

    def as_list(self):
        return self._err_list


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
    def _is_user_req(self, req_name):
        return util.is_user_req(req_name, self.cfg['REQUIREMENT_PREFIX']
                                + self.cfg['USER_REQ_TAG'])

    def _is_sys_req(self, req_name):
        return util.is_sys_req(req_name, self.cfg['REQUIREMENT_PREFIX']
                               + self.cfg['SYS_REQ_TAG'])

    def _is_sw_req(self, req_name):
        return util.is_sw_req(req_name, self.cfg['REQUIREMENT_PREFIX']
                              + self.cfg['SW_REQ_TAG'])

    # helper functions to determine upstream/downstream relations
    # purely according to naming conventions
    def _is_upstream(self, r1, r2):
        return util.is_upstream(r1, r2,
                                self.cfg['REQUIREMENT_PREFIX'] +
                                self.cfg['USER_REQ_TAG'],
                                self.cfg['REQUIREMENT_PREFIX'] +
                                self.cfg['SYS_REQ_TAG'],
                                self.cfg['REQUIREMENT_PREFIX'] +
                                self.cfg['SW_REQ_TAG'])

    def _is_downstream(self, r1, r2):
        return util.is_downstream(r1, r2,
                                  self.cfg['REQUIREMENT_PREFIX'] +
                                  self.cfg['USER_REQ_TAG'],
                                  self.cfg['REQUIREMENT_PREFIX'] +
                                  self.cfg['SYS_REQ_TAG'],
                                  self.cfg['REQUIREMENT_PREFIX'] +
                                  self.cfg['SW_REQ_TAG'])

    def _group_split(self, group):
        return util.group_split(group,
                                self.cfg['REQUIREMENT_PREFIX'],
                                self.cfg['DESIGN_PREFIX'])

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
        # collect errors, return empty list if all ok
        result = ErrorList()
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
                    if self._is_upstream(rr, r.name):
                        # rr considered upstream of r.name
                        if rr not in r.upstream_reqs:
                            r.upstream_reqs.append(rr)
                            # appended rr to upstream reqs of r.name
                    elif self._is_downstream(rr, r.name):
                        # rr is considered downstream of r.name
                        if rr not in r.downstream_reqs:
                            r.downstream_reqs.append(rr)
                            # appended rr to downstream reqs of r.name
                    else:
                        result.append(
                            "'%s' : traceability on same level: '%s'"
                            % (r.name, rr))
        return result.as_list()

    def check(self):
        ''' check traceability '''
        print("checking requirements file: %s" % self.reqfile)
        errors = self.check_requirements_consistency()
        if self.desfile:
            print("checking design file: %s" % self.desfile)
            errors += self.check_design_consistency()
        return errors

    def check_sw_reqs_have_des_elems(self):
        ''' check that each SW-req has associated design elem(s) '''
        errors = ErrorList()
        for r in self.requirements:
            if self._is_sw_req(r.name):
                referencing_elems = []
                for d in self.design_elements:
                    if d.is_linked_to_req(r.name):
                        referencing_elems.append(d)
                if not referencing_elems:
                    errors.append(
                        "software requirement '%s' has no associated "
                        "design element" % r.name)
        return errors.as_list()

    def check_all_des_elems_linked_to_sw_reqs(self):
        '''
        check that all design element(s) have linked SW-REQs
        and that only SW reqs are linked
        '''
        errors = ErrorList()
        for d in self.design_elements:
            if not d.linked_reqs:
                errors.append(
                    "design element '%s' is not linked to software "
                    "requirement(s)" % d.name)
            else:
                for lr in d.linked_reqs:
                    if not self._is_sw_req(lr):
                        errors.append(
                            "%s: linked requirement '%s' is not a "
                            "software requirement" % (d.name, lr))
                    if not self.find_requirement(lr):
                        errors.append(
                            "%s: linked requirement '%s' was not found"
                            % (d.name, lr))
        return errors.as_list()

    def check_design_consistency(self):
        ''' check consistency for design elements '''
        errors = ErrorList()
        # we definitely expect requirements for cross-reference purposes
        assert(self.requirements)
        if not self.design_elements:
            errors.append("No design elements found.")
        else:
            # check #1. check that each SW-req has associated design elem(s)
            for error in self.check_sw_reqs_have_des_elems():
                errors.append(error)

            # check #2. check that all design element(s) have linked SW-REQs
            # and that only SW reqs are linked
            for error in self.check_all_des_elems_linked_to_sw_reqs():
                errors.append(error)

            # check #3. TODO: consistency and completeness check between
            # req->des and des->req tables

            # check #4. TODO: well-formedness of all design element ids

        return errors.as_list()

    def check_user_req_linkage(self, req_obj):
        ''' checks linkage of a user requirement '''
        errors = ErrorList()
        if not req_obj.downstream_reqs:
            errors.append(
                "no system requirements for user requirement %s"
                % req_obj.name)
        else:
            for dr_name in req_obj.downstream_reqs:
                if not self._is_sys_req(dr_name):
                    errors.append(
                        "%s: bad downstream requirement %s (must be "
                        "system requirement)" % (req_obj.name, dr_name))
        return errors.as_list()

    def check_sys_req_linkage(self, req_obj):
        ''' checks linkage of a system requirement '''
        errors = ErrorList()
        if not req_obj.upstream_reqs:
            errors.append(
                "no user requirements for system requirement %s"
                % req_obj.name)
        else:
            for ur_name in req_obj.upstream_reqs:
                if not self._is_user_req(ur_name):
                    errors.append(
                        "%s: bad upstream requirement %s (must be "
                        "user requirement)" % (req_obj.name, ur_name))
        if not req_obj.downstream_reqs:
            errors.append(
                "no software requirements for system requirement %s"
                % req_obj.name)
        else:
            for dr_name in req_obj.downstream_reqs:
                if not self._is_sw_req(dr_name):
                    errors.append(
                        "%s: bad downstream requirement %s (must be "
                        "software requirement)" % (req_obj.name, dr_name))
        return errors.as_list()

    def check_sw_req_linkage(self, req_obj):
        ''' checks linkage of a software requirement '''
        errors = ErrorList()
        if not req_obj.upstream_reqs:
            errors.append(
                "No system requirements for software requirement %s"
                % req_obj.name)
        else:
            for ur_name in req_obj.upstream_reqs:
                if not self._is_sys_req(ur_name):
                    errors.append(
                        "%s: bad upstream requirement %s (must be "
                        "system requirement)" % (req_obj.name, ur_name))
        return errors.as_list()

    def check_requirement_linkage(self, req_name, req_obj=None):
        '''
        check whether a named requirement is adequately linked to up- and
        downstream requirements
        '''
        errors = ErrorList()
        if not req_obj:
            r = self.find_requirement(req_name)
        else:
            r = req_obj
        if self.cfg['USER_REQ_TAG'] in req_name:
            assert(not r.upstream_reqs)  # should not be possible at all
            for error in self.check_user_req_linkage(r):
                errors.append(error)
        elif self.cfg['SYS_REQ_TAG'] in req_name:
            for error in self.check_sys_req_linkage(r):
                errors.append(error)
        elif self.cfg['SW_REQ_TAG'] in req_name:
            assert(not r.downstream_reqs)
            for error in self.check_sw_req_linkage(r):
                errors.append(error)

        else:
            errors.append(
                "not recognized as a user, system or software "
                "requirement name: %s" % req_name)

        return errors.as_list()

    def check_requirements_consistency(self):
        ''' check consistency for requirements '''
        errors = ErrorList()
        if not self.requirements:
            errors.append("no valid requirements found.")

        for r in self.requirements:
            # go through the raw trace reqs and build upstream/downstream reqs
            if ((not r.upstream_reqs and not r.downstream_reqs) or
                    not r.are_ups_and_downs_consistent_with_raw_reqs()):
                error_list = self._rebuild_ups_and_downs()
                if error_list:
                    for e in error_list:
                        errors.append(e)

            if not r.name.startswith(self.cfg['REQUIREMENT_PREFIX']):
                errors.append("invalid requirement prefix: %s" % r.name)

            #  check that the requirement is properly linked up and down
            for error in self.check_requirement_linkage(r.name, r):
                errors.append(error)

        return errors.as_list()

    def read_requirements(self):
        ''' read a requirements file and construct set of
        Requirement objects for later checking '''
        try:
            rf = open(self.reqfile, 'rt')
        except Exception as e:
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
                        for e in self._group_split(trace_group):
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
                        last_req_obj = requirement.Requirement(last_req)
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
                    for e in self._group_split(trace_group):
                        traceability.append(e)

    def read_design(self):
        ''' read a design file and construct set of DesignElement objects
        for later checking.
        In the input file, all design elements must precede the tables
        that cross-reference requirements and design. '''
        try:
            df = open(self.desfile, 'rt')
        except Exception as e:
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
                    req_group_split = self._group_split(
                        match_req_to_des_cont.group(1))
                    des_group_split = self._group_split(
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
                    des_group_split = self._group_split(
                        match_des_to_req_cont.group(1))
                    req_group_split = self._group_split(
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
                    des_elem_obj = designelement.DesignElement(des_elem)
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
