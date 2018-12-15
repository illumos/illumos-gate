from collections import defaultdict
import copy
import json
import sys
import pprint

from constants import (
    GLOBAL_BLACKLIST,
    IMPL_DEP_FILE_STR,
    OUTPUT_FILE_STR,
    SYSCALL_PREFIXES,
    ListType,
    hardcode_syscall_read_fields,
    hardcode_syscall_write_fields,
)

class Parser(object):
    def __init__(
        self,
        impl_dep_file_str=IMPL_DEP_FILE_STR,
        output_file_str=OUTPUT_FILE_STR,
        verbose=False,
        pretty=False
    ):
        try:
            self.impl_dep_file = file(impl_dep_file_str, 'r')
            self.output_file = file(output_file_str + '.json', 'w+')
            if verbose:
                self.output_file_verbose = file(output_file_str + '_verbose.json', 'w+')
            if pretty:
                self.pretty_output_file = file(output_file_str + '.pretty', 'w+')
                self.pretty_output_file_verbose = file(output_file_str + '_verbose.pretty', 'w+')
        except IOError:
            sys.stderr.write("ERROR: Cannot open files %s %s.\n" % (impl_dep_file_str, output_file_str))
            sys.exit(1)
        self.verbose = verbose
        self.pretty = pretty
        self.syscall_read_fields = defaultdict(set)
        self.syscall_write_fields = defaultdict(set)
        self.implicit_dependencies = defaultdict(set)
        self.verbose_impl_dep = defaultdict(list)
        self.deref_counter = defaultdict(int)  # count which struct->members are most common

        for syscall,fields in hardcode_syscall_read_fields.iteritems():
            self.syscall_read_fields[syscall].update(set(fields))

        for syscall,fields in hardcode_syscall_write_fields.iteritems():
            self.syscall_write_fields[syscall].update(set(fields))

    def _sanitize_syscall(self, syscall):
        for prefix in SYSCALL_PREFIXES:
            if syscall.startswith(prefix):
                return syscall[len(prefix):]
        return syscall

    def _deref_to_tuple(self, deref):
        """ (struct a)->b ==> (a,b) """
        struct, member = deref.split('->')
        struct = struct[1:-1]  # strip parens
        struct = struct.split(' ')[1]  # drop struct keyword
        return (struct, member)

    def _split_field(self, field):
        field = field.strip()
        field = field[1: -1]  # strip square brackets
        derefs = [struct.strip() for struct in field.strip().split(',') if struct]
        return map(
            lambda deref: self._deref_to_tuple(deref),
            derefs
        )

    def _sanitize_line(self, line):
        syscall_and_listtype, field = line.split(':')
        syscall, list_type = syscall_and_listtype.split(' ')
        syscall = self._sanitize_syscall(syscall)
        derefs = self._split_field(field)
        return syscall, list_type, derefs

    def _add_fields(self, syscall, list_type, derefs):
        if list_type == ListType.READ:
            d = self.syscall_read_fields
        elif list_type == ListType.WRITE:
            d = self.syscall_write_fields
        for deref in derefs:
            if deref in GLOBAL_BLACKLIST:  # ignore spammy structs
                continue
            d[syscall].add(deref)

    def _construct_implicit_deps(self):
        """ just do a naive O(n^2) loop to see intersections between write_list and read_list """
        for this_call,read_fields in self.syscall_read_fields.iteritems():
            for that_call,write_fields in self.syscall_write_fields.iteritems():
                if that_call == this_call:  # calls are obviously dependent on themselves. ignore.
                    continue
                intersection = read_fields & write_fields
                if intersection:
                    self.implicit_dependencies[this_call].add(that_call)
                if intersection and self.verbose:
                    self.verbose_impl_dep[this_call].append({
                        'call': that_call,
                        'reason': intersection,
                    })
                    for deref in intersection:
                        self.deref_counter[deref] += 1

    def parse(self):
        for line in self.impl_dep_file:
            syscall, list_type, derefs = self._sanitize_line(line)
            self._add_fields(syscall, list_type, derefs)
        # pprint.pprint(dict(self.syscall_write_fields))
        # pprint.pprint(dict(self.syscall_read_fields))
        self._construct_implicit_deps()
        # pprint.pprint(dict(self.implicit_dependencies))
        # pprint.pprint(dict(self.verbose_impl_dep))

    def _listify_verbose_reason(self, reason):
        r = copy.deepcopy(reason)
        r['reason'] = list(r['reason'])
        r['reason'] = map(
            lambda (struct,field): struct + '->' + field,
            r['reason']
        )
        return r

    def _get_json_dependencies(self):
        implicit_dependencies = {}
        verbose_impl_dep = {}
        for call, dep_set in self.implicit_dependencies.iteritems():
            implicit_dependencies[call] = list(dep_set)
        for call, call_reasons in self.verbose_impl_dep.iteritems():
            verbose_impl_dep[call] = map(
                lambda reason: self._listify_verbose_reason(reason),
                call_reasons,
            )
        return implicit_dependencies, verbose_impl_dep

    def write(self):
        implicit_dependencies, verbose_impl_dep = self._get_json_dependencies()
        json.dump(implicit_dependencies, self.output_file)
        if self.verbose:
            json.dump(verbose_impl_dep, self.output_file_verbose)
        if self.pretty:
            pprint.pprint(dict(self.implicit_dependencies), self.pretty_output_file)
            pprint.pprint(dict(self.verbose_impl_dep), self.pretty_output_file_verbose)
        for deref, count in sorted(self.deref_counter.iteritems(), key=lambda (k,v): (v,k)):
            print "%s: %d" % (deref, count)

    def close(self):
        self.output_file.close()
        self.impl_dep_file.close()
        if self.verbose:
            self.output_file_verbose.close()
