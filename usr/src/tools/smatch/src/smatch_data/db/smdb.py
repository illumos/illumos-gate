#!/usr/bin/python

# Copyright (C) 2013 Oracle.
#
# Licensed under the Open Software License version 1.1

import sqlite3
import sys
import re
import subprocess

try:
    con = sqlite3.connect('smatch_db.sqlite')
except sqlite3.Error, e:
    print "Error %s:" % e.args[0]
    sys.exit(1)

def usage():
    print "%s" %(sys.argv[0])
    print "<function> - how a function is called"
    print "info <type> - how a function is called, filtered by type"
    print "return_states <function> - what a function returns"
    print "call_tree <function> - show the call tree"
    print "where <struct_type> <member> - where a struct member is set"
    print "type_size <struct_type> <member> - how a struct member is allocated"
    print "data_info <struct_type> <member> - information about a given data type"
    print "function_ptr <function> - which function pointers point to this"
    print "trace_param <function> <param> - trace where a parameter came from"
    print "find_tagged <function> <param> - find the source of a tagged value (arm64)"
    print "parse_warns_tagged <smatch_warns.txt> - parse warns file for summary of tagged issues (arm64)"
    print "locals <file> - print the local values in a file."
    sys.exit(1)

function_ptrs = []
searched_ptrs = []
def get_function_pointers_helper(func):
    cur = con.cursor()
    cur.execute("select distinct ptr from function_ptr where function = '%s';" %(func))
    for row in cur:
        ptr = row[0]
        if ptr in function_ptrs:
            continue
        function_ptrs.append(ptr)
        if not ptr in searched_ptrs:
            searched_ptrs.append(ptr)
            get_function_pointers_helper(ptr)

def get_function_pointers(func):
    global function_ptrs
    global searched_ptrs
    function_ptrs = [func]
    searched_ptrs = [func]
    get_function_pointers_helper(func)
    return function_ptrs

db_types = {   0: "INTERNAL",
             101: "PARAM_CLEARED",
             103: "PARAM_LIMIT",
             104: "PARAM_FILTER",
            1001: "PARAM_VALUE",
            1002: "BUF_SIZE",
            1004: "CAPPED_DATA",
            1005: "RETURN_VALUE",
            1006: "DEREFERENCE",
            1007: "RANGE_CAP",
            1008: "LOCK_HELD",
            1009: "LOCK_RELEASED",
            1010: "ABSOLUTE_LIMITS",
            1012: "PARAM_ADD",
            1013: "PARAM_FREED",
            1014: "DATA_SOURCE",
            1015: "FUZZY_MAX",
            1016: "STR_LEN",
            1017: "ARRAY_LEN",
            1018: "CAPABLE",
            1019: "NS_CAPABLE",
            1022: "TYPE_LINK",
            1023: "UNTRACKED_PARAM",
            1024: "CULL_PATH",
            1025: "PARAM_SET",
            1026: "PARAM_USED",
            1027: "BYTE_UNITS",
            1028: "COMPARE_LIMIT",
            1029: "PARAM_COMPARE",
            1030: "EXPECTS_TYPE",
            1031: "CONSTRAINT",
            1032: "PASSES_TYPE",
            1033: "CONSTRAINT_REQUIRED",
            1034: "BIT_INFO",
            1035: "NOSPEC",
            1036: "NOSPEC_WB",
            1037: "STMT_CNT",
            1038: "TERMINATED",
            1039: "SLEEP",
            1040: "NO_SLEEP_CNT",
            1041: "SMALLISH",
            1042: "FRESH_MTAG",

            8017: "USER_DATA",
            9017: "USER_DATA_SET",
            8018: "NO_OVERFLOW",
            8019: "NO_OVERFLOW_SIMPLE",
            8020: "LOCKED",
            8021: "UNLOCKED",
            8023: "ATOMIC_INC",
            8024: "ATOMIC_DEC",
};

def add_range(rl, min_val, max_val):
    check_next = 0
    done = 0
    ret = []
    idx = 0

    if len(rl) == 0:
        return [[min_val, max_val]]

    for idx in range(len(rl)):
        cur_min = rl[idx][0]
        cur_max = rl[idx][1]

        # we already merged the new range but we might need to change later
        # ranges if they over lap with more than one
        if check_next:
            # join with added range
            if max_val + 1 == cur_min:
                ret[len(ret) - 1][1] = cur_max
                done = 1
                break
            # don't overlap
            if max_val < cur_min:
                ret.append([cur_min, cur_max])
                done = 1
                break
            # partially overlap
            if max_val < cur_max:
                ret[len(ret) - 1][1] = cur_max
                done = 1
                break
            # completely overlap
            continue

        # join 2 ranges into one
        if max_val + 1 == cur_min:
            ret.append([min_val, cur_max])
            done = 1
            break
        # range is entirely below
        if max_val < cur_min:
            ret.append([min_val, max_val])
            ret.append([cur_min, cur_max])
            done = 1
            break
        # range is partially below
        if min_val < cur_min:
            if max_val <= cur_max:
                ret.append([min_val, cur_max])
                done = 1
                break
            else:
                ret.append([min_val, max_val])
                check_next = 1
                continue
        # range already included
        if max_val <= cur_max:
            ret.append([cur_min, cur_max])
            done = 1
            break;
        # range partially above
        if min_val <= cur_max:
            ret.append([cur_min, max_val])
            check_next = 1
            continue
        # join 2 ranges on the other side
        if min_val - 1 == cur_max:
            ret.append([cur_min, max_val])
            check_next = 1
            continue
        # range is above
        ret.append([cur_min, cur_max])

    if idx + 1 < len(rl):          # we hit a break statement
        ret = ret + rl[idx + 1:]
    elif done:                     # we hit a break on the last iteration
        pass
    elif not check_next:           # it's past the end of the rl
        ret.append([min_val, max_val])

    return ret;

def rl_union(rl1, rl2):
    ret = []
    for r in rl1:
        ret = add_range(ret, r[0], r[1])
    for r in rl2:
        ret = add_range(ret, r[0], r[1])

    if (rl1 or rl2) and not ret:
        print "bug: merging %s + %s gives empty" %(rl1, rl2)

    return ret

def txt_to_val(txt):
    if txt == "s64min":
        return -(2**63)
    elif txt == "s32min":
        return -(2**31)
    elif txt == "s16min":
        return -(2**15)
    elif txt == "s64max":
        return 2**63 - 1
    elif txt == "s32max":
        return 2**31 - 1
    elif txt == "s16max":
        return 2**15 - 1
    elif txt == "u64max":
        return 2**64 - 1
    elif txt == "ptr_max":
        return 2**64 - 1
    elif txt == "u32max":
        return 2**32 - 1
    elif txt == "u16max":
        return 2**16 - 1
    else:
        try:
            return int(txt)
        except ValueError:
            return 0

def val_to_txt(val):
    if val == -(2**63):
        return "s64min"
    elif val == -(2**31):
        return "s32min"
    elif val == -(2**15):
        return "s16min"
    elif val == 2**63 - 1:
        return "s64max"
    elif val == 2**31 - 1:
        return "s32max"
    elif val == 2**15 - 1:
        return "s16max"
    elif val == 2**64 - 1:
        return "u64max"
    elif val == 2**32 - 1:
        return "u32max"
    elif val == 2**16 - 1:
        return "u16max"
    elif val < 0:
        return "(%d)" %(val)
    else:
        return "%d" %(val)

def get_next_str(txt):
    val = ""
    parsed = 0

    if txt[0] == '(':
        parsed += 1
        for char in txt[1:]:
            if char == ')':
                break
            parsed += 1
        val = txt[1:parsed]
        parsed += 1
    elif txt[0] == 's' or txt[0] == 'u':
        parsed += 6
        val = txt[:parsed]
    else:
        if txt[0] == '-':
            parsed += 1
        for char in txt[parsed:]:
            if char == '-' or char == '[':
                break
            parsed += 1
        val = txt[:parsed]
    return [parsed, val]

def txt_to_rl(txt):
    if len(txt) == 0:
        return []

    ret = []
    pairs = txt.split(",")
    for pair in pairs:
        cnt, min_str = get_next_str(pair)
        if cnt == len(pair):
            max_str = min_str
        else:
            cnt, max_str = get_next_str(pair[cnt + 1:])
        min_val = txt_to_val(min_str)
        max_val = txt_to_val(max_str)
        ret.append([min_val, max_val])

#    Hm...  Smatch won't call INT_MAX s32max if the variable is unsigned.
#    if txt != rl_to_txt(ret):
#        print "bug: converting: text = %s rl = %s internal = %s" %(txt, rl_to_txt(ret), ret)

    return ret

def rl_to_txt(rl):
    ret = ""
    for idx in range(len(rl)):
        cur_min = rl[idx][0]
        cur_max = rl[idx][1]

        if idx != 0:
            ret += ","

        if cur_min == cur_max:
            ret += val_to_txt(cur_min)
        else:
            ret += val_to_txt(cur_min)
            ret += "-"
            ret += val_to_txt(cur_max)
    return ret

def type_to_str(type_int):

    t = int(type_int)
    if db_types.has_key(t):
        return db_types[t]
    return type_int

def type_to_int(type_string):
    for k in db_types.keys():
        if db_types[k] == type_string:
            return k
    return -1

def display_caller_info(printed, cur, param_names):
    for txt in cur:
        if not printed:
            print "file | caller | function | type | parameter | key | value |"
        printed = 1

        parameter = int(txt[6])
        key = txt[7]
        if len(param_names) and parameter in param_names:
            key = key.replace("$", param_names[parameter])

        print "%20s | %20s | %20s |" %(txt[0], txt[1], txt[2]),
        print " %10s |" %(type_to_str(txt[5])),
        print " %d | %s | %s" %(parameter, key, txt[8])
    return printed

def get_caller_info(filename, ptrs, my_type):
    cur = con.cursor()
    param_names = get_param_names(filename, func)
    printed = 0
    type_filter = ""
    if my_type != "":
        type_filter = "and type = %d" %(type_to_int(my_type))
    for ptr in ptrs:
        cur.execute("select * from caller_info where function = '%s' %s;" %(ptr, type_filter))
        printed = display_caller_info(printed, cur, param_names)

def print_caller_info(filename, func, my_type = ""):
    ptrs = get_function_pointers(func)
    get_caller_info(filename, ptrs, my_type)

def merge_values(param_names, vals, cur):
    for txt in cur:
        parameter = int(txt[0])
        name = txt[1]
        rl = txt_to_rl(txt[2])
        if parameter in param_names:
            name = name.replace("$", param_names[parameter])

        if not parameter in vals:
            vals[parameter] = {}

        # the first item on the list is the number of rows.  it's incremented
        # every time we call merge_values().
        if name in vals[parameter]:
            vals[parameter][name] = [vals[parameter][name][0] + 1, rl_union(vals[parameter][name][1], rl)]
        else:
            vals[parameter][name] = [1, rl]

def get_param_names(filename, func):
    cur = con.cursor()
    param_names = {}
    cur.execute("select parameter, value from parameter_name where file = '%s' and function = '%s';" %(filename, func))
    for txt in cur:
        parameter = int(txt[0])
        name = txt[1]
        param_names[parameter] = name
    if len(param_names):
        return param_names

    cur.execute("select parameter, value from parameter_name where function = '%s';" %(func))
    for txt in cur:
        parameter = int(txt[0])
        name = txt[1]
        param_names[parameter] = name
    return param_names

def get_caller_count(ptrs):
    cur = con.cursor()
    count = 0
    for ptr in ptrs:
        cur.execute("select count(distinct(call_id)) from caller_info where function = '%s';" %(ptr))
        for txt in cur:
            count += int(txt[0])
    return count

def print_merged_caller_values(filename, func, ptrs, param_names, call_cnt):
    cur = con.cursor()
    vals = {}
    for ptr in ptrs:
        cur.execute("select parameter, key, value from caller_info where function = '%s' and type = %d;" %(ptr, type_to_int("PARAM_VALUE")))
        merge_values(param_names, vals, cur);

    for param in sorted(vals):
        for name in sorted(vals[param]):
            if vals[param][name][0] != call_cnt:
                continue
            print "%d %s -> %s" %(param, name, rl_to_txt(vals[param][name][1]))


def print_unmerged_caller_values(filename, func, ptrs, param_names):
    cur = con.cursor()
    for ptr in ptrs:
        prev = -1
        cur.execute("select file, caller, call_id, parameter, key, value from caller_info where function = '%s' and type = %d;" %(ptr, type_to_int("PARAM_VALUE")))
        for filename, caller, call_id, parameter, name, value in cur:
            if prev != int(call_id):
                prev = int(call_id)

            parameter = int(parameter)
            if parameter < len(param_names):
                name = name.replace("$", param_names[parameter])
            else:
                name = name.replace("$", "$%d" %(parameter))

            print "%s | %s | %s | %s" %(filename, caller, name, value)
        print "=========================="

def print_caller_values(filename, func, ptrs):
    param_names = get_param_names(filename, func)
    call_cnt = get_caller_count(ptrs)

    print_merged_caller_values(filename, func, ptrs, param_names, call_cnt)
    print "=========================="
    print_unmerged_caller_values(filename, func, ptrs, param_names)

def caller_info_values(filename, func):
    ptrs = get_function_pointers(func)
    print_caller_values(filename, func, ptrs)

def print_return_states(func):
    cur = con.cursor()
    cur.execute("select * from return_states where function = '%s';" %(func))
    count = 0
    for txt in cur:
        printed = 1
        if count == 0:
            print "file | function | return_id | return_value | type | param | key | value |"
        count += 1
        print "%s | %s | %2s | %13s" %(txt[0], txt[1], txt[3], txt[4]),
        print "| %13s |" %(type_to_str(txt[6])),
        print " %2d | %20s | %20s |" %(txt[7], txt[8], txt[9])

def print_return_implies(func):
    cur = con.cursor()
    cur.execute("select * from return_implies where function = '%s';" %(func))
    count = 0
    for txt in cur:
        if not count:
            print "file | function | type | param | key | value |"
        count += 1
        print "%15s | %15s" %(txt[0], txt[1]),
        print "| %15s" %(type_to_str(txt[4])),
        print "| %3d | %s | %15s |" %(txt[5], txt[6], txt[7])

def print_type_size(struct_type, member):
    cur = con.cursor()
    cur.execute("select * from type_size where type like '(struct %s)->%s';" %(struct_type, member))
    print "type | size"
    for txt in cur:
        print "%-15s | %s" %(txt[0], txt[1])

    cur.execute("select * from function_type_size where type like '(struct %s)->%s';" %(struct_type, member))
    print "file | function | type | size"
    for txt in cur:
        print "%-15s | %-15s | %-15s | %s" %(txt[0], txt[1], txt[2], txt[3])

def print_data_info(struct_type, member):
    cur = con.cursor()
    cur.execute("select * from data_info where data like '(struct %s)->%s';" %(struct_type, member))
    print "file | data | type | value"
    for txt in cur:
        print "%-15s | %-15s | %-15s | %s" %(txt[0], txt[1], type_to_str(txt[2]), txt[3])

def print_fn_ptrs(func):
    ptrs = get_function_pointers(func)
    if not ptrs:
        return
    print "%s = " %(func),
    print(ptrs)

def print_functions(member):
    cur = con.cursor()
    cur.execute("select * from function_ptr where ptr like '%%->%s';" %(member))
    print "File | Pointer | Function | Static"
    for txt in cur:
        print "%-15s | %-15s | %-15s | %s" %(txt[0], txt[2], txt[1], txt[3])

def get_callers(func):
    ret = []
    cur = con.cursor()
    ptrs = get_function_pointers(func)
    for ptr in ptrs:
        cur.execute("select distinct caller from caller_info where function = '%s';" %(ptr))
        for row in cur:
            ret.append(row[0])
    return ret

printed_funcs = []
def call_tree_helper(func, indent = 0):
    global printed_funcs
    if func in printed_funcs:
        return
    print "%s%s()" %(" " * indent, func)
    if func == "too common":
        return
    if indent > 6:
        return
    printed_funcs.append(func)
    callers = get_callers(func)
    if len(callers) >= 20:
        print "Over 20 callers for %s()" %(func)
        return
    for caller in callers:
        call_tree_helper(caller, indent + 2)

def print_call_tree(func):
    global printed_funcs
    printed_funcs = []
    call_tree_helper(func)

def function_type_value(struct_type, member):
    cur = con.cursor()
    cur.execute("select * from function_type_value where type like '(struct %s)->%s';" %(struct_type, member))
    for txt in cur:
        print "%-30s | %-30s | %s | %s" %(txt[0], txt[1], txt[2], txt[3])

def rl_too_big(txt):
    rl = txt_to_rl(txt)
    ret = ""
    for idx in range(len(rl)):
        cur_max = rl[idx][1]
        if (cur_max > 0xFFFFFFFFFFFFFF):
            return 1

    return 0

def rl_has_min_untagged(txt):
    rl = txt_to_rl(txt)
    ret = ""
    for idx in range(len(rl)):
        cur_min = rl[idx][0]
        if (cur_min == 0xff80000000000000):
            return 1

    return 0

def rl_is_tagged(txt):
    if not rl_too_big(txt):
        return 0

    if rl_has_min_untagged(txt):
        return 0

    return 1

def rl_is_treat_untagged(txt):
    if "[u]" in txt:
        return 1;

    return 0

def parse_warns_tagged(filename):
    proc = subprocess.Popen(['cat %s | grep "potentially tagged" | sort | uniq' %(filename)], shell=True, stdout=subprocess.PIPE)
    while True:
        line = proc.stdout.readline()
        if not line:
            break

	linepos = re.search("([^\s]+)", line).group(1)
	groupre = re.search("potentially tagged address \(([^,]+), ([^,]+), ([^\)]+)\)", line)
	groupre.group(1)

	func = groupre.group(1)
	param = int(groupre.group(2))
	var = groupre.group(3)

	if ("end" in var or "size" in var or "len" in var):
		continue

	print "\n%s (func: %s, param: %d:%s) may be caused by:" %(linepos, func, param, var)

	if (param != -1):
		if not find_tagged(func, param, 0, []):
			print "    %s (param %d) (can't walk call tree)" % (func, param)
	else:
		print "    %s (variable %s (can't walk call tree)" % (func, var)

def find_tagged(func, param, caller_call_id, printed):

    callers = {}
    cur = con.cursor()
    ptrs = get_function_pointers(func)
    found = 0

    for ptr in ptrs:
        cur.execute("select call_id, value from caller_info where function = '%s' and parameter=%d and type=%d" %(ptr, param, type_to_int("DATA_SOURCE")))

        for row in cur:
            if (row[1][0] == '$'):
                if row[0] not in callers:
                    callers[row[0]] = {}
                callers[row[0]]["param"] = int(row[1][1])

    for ptr in ptrs:
        cur.execute("select caller, call_id, value from caller_info where function = '%s' and parameter=%d and type=%d" %(ptr, param, type_to_int("USER_DATA")))

        for row in cur:
            if not rl_is_tagged(row[2]):
                continue
	    if rl_is_treat_untagged(row[2]):
	        continue
            found = 1
            if row[1] not in callers:
                callers[row[1]] = {}
            if "param" not in callers[row[1]]:
                line = "    %s (param ?) -> %s (param %d)" % (row[0], func, param)
                if line not in printed:
                        printed.append(line)
                        print line
                continue
            if row[0] not in printed:
                printed.append(row[0])
                if not find_tagged(row[0], callers[row[1]]["param"], row[1], printed):
                    print "    %s (param %d)" % (row[0], param)

    return found

def trace_callers(func, param):
    sources = []
    prev_type = 0

    cur = con.cursor()
    ptrs = get_function_pointers(func)
    for ptr in ptrs:
        cur.execute("select type, caller, value from caller_info where function = '%s' and (type = 0 or type = 1014 or type = 1028) and (parameter = -1 or parameter = %d);" %(ptr, param))
        for row in cur:
            data_type = int(row[0])
            if data_type == 1014:
                sources.append((row[1], row[2]))
            elif data_type == 1028:
                sources.append(("%", row[2])) # hack...
            elif data_type == 0 and prev_type == 0:
                sources.append((row[1], ""))
            prev_type = data_type
    return sources

def trace_param_helper(func, param, indent = 0):
    global printed_funcs
    if func in printed_funcs:
        return
    print "%s%s(param %d)" %(" " * indent, func, param)
    if func == "too common":
        return
    if indent > 20:
        return
    printed_funcs.append(func)
    sources = trace_callers(func, param)
    for path in sources:

        if len(path[1]) and path[1][0] == '$':
            p = int(re.findall('\d+', path[1][1:])[0])
            trace_param_helper(path[0], p, indent + 2)
        elif len(path[0]) and path[0][0] == '%':
            print "  %s%s" %(" " * indent, path[1])
        else:
            print "* %s%s %s" %(" " * (indent - 1), path[0], path[1])

def trace_param(func, param):
    global printed_funcs
    printed_funcs = []
    print "tracing %s %d" %(func, param)
    trace_param_helper(func, param)

def print_locals(filename):
    cur = con.cursor()
    cur.execute("select file,data,value from data_info where file = '%s' and type = 8029 and value != 0;" %(filename))
    for txt in cur:
        print "%s | %s | %s" %(txt[0], txt[1], txt[2])

def constraint(struct_type, member):
    cur = con.cursor()
    cur.execute("select * from constraints_required where data like '(struct %s)->%s' or bound like '(struct %s)->%s';" %(struct_type, member, struct_type, member))
    for txt in cur:
        print "%-30s | %-30s | %s | %s" %(txt[0], txt[1], txt[2], txt[3])

if len(sys.argv) < 2:
    usage()

if len(sys.argv) == 2:
    func = sys.argv[1]
    print_caller_info("", func)
elif sys.argv[1] == "info":
    my_type = ""
    if len(sys.argv) == 4:
        my_type = sys.argv[3]
    func = sys.argv[2]
    print_caller_info("", func, my_type)
elif sys.argv[1] == "call_info":
    if len(sys.argv) != 4:
        usage()
    filename = sys.argv[2]
    func = sys.argv[3]
    caller_info_values(filename, func)
    print_caller_info(filename, func)
elif sys.argv[1] == "function_ptr" or sys.argv[1] == "fn_ptr":
    func = sys.argv[2]
    print_fn_ptrs(func)
elif sys.argv[1] == "return_states":
    func = sys.argv[2]
    print_return_states(func)
    print "================================================"
    print_return_implies(func)
elif sys.argv[1] == "return_implies":
    func = sys.argv[2]
    print_return_implies(func)
elif sys.argv[1] == "type_size" or sys.argv[1] == "buf_size":
    struct_type = sys.argv[2]
    member = sys.argv[3]
    print_type_size(struct_type, member)
elif sys.argv[1] == "data_info":
    struct_type = sys.argv[2]
    member = sys.argv[3]
    print_data_info(struct_type, member)
elif sys.argv[1] == "call_tree":
    func = sys.argv[2]
    print_call_tree(func)
elif sys.argv[1] == "find_tagged":
    func = sys.argv[2]
    param = int(sys.argv[3])
    find_tagged(func, param, 0, [])
elif sys.argv[1] == "parse_warns_tagged":
    filename = sys.argv[2]
    parse_warns_tagged(filename)
elif sys.argv[1] == "where":
    if len(sys.argv) == 3:
        struct_type = "%"
        member = sys.argv[2]
    elif len(sys.argv) == 4:
        struct_type = sys.argv[2]
        member = sys.argv[3]
    function_type_value(struct_type, member)
elif sys.argv[1] == "local":
    filename = sys.argv[2]
    variable = ""
    if len(sys.argv) == 4:
        variable = sys.argv[3]
    local_values(filename, variable)
elif sys.argv[1] == "functions":
    member = sys.argv[2]
    print_functions(member)
elif sys.argv[1] == "trace_param":
    if len(sys.argv) != 4:
        usage()
    func = sys.argv[2]
    param = int(sys.argv[3])
    trace_param(func, param)
elif sys.argv[1] == "locals":
    if len(sys.argv) != 3:
        usage()
    filename = sys.argv[2]
    print_locals(filename);
elif sys.argv[1] == "constraint":
    if len(sys.argv) == 3:
        struct_type = "%"
        member = sys.argv[2]
    elif len(sys.argv) == 4:
        struct_type = sys.argv[2]
        member = sys.argv[3]
    constraint(struct_type, member)
else:
    usage()
