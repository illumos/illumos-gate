#!/usr/bin/ksh
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2026 Hans Rosenfeld
#

# This test exercises the 'dladm {create,show,delete}-vnic' commands and the
# underlying operations of libdladm and the vnic driver.
#
# The test repeatedly creates a vnic with various differing configurations,
# some of which are illegal and expected to fail. For those cases that are
# expected to succeed, the test verifies that the persistent and active
# configurations match what was created. Afterwards, the test  deletes the
# created vnic device and verifies it is no longer present in the active and
# the persistent configuration.


unalias -a
set -o pipefail
export LANG=C.UTF-8

dl_exit=0
dl_stub="UTILtest_stub$$"
dl_vnic="UTILtest_vnic$$"
dl_vrid="12"

dl_create="dladm create-vnic"
dl_delete="dladm delete-vnic"
dl_show="dladm show-vnic"

typeset -A dl_macs
dl_macs["random0"]="2:8:20"
dl_macs["random"]="2:8:20"
dl_macs["prefix"]="8:0:2b"
dl_macs["fixed"]="${dl_macs[prefix]}:12:34:56"
dl_macs["vrrp_inet"]=$(printf "0:0:5e:0:1:%x" ${dl_vrid})
dl_macs["vrrp_inet6"]=$(printf "0:0:5e:0:2:%x" ${dl_vrid})

typeset -A dl_vlan
dl_vlan["novlan"]="0"
dl_vlan["vlan"]="123"

typeset -A dl_configs
# "factory MACs" apparently exist only in nxge(4d), so we expect them to fail
dl_configs["fail_factory"]="-m factory -n 12"
dl_configs["fail_fixed"]="-m fixed"

dl_configs["fail_dup_m"]="-m random -m random"
dl_configs["fail_dup_n"]="-m factory -n 12 -n 12"
dl_configs["fail_dup_v"]="-v ${dl_vlan[vlan]} -v ${dl_vlan[vlan]}"

dl_configs["fail_no_m_r"]="-r ${dl_macs[prefix]}"
dl_configs["fail_no_m_r"]="-n 12"
dl_configs["fail_no_v_f"]="-f"
dl_configs["fail_no_VA"]="-m vrrp"
dl_configs["fail_no_V"]="-m vrrp -A inet"
dl_configs["fail_no_A"]="-m vrrp -V ${dl_vrid}"

dl_configs["fail_invalid_v_4095"]="-v 4095"
dl_configs["fail_invalid_v_12345"]="-v 12345"
dl_configs["fail_invalid_A"]="-m vrrp -V ${dl_vrid} -A unix"
dl_configs["fail_invalid_prefix"]="-m radnom -r ${dl_macs[fixed]}"


dl_configs["random0"]=
dl_configs["random"]="-m random"
dl_configs["prefix"]="-m random -r ${dl_macs[prefix]}"
dl_configs["fixed"]="-m ${dl_macs[fixed]}"
dl_configs["vrrp_inet"]="-m vrrp -V ${dl_vrid} -A inet"
dl_configs["vrrp_inet6"]="-m vrrp -V ${dl_vrid} -A inet6"

typeset -A dl_types
dl_types["random0"]="random"
dl_types["random"]="random"
dl_types["prefix"]="random"
dl_types["fixed"]="fixed"
dl_types["vrrp_inet"]="vrrp, ${dl_vrid}/inet"
dl_types["vrrp_inet6"]="vrrp, ${dl_vrid}/inet6"

typeset -A dl_extra_configs
dl_extra_configs["novlan"]=""
dl_extra_configs["vlan"]="-v ${dl_vlan[vlan]}"

fatal()
{
    typeset msg="$*"
    echo "TEST FAILED: $msg" >&2
    exit 1
}

warn()
{
    typeset msg="$*"
    echo "TEST FAILED: $msg" >&2
    dl_exit=1
}

cleanup()
{
    dladm delete-etherstub ${dl_stub} 2>/dev/null
}

setup()
{
    dladm create-etherstub ${dl_stub} || fatal "failed to create ${dl_stub}"
}

test_create()
{
    typeset conf="$1"
    typeset extra="$2"
    typeset args="$3"

    typeset config="${dl_configs[${conf}]} ${dl_extra_configs[${extra}]}"
    typeset create="${dl_create}"
    typeset out
    typeset ret

    [[ ! -z "${args}" ]] && create="${dl_create} ${args}"

    out=$(${create} -l ${dl_stub} ${config} ${dl_vnic} 2>&1)
    ret=$?

    if [[ "${conf:0:4}" == "fail" ]]; then
        if (( ret == 0 )); then
            warn "'${create}' [$conf, $extra] returned ${ret}"
        fi
        return ${ret}
    else
        if (( ret != 0 )); then
	    warn "'${create}' [$conf, $extra] returned ${ret}, " \
                 "error message:\n${out}"
        fi
        return ${ret}
    fi
}

compare()
{
    typeset cmd=$1
    typeset name=$2
    typeset val=$3
    typeset exp=$4

    if [[ "${val}" != "${exp}" ]]; then
        warn "'${cmd}' [$c, $e] returned wrong value for ${name}: '${val}'" \
            "(expected '${exp}')"
    fi
}

test_show()
{
    typeset conf="$1"
    typeset extra="$2"
    typeset args="$3"

    typeset show=${dl_show}
    typeset fields="link,over,macaddress,macaddrtype,vid"
    typeset out
    typeset ret

    [[ ! -z "${args}" ]] && show="${dl_show} ${args}"

    out=$(${show} -p -o ${fields} ${dl_vnic} 2>&1)
    ret=$?

    if (( ret != 0 )); then
	warn "'${show}' [${conf}, ${extra}] returned ${ret}, error message:\n" \
             "${out}"
        return
    fi

    if [[ -z "${out}" ]]; then
        warn "'${show}' [${conf}, ${extra}] output was empty"
        return
    fi

    typeset link
    typeset over
    typeset addr
    typeset type
    typeset vid

    echo "${out}" | IFS=":" read link over addr type vid

    compare "${show}" "link" "${link}" "${dl_vnic}"
    ret=$?
    [[ ${ret} != 0 ]] && return ${ret};

    compare "${show}" "over" "${over}" "${dl_stub}"
    ret=$?
    [[ ${ret} != 0 ]] && return ${ret};

    if [[ "${conf}" == "prefix" || "${dl_types[${conf}]}" == "random" ]]; then
        compare "${show}" "addr" "${addr:0:6}" "${dl_macs[${conf}]}"
        ret=$?
    else
        compare "${show}" "addr" "${addr}" "${dl_macs[${conf}]}"
        ret=$?
    fi
    [[ ${ret} != 0 ]] && return ${ret};

    compare "${show}" "type" "${type}" "${dl_types[${conf}]}"
    ret=$?
    [[ ${ret} != 0 ]] && return ${ret};

    compare "${show}" "vid" "${vid}" "${dl_vlan[${extra}]}"
    ret=$?

    return ${ret};
}

test_delete()
{
    typeset conf="$1"
    typeset extra="$2"
    typeset out
    typeset ret

    out=$(${dl_delete} ${dl_vnic} 2>&1)
    ret=$?

    if (( ret != 0 )); then
	warn "'${dl_delete}' [$conf, $extra] returned ${ret}, error message:\n" \
             "${out}"
        return
    fi

    out=$(${dl_show} -p -o link ${dl_vnic} 2>&1)
    ret=$?

    if (( ret == 0 )); then
	warn "'${dl_show}' after '${dl_delete}' [$conf, $extra] returned " \
             "${ret}, output:\n${out}"
        return
    fi

    out=$(${dl_show} -P -p -o link ${dl_vnic} 2>&1)
    ret=$?

    if (( ret == 0 )); then
	warn "'${dl_show} -P' after '${dl_delete}' [$conf, $extra] returned " \
             "${ret}, output:\n${out}"
        return
    fi
}

trap cleanup EXIT

setup
for c in "${!dl_configs[@]}"; do
    for e in "${!dl_extra_configs[@]}"; do
        test_create "$c" "$e"
        ret=$?
        [[ ${ret} != 0 ]] && break;

        test_show "$c" "$e"
        test_show "$c" "$e" "-P"
        test_delete "$c" "$e"
    done
done
cleanup

if (( dl_exit == 0 )); then
	printf "All tests passed successfully\n"
fi
exit $dl_exit
