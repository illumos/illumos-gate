#!/bin/sh

#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#
# Copyright 2001, 2002, 2003 by the Massachusetts Institute of Technology.
# All Rights Reserved.
#
# Export of this software from the United States of America may
#   require a specific license from the United States Government.
#   It is the responsibility of any person or organization contemplating
#   export to obtain such a license before exporting.
# 
# WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
# distribute this software and its documentation for any purpose and
# without fee is hereby granted, provided that the above copyright
# notice appear in all copies and that both that copyright notice and
# this permission notice appear in supporting documentation, and that
# the name of M.I.T. not be used in advertising or publicity pertaining
# to distribution of the software without specific, written prior
# permission.  Furthermore if you modify this software you must label
# your software as modified software and not distribute it in such a
# fashion that it might be confused with the original M.I.T. software.
# M.I.T. makes no representations about the suitability of
# this software for any purpose.  It is provided "as is" without express
# or implied warranty.
# 
#

# Configurable parameters set by autoconf
version_string="Solaris Kerberos (based on MIT Kerberos 5 release 1.6.3)"

prefix=/usr
exec_prefix=${prefix}
includedir=${prefix}/include/kerberosv5
libdir=${exec_prefix}/lib

# Defaults for program
library=krb5

# Some constants
vendor_string="Sun Microsystems, Inc."

# Process arguments
# Yes, we are sloppy, library specifications can come before options
while test $# != 0; do
    case $1 in
	--all)
	    do_all=1
	    ;;
	--cflags)
	    do_cflags=1
	    ;;
	--deps)
	    do_deps=1
	    ;;
	--exec-prefix)
	    do_exec_prefix=1
	    ;;
	--help)
	    do_help=1
	    ;;
	--libs)
	    do_libs=1
	    ;;
	--prefix)
	    do_prefix=1
	    ;;
	--vendor)
	    do_vendor=1
	    ;;
	--version)
	    do_version=1
	    ;;
	krb5)
	    library=krb5
	    ;;
	gssapi)
	    library=gssapi
	    ;;
	*)
	    echo "$0: Unknown option \`$1' -- use \`--help' for usage"
	    exit 1
    esac
    shift
done

# If required options - provide help
if test -z "$do_all" -a -z "$do_version" -a -z "$do_vendor" -a -z "$do_prefix" -a -z "$do_vendor" -a -z "$do_exec_prefix" -a -z "$do_cflags" -a -z "$do_libs"; then
    do_help=1
fi


if test -n "$do_help"; then
    echo "Usage: $0 [OPTIONS] [LIBRARIES]"
    echo "Options:"
    echo "        [--help]          Help"
    echo "        [--all]           Display version, vendor, and various values"
    echo "        [--version]       Version information"
    echo "        [--vendor]        Vendor information"
    echo "        [--prefix]        Kerberos installed prefix"
    echo "        [--exec-prefix]   Kerberos installed exec_prefix"
    echo "        [--cflags]        Compile time CFLAGS"
    echo "        [--libs]          List libraries required to link [LIBRARIES]"
    echo "Libraries:"
    echo "        krb5              Kerberos 5 application"
    echo "        gssapi            GSSAPI application"
 
    exit 0
fi

if test -n "$do_all"; then
    all_exit=
    do_version=1
    do_prefix=1
    do_exec_prefix=1
    do_vendor=1
    title_version="Version:     "
    title_prefix="Prefix:      "
    title_exec_prefix="Exec_prefix: "
    title_vendor="Vendor:      "
else
    all_exit="exit 0"
fi

if test -n "$do_version"; then
    echo "$title_version$version_string"
    $all_exit
fi

if test -n "$do_vendor"; then
    echo "$title_vendor$vendor_string"
    $all_exit
fi

if test -n "$do_prefix"; then
    echo "$title_prefix$prefix"
    $all_exit
fi

if test -n "$do_exec_prefix"; then
    echo "$title_exec_prefix$exec_prefix"
    $all_exit
fi

if test -n "$do_cflags"; then
    echo "-I${includedir}"
fi

if test -n "$do_libs"; then
    lib_flags="-L$libdir"

    if test $library = 'gssapi'; then
       lib_flags="$lib_flags -lgss"
       library=krb5
    fi

    if test $library = 'krb5'; then
       lib_flags="$lib_flags -lkrb5"
    fi

    echo "$lib_flags"
fi

exit 0
