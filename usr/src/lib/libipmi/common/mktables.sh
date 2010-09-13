#!/bin/sh

#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Construct translation tables for defines in libipmi.h to translate to readable
# strings.
#

if [ $# -ne 1 ]; then
	echo >&2 "USAGE: $0 <path to libimpi.h>"
	exit 1
fi

if [ -r $1 ]; then
	libipmi_h=$1
else
	echo >&2 "USAGE: $0 <path to libimpi.h>"
	echo >&2 "Make sure libipmi.h exists and is readable"
	exit 1
fi

echo "\
/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <libipmi.h>
#include <ipmi_impl.h>"

#
# Error table.
#
echo "
ipmi_name_trans_t ipmi_errno_table[] = {"

pattern="	\(EIPMI_[0-9A-Z_]*\)[^ \/]*\/\* \(.*\) \*\/$"
replace="	{ \1, \"\2\" },"

cat $libipmi_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

#
# Entity table.
#
echo "\nipmi_name_trans_t ipmi_entity_table[] = {"

pattern="#define	IPMI_ET_\([A-Z0-9_]*\).*\$"
replace="	{ IPMI_ET_\1, \"\1\" },"

cat $libipmi_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

#
# Sensor types.
#
echo "\nipmi_name_trans_t ipmi_sensor_type_table[] = {"

pattern="#define	IPMI_ST_\([A-Z0-9_]*\).*\$"
replace="	{ IPMI_ST_\1, \"\1\" },"

cat $libipmi_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

#
# Reading types.
#
echo "\nipmi_name_trans_t ipmi_reading_type_table[] = {"

pattern="#define	IPMI_RT_\([A-Z0-9_]*\).*\$"
replace="	{ IPMI_RT_\1, \"\1\" },"

cat $libipmi_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

#
# Units
#
echo "\nipmi_name_trans_t ipmi_units_type_table[] = {"

pattern="#define	IPMI_UNITS_\([A-Z0-9_]*\).*\$"
replace="	{ IPMI_UNITS_\1, \"\1\" },"

cat $libipmi_h | sed -n "s/$pattern/$replace/p" || exit 1

echo "\t{ 0, NULL }
};"

