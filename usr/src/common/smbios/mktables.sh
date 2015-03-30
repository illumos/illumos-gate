#!/bin/sh
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2015 OmniTI Computer Consulting, Inc.  All rights reserved.
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# The SMBIOS interfaces defined in <sys/smbios.h> include a set of integer-to-
# string conversion routines for the various constants defined in the SMBIOS
# spec.  These functions are used by smbios(1M) and prtdiag(1M) and can be
# leveraged by other clients as well.  To simplify maintenance of the source
# base, this shell script automatically generates the source code for all of
# these functions from the <sys/smbios.h> header file and its comments.  Each
# set of constants should be given a unique #define prefix, listed in the
# tables below.  The smbios_*_name() functions return the identifier of the
# cpp define, and the smbios_*_desc() functions return the text of the comment.
#

name_funcs='
SMB_BBFL_	smbios_bboard_flag_name		uint_t
SMB_BIOSFL_	smbios_bios_flag_name		uint64_t
SMB_BIOSXB1_	smbios_bios_xb1_name		uint_t
SMB_BIOSXB2_	smbios_bios_xb2_name		uint_t
SMB_CAT_	smbios_cache_ctype_name		uint_t
SMB_CAF_	smbios_cache_flag_name		uint_t
SMB_EVFL_	smbios_evlog_flag_name		uint_t
SMB_IPMI_F_	smbios_ipmi_flag_name		uint_t
SMB_MDF_	smbios_memdevice_flag_name	uint_t
SMB_PRC_	smbios_processor_core_flag_name	uint_t
SMB_TYPE_ 	smbios_type_name		uint_t
SMB_SLCH1_	smbios_slot_ch1_name		uint_t
SMB_SLCH2_	smbios_slot_ch2_name		uint_t
'

desc_funcs='
SMB_BBFL_	smbios_bboard_flag_desc		uint_t
SMB_BBT_	smbios_bboard_type_desc		uint_t
SMB_BIOSFL_	smbios_bios_flag_desc		uint64_t
SMB_BIOSXB1_	smbios_bios_xb1_desc		uint_t
SMB_BIOSXB2_	smbios_bios_xb2_desc		uint_t
SMB_BOOT_	smbios_boot_desc		uint_t
SMB_CAA_	smbios_cache_assoc_desc		uint_t
SMB_CAT_	smbios_cache_ctype_desc		uint_t
SMB_CAE_	smbios_cache_ecc_desc		uint_t
SMB_CAF_	smbios_cache_flag_desc		uint_t
SMB_CAL_	smbios_cache_loc_desc		uint_t
SMB_CAG_	smbios_cache_logical_desc	uint_t
SMB_CAM_	smbios_cache_mode_desc		uint_t
SMB_CHST_	smbios_chassis_state_desc	uint_t
SMB_CHT_	smbios_chassis_type_desc	uint_t
SMB_EVFL_	smbios_evlog_flag_desc		uint_t
SMB_EVHF_	smbios_evlog_format_desc	uint_t
SMB_EVM_	smbios_evlog_method_desc	uint_t
SMB_HWSEC_PS_	smbios_hwsec_desc		uint_t
SMB_IPMI_F_	smbios_ipmi_flag_desc		uint_t
SMB_IPMI_T_	smbios_ipmi_type_desc		uint_t
SMB_MAL_	smbios_memarray_loc_desc	uint_t
SMB_MAU_	smbios_memarray_use_desc	uint_t
SMB_MAE_	smbios_memarray_ecc_desc	uint_t
SMB_MDF_	smbios_memdevice_flag_desc	uint_t
SMB_MDFF_	smbios_memdevice_form_desc	uint_t
SMB_MDT_	smbios_memdevice_type_desc	uint_t
SMB_MDR_	smbios_memdevice_rank_desc	uint_t
SMB_POC_	smbios_port_conn_desc		uint_t
SMB_POT_	smbios_port_type_desc		uint_t
SMB_PRC_	smbios_processor_core_flag_desc	uint_t
SMB_PRF_	smbios_processor_family_desc	uint_t
SMB_PRS_	smbios_processor_status_desc	uint_t
SMB_PRT_	smbios_processor_type_desc	uint_t
SMB_PRU_	smbios_processor_upgrade_desc	uint_t
SMB_SLCH1_	smbios_slot_ch1_desc		uint_t
SMB_SLCH2_	smbios_slot_ch2_desc		uint_t
SMB_SLL_	smbios_slot_length_desc		uint_t
SMB_SLT_	smbios_slot_type_desc		uint_t
SMB_SLU_	smbios_slot_usage_desc		uint_t
SMB_SLW_	smbios_slot_width_desc		uint_t
SMB_TYPE_ 	smbios_type_desc		uint_t
SMB_WAKEUP_	smbios_system_wakeup_desc	uint_t
'

if [ $# -ne 1 ]; then
	echo "Usage: $0 file.h > file.c" >&2
	exit 2
fi

echo "\
/*\n\
 * Copyright 2015 OmniTI Computer Consulting, Inc.  All rights reserved.\n\
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.\n\
 * Use is subject to license terms.\n\
 */\n\
\n\
#include <smbios.h>"

echo "$name_funcs" | while read p name type; do
	[ -z "$p" ] && continue
	pattern="^#define[	 ]\($p[A-Za-z0-9_]*\)[	 ]*[A-Z0-9]*.*$"
	replace='	case \1: return ("\1");'

	echo "\nconst char *\n$name($type x)\n{\n\tswitch (x) {"
	sed -n "s@$pattern@$replace@p" < $1 || exit 1
	echo "\t}\n\treturn (NULL);\n}"
done

#
# Generate the description functions based on the comment next to a #define.
# The transformations for descriptive comments are slightly more complicated
# than those used for the identifier->name functions above:
#
# (1) strip any [RO] suffix from the comment (a header file convention)
# (2) replace any " with \" so it is escaped for the final output string
# (3) replace return (...); with return ("..."); to finish the code
#
echo "$desc_funcs" | while read p name type; do
	[ -z "$p" ] && continue
	pattern="^#define[	 ]\($p[A-Za-z0-9_]*\)[	 ]*.*/\\* \(.*\) \\*/$"
	replace='	case \1: return (\2);'

	echo "\nconst char *\n$name($type x)\n{\n\tswitch (x) {"
	sed -n "s@$pattern@$replace@p" < $1 | sed 's/ ([RO]))/)/' | \
	    sed 's/"/\\"/g' | sed 's/(/("/;s/);$/");/' || exit 1
	echo "\t}\n\treturn (NULL);\n}"
done

exit 0
