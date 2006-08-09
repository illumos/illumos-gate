#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libdhcpagent/spec/dhcputil.spec

function        dhcpmsg
include         <dhcpmsg.h>
declaration     void dhcpmsg(int level, const char *format, ...)
version         SUNWprivate_1.1
end

function        dhcpmsg_init
include         <dhcpmsg.h>
declaration     void dhcpmsg_init(const char *program_name, boolean_t	\
		    is_daemon, boolean_t is_verbose, int debugging_level)
version         SUNWprivate_1.1
end

function        dhcpmsg_fini
include         <dhcpmsg.h>
declaration     void dhcpmsg_fini(void)
version         SUNWprivate_1.1
end

function        inittab_load
include         <dhcp_inittab.h>
declaration     dhcp_symbol_t *inittab_load(uchar_t categories, char	\
		   consumer, size_t *n_entries)
version         SUNWprivate_1.1
end

function        inittab_getbyname
include         <dhcp_inittab.h>
declaration     dhcp_symbol_t *inittab_getbyname(uchar_t categories,	\
		    char consumer, const char *name)
version         SUNWprivate_1.1
end

function        inittab_getbycode
include         <dhcp_inittab.h>
declaration     dhcp_symbol_t *inittab_getbycode(uchar_t categories,	\
		    char consumer, uint16_t code)
version         SUNWprivate_1.1
end

function        inittab_verify
include         <dhcp_inittab.h>
declaration     int inittab_verify(dhcp_symbol_t *inittab_entry,	\
		    dhcp_symbol_t *internal_entry)
version         SUNWprivate_1.1
end

function        inittab_encode
include         <dhcp_inittab.h>
declaration     uchar_t *inittab_encode(dhcp_symbol_t *inittab_entry,	\
		    const char *value, uint16_t *lengthp, boolean_t	\
		    just_payload)
version         SUNWprivate_1.1
end

function        inittab_decode
include         <dhcp_inittab.h>
declaration     char *inittab_decode(dhcp_symbol_t *inittab_entry,	\
		    uchar_t *payload, uint16_t length, boolean_t	\
		    just_payload)
version         SUNWprivate_1.1
end

function        inittab_encode_e
include         <dhcp_inittab.h>
declaration     uchar_t *inittab_encode_e(dhcp_symbol_t *inittab_entry, \
		    const char *value, uint16_t *lengthp, boolean_t	\
		    just_payload, int *ierrnop)
version         SUNWprivate_1.1
end

function        inittab_decode_e
include         <dhcp_inittab.h>
declaration     char *inittab_decode_e(dhcp_symbol_t *inittab_entry,	\
		    uchar_t *payload, uint16_t length, boolean_t	\
		    just_payload, int *ierrno)
version         SUNWprivate_1.1
end

function        inittab_type_to_size
include         <dhcp_inittab.h>
declaration     uint8_t inittab_type_to_size(dhcp_symbol_t *inittab_entry)
version         SUNWprivate_1.1
end

function        dsym_close_parser
include         <dhcp_symbol.h>
declaration     void dsym_close_parser(char **fields, dhcp_symbol_t *sym)
version         SUNWprivate_1.1
end

function        dsym_free_classes
include         <dhcp_symbol.h>
declaration     void dsym_free_classes(dhcp_classes_t *classes)
version         SUNWprivate_1.1
end

function        dsym_free_fields
include         <dhcp_symbol.h>
declaration     void dsym_free_fields(char **fields)
version         SUNWprivate_1.1
end

function        dsym_init_parser
include         <dhcp_symbol.h>
declaration     dsym_errcode_t dsym_init_parser(const char * name, \
		    const char *value, char ***fields_ret, dhcp_symbol_t *sym)
version         SUNWprivate_1.1
end

function        dsym_parse_field
include         <dhcp_symbol.h>
declaration     dsym_errcode_t dsym_parse_field(int field_num, \
		    char **fields, dhcp_symbol_t *sym)
version         SUNWprivate_1.1
end

function        dsym_parser
include         <dhcp_symbol.h>
declaration     dsym_errcode_t dsym_parser(char **fields, dhcp_symbol_t *sym, \
		    int *lastField, boolean_t bestEffort)
version         SUNWprivate_1.1
end

function        dsym_get_cat_id
include         <dhcp_symbol.h>
declaration     dsym_errcode_t dsym_get_cat_id(const char *cat, \
		    dsym_category_t *id, boolean_t cs)
version         SUNWprivate_1.1
end

function        dsym_get_code_ranges
include         <dhcp_symbol.h>
declaration     dsym_errcode_t dsym_get_code_ranges(const char *cat, \
		    ushort_t *min, ushort_t *max, boolean_t cs)
version         SUNWprivate_1.1
end

function        dsym_get_type_id
include         <dhcp_symbol.h>
declaration     dsym_errcode_t dsym_get_type_id(const char *type, \
		    dsym_cdtype_t *id, boolean_t cs)
version         SUNWprivate_1.1
end

function	dhcp_options_scan
include		<dhcp_impl.h>
declaration	int dhcp_options_scan(PKT_LIST *pl, boolean_t scan_vendor)
version		SUNWprivate_1.2
end
