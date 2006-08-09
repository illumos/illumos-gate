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
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# The mid-level repository interfaces
#

function	_smf_refresh_instance_i
include		<libscf.h>
declaration	int _smf_refresh_instance_h(scf_instance_t *);
version		SUNWprivate_1.1
end

function	scf_simple_app_props_free
include		<libscf.h>
declaration	void scf_simple_app_props_free(scf_simple_app_props_t *);
version		SUNW_1.1
end

function	scf_simple_app_props_get
include		<libscf.h>
declaration	scf_simple_app_props_t *scf_simple_app_props_get(scf_handle_t *, const char *);
version		SUNW_1.1
end

function	scf_simple_app_props_next
include		<libscf.h>
declaration	const scf_simple_prop_t *scf_simple_app_props_next(const scf_simple_app_props_t *, scf_simple_prop_t *);
version		SUNW_1.1
end

function	scf_simple_app_props_search
include		<libscf.h>
declaration	const scf_simple_prop_t *scf_simple_app_props_search(const scf_simple_app_props_t *, const char *, const char *);
version		SUNW_1.1
end

function	scf_simple_prop_free
include		<libscf.h>
declaration	void scf_simple_prop_free(scf_simple_prop_t *);
version		SUNW_1.1
end

function	scf_simple_prop_get
include		<libscf.h>
declaration	scf_simple_prop_t *scf_simple_prop_get(scf_handle_t *, const char *, const char *, const char *);
version		SUNW_1.1
end

function	scf_simple_prop_name
include		<libscf.h>
declaration	char *scf_simple_prop_name(const scf_simple_prop_t *);
version		SUNW_1.1
end

function	scf_simple_prop_next_astring
include		<libscf.h>
declaration	char *scf_simple_prop_next_astring(scf_simple_prop_t *);
version		SUNW_1.1
end

function	scf_simple_prop_next_boolean
include		<libscf.h>
declaration	uint8_t *scf_simple_prop_next_boolean(scf_simple_prop_t *);
version		SUNW_1.1
end

function	scf_simple_prop_next_count
include		<libscf.h>
declaration	uint64_t *scf_simple_prop_next_count(scf_simple_prop_t *);
version		SUNW_1.1
end

function	scf_simple_prop_next_integer
include		<libscf.h>
declaration	int64_t *scf_simple_prop_next_integer(scf_simple_prop_t *);
version		SUNW_1.1
end

function	scf_simple_prop_next_opaque
include		<libscf.h>
declaration	void *scf_simple_prop_next_opaque(scf_simple_prop_t *, size_t *);
version		SUNW_1.1
end

function	scf_simple_prop_next_reset
include		<libscf.h>
declaration	void scf_simple_prop_next_reset(scf_simple_prop_t *);
version		SUNW_1.1
end

function	scf_simple_prop_next_time
include		<libscf.h>
declaration	int64_t *scf_simple_prop_next_time(scf_simple_prop_t *, int32_t *);
version		SUNW_1.1
end

function	scf_simple_prop_next_ustring
include		<libscf.h>
declaration	char *scf_simple_prop_next_ustring(scf_simple_prop_t *);
version		SUNW_1.1
end

function	scf_simple_prop_numvalues
include		<libscf.h>
declaration	ssize_t scf_simple_prop_numvalues(const scf_simple_prop_t *);
version		SUNW_1.1
end

function	scf_simple_prop_pgname
include		<libscf.h>
declaration	char *scf_simple_prop_pgname(const scf_simple_prop_t *);
version		SUNW_1.1
end

function	scf_simple_prop_type
include		<libscf.h>
declaration	scf_type_t scf_simple_prop_type(const scf_simple_prop_t *);
version		SUNW_1.1
end

function	scf_simple_walk_instances
include		<libscf.h>
declaration	int scf_simple_walk_instances(uint_t, void *, int (*inst_callback)(scf_handle_t *, scf_instance_t *, void *));
version		SUNW_1.1
end

function	smf_degrade_instance
include		<libscf.h>
declaration	int smf_degrade_instance(const char *, int);
version		SUNW_1.1
end

function	smf_disable_instance
include		<libscf.h>
declaration	int smf_disable_instance(const char *, int);
version		SUNW_1.1
end

function	smf_enable_instance
include		<libscf.h>
declaration	int smf_enable_instance(const char *, int);
version		SUNW_1.1
end

function	smf_get_state
include		<libscf.h>
declaration	char *smf_get_state(const char *);
version		SUNW_1.1
end

function	smf_maintain_instance
include		<libscf.h>
declaration	int smf_maintain_instance(const char *, int);
version		SUNW_1.1
end

function	smf_refresh_instance
include		<libscf.h>
declaration	int smf_refresh_instance(const char *);
version		SUNW_1.1
end

function	smf_restart_instance
include		<libscf.h>
declaration	int smf_restart_instance(const char *);
version		SUNW_1.1
end

function	smf_restore_instance
include		<libscf.h>
declaration	int smf_restore_instance(const char *);
version		SUNW_1.1
end
