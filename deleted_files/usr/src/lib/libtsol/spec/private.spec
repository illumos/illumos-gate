#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#	Project Private to the Trusted eXtensions project.
#	Not for public consumption or to be documented.
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
# ident	"%Z%%M%	%I%	%E% SMI"
#

function	bclearhigh
include		<tsol/label.h>
declaration	void bclearhigh(bclear_t *clearance);
version		SUNWprivate_1.1
end

function	bclearlow
include		<tsol/label.h>
declaration	void bclearlow(bclear_t *clearance);
version		SUNWprivate_1.1
end

function	bcleartos
include		<tsol/label.h>
declaration	ssize_t bcleartos(const bclear_t *clearance, char **string, \
		    size_t str_len, int flags);
version		SUNWprivate_1.1
end

function	bclearundef
include		<tsol/label.h>
declaration	void bclearundef(bclear_t *clearance);
version		SUNWprivate_1.1
end

function	bclearvalid
include		<tsol/label.h>
declaration	int bclearvalid(const bclear_t *clearance);
version		SUNWprivate_1.1
end

function	bclearcvtfull
include		<tsol/label.h>
declaration	int bclearcvtfull(const bclear_t *clearance, \
		    const blrange_t *bounds, int flags, char **string, \
		    char **long_words[], char **short_words[], \
		    char *display[], int *first_compartment, \
		    int *display_size);
version		SUNWprivate_1.1
end

function	bclearcvt
include		<tsol/label.h>
declaration	int bclearcvt(const bclear_t *clearance, int flags, \
		    char **string, char *display[]);
version		SUNWprivate_1.1
end

function	blinrange
include		<tsol/label.h>
declaration	int blinrange(const blevel_t *label, const blrange_t *range);
version		SUNWprivate_1.1
end

function	blinset
include		<tsol/label.h>
declaration	int blinset(const bslabel_t *label, const set_id *id);
version		SUNWprivate_1.1
end

function	blmaximum
include		<tsol/label.h>
declaration	void blmaximum(blevel_t *label1, const blevel_t *label2);
version		SUNWprivate_1.1
end

function	blminimum
include		<tsol/label.h>
declaration	void blminimum(blevel_t *label1, const blevel_t *label2);
version		SUNWprivate_1.1
end

function	bltype
include		<tsol/label.h>
declaration	int bltype(const void *label, uint8_t type);
version		SUNWprivate_1.1
end

function	bslcvtfull
include		<tsol/label.h>
declaration	int bslcvtfull(const bslabel_t *label,
		    const blrange_t *bounds, \
		    int flags, char **string, char **long_words[], \
		    char **short_words[], char *display[], \
		    int *first_compartment, int *display_size);
version		SUNWprivate_1.1
end

function	bslcvt
include		<tsol/label.h>
declaration	int bslcvt(const bslabel_t *label, int flags, char **string, \
		    char *display[]);
version		SUNWprivate_1.1
end

function	bslhigh
include		<tsol/label.h>
declaration	void bslhigh(bslabel_t *label);
version		SUNWprivate_1.1
end

function	bsllow
include		<tsol/label.h>
declaration	void bsllow(bslabel_t *label);
version		SUNWprivate_1.1
end

function	bslundef
include		<tsol/label.h>
declaration	void bslundef(bslabel_t *label);
version		SUNWprivate_1.1
end

function	bslvalid
include		<tsol/label.h>
declaration	int bslvalid(const bslabel_t *label);
version		SUNWprivate_1.1
end

function	labelinfo
include		<tsol/label.h>
declaration	int labelinfo(struct label_info *info);
version		SUNWprivate_1.1
end

function	labelfields
include		<tsol/label.h>
declaration	int labelfields(struct name_fields *fields);
version		SUNWprivate_1.1
end

function	labelvers
include		<tsol/label.h>
declaration	ssize_t labelvers(char **version, int len);
version		SUNWprivate_1.1
end

function	getpathbylabel
include		<tsol/label.h>
declaration	char *getpathbylabel(const char *path_name, \
		    char *resolved_path, size_t bufsize, const bslabel_t *sl);
version		SUNWprivate_1.1
end

function	getlabelbypath
include		<tsol/label.h>
declaration	m_label_t *getlabelbypath(char *path);
version		SUNWprivate_1.1
end

function	blabel_alloc
include		<tsol/label.h>
declaration	blevel_t *blabel_alloc(void);
version		SUNWprivate_1.1
end

function	blabel_free
include		<tsol/label.h>
declaration	void blabel_free(blevel_t *label_p);
version		SUNWprivate_1.1
end

function	blabel_size
include		<tsol/label.h>
declaration	size_t blabel_size(void);
version		SUNWprivate_1.1
end

function	setbltype
include		<tsol/label.h>
declaration	void setbltype(void *label, uint8_t type);
version		SUNWprivate_1.1
end

function	bisinvalid
include		<tsol/label.h>
declaration	boolean_t bisinvalid(const void *label);
version		SUNWprivate_1.1
end

function	set_effective_priv
include		<tsol/label.h>
declaration	int set_effective_priv(priv_op_t op, int num_priv, ...);
version		SUNWprivate_1.1
end

function	set_inheritable_priv
include		<tsol/label.h>
declaration	int set_inheritable_priv(priv_op_t op, int num_priv, ...);
version		SUNWprivate_1.1
end

function	set_permitted_priv
include		<tsol/label.h>
declaration	int set_permitted_priv(priv_op_t op, int num_priv, ...);
version		SUNWprivate_1.1
end

function	userdefs
include		<tsol/label.h>
declaration	int userdefs(bslabel_t *sl, bclear_t *clear);
version		SUNWprivate_1.1
end

function	zonecopy
include		<tsol/label.h>
declaration	int zonecopy(bslabel_t *src_win_sl, char *remote_dir, \
		    char *filename, char *local_dir, int transfer_mode);
version		SUNWprivate_1.1
end
