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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2012 Milan Jurik. All rights reserved.
#

# This is a "lint tail" that removes all the
# uninteresting lines from our lint output.
# It's nawk because sed doesn't do (a|b).
# Also comments are easier here.

# There's no lintlib for krb5 yet (CR 6911968)
/: Warning: -lkrb5 not found/			{ next; }
/: Warning: library -lkrb5 not found/		{ next; }

# Kill noise from xti.h with _XOPEN_SOURCE vs not. (CR 6911717)
/: _xti_.* .E_INCONS_ARG_DECL2./		{ next; }
/: _xti_.* .E_INCONS_ARG_USED2./		{ next; }
/: _xti_.* .E_INCONS_VAL_TYPE_DECL2./		{ next; }

# This is third-party code we'd rather not "fix"
/\/spnego.c.* .E_STMT_NOT_REACHED./		{ next; }

# The mb_put/md_get functions are intentionally used both
# with and without return value checks.  Not a concern.
/: mb_put_.* .E_FUNC_RET_[A-Z]*_IGNOR/		{ next; }
/: md_get_.* .E_FUNC_RET_[A-Z]*_IGNOR/		{ next; }

# The rc_get* functions clear the out arg even on failure,
# so most callers don't need to check the return value.
/: rc_get[a-z]* .E_FUNC_RET_[A-Z]*_IGNOR/	{ next; }

# These have uninteresting return values, usually ignored.
/: (n|sm)b_ctx_readrcsection .E_FUNC_RET_[A-Z]*_IGNOR/	{ next; }
/: nls_str_(lower|upper) .E_FUNC_RET_[A-Z]*_IGNOR/	{ next; }
/: rc_(close|freesect) .E_FUNC_RET_[A-Z]*_IGNOR/	{ next; }

# Other functions for which we often ignore return values.
/: [a-z]*close .E_FUNC_RET_[A-Z]*_IGNOR/	{ next; }
/: [a-z]*flush .E_FUNC_RET_[A-Z]*_IGNOR/	{ next; }
/: [a-z]*printf .E_FUNC_RET_[A-Z]*_IGNOR/	{ next; }
/: mem(cpy|move|set) .E_FUNC_RET_[A-Z]*_IGNOR/	{ next; }
/: mutex_.* .E_FUNC_RET_[A-Z]*_IGNOR/		{ next; }
/: str[ln]?(cat|cpy) .E_FUNC_RET_[A-Z]*_IGNOR/	{ next; }

{ print; }
