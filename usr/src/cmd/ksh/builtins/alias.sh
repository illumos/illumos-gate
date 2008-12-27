#!/usr/bin/ksh93

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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

# Get name of builtin
builtin basename
typeset cmd="$(basename "$0")"

# If the requested command is not an alias load it explicitly
# to make sure it is not bound to a path (those built-ins which
# are mapped via shell aliases point to commands which are
# "special shell built-ins" which cannot be bound to a specific
# PATH element) - otherwise we may execute the wrong command
# if an executable with the same name sits in a PATH element
# before /usr/bin (e.g. /usr/xpg4/bin/ls would be executed
# before /usr/bin/ls if would look like
# PATH=/usr/xpg4/bin:/usr/bin).
if [[ "${cmd}" != ~(Elr)(alias|unalias|command) ]] && ! alias "${cmd}" >/dev/null 2>&1 ; then
	builtin "${cmd}"
fi

# command is a keyword and needs to be handled separately
if [[ "${cmd}" == "command" ]] ; then
	command "$@"
else
	"${cmd}" "$@"
fi
