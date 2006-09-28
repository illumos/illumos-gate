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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

# input file
PCIIDS_TXT=$1

[ ! -f $PCIIDS_TXT ] && exit 1

cat <<EOF
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file is auto-generated from the drm_pciids.txt in the DRM CVS
 * Please contact dri-devel@lists.sf.net to add new cards to this list
 */


EOF

cat $PCIIDS_TXT |grep -v '^#' | nawk '
{sub(/^\[/, "#defineSPACE")}
{sub(/\]/, "_PCI_IDS\\\\")}
{sub(/^0x/, "	{0x")}
{sub(/ +/, ",,")}
{sub(/ +/, ",,")}
{sub(/ +/, ",,")}
{sub(/\"/, ",,")}
{sub(/\"$/, "\"}, \\")}
{sub(/,,/, ", ")}
{sub(/,,/, ", ")}
{sub(/,,,,/, ", \"")}
{sub(/\\\\/, " \\")}
{sub(/^$/, "	{0, 0, 0, NULL}\nNEWLINE")}
{sub(/SPACE/, " ")}
{sub(/NEWLINE/, "")}
{print}
'

echo "	{0, 0, 0, NULL}"

