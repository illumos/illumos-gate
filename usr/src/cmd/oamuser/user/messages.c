/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 2013 Gary Mills
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

char *errmsgs[] = {
	"WARNING: uid %ld is reserved.\n",
	"WARNING: more than NGROUPS_MAX(%d) groups specified.\n",
	"ERROR: invalid syntax.\n"
	    "usage:  useradd [-u uid [-o] | -g group | -G group[[,group]...] |"
	    "-d dir | -b base_dir |\n"
	    "\t\t-s shell | -c comment | -m [-z|Z] [-k skel_dir] |"
	    "-f inactive |\n"
	    "\t\t-e expire | -A authorization [, authorization ...] |\n"
	    "\t\t-P profile [, profile ...] | -R role [, role ...] |\n"
	    "\t\t-K key=value | -p project [, project ...]] login\n"
	    "\tuseradd -D [-g group | -b base_dir | -f inactive | -e expire\n"
	    "\t\t-A authorization [, authorization ...] |\n"
	    "\t\t-P profile [, profile ...] | -R role [, role ...] |\n"
	    "\t\t-K key=value ... -p project] | [-s shell] | [-k skel_dir]\n",
	"ERROR: Invalid syntax.\nusage:  userdel [-r] login\n",
	"ERROR: Invalid syntax.\n"
	    "usage:  usermod -u uid [-o] | -g group | -G group[[,group]...] |\n"
	    "\t\t-d dir [-m [-z|Z]] | -s shell | -c comment |\n"
	    "\t\t-l new_logname | -f inactive | -e expire |\n"
	    "\t\t-A authorization [, authorization ...] | -K key=value ... |\n"
	    "\t\t-P profile [, profile ...] | -R role [, role ...] login\n",
	"ERROR: Unexpected failure.  Defaults unchanged.\n",
	"ERROR: Unable to remove files from home directory.\n",
	"ERROR: Unable to remove home directory.\n",
	"ERROR: Cannot update system files - login cannot be %s.\n",
	"ERROR: uid %ld is already in use.  Choose another.\n",
	"ERROR: %s is already in use.  Choose another.\n",
	"ERROR: %s does not exist.\n",
	"ERROR: %s is not a valid %s.  Choose another.\n",
	"ERROR: %s is in use.  Cannot %s it.\n",
	"WARNING: %s has no permissions to use %s.\n",
	"ERROR: There is not sufficient space to move %s home directory to %s"
	    "\n",
	"ERROR: %s %ld is too big.  Choose another.\n",
	"ERROR: group %s does not exist.  Choose another.\n",
	"ERROR: Unable to %s: %s.\n",
	"ERROR: %s is not a full path name.  Choose another.\n",
	"ERROR: %s is the primary group name.  Choose another.\n",
	"ERROR: Inconsistent password files.  See pwconv(1M).\n",
	"ERROR: %s is not a local user.\n",
	"ERROR: Permission denied.\n",
	"WARNING: Group entry exceeds 2048 char: /etc/group entry truncated.\n",
	"ERROR: invalid syntax.\n"
	    "usage:  roleadd [-u uid [-o] | -g group | -G group[[,group]...] |"
	    "-d dir |\n"
	    "\t\t-s shell | -c comment | -m [-k skel_dir] | -f inactive |\n"
	    "\t\t-e expire | -A authorization [, authorization ...] |\n"
	    "\t\t-P profile [, profile ...] | -K key=value ] login\n"
	    "\troleadd -D [-g group | -b base_dir | -f inactive | -e expire\n"
	    "\t\t-A authorization [, authorization ...] |\n"
	    "\t\t-P profile [, profile ...]]\n",
	"ERROR: Invalid syntax.\nusage:  roledel [-r] login\n",
	"ERROR: Invalid syntax.\n"
	    "usage:  rolemod -u uid [-o] | -g group | -G group[[,group]...] |\n"
	    "\t\t-d dir [-m] | -s shell | -c comment |\n"
	    "\t\t-l new_logname | -f inactive | -e expire |\n"
	    "\t\t-A authorization [, authorization ...] | -K key=value |\n"
	    "\t\t-P profile [, profile ...] login\n",
	"ERROR: project %s does not exist.  Choose another.\n",
	"WARNING: more than NPROJECTS_MAX(%d) projects specified.\n",
	"WARNING: Project entry exceeds %d char: /etc/project entry truncated."
	    "\n",
	"ERROR: Invalid key.\n",
	"ERROR: Missing value specification.\n",
	"ERROR: Multiple definitions of key ``%s''.\n",
	"ERROR: Roles must be modified with ``rolemod''.\n",
	"ERROR: Users must be modified with ``usermod''.\n",
	"WARNING: gid %ld is reserved.\n",
	"ERROR: Failed to read /etc/group file due to invalid entry or"
	    " read error.\n",
	"ERROR: %s is too long.  Choose another.\n",
	"WARNING: Avoided creating ZFS filesystem as parent directory %s is not"
	    " a ZFS mount point.\n",
};

int lasterrmsg = sizeof (errmsgs) / sizeof (char *);
