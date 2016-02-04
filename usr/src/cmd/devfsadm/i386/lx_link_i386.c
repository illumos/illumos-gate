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

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2016 Joyent, Inc.
 */

#include <devfsadm.h>
#include <strings.h>
#include <stdio.h>
#include <sys/lx_ptm.h>
#include <sys/lx_audio.h>
#include <sys/lx_autofs.h>

static int lx_ptm(di_minor_t minor, di_node_t node);
static int lx_audio(di_minor_t minor, di_node_t node);
static int lx_autofs(di_minor_t minor, di_node_t node);
static int lx_systrace(di_minor_t minor, di_node_t node);

static devfsadm_create_t lx_create_cbt[] = {
	{ "pseudo", "ddi_pseudo", LX_PTM_DRV,
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, lx_ptm },
	{ "pseudo", "ddi_pseudo", LX_AUDIO_DRV,
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, lx_audio },
	{ "pseudo", "ddi_pseudo", LX_AUTOFS_NAME,
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, lx_autofs },
	{ "pseudo", "ddi_pseudo", "lx_systrace",
	    TYPE_EXACT | DRV_EXACT, ILEVEL_0, lx_systrace },
};

DEVFSADM_CREATE_INIT_V0(lx_create_cbt);

static int
lx_ptm(di_minor_t minor, di_node_t node)
{
	char *mname = di_minor_name(minor);

	if (strcmp(LX_PTM_MINOR_NODE, mname) == 0)
		(void) devfsadm_mklink("brand/lx/ptmx", node, minor, 0);

	return (DEVFSADM_CONTINUE);
}

static int
lx_audio(di_minor_t minor, di_node_t node)
{
	char *mname = di_minor_name(minor);

	if (strcmp(LXA_MINORNAME_DEVCTL, mname) == 0)
		(void) devfsadm_mklink("brand/lx/audio_devctl", node, minor, 0);
	if (strcmp(LXA_MINORNAME_DSP, mname) == 0)
		(void) devfsadm_mklink("brand/lx/dsp", node, minor, 0);
	if (strcmp(LXA_MINORNAME_MIXER, mname) == 0)
		(void) devfsadm_mklink("brand/lx/mixer", node, minor, 0);

	return (DEVFSADM_CONTINUE);
}

static int
lx_autofs(di_minor_t minor, di_node_t node)
{
	char *mname = di_minor_name(minor);

	if (strcmp(LX_AUTOFS_MINORNAME, mname) == 0)
		(void) devfsadm_mklink("brand/lx/autofs", node, minor, 0);

	return (DEVFSADM_CONTINUE);
}

static int
lx_systrace(di_minor_t minor, di_node_t node)
{
	char *mname = di_minor_name(minor);
	char path[MAXPATHLEN];

	(void) snprintf(path, sizeof (path), "dtrace/provider/%s", mname);
	(void) devfsadm_mklink(path, node, minor, 0);

	return (DEVFSADM_CONTINUE);
}
