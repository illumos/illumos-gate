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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <synch.h>

#define	Q_DEFAULT		"default"
#define	BUFLEN			256

static int qop_num_pair_cnt;
static const char    QOP_NUM_FILE[] = "/etc/gss/qop";
static qop_num	qop_num_pairs[MAX_QOP_NUM_PAIRS+1];
static mutex_t qopfile_lock = DEFAULTMUTEX;

static OM_uint32 __gss_read_qop_file(void);

/*
 * This routine fetches qop and num from "/etc/gss/qop".
 * There is a memory leak associated with rereading this file,
 * because we can't free the qop_num_pairs array when we reread
 * the file (some callers may have been given these pointers).
 * In general, this memory leak should be a small one, because
 * we don't expect the qop file to be changed and reread often.
 */
static OM_uint32
__gss_read_qop_file(void)
{
	char 	buf[BUFLEN];	/* one line from the file */
	char	*name, *next;
	char	*qopname, *num_str;
	char 	*line;
	FILE 	*fp;
	static int last = 0;
	struct stat stbuf;
	OM_uint32 major = GSS_S_COMPLETE;

	(void) mutex_lock(&qopfile_lock);
	if (stat(QOP_NUM_FILE, &stbuf) != 0 || stbuf.st_mtime < last) {
		if (!qop_num_pairs[0].qop) {
			major = GSS_S_FAILURE;
		}
		goto done;
	}
	last = stbuf.st_mtime;

	fp = fopen(QOP_NUM_FILE, "rF");
	if (fp == (FILE *)0) {
		major = GSS_S_FAILURE;
		goto done;
	}

	/*
	 * For each line in the file parse it appropriately.
	 * File format : qopname	num(int)
	 * Note that we silently ignore corrupt entries.
	 */
	qop_num_pair_cnt = 0;
	while (!feof(fp)) {
		line = fgets(buf, BUFLEN, fp);
		if (line == NULL)
			break;

		/* Skip comments and blank lines */
		if ((*line == '#') || (*line == '\n'))
			continue;

		/* Skip trailing comments */
		next = strchr(line, '#');
		if (next)
			*next = '\0';

		name = &(buf[0]);
		while (isspace(*name))
			name++;
		if (*name == '\0')	/* blank line */
			continue;

		qopname = name;	/* will contain qop name */
		while (!isspace(*qopname))
			qopname++;
		if (*qopname == '\0') {
			continue;
		}
		next = qopname+1;
		*qopname = '\0';	/* null terminate qopname */
		qop_num_pairs[qop_num_pair_cnt].qop = strdup(name);
		if (qop_num_pairs[qop_num_pair_cnt].qop == NULL)
			continue;

		name = next;
		while (isspace(*name))
			name++;
		if (*name == '\0') { 	/* end of line, no num */
			free(qop_num_pairs[qop_num_pair_cnt].qop);
			continue;
		}
		num_str = name;	/* will contain num (n) */
		while (!isspace(*num_str))
			num_str++;
		next = num_str+1;
		*num_str++ = '\0';	/* null terminate num_str */

		qop_num_pairs[qop_num_pair_cnt].num = (OM_uint32)atoi(name);
		name = next;
		while (isspace(*name))
			name++;
		if (*name == '\0') { 	/* end of line, no mechanism */
			free(qop_num_pairs[qop_num_pair_cnt].qop);
			continue;
		}
		num_str = name;	/* will contain mech */
		while (!isspace(*num_str))
			num_str++;
		*num_str = '\0';

		qop_num_pairs[qop_num_pair_cnt].mech = strdup(name);
		if (qop_num_pairs[qop_num_pair_cnt].mech == NULL) {
			free(qop_num_pairs[qop_num_pair_cnt].qop);
			continue;
		}

		if (qop_num_pair_cnt++ >= MAX_QOP_NUM_PAIRS)
			break;
	}
	(void) fclose(fp);
done:
	(void) mutex_unlock(&qopfile_lock);
	return (major);
}

OM_uint32
__gss_qop_to_num(
	char		*qop,
	char		*mech,
	OM_uint32	*num
)
{
	int i;
	OM_uint32 major = GSS_S_FAILURE;

	if (!num)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	if (qop == NULL || strlen(qop) == 0 ||
			strcasecmp(qop, Q_DEFAULT) == 0) {
		*num = GSS_C_QOP_DEFAULT;
		return (GSS_S_COMPLETE);
	}

	if ((major = __gss_read_qop_file()) != GSS_S_COMPLETE)
		return (major);

	for (i = 0; i < qop_num_pair_cnt; i++) {
		if ((strcasecmp(mech, qop_num_pairs[i].mech) == 0) &&
		    (strcasecmp(qop, qop_num_pairs[i].qop) == 0)) {
			*num = qop_num_pairs[i].num;
			return (GSS_S_COMPLETE);
		}
	}

	return (GSS_S_FAILURE);
}

OM_uint32
__gss_num_to_qop(
	char		*mech,
	OM_uint32	num,
	char		**qop
)
{
	int i;
	OM_uint32 major;

	if (!qop)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);
	*qop = NULL;

	if (num == GSS_C_QOP_DEFAULT) {
		*qop = Q_DEFAULT;
		return (GSS_S_COMPLETE);
	}

	if (mech == NULL)
		return (GSS_S_CALL_INACCESSIBLE_READ);

	if ((major = __gss_read_qop_file()) != GSS_S_COMPLETE)
		return (major);

	for (i = 0; i < qop_num_pair_cnt; i++) {
		if ((strcasecmp(mech, qop_num_pairs[i].mech) == 0) &&
		    (num == qop_num_pairs[i].num)) {
			*qop = qop_num_pairs[i].qop;
			return (GSS_S_COMPLETE);
		}
	}
	return (GSS_S_FAILURE);
}

/*
 * For a given mechanism pass back qop information about it in a buffer
 * of size MAX_QOPS_PER_MECH+1.
 */
OM_uint32
__gss_get_mech_info(
	char		*mech,
	char		**qops
)
{
	int i, cnt = 0;
	OM_uint32 major = GSS_S_COMPLETE;

	if (!qops)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);
	*qops = NULL;

	if (!mech)
		return (GSS_S_CALL_INACCESSIBLE_READ);

	if ((major = __gss_read_qop_file()) != GSS_S_COMPLETE)
		return (major);

	for (i = 0; i < qop_num_pair_cnt; i++) {
		if (strcmp(mech, qop_num_pairs[i].mech) == 0) {
		    if (cnt >= MAX_QOPS_PER_MECH) {
			return (GSS_S_FAILURE);
		    }
		    qops[cnt++] = qop_num_pairs[i].qop;
		}
	}
	qops[cnt] = NULL;
	return (GSS_S_COMPLETE);
}

/*
 * Copy the qop values and names for the mechanism back in a qop_num
 * buffer of size MAX_QOPS_PER_MECH provided by the caller.
 */
OM_uint32
__gss_mech_qops(
	char *mech,
	qop_num *mechqops,
	int *numqop
)
{
	int i;
	OM_uint32 major;
	int cnt = 0;

	if (!mechqops || !numqop)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);
	*numqop = 0;

	if (!mech)
		return (GSS_S_CALL_INACCESSIBLE_READ);

	if ((major = __gss_read_qop_file()) != GSS_S_COMPLETE)
		return (major);

	for (i = 0; i < qop_num_pair_cnt; i++) {
	    if (strcasecmp(mech, qop_num_pairs[i].mech) == 0) {
		if (cnt >= MAX_QOPS_PER_MECH) {
			return (GSS_S_FAILURE);
		}
		mechqops[cnt++] = qop_num_pairs[i];
	    }
	}
	*numqop = cnt;
	return (GSS_S_COMPLETE);
}
