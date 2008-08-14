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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <pthread.h>
#include <strings.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/varargs.h>
#include <mms_sym.h>
#include <dm_impl.h>
#include <dm_msg.h>
#include <mms_trace.h>
#include <dm_proto.h>
#include <mms_strapp.h>

static	char *_SrcFile = __FILE__;

static	mms_sym_t	_dm_msg_cat[] = {
	"$dm$: syntax error: $error$", 6500,
	"$dm$: activate $type$ failed: $error$", 6501,
	"$dm$: reserved. Preempt reservation? reply yes/no/retry.", 6502,
	"$dm$: volume has no label. Enter volume id (VSN) or abort", 6503,
	"$dm$: USCSICMD error: $error$", 6504,
	"$dm$: no matching command: $error$", 6505,
	"$dm$: internal error: $error$", 6506,
	"$dm$: unknown capability: $error$", 6507,
	"$dm$: attach error: $error$", 6508,
	"$dm$: I/O error: $error$", 6509,
	"$dm$: identify error: $error$", 6510,
	"$dm$: detach error: $error$", 6511,
	"$dm$: get request: $error$", 6512,
	"$dm$: set blocksize error: $error$", 6513,
	"$dm$: get blocksize error: $error$", 6514,
	"$dm$: unsupported MTIOCTOP function: $error$", 6515,
	"$dm$: open error: $error$", 6516,
	"$dm$: load command error: $error$", 6517,
	"$dm$: overwrite data on $pcl$? reply yes/no.", 6518,
	"$dm$: switch label from $from$ to $to$ on $pcl$? reply yes/no.", 6519,
	"$dm$: switch label from $from$ to $to$ and writeover data on $pcl$? "
	"reply yes/no.", 6520,
	"$dm$: $drive$ is still opened by pid $pid$", 6521,
	"$dm$: MTSEEK error: $error$", 6522,
	"$dm$: MTTELL error: $error$", 6523,
	"$dm$: DM restarting because of attach error: $error$", 6524,
	"$dm$: DM initialization error: $error$", 6525,
	"$dm$: DM restarting: $error$", 6526,
	"$dm$: mount command error: $error$", 6527,
	"$dm$: DM exiting: $error$", 6528
};

mms_sym_t	*dm_msg_cat = _dm_msg_cat;
int	dm_msg_cat_num = sizeof (_dm_msg_cat) / sizeof (mms_sym_t);

void
dm_msg_create_hdr(void)
{
	dm_msg_hdr_t	*mh;

	mh = (dm_msg_hdr_t *)malloc(sizeof (dm_msg_hdr_t));
	if (mh == NULL) {
		TRACE((MMS_ERR, "Out of memory"));
		DM_EXIT(DM_RESTART);
	}
	mms_list_create(&mh->msg_msglist, sizeof (dm_msg_t),
	    offsetof(dm_msg_t, msg_next));
	mh->msg_tid = pthread_self();
	mms_list_insert_tail(&dm_msg_hdr_list, mh);
}

dm_msg_hdr_t	*
dm_msg_get_hdr(void)
{
	pthread_t	tid;
	dm_msg_hdr_t	*mh;

	tid = pthread_self();
	mms_list_foreach(&dm_msg_hdr_list, mh) {
		if (pthread_equal(mh->msg_tid, tid)) {
			return (mh);
		}
	}
	assert(mh != NULL);
	return (NULL);
}

void
dm_msg_remove(dm_msg_t *msg)
{
	dm_msg_hdr_t	*mh;

	mh = dm_msg_get_hdr();
	mms_list_remove(&mh->msg_msglist, &msg->msg_next);
	if (msg->msg_text) {
		free(msg->msg_text);
	}
	free(msg);
}

void
dm_msg_destroy(void)
{
	dm_msg_hdr_t	*mh;
	dm_msg_t	*msg;
	dm_msg_t	*tmp;

	mh = dm_msg_get_hdr();
	mms_list_foreach_safe(&mh->msg_msglist, msg, tmp) {
		dm_msg_remove(msg);
	}
}

char	*
dm_msg_add_aux(int tail, int class, int code, char *fmt, va_list args)
{
	va_list		ap;
	char		*text;
	dm_msg_t	*msg;
	dm_msg_hdr_t	*mh;
	int		i;

	assert(fmt != NULL);

	ap = args;
	text = mms_vstrapp(NULL, fmt, ap);
	/* Allocate a message struct */
	msg = (dm_msg_t *)malloc(sizeof (dm_msg_t));
	if (msg == NULL) {
		return (NULL);
	}
	memset(msg, 0, sizeof (dm_msg_t));

	msg->msg_class = class;
	msg->msg_code = code;
	msg->msg_text = text;
	/* Replace single quotes (') with double quotes (") */
	for (i = 0; msg->msg_text[i] != 0; i++) {
		if (msg->msg_text[i] == '\'') {
			msg->msg_text[i] = '\"';
		}
	}
	mh = dm_msg_get_hdr();
	if (tail) {
		mms_list_insert_tail(&mh->msg_msglist, msg);
	} else {
		mms_list_insert_head(&mh->msg_msglist, msg);
	}
	return (msg->msg_text);
}

char	*
dm_msg_add(int class, int code, char *fmt, ...)
{
	va_list		args;
	char		*rc;

	va_start(args, fmt);
	rc = dm_msg_add_aux(1, class, code, fmt, args);
	va_end(args);
	return (rc);
}

char	*
dm_msg_add_head(int class, int code, char *fmt, ...)
{
	va_list		args;
	char		*rc;

	va_start(args, fmt);
	rc = dm_msg_add_aux(0, class, code, fmt, args);
	va_end(args);
	return (rc);
}

/*
 * Get the first message
 */
char	*
dm_msg_text(void)
{
	dm_msg_hdr_t	*mh;
	dm_msg_t	*msg;

	mh = dm_msg_get_hdr();
	if (mms_list_empty(&mh->msg_msglist)) {
		return (NULL);
	}
	msg = mms_list_head(&mh->msg_msglist);
	return (msg->msg_text);
}

int
dm_msg_class(void)
{
	dm_msg_hdr_t	*mh;
	dm_msg_t	*msg;

	mh = dm_msg_get_hdr();
	if (mms_list_empty(&mh->msg_msglist)) {
		return (MMS_INTERNAL);
	}
	msg = mms_list_head(&mh->msg_msglist);
	return (msg->msg_class);
}

int
dm_msg_code(void)
{
	dm_msg_hdr_t	*mh;
	dm_msg_t	*msg;

	mh = dm_msg_get_hdr();
	if (mms_list_empty(&mh->msg_msglist)) {
		return (MMS_DM_E_UNKNOWN);
	}
	msg = mms_list_head(&mh->msg_msglist);
	return (msg->msg_code);
}

char *
dm_msg_prepend(char *fmt, ...)
{
	dm_msg_hdr_t	*mh;
	dm_msg_t	*msg;
	char		*newtext;
	va_list		args;

	va_start(args, fmt);
	newtext = mms_vstrapp(NULL, fmt, args);
	va_end(args);
	mh = dm_msg_get_hdr();
	if (mms_list_empty(&mh->msg_msglist)) {
		return (dm_msg_add(MMS_INTERNAL, MMS_DM_E_INTERNAL, newtext));
	}
	msg = mms_list_head(&mh->msg_msglist);

	msg->msg_text = mms_strapp(newtext, "%s", msg->msg_text);
	return (msg->msg_text);
}
