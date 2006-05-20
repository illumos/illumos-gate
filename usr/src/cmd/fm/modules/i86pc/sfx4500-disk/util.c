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
#include <inttypes.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <assert.h>
#include <smbios.h>

#include <fm/fmd_api.h>

#include "util.h"
#include "sfx4500-disk.h"

extern log_class_t g_verbose;

static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

static void log_msg_nl(log_class_t cl, const char *fmt, ...);

/*
 * Search a string list for a particular value.
 * Return the string associated with that value.
 */
char *
find_string(slist_t *slist, int match_value)
{
	for (; slist->str != NULL; slist++) {
		if (slist->value == match_value) {
			return (slist->str);
		}
	}

	return ((char *)NULL);
}

/*
 * Produce a pretty dump of memory
 * <X> <Byte_i-1> <Byte_i> <Byte_i+1> ... [TEXT REPRESENTATION]
 */
static void
dump(log_class_t cl, char *label, char *start, unsigned length)
{
	int byte_count;
	int i;
#define	LINEBUFLEN 128
	char linebuf[LINEBUFLEN];
	char *linep;
	int bufleft, len;

	if (label != NULL)
		log_msg_nl(cl, "%s\n", label);

	linep = linebuf;
	bufleft = LINEBUFLEN;

	for (byte_count = 0; byte_count < length; byte_count += i) {

		(void) snprintf(linep, bufleft, "%s0x%08" PRIX64 " ", "",
		    (uint64_t)byte_count);
		len = strlen(linep);
		bufleft -= len;
		linep += len;

		/*
		 * Inner loop processes 16 bytes at a time, or less
		 * if we have less than 16 bytes to go
		 */
		for (i = 0; (i < 16) && ((byte_count + i) < length); i++) {
			(void) snprintf(linep, bufleft, "%02X", (unsigned int)
			    (unsigned char) start[byte_count + i]);

			len = strlen(linep);
			bufleft -= len;
			linep += len;

			if (bufleft >= 2) {
				if (i == 7)
					*linep = '-';
				else
					*linep = ' ';

				--bufleft;
				++linep;
			}
		}

		/*
		 * If i is less than 16, then we had less than 16 bytes
		 * written to the output.  We need to fixup the alignment
		 * to allow the "text" output to be aligned
		 */
		if (i < 16) {
			int numspaces = (16 - i) * 3;
			while (numspaces-- > 0) {
				if (bufleft >= 2) {
					*linep = ' ';
					--bufleft;
					linep++;
				}
			}
		}

		if (bufleft >= 2) {
			*linep = ' ';
			--bufleft;
			++linep;
		}

		for (i = 0; (i < 16) && ((byte_count + i) < length); i++) {
			int subscript = byte_count + i;
			char ch =  (isprint(start[subscript]) ?
			    start[subscript] : '.');

			if (bufleft >= 2) {
				*linep = ch;
				--bufleft;
				++linep;
			}
		}

		linebuf[LINEBUFLEN - bufleft] = 0;

		log_msg_nl(cl, "%s\n", linebuf);

		linep = linebuf;
		bufleft = LINEBUFLEN;
	}
}

void
log_dump(log_class_t cl, char *label, char *start, unsigned length)
{
	if ((g_verbose & cl) != cl)
		return;

	assert(pthread_mutex_lock(&log_mutex) == 0);
	dump(cl, label, start, length);
	assert(pthread_mutex_unlock(&log_mutex) == 0);
}

static void
verror(const char *fmt, va_list ap)
{
	int error = errno;

	assert(pthread_mutex_lock(&log_mutex) == 0);
	fmd_hdl_vdebug(g_fm_hdl, fmt, ap);

	if (fmt[strlen(fmt) - 1] != '\n')
		fmd_hdl_debug(g_fm_hdl, ": %s\n", strerror(error));

	assert(pthread_mutex_unlock(&log_mutex) == 0);
}

static void
vwarn_e(const char *fmt, va_list ap)
{
	int error = errno;

	assert(pthread_mutex_lock(&log_mutex) == 0);
	fmd_hdl_debug(g_fm_hdl, "WARNING: ");
	fmd_hdl_vdebug(g_fm_hdl, fmt, ap);

	if (fmt[strlen(fmt) - 1] != '\n')
		fmd_hdl_debug(g_fm_hdl, ": %s\n", strerror(error));

	assert(pthread_mutex_unlock(&log_mutex) == 0);
}

static void
vwarn(const char *fmt, va_list ap)
{
	assert(pthread_mutex_lock(&log_mutex) == 0);
	fmd_hdl_debug(g_fm_hdl, "WARNING: ");
	fmd_hdl_vdebug(g_fm_hdl, fmt, ap);
	assert(pthread_mutex_unlock(&log_mutex) == 0);
}

void
vcont(log_class_t cl, const char *fmt, va_list ap)
{
	int error = errno;

	if ((g_verbose & cl) != cl)
		return;

	assert(pthread_mutex_lock(&log_mutex) == 0);
	fmd_hdl_vdebug(g_fm_hdl, fmt, ap);

	if (fmt[strlen(fmt) - 1] != '\n')
		fmd_hdl_debug(g_fm_hdl, ": %s\n", strerror(error));

	assert(pthread_mutex_unlock(&log_mutex) == 0);
}

static void
log_msg_nl(log_class_t cl, const char *fmt, ...)
{
	va_list ap;

	if ((g_verbose & cl) != cl)
		return;

	va_start(ap, fmt);
	fmd_hdl_vdebug(g_fm_hdl, fmt, ap);
	va_end(ap);
}

void
log_msg(log_class_t cl, const char *fmt, ...)
{
	va_list ap;

	if ((g_verbose & cl) != cl)
		return;

	assert(pthread_mutex_lock(&log_mutex) == 0);
	va_start(ap, fmt);
	fmd_hdl_vdebug(g_fm_hdl, fmt, ap);
	va_end(ap);
	assert(pthread_mutex_unlock(&log_mutex) == 0);
}

/*PRINTFLIKE1*/
void
log_err(const char *fmt, ...)
{
	va_list ap;

	if ((g_verbose & MM_ERR) != MM_ERR)
		return;

	va_start(ap, fmt);
	verror(fmt, ap);
	va_end(ap);
}

/*PRINTFLIKE1*/
void
log_warn(const char *fmt, ...)
{
	va_list ap;

	if ((g_verbose & MM_WARN) != MM_WARN)
		return;

	va_start(ap, fmt);
	vwarn(fmt, ap);
	va_end(ap);
}

/*PRINTFLIKE1*/
void
log_warn_e(const char *fmt, ...)
{
	va_list ap;

	if ((g_verbose & MM_WARN) != MM_WARN)
		return;

	va_start(ap, fmt);
	vwarn_e(fmt, ap);
	va_end(ap);
}

void
dfree(void *p, size_t sz)
{
	fmd_hdl_free(g_fm_hdl, p, sz);
}

void
dstrfree(char *s)
{
	fmd_hdl_strfree(g_fm_hdl, s);
}

void *
dmalloc(size_t sz)
{
	return (fmd_hdl_alloc(g_fm_hdl, sz, FMD_SLEEP));
}

void *
dzmalloc(size_t sz)
{
	return (fmd_hdl_zalloc(g_fm_hdl, sz, FMD_SLEEP));
}


char *
dstrdup(const char *s)
{
	return (fmd_hdl_strdup(g_fm_hdl, s, FMD_SLEEP));
}

void
queue_add(qu_t *qp, void *data)
{
	struct q_node *qnp =
	    (struct q_node *)qp->nalloc(sizeof (struct q_node));
	struct q_node *nodep;

	qnp->data = data;
	qnp->next = NULL;
	assert(pthread_mutex_lock(&qp->mutex) == 0);

	if (qp->nodep == NULL)
		qp->nodep = qnp;
	else {
		nodep = qp->nodep;

		while (nodep->next != NULL)
			nodep = nodep->next;

		nodep->next = qnp;
	}

	/* If the queue was empty, we need to wake people up */
	if (qp->boe && qp->nodep == qnp)
		assert(pthread_cond_broadcast(&qp->cvar) == 0);
	assert(pthread_mutex_unlock(&qp->mutex) == 0);
}

void *
queue_remove(qu_t *qp)
{
	void *rv = NULL;
	struct q_node *nextnode;

	assert(pthread_mutex_lock(&qp->mutex) == 0);

	/* Wait while the queue is empty */
	while (qp->boe && qp->nodep == NULL) {
		(void) pthread_cond_wait(&qp->cvar, &qp->mutex);
	}

	/*
	 * If Block-On-Empty is false, the queue may be empty
	 */
	if (qp->nodep != NULL) {
		rv = qp->nodep->data;
		nextnode = qp->nodep->next;
		qp->nfree(qp->nodep, sizeof (struct q_node));
		qp->nodep = nextnode;
	}

	assert(pthread_mutex_unlock(&qp->mutex) == 0);
	return (rv);
}

qu_t *
new_queue(boolean_t block_on_empty, void *(*nodealloc)(size_t),
    void (*nodefree)(void *, size_t), void (*data_deallocator)(void *))
{
	qu_t *newqp = (qu_t *)dmalloc(sizeof (qu_t));

	newqp->boe = block_on_empty;
	newqp->nalloc = nodealloc;
	newqp->nfree = nodefree;
	newqp->data_dealloc = data_deallocator;
	assert(pthread_mutex_init(&newqp->mutex, NULL) == 0);
	assert(pthread_cond_init(&newqp->cvar, NULL) == 0);
	newqp->nodep = NULL;

	return (newqp);
}

void
queue_free(qu_t **qpp)
{
	qu_t *qp = *qpp;
	void *item;

	assert(pthread_mutex_destroy(&qp->mutex) == 0);
	assert(pthread_cond_destroy(&qp->cvar) == 0);

	qp->boe = B_FALSE;

	while ((item = queue_remove(qp)) != NULL) {
		qp->data_dealloc(item);
	}

	assert(qp->nodep == NULL);

	dfree(qp, sizeof (qu_t));
	*qpp = NULL;
}
