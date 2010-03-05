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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/t_lock.h>
#include <sys/thread.h>
#include <sys/systm.h>
#include <c2/audit.h>
#include <c2/audit_kernel.h>
#include <c2/audit_record.h>

static kmem_cache_t *au_buf_cache;

/*
 * au_buff_t and token_t are equivalent (see audit_record.h).  Don't
 * confuse this token_t with the one that is defined for userspace
 * in the same header file.
 */

/*
 * Function: au_get_buff
 * args:
 */
struct au_buff *
au_get_buff(void)
{
	au_buff_t *buffer;
	t_audit_data_t *tad = U2A(u);

	ASSERT(tad);

	/*
	 * If asynchronous (interrupt) thread, then we can't sleep
	 * (the tad ERRJMP flag is set at the start of async processing).
	 */
	if (tad->tad_ctrl & PAD_ERRJMP) {
		buffer = kmem_cache_alloc(au_buf_cache, KM_NOSLEEP);
		if (buffer == NULL) {
			/* return to top of stack & report an error */
			ASSERT(tad->tad_errjmp);
			longjmp(tad->tad_errjmp);
		}
	} else {
		buffer = kmem_cache_alloc(au_buf_cache, KM_SLEEP);
	}
	/* Never gets here when buffer == NULL */
	bzero(buffer, sizeof (*buffer));
	return (buffer);
}

/*
 * Function: au_free_rec
 * args:
 *	au_buff_t *buf;		start of the record chain
 */
void
au_free_rec(au_buff_t *buf)
{
	au_buff_t *next;
	t_audit_data_t *tad = U2A(u);

	ASSERT(tad);

	/*
	 * If asynchronous (interrupt) thread, schedule the release
	 * (the tad ERRJMP flag is set at the start of async processing).
	 */
	if (tad->tad_ctrl & PAD_ERRJMP) {
		/* Discard async events via softcall. */
		softcall(audit_async_discard_backend, buf);
	}

	while (buf != NULL) {
		next = buf->next_buf;
		kmem_cache_free(au_buf_cache, buf);
		buf = next;
	}
}

/*
 * Backend routine to discard an async event. Invoked from softcall.
 * (Note: the freeing of memory for the event can't be done safely in high
 * interrupt context due to the chance of sleeping on an adaptive mutex.
 * Hence the softcall.)
 */
void
audit_async_discard_backend(void *addr)
{
	au_toss_token(addr);
}

/*
 * Function: au_append_rec
 * args:
 *	au_buff_t *rec;		start of the record chain
 *	au_buff_t *buf;		buffer to append
 *	int        pack;	AU_PACK/1 - pack data, AU_LINK/0 - link buffer
 */
int
au_append_rec(au_buff_t *rec, au_buff_t *buf, int pack)
{
	if (!rec)
		return (-1);

	while (rec->next_buf)
		rec = rec->next_buf;
	if (((int)(rec->len + buf->len) <= AU_BUFSIZE) && pack) {
		bcopy(buf->buf, (char *)(rec->buf + rec->len),
		    (uint_t)buf->len);
		rec->len += buf->len;
		rec->next_buf = buf->next_buf;
		kmem_cache_free(au_buf_cache, buf);
	} else {
		rec->next_buf = buf;
	}
	return (0);
}

/*
 * Function: au_append_buf
 * args:
 *	char *data;		data buffer to append
 *	int len;		size of data to append
 *	au_buff_t *buf;		buffer to append to
 */
int
au_append_buf(const char *data, int len, au_buff_t *buf)
{
	au_buff_t *new_buf;
	int	new_len;

	while (buf->next_buf != NULL)
		buf = buf->next_buf;

	new_len = (uint_t)(buf->len + len) > AU_BUFSIZE ?
	    AU_BUFSIZE - buf->len : len;
	bcopy(data, (buf->buf + buf->len), (uint_t)new_len);
	buf->len += (uchar_t)new_len;
	len -= new_len;

	while (len > 0) {
		data += new_len;
		if ((new_buf = au_get_buff()) == NULL) {
			return (-1);
		}
		buf->next_buf = new_buf;
		buf = new_buf;
		new_len = len > AU_BUFSIZE ? AU_BUFSIZE : len;
		bcopy(data, buf->buf, (uint_t)new_len);
		buf->len = (uchar_t)new_len;
		len -= new_len;
	}
	return (0);
}

void
au_mem_init()
{
	au_buf_cache = kmem_cache_create("audit_buffer",
	    sizeof (au_buff_t), 0, NULL, NULL, NULL, NULL, NULL, 0);
}
