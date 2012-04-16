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
 * Copyright (c) 2012, OmniTI Computer Consulting, Inc. All rights reserved.
 */

#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#include <sys/socketvar.h>
#include <sys/sockfilter.h>
#include <sys/note.h>
#include <sys/taskq.h>

static struct modlmisc httpf_modlmisc = {
	&mod_miscops,
	"Kernel HTTP socket filter"
};

static struct modlinkage httpf_modlinkage = {
	MODREV_1,
	&httpf_modlmisc,
	NULL
};
/*
 * Name of the HTTP filter
 */
#define	HTTPFILT_MODULE	"httpfilt"
#define	MAX_HTTP_FILTER_SIZE 8192

/*
 * httpf filter cookie
 */
typedef struct httpf {
	size_t	httpf_bytes_in;	/* bytes read */
	int	httpf_method;	/* HTTP method */
	int	httpf_sm;	/* \r\n\r\n | \n\n state machine */
	char	httpf_ff[4];	/* the first 4 bytes of the data stream */
	union {
		char httpfu_ff[4]; /* the first 4 bytes of the data stream */
		uint32_t httpfu_w; /* in an easy-to-compare 32-bit word */
	} httpf_u;
#define	httpf_ff httpf_u.httpfu_ff
#define	httpf_ffw httpf_u.httpfu_w
} httpf_t;

#ifdef _BIG_ENDIAN
#define	CHAR_TO_32(a, b, c, d) ((d) + ((c) << 8) + ((b) << 16) + ((a) << 24))
#else
#define	CHAR_TO_32(a, b, c, d) ((a) + ((b) << 8) + ((c) << 16) + ((d) << 24))
#endif

#define	WORD_GET	CHAR_TO_32('G', 'E', 'T', ' ')
#define	WORD_PUT	CHAR_TO_32('P', 'U', 'T', ' ')
#define	WORD_POST	CHAR_TO_32('P', 'O', 'S', 'T')
#define	WORD_HEAD	CHAR_TO_32('H', 'E', 'A', 'D')

#define	HTTPF_METHOD_INVALID -1
#define	HTTPF_METHOD_UNSET 0
#define	HTTPF_METHOD_GET   1
#define	HTTPF_METHOD_HEAD  2
#define	HTTPF_METHOD_PUT   3
#define	HTTPF_METHOD_POST  4

static int
httpf_method_from_ff(uint32_t ffw)
{
	switch (ffw) {
	case WORD_GET:
		return (HTTPF_METHOD_GET);
	case WORD_PUT:
		return (HTTPF_METHOD_PUT);
	case WORD_POST:
		return (HTTPF_METHOD_POST);
	case WORD_HEAD:
		return (HTTPF_METHOD_HEAD);
	}

	return (HTTPF_METHOD_INVALID);
}

static int
httpf_progress_crlfcrlf_state(httpf_t *httpf, unsigned char ch) {
#define	HTTPF_STATE(a) httpf->httpf_sm = (a)
#define	IF_HTTPF_TOKEN(a) if ((ch) == (a))
	switch (httpf->httpf_sm) {
	case 0:
		IF_HTTPF_TOKEN('\r') HTTPF_STATE(1);
		IF_HTTPF_TOKEN('\n') HTTPF_STATE(3);
		break;
	case 1:
		IF_HTTPF_TOKEN('\n') HTTPF_STATE(2);
		else HTTPF_STATE(0);
		break;
	case 2:
		IF_HTTPF_TOKEN('\n') return (0);
		IF_HTTPF_TOKEN('\r') HTTPF_STATE(3);
		else HTTPF_STATE(0);
		break;
	case 3:
		IF_HTTPF_TOKEN('\n') return (0);
		IF_HTTPF_TOKEN('\r') HTTPF_STATE(1);
		else HTTPF_STATE(0);
		break;
	}
	return (-1);
}

static int
httpf_process_input(httpf_t *httpf, mblk_t *mp) {
	int i, dlen = MBLKL(mp);

	for (i = 0; i < dlen; i++) {
		/* Collect the first four bytes for a protocol validation */
		if (httpf->httpf_method == HTTPF_METHOD_UNSET &&
		    httpf->httpf_bytes_in < 4)
			httpf->httpf_ff[httpf->httpf_bytes_in] = mp->b_rptr[i];

		httpf->httpf_bytes_in++;

		/*
		 * if we haven't yet determined out HTTP method, do it at
		 * exactly 4 bytes into the stream.
		 */
		if (httpf->httpf_method == HTTPF_METHOD_UNSET &&
		    httpf->httpf_bytes_in == 4) {
			/*
			 * if we find no good method, we can't defer this stream
			 */
			httpf->httpf_method =
			    httpf_method_from_ff(httpf->httpf_ffw);
			if (httpf->httpf_method == HTTPF_METHOD_INVALID)
				return (-1);
		}

		/*
		 * if the method is set, start looking for either
		 *  \r\n\r\n or \n\n
		 */
		if (httpf->httpf_method > HTTPF_METHOD_UNSET)
			if (httpf_progress_crlfcrlf_state(httpf, mp->b_rptr[i])
			    == 0) {
				return (1);
			}
	}
	return (0);
}

/*
 * Allocate httpf state
 */
sof_rval_t
httpf_attach_passive_cb(sof_handle_t handle, sof_handle_t ph,
    void *parg, struct sockaddr *laddr, socklen_t laddrlen,
    struct sockaddr *faddr, socklen_t faddrlen, void **cookiep)
{
	httpf_t *new;

	_NOTE(ARGUNUSED(handle, ph, parg, faddr, faddrlen, laddr, laddrlen));

	/* Allocate the SSL context for the new connection */
	new = kmem_zalloc(sizeof (httpf_t), KM_NOSLEEP);
	if (new == NULL)
		return (SOF_RVAL_ENOMEM);

	new->httpf_bytes_in = 0;
	new->httpf_method = HTTPF_METHOD_UNSET;

	*cookiep = new;
	/*
	 * We are awaiting a request, defer the notification of this
	 * connection until it is completed.
	 */
	return (SOF_RVAL_DEFER);
}

void
httpf_detach_cb(sof_handle_t handle, void *cookie, cred_t *cr)
{
	httpf_t *httpf = (httpf_t *)cookie;

	_NOTE(ARGUNUSED(handle, cr));

	if (httpf == NULL)
		return;

	kmem_free(httpf, sizeof (httpf_t));
}

/*
 * Called for each incoming segment.
 */
mblk_t *
httpf_data_in_cb(sof_handle_t handle, void *cookie, mblk_t *mp, int flags,
    size_t *lenp)
{
	httpf_t	*httpf = cookie;

	_NOTE(ARGUNUSED(flags, lenp));

	if (httpf == NULL) {
		sof_bypass(handle);
		return (mp);
	}

	if (mp == NULL)
		return (mp);

	if (httpf_process_input(httpf, mp))
		sof_newconn_ready(handle);

	if (httpf->httpf_bytes_in > MAX_HTTP_FILTER_SIZE)
		sof_newconn_ready(handle);

	return (mp);
}

sof_ops_t httpf_ops = {
	.sofop_attach_passive = httpf_attach_passive_cb,
	.sofop_detach = httpf_detach_cb,
	.sofop_data_in = httpf_data_in_cb,
};

int
_init(void)
{
	int error;

	if ((error = sof_register(SOF_VERSION, HTTPFILT_MODULE, &httpf_ops, 0))
	    != 0) {
		return (error);
	}
	if ((error = mod_install(&httpf_modlinkage)) != 0)
		(void) sof_unregister(HTTPFILT_MODULE);

	return (error);
}

int
_fini(void)
{
	int error;

	if ((error = sof_unregister(HTTPFILT_MODULE)) != 0)
		return (error);

	return (mod_remove(&httpf_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&httpf_modlinkage, modinfop));
}
