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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/param.h>
#include <sys/time.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <bsm/audit.h>
#include <bsm/libbsm.h>
#include <bsm/audit_record.h>
#include <synch.h>


/*
 * Open an audit record = find a free descriptor and pass it back.
 * The descriptors are in a "fixed" length array which is extended
 * whenever it gets full.
 *
 *  Since the expected frequency of copies is expected to be low,
 *  and since realloc loses data if it fails to expand the buffer,
 *  calloc() is used rather than realloc().
 */

/*
 * AU_TABLE_MAX must be a integer multiple of AU_TABLE_LENGTH
 */
#define	AU_TABLE_LENGTH	16
#define	AU_TABLE_MAX	256

static token_t	**au_d;
static int	au_d_length = 0;	/* current table length */
static int	au_d_required_length = AU_TABLE_LENGTH; /* new table length */
static mutex_t  mutex_au_d = DEFAULTMUTEX;

int
au_open(void)
{
	int d;			/* descriptor */
	token_t	**au_d_new;

	(void) mutex_lock(&mutex_au_d);

	if (au_d_required_length > au_d_length) {
		au_d_new = (token_t **)calloc(au_d_required_length,
		    sizeof (au_d));

		if (au_d_new == NULL) {
			au_d_required_length = au_d_length;
			(void) mutex_unlock(&mutex_au_d);
			return (-1);
		}
		if (au_d_length > 0) {
			(void) memcpy(au_d_new, au_d, au_d_length *
			    sizeof (au_d));
			free(au_d);
		}
		au_d = au_d_new;
		au_d_length = au_d_required_length;
	}
	for (d = 0; d < au_d_length; d++) {
		if (au_d[d] == (token_t *)0) {
			au_d[d] = (token_t *)&au_d;
			(void) mutex_unlock(&mutex_au_d);
			return (d);
		}
	}
	/*
	 * table full; make more room.
	 * AU_TABLE_MAX limits recursion.
	 * Logic here expects AU_TABLE_MAX to be multiple of AU_TABLE_LENGTH
	 */
	if (au_d_length >= AU_TABLE_MAX) {
		(void) mutex_unlock(&mutex_au_d);
		return (-1);
	}
	au_d_required_length += AU_TABLE_LENGTH;
	(void) mutex_unlock(&mutex_au_d);

	return (au_open());
}

/*
 * Write to an audit descriptor.
 * Add the mbuf to the descriptor chain and free the chain passed in.
 */

int
au_write(int d, token_t *m)
{
	token_t *mp;

	if (d < 0)
		return (-1);
	if (m == (token_t *)0)
		return (-1);
	(void) mutex_lock(&mutex_au_d);
	if ((d >= au_d_length) || (au_d[d] == (token_t *)0)) {
		(void) mutex_unlock(&mutex_au_d);
		return (-1);
	} else if (au_d[d] == (token_t *)&au_d) {
		au_d[d] = m;
		(void) mutex_unlock(&mutex_au_d);
		return (0);
	}
	for (mp = au_d[d]; mp->tt_next != (token_t *)0; mp = mp->tt_next)
		;
	mp->tt_next = m;
	(void) mutex_unlock(&mutex_au_d);
	return (0);
}

/*
 * Close an audit descriptor.
 * Use the second parameter to indicate if it should be written or not.
 */
int
au_close(int d, int right, au_event_t e_type)
{
	au_emod_t e_mod;
	struct timeval now;	/* current time */
	adr_t adr;		/* adr header */
	auditinfo_addr_t	audit_info;
	au_tid_addr_t	*host_info = &audit_info.ai_termid;
	token_t *dchain;	/* mbuf chain which is the tokens */
	token_t *record;	/* mbuf chain which is the record */
	char data_header;	/* token type */
	char version;		/* token version */
	char *buffer;		/* to build record into */
	int  byte_count;	/* bytes in the record */
	int   v;

	(void) mutex_lock(&mutex_au_d);
	if (d < 0 || d >= au_d_length ||
	    ((dchain = au_d[d]) == (token_t *)0)) {
		(void) mutex_unlock(&mutex_au_d);
		return (-1);
	}

	au_d[d] = (token_t *)0;

	if (dchain == (token_t *)&au_d) {
		(void) mutex_unlock(&mutex_au_d);
		return (0);
	}
	/*
	 * If not to be written toss the record
	 */
	if (!right) {
		while (dchain != (token_t *)0) {
			record = dchain;
			dchain = dchain->tt_next;
			free(record->tt_data);
			free(record);
		}
		(void) mutex_unlock(&mutex_au_d);
		return (0);
	}

	/*
	 * Count up the bytes used in the record.
	 */
	byte_count = sizeof (char) * 2 + sizeof (short) * 2 +
	    sizeof (int32_t) + sizeof (struct timeval);

	for (record = dchain; record != (token_t *)0;
	    record = record->tt_next) {
		byte_count += record->tt_size;
	}

#ifdef _LP64
#define	HEADER_ID	AUT_HEADER64
#define	HEADER_ID_EX	AUT_HEADER64_EX
#else
#define	HEADER_ID	AUT_HEADER32
#define	HEADER_ID_EX	AUT_HEADER32_EX
#endif

	/* Use the extended headed if our host address can be determined. */

	data_header = HEADER_ID;		/* Assume the worst */
	if (auditon(A_GETKAUDIT, (caddr_t)&audit_info,
	    sizeof (audit_info)) == 0) {
		int	have_valid_addr;

		if (host_info->at_type == AU_IPv6)
			have_valid_addr = IN6_IS_ADDR_UNSPECIFIED(
			    (in6_addr_t *)host_info->at_addr) ? 0 : 1;
		else
			have_valid_addr = (host_info->at_addr[0] ==
			    htonl(INADDR_ANY)) ? 0 : 1;

		if (have_valid_addr) {
			data_header = HEADER_ID_EX;
			byte_count += sizeof (int32_t) + host_info->at_type;
		}
	}

	/*
	 * Build the header
	 */
	if ((buffer = malloc((size_t)byte_count)) == NULL) {
		/* free the token chain */
		while (dchain != (token_t *)0) {
			record = dchain;
			dchain = dchain->tt_next;
			free(record->tt_data);
			free(record);
		}
		(void) mutex_unlock(&mutex_au_d);
		return (-1);
	}
	(void) gettimeofday(&now, NULL);
	version = TOKEN_VERSION;
	e_mod = 0;
	adr_start(&adr, buffer);
	adr_char(&adr, &data_header, 1);
	adr_int32(&adr, (int32_t *)&byte_count, 1);
	adr_char(&adr, &version, 1);
	adr_ushort(&adr, &e_type, 1);
	adr_ushort(&adr, &e_mod, 1);
	if (data_header == HEADER_ID_EX) {
		adr_int32(&adr, (int32_t *)&host_info->at_type, 1);
		adr_char(&adr, (char *)&host_info->at_addr[0],
		    (int)host_info->at_type);
	}
#ifdef _LP64
	adr_int64(&adr, (int64_t *)&now, 2);
#else
	adr_int32(&adr, (int32_t *)&now, 2);
#endif
	/*
	 * Tack on the data, and free the tokens.
	 * We're not supposed to know how adr works, but ...
	 */
	while (dchain != (token_t *)0) {
		(void) memcpy(adr.adr_now, dchain->tt_data, dchain->tt_size);
		adr.adr_now += dchain->tt_size;
		record = dchain;
		dchain = dchain->tt_next;
		free(record->tt_data);
		free(record);
	}
	/*
	 * Send it down to the system
	 */
	v = audit((caddr_t)buffer, byte_count);
	free(buffer);
	(void) mutex_unlock(&mutex_au_d);
	return (v);
}
