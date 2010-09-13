/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2001, 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "gnu_msgfmt.h"
#include "../../lib/libc/inc/msgfmt.h"

struct messages	*
search_msg(struct catalog *p, const char *id, unsigned int hash_val)
{
	unsigned int	i, idx, inc;
	struct messages	*m;

	idx = hash_val % p->thash_size;
	inc = 1 + (hash_val % (p->thash_size - 2));
	if (!p->thash[idx])
		return (NULL);

	m = p->msg;
	for (m = p->msg; (i = p->thash[idx]) != 0;
		idx = (idx + inc) % p->thash_size) {
		if (strcmp(m[i - 1].id, id) == 0) {
			/* found */
			return (&m[i - 1]);
		}
	}
	return (NULL);
}

static int
msg_cmp(struct messages *m1, struct messages *m2)
{
	return (strcmp(m1->id, m2->id));
}

void
output_all_gnu_mo_files(void)
{
	struct catalog	*p, *op;
	struct messages	*m;
	size_t	id_len, str_len, id_off, str_off, ids_top, strs_top;
	unsigned int	*hash_tbl;
	unsigned int	hash_size;
	unsigned int	num = 0, fnum = 0, unum = 0;
	unsigned int	i, idx;
	char	*ids, *strs;
	struct msgtbl	*id_tbl, *str_tbl;
	struct gnu_msg_info	header;
	FILE	*out;

	p = catalog_head;

	while (p) {
		num += p->nmsg;
		fnum += p->fnum;
		unum += p->unum;


		free(p->thash);
		if (p->nmsg == 0) {
			/*
			 * no message in this file
			 * skip generating a mo
			 */
			goto skip;
		}

		if (p->header)
			num--;

		p->msg = (struct messages *)Xrealloc(p->msg,
			sizeof (struct messages) * p->nmsg);

		/*
		 * Sort the message array
		 */
		qsort(p->msg, p->nmsg, sizeof (struct messages),
			(int (*)(const void *, const void *))msg_cmp);


		hash_size = find_prime(p->nmsg);
		hash_tbl = (unsigned int *)Xcalloc(hash_size,
			sizeof (unsigned int));


		/* Setting Header info */
		header.magic = GNU_MAGIC;
		header.revision = GNU_REVISION;
		header.num_of_str = p->nmsg;
		header.off_msgid_tbl = sizeof (struct gnu_msg_info);
		header.off_msgstr_tbl = sizeof (struct gnu_msg_info) +
			p->nmsg * sizeof (struct msgtbl);
		header.sz_hashtbl = hash_size;
		header.off_hashtbl = header.off_msgstr_tbl +
			p->nmsg * sizeof (struct msgtbl);

		m = p->msg;

		id_len = 0;
		str_len = 0;
		for (i = 0; i < p->nmsg; i++) {
			id_len += m[i].id_len;
			str_len += m[i].str_len;
		}
		ids = (char *)Xmalloc(id_len);
		strs = (char *)Xmalloc(str_len);
		id_tbl = (struct msgtbl *)Xmalloc(sizeof (struct msgtbl) *
			p->nmsg);
		str_tbl = (struct msgtbl *)Xmalloc(sizeof (struct msgtbl) *
			p->nmsg);
		id_off = 0;
		str_off = 0;
		ids_top = header.off_hashtbl +
			sizeof (unsigned int) * hash_size;
		strs_top = ids_top + id_len;
		for (i = 0; i < p->nmsg; i++) {
			/*
			 * Set the hash table
			 */
			idx = get_hash_index(hash_tbl, m[i].hash, hash_size);
			hash_tbl[idx] = i + 1;

			/*
			 * rearrange msgid and msgstr
			 */
			id_tbl[i].len = m[i].id_len - 1;
			str_tbl[i].len = m[i].str_len - 1;
			id_tbl[i].offset = id_off + ids_top;
			str_tbl[i].offset = str_off + strs_top;
			(void) memcpy(ids + id_off, m[i].id, m[i].id_len);
			(void) memcpy(strs + str_off, m[i].str, m[i].str_len);
			id_off += m[i].id_len;
			str_off += m[i].str_len;
			free(m[i].id);
			free(m[i].str);
		}

		if ((out = fopen(p->fname, "w")) == NULL) {
			error(gettext(ERR_OPEN_FAILED), p->fname);
			/* NOTREACHED */
		}

		/* writing header */
		(void) fwrite(&header, sizeof (struct gnu_msg_info),
			1, out);

		/* writing msgid offset table */
		(void) fwrite(id_tbl, sizeof (struct msgtbl),
			p->nmsg, out);
		/* writing msgstr offset table */
		(void) fwrite(str_tbl, sizeof (struct msgtbl),
			p->nmsg, out);
		/* writing hash table */
		(void) fwrite(hash_tbl, sizeof (unsigned int),
			hash_size, out);
		/* writing msgid table */
		(void) fwrite(ids, id_len, 1, out);
		/* writing msgstr table */
		(void) fwrite(strs, str_len, 1, out);

		(void) fclose(out);
		free(id_tbl);
		free(str_tbl);
		free(hash_tbl);
		free(ids);
		free(strs);
skip:
		free(p->fname);
		free(p->msg);
		op = p->next;
		free(p);
		p = op;
	}
	if (verbose_flag) {
		diag(gettext(DIAG_RESULTS), num, fnum, unum);
	}
}
