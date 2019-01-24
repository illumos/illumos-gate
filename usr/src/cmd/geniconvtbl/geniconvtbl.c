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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <synch.h>

#if defined(DEBUG)
#include <stdarg.h>
#endif /* !DEBUG */

#include "iconv_tm.h"
#include "hash.h"


/*
 * Debug
 */
#if defined(DEBUG)

static void	trace_init(void);
static void	trace_message(char *, ...);

static char	trace_option[128];

#define	TRACE(c)		(*(trace_option + (c & 0x007f)))
#define	TRACE_MESSAGE(c, args)	((TRACE(c))? trace_message args: (void)0)

#else /* !DEBUG */

#define	trace_init()
#define	TRACE()
#define	TRACE_MESSAGE(c, args)

#endif /* !DEBUG */


/*
 * ITM reference information
 */
typedef struct _itm_ref {
	char		*name;		/* ITM file name */
	itm_hdr_t	*hdr;		/* address of ITM */
	size_t		len;		/* length of ITM */
} itm_ref_t;


/*
 * struct _icv_state; to keep status
 */
typedef struct _icv_state {
	struct _itm_ref	*itm;		/* reference to ITM */
	itm_hdr_t	*itm_hdr;	/* address of ITM */
	itm_tbl_hdr_t	*direc;		/* current direction */
	itm_place_t	default_action;	/* default action */
	itm_num_t	*regs;		/* register */
	itm_num_t	reg_num;	/* number of register */
#if defined(OP_DEPTH_MAX)
	int		op_depth;	/* depth of operation */
#endif /* OP_DEPTH_MAX */
} icv_state_t;


/*
 * function prototype
 */
void *	_icv_open(const char *);
void	_icv_close(icv_state_t *);
size_t	_icv_iconv(icv_state_t *, const unsigned char **,
		    size_t *, unsigned char **, size_t *);

static size_t	map_i_f(itm_tbl_hdr_t *,
			const unsigned char **, size_t *,
			unsigned char **, size_t *, long);
static size_t	map_l_f(itm_tbl_hdr_t *,
			const unsigned char **, size_t *,
			unsigned char **, size_t *, long);
static size_t	map_h_l(itm_tbl_hdr_t *,
			const unsigned char **, size_t *,
			unsigned char **, size_t *, long);
static size_t	map_d_e_l(itm_tbl_hdr_t *,
			const unsigned char **, size_t *,
			unsigned char **, size_t *, long);
static size_t	eval_cond_tbl(icv_state_t *, itm_place_t,
			const unsigned char **, size_t *,
			size_t, itm_direc_t *);
static size_t	eval_op_tbl(icv_state_t *, itm_place_t,
			const unsigned char **, size_t *,
			unsigned char **, size_t *);
static size_t	eval_op(icv_state_t *, itm_place2_t,
			const unsigned char **, size_t *,
			unsigned char **, size_t *);

static itm_num_t	eval_expr(icv_state_t *, itm_place_t,
				size_t, const unsigned char *, size_t);

static void		itm_ref_free(int, void *, void *, void *, size_t);
static itm_ref_t	*itm_ref_inc(const char *);
static void		itm_ref_dec(itm_ref_t *);

static void		op_init_default(icv_state_t *);
static void		op_reset_default(icv_state_t *);
static void		regs_init(icv_state_t *);


/*
 * macro definition
 */

#define	ADDR(place)	((void *)(((char *)(ist->itm_hdr)) +\
				((itm_place2_t)(place.itm_ptr))))
#define	ADDR2(place2)	((void *)(((char *)(ist->itm_hdr)) +\
				((itm_place2_t)(place2))))
#define	DADDR(n)	(((n)->size <= (sizeof ((n)->place.itm_64d))) ?	\
				((unsigned char *)(&((n)->place.itm_64d))) :\
				((unsigned char *)(ADDR((n)->place))))

#define	REG(n)		(*(ist->regs + (n)))
#define	DISCARD(c)	(((*inbuf) = (void *)((*inbuf) + (c))),\
			((*inbytesleft) -= (c)))
#define	GET(c)		((c) = **inbuf, (*inbuf)++, (*inbytesleft)--)
#define	PUT(c)		(**outbuf = (c), (*outbuf)++, (*outbytesleft)--)

#define	RETVALERR	((size_t)(-1))
#define	RETVALDIR	((size_t)(-2))
#define	RETVALBRK	((size_t)(-3))
#define	RETVALRET	((size_t)(-4))

#define	UPDATE_ARGS()	(*inbuf = ip, \
			 *inbytesleft = ileft, \
			 *outbuf = op, \
			 *outbytesleft = oleft)

/*
 * Open; called from iconv_open()
 */
void *
_icv_open(const char	*itm)
{
	icv_state_t	*ist;
	itm_hdr_t	*hdr;
	itm_ref_t	*itm_ref;
	int		r;

	/*
	 * for debug
	 */
	trace_init();

	/*
	 * _icv_open() primaty task
	 */
	itm_ref = itm_ref_inc(itm);
	if (NULL == itm_ref) {
		return ((void *)(-1));
	}

	if (NULL == (ist = malloc(sizeof (icv_state_t)))) {
		r = errno;
		itm_ref_dec(itm_ref);
		errno = r;
		return	(NULL);
	}

	ist->itm = itm_ref;
	ist->itm_hdr = ist->itm->hdr;
	ist->reg_num = ist->itm->hdr->reg_num;

	hdr =  ist->itm->hdr;
	ist->direc = ADDR(hdr->direc_init_tbl);
	ist->default_action.itm_64d = 0;
#if defined(OP_DEPTH_MAX)
	ist->op_depth = 0;
#endif /* OP_DEPTH_MAX */


	/*
	 * brief sanity check
	 */
	if (hdr->itm_size.itm_ptr <= hdr->direc_init_tbl.itm_ptr) {
		_icv_close(ist);
		errno = ELIBBAD;
		return ((void *)(-1));
	}


	/* allocate register region */
	if (hdr->reg_num <= 0) {
		ist->regs = NULL;
	} else {
		ist->regs = malloc((sizeof (itm_num_t)) * hdr->reg_num);
		if (NULL == ist->regs) {
			r = errno;
			_icv_close(ist);
			errno = r;
			return ((void *)(-1));
		}
		(void) memset(ist->regs, 0,
		    (sizeof (itm_num_t)) * hdr->reg_num);
	}


	/* evaluate init operation */
	if (0 != ist->itm_hdr->op_init_tbl.itm_ptr) {
		const unsigned char	*ip = NULL;
		size_t			ileft = 0;
		unsigned char		*op = NULL;
		size_t			oleft = 0;
		(void) eval_op_tbl(ist, ist->itm_hdr->op_init_tbl, &ip,
		    &ileft, &op, &oleft);
	} else {
		op_init_default(ist);
	}

	return	(ist);
}


/*
 * Close; called from iconv_close
 */
void
_icv_close(icv_state_t		*ist)
{
	if (NULL == ist) {
		errno = EBADF;
		return;
	}
	itm_ref_dec(ist->itm);
	free(ist->regs);
	free(ist);
}


/*
 * Actual conversion; called from iconv()
 */
size_t
_icv_iconv(
	icv_state_t		*ist,
	const unsigned char	**inbuf,
	size_t			*inbytesleft,
	unsigned char		**outbuf,
	size_t			*outbytesleft)
{
	size_t			retval;
	itm_hdr_t		*hdr;
	itm_type_t		type;
	const unsigned char	*ip;
	size_t			ileft;
	itm_place_t		action;

	if (NULL == ist) {
		errno = EBADF;
		TRACE_MESSAGE('e', ("_icv_iconv: error=%d\n", errno));
		return ((size_t)(-1));
	}
	if (NULL == inbuf) {
		ip = NULL;
		inbuf = &ip;
	}
	if (NULL == inbytesleft) {
		ileft = 0;
		inbytesleft = &ileft;
	}

	hdr = ist->itm_hdr;

	retval = 0;

	TRACE_MESSAGE('i', ("_icv_iconv(inbuf=%p inbytesleft=%ld "
	    "outbuf=%p outbytesleft=%ld)\n", (NULL == inbuf) ? 0 : *inbuf,
	    (NULL == inbytesleft) ? 0 : *inbytesleft,
	    (NULL == outbuf) ? 0 : *outbuf,
	    (NULL == outbytesleft) ? 0 : *outbytesleft));

	/*
	 * If (NULL == inbuf || NULL == *inbuf) then this conversion is
	 * placed into initial state.
	 */
	if ((NULL == inbuf) || (NULL == *inbuf)) {
		if (0 != hdr->op_reset_tbl.itm_ptr) {
			ist->direc = ADDR(hdr->direc_init_tbl);
			retval = eval_op_tbl(ist, hdr->op_reset_tbl, inbuf,
			    inbytesleft, outbuf, outbytesleft);
			if ((size_t)(-1) == retval) {
				return	(retval);
			}
		} else {
			op_reset_default(ist);
		}
		return ((size_t)(0));
	}

	if (ITM_TBL_MAP_INDEX_FIXED_1_1 == ist->direc->type) {
		itm_map_idx_fix_hdr_t	*map_hdr;
		char			*map;
		const unsigned char	*ip;
		size_t			ileft;
		unsigned char		*op;
		size_t			oleft;

		map_hdr = (itm_map_idx_fix_hdr_t *)(ist->direc + 1);
		map = (char *)(map_hdr + 1);

		if (1 == map_hdr->default_error) {
			retval = map_i_f(ist->direc, inbuf, inbytesleft,
			    outbuf, outbytesleft, 0);
			return	(retval);
		}

		ip = *inbuf;
		ileft = *inbytesleft;
		op = *outbuf;
		oleft = *outbytesleft;

		while (1 <= ileft) {
			if (oleft < 1) {
				UPDATE_ARGS();
				errno = E2BIG;
				TRACE_MESSAGE('e', ("_icv_iconv: error=%d\n",
				    errno));
				return ((size_t)-1);
			}
			*(op++) = *(map + *(ip++));
			ileft--;
			oleft--;

		}
		UPDATE_ARGS();
		return (0);
	} else if (ITM_TBL_MAP_INDEX_FIXED == ist->direc->type) {
		retval = map_i_f(ist->direc, inbuf, inbytesleft,
		    outbuf, outbytesleft, 0);
		return	(retval);
	} else if (ITM_TBL_MAP_HASH == ist->direc->type) {
		retval = map_h_l(ist->direc, inbuf, inbytesleft,
		    outbuf, outbytesleft, 0);
		return	(retval);
	} else if (ITM_TBL_MAP_DENSE_ENC == ist->direc->type) {
		retval = map_d_e_l(ist->direc, inbuf, inbytesleft,
		    outbuf, outbytesleft, 0);
		return	(retval);
	} else if (ITM_TBL_MAP_LOOKUP == ist->direc->type) {
		retval = map_l_f(ist->direc, inbuf, inbytesleft,
		    outbuf, outbytesleft, 0);
		return	(retval);
	}

#if defined(OP_DEPTH_MAX)
	ist->op_depth = 0;
#endif /* OP_DEPTH_MAX */


	/*
	 * Main loop; basically 1 loop per 1 output character
	 */
retry_cond_eval:
	while (0 < *inbytesleft) {
		itm_tbl_hdr_t	*direc_hdr;
		itm_direc_t	*direc;
		long		i;

		direc_hdr = ist->direc;
		direc = (itm_direc_t *)(ist->direc + 1);
		for (i = 0; /* NULL */; i++, direc++) {
			if (i >= direc_hdr->number) {
				if (0 == ist->default_action.itm_ptr) {
					errno = EILSEQ;
					TRACE_MESSAGE('e',
					    ("_icv_iconv:error=%d\n", errno));
					return ((size_t)(-1));
				}



				action = ist->default_action;
				type = ((itm_tbl_hdr_t *)(ADDR(action)))->type;
				TRACE_MESSAGE('E',
				    ("escape seq (default action=%6p, "
				    "type=%ld) executing\n",
				    action.itm_ptr, type));
			} else if (0 != direc->condition.itm_ptr) {
				retval = eval_cond_tbl(ist, direc->condition,
				    inbuf, inbytesleft, *outbytesleft, direc);
				if ((size_t)(0) == retval) {
					continue;
				} else if ((size_t)(-1) == retval) {
					return	(retval);
				} else if ((size_t)(2) == retval) {
					goto retry_cond_eval;
				}
				action = direc->action;
				type = ((itm_tbl_hdr_t *)(ADDR(action)))->type;
			} else {
				action = direc->action;
				type = ((itm_tbl_hdr_t *)(ADDR(action)))->type;
			}

			TRACE_MESSAGE('a',
			    ("inbytesleft=%ld; type=%ld:action=%p\n",
			    *inbytesleft, type, action.itm_ptr));
			switch (ITM_TBL_MASK & type) {
			case ITM_TBL_OP:
				retval = eval_op_tbl(ist, action,
				    inbuf, inbytesleft, outbuf, outbytesleft);
				if ((size_t)(-1) == retval) {
					return	(retval);
				}
				break;
			case ITM_TBL_DIREC:
				ist->direc = ADDR(action);
				break;
			case ITM_TBL_MAP:
				switch (type) {
				case ITM_TBL_MAP_INDEX_FIXED_1_1:
				case ITM_TBL_MAP_INDEX_FIXED:
					retval = map_i_f(ADDR(action),
					    inbuf, inbytesleft,
					    outbuf, outbytesleft, 1);
					break;
				case ITM_TBL_MAP_HASH:
					retval = map_h_l(ADDR(action),
					    inbuf, inbytesleft,
					    outbuf, outbytesleft, 1);
					break;
				case ITM_TBL_MAP_DENSE_ENC:
					retval = map_d_e_l(ADDR(action),
					    inbuf, inbytesleft,
					    outbuf, outbytesleft, 1);
					break;
				case ITM_TBL_MAP_LOOKUP:
					retval = map_l_f(ADDR(action),
					    inbuf, inbytesleft,
					    outbuf, outbytesleft, 1);
					break;
				default:
					errno = ELIBBAD;
					TRACE_MESSAGE('e',
					    ("_icv_iconv:error=%d\n", errno));
					return ((size_t)(-1));

				}
				if ((size_t)(-1) == retval) {
					return	(retval);
				}
				break;
			default:	/* never */
				errno = ELIBBAD;
				TRACE_MESSAGE('e',
				    ("_icv_iconv:error=%d\n", errno));
				return ((size_t)(-1));
			}
			break;
		}
	}
	return	(retval);
}



/*
 * map-indexed-fixed
 */
static size_t
map_i_f(
	itm_tbl_hdr_t		*tbl_hdr,
	const unsigned char	**inbuf,
	size_t			*inbytesleft,
	unsigned char		**outbuf,
	size_t			*outbytesleft,
	long			once)
{
	itm_map_idx_fix_hdr_t	*map_hdr;
	long			i;
	unsigned char		c;
	unsigned long		j;
	const unsigned char	*p;

	TRACE_MESSAGE('i', ("map_i_f\n"));

	map_hdr = (itm_map_idx_fix_hdr_t *)(tbl_hdr + 1);

	do {
		if (*inbytesleft < map_hdr->source_len) {
			errno = EINVAL;
			TRACE_MESSAGE('e', ("map_i_f:error=%d\n", errno));
			return ((size_t)(-1));
		}

		j = 0;
		for (i = 0; i < map_hdr->source_len; i++) {
			GET(c);
			j = ((j << 8) | c);
		}

		if (((j < map_hdr->start.itm_ptr) ||
		    (map_hdr->end.itm_ptr < j)) &&
		    (0 < map_hdr->default_error)) {
			errno = EILSEQ;
			(*inbuf) = (void*) ((*inbuf) - map_hdr->source_len);
			(*inbytesleft) += map_hdr->source_len;
			TRACE_MESSAGE('e', ("map_i_f:error=%d\n", errno));
			return ((size_t)(-1));
		}

		if (*outbytesleft < map_hdr->result_len) {
			errno = E2BIG;
			(*inbuf) = (void *)((*inbuf) - map_hdr->source_len);
			(*inbytesleft) += map_hdr->source_len;
			TRACE_MESSAGE('e', ("map_i_f:error=%d\n", errno));
			return ((size_t)(-1));
		}

		if ((j < map_hdr->start.itm_ptr) ||
		    (map_hdr->end.itm_ptr < j)) {
			if (0 == map_hdr->default_error) {
				p = (((unsigned char *)(map_hdr + 1)) +
				    (map_hdr->result_len * (tbl_hdr->number)));
				for (i = 0; i < map_hdr->result_len; i++) {
					PUT(*(p + i));
				}
			} else {
				p = ((*inbuf) - map_hdr->source_len);
				for (i = 0; i < map_hdr->source_len; i++) {
					PUT(*(p + i));
				}
			}
		} else {
			char	*map_error;
			map_error = (((char *)(map_hdr + 1)) +
			    (map_hdr->result_len * (tbl_hdr->number)) +
			    (j - map_hdr->start.itm_ptr));
			if (0 == map_hdr->default_error) {
				map_error = (void *)
				    (map_error + map_hdr->result_len);
			}
			if (((1 == map_hdr->default_error) ||
			    (0 < map_hdr->error_num)) &&
			    (0 != *(map_error))) {
				errno = EILSEQ;
				(*inbuf) = (void *)
				    ((*inbuf) - map_hdr->source_len);
				(*inbytesleft) += map_hdr->source_len;
				TRACE_MESSAGE('e',
				    ("map_i_f:error=%d\n", errno));
				return ((size_t)(-1));
			}
			p = (((unsigned char *)(map_hdr + 1)) +
			    (map_hdr->result_len *
			    (j - map_hdr->start.itm_ptr)));
			for (i = 0; i < map_hdr->result_len; i++) {
				PUT(*(p + i));
			}
		}
	} while ((0 < *inbytesleft) && (0 == once));

	return (size_t)(0);
}


/*
 * map-lookup-fixed
 */
static size_t
map_l_f(
	itm_tbl_hdr_t	*tbl_hdr,
	const unsigned char	**inbuf,
	size_t		*inbytesleft,
	unsigned char	**outbuf,
	size_t		*outbytesleft,
	long		once)
{
	itm_map_lookup_hdr_t	*map_hdr;
	long			i;
	unsigned char		*map;
	const unsigned char	*p;
	long			high;
	long			mid;
	long			low;
	long			result;
	itm_size_t		pair_size;

	TRACE_MESSAGE('i', ("map_l_f\n"));

	map_hdr = (itm_map_lookup_hdr_t *)(tbl_hdr + 1);
	map = (unsigned char *)(map_hdr + 1);
	pair_size = map_hdr->source_len + 1 + map_hdr->result_len;

	do {
		if (*inbytesleft < map_hdr->source_len) {
			errno = EINVAL;
			TRACE_MESSAGE('e', ("map_l_f:error=%d\n", errno));
			return ((size_t)(-1));
		}

		for (low = 0, high = tbl_hdr->number; low < high; ) {
			mid = (low + high) / 2;
			p = map + (pair_size * mid);
			for (i = 0, result = 0; i < map_hdr->source_len;
			    i++, p++) {
				if (*(unsigned char *)(*inbuf + i) < *p) {
					result = -1;
					break;
				}
				if (*p < *(unsigned char *)(*inbuf + i)) {
					result = 1;
					break;
				}
			}
			if (result < 0) {
				high = mid;
			} else if (0 < result) {
				low = mid + 1;
			} else { /* 0 == result */
				break;
			}
		}

		if (0 != result) {
			if (map_hdr->default_error < 0) {
				p = *inbuf;
			} else if (0 == map_hdr->default_error) {
				p = map + (pair_size * tbl_hdr->number) +
				    map_hdr->source_len + 1;
			} else if (0 < map_hdr->default_error) {
				errno = EILSEQ;
				TRACE_MESSAGE('e', ("map_l_f:error=%d\n",
				    errno));
				return ((size_t)(-1));
			}
		} else {
			if (0 != (*p)) {
				errno = EILSEQ;
				TRACE_MESSAGE('e', ("map_l_f:error=%d\n",
				    errno));
				return ((size_t)(-1));
			}
			p++;
		}

		if (*outbytesleft < map_hdr->result_len) {
			errno = E2BIG;
			TRACE_MESSAGE('e', ("map_l_f:error=%d\n", errno));
			return ((size_t)(-1));
		}
		DISCARD(map_hdr->source_len);

		for (i = 0; i < map_hdr->result_len; i++) {
			PUT(*(p + i));
		}
	} while ((0 < *inbytesleft) && (0 == once));

	return ((size_t)(0));
}


/*
 * map-hash-lookup
 */
static size_t
map_h_l(
	itm_tbl_hdr_t	*tbl_hdr,
	const unsigned char	**inbuf,
	size_t		*inbytesleft,
	unsigned char	**outbuf,
	size_t		*outbytesleft,
	long		once)
{
	itm_map_hash_hdr_t	*map_hdr;
	long			i;
	unsigned char	*map_error;
	unsigned char	*map_hash;
	unsigned char	*map_of;
	const unsigned char	*p;
	const unsigned char	*q;
	long			high;
	long			mid;
	long			low;
	long			result;
	itm_size_t		pair_size;
	itm_size_t		hash_value;
	itm_size_t		source_len;
	itm_size_t		result_len;

	TRACE_MESSAGE('i', ("map_hash\n"));

	map_hdr = (itm_map_hash_hdr_t *)(tbl_hdr + 1);
	map_error = (unsigned char *)(map_hdr + 1);
	map_hash = (map_error + map_hdr->hash_tbl_num);
	map_of = map_hash + map_hdr->hash_tbl_size;
	pair_size = map_hdr->source_len + 1 + map_hdr->result_len;
	source_len = map_hdr->source_len;
	result_len = map_hdr->result_len;

	do {
		if (*inbytesleft < source_len) {
			errno = EINVAL;
			TRACE_MESSAGE('e', ("map_h_l:error=%d\n", errno));
			return ((size_t)(-1));
		}

		result = 1;
		q = *inbuf;
		hash_value = hash((const char *)(q), source_len,
		    map_hdr->hash_tbl_num);
		p = map_hash + (pair_size * hash_value);
		if (1 == *(map_error + hash_value)) {
			for (i = 0, result = 0; i < source_len; i++) {
				if (*(q + i) != *(p++)) {
					result = -2;
					break;
				}
			}
			TRACE_MESSAGE('G',
			    ("(h=%d): find pair without conflict\n",
			    hash_value));
		} else if (0 == *(map_error + hash_value)) {
			TRACE_MESSAGE('G', ("(h=%d): No Pair\n", hash_value));
			result = -3;
		} else /* if (0 < *(map_error + hash_value)) */ {
			for (i = 0, result = 0; i < source_len; i++) {
				if (*(q + i) != *(p++)) {
					result = 1;
					break;
				}
			}
			if (0 < result) {
				for (low = 0, high = map_hdr->hash_of_num;
				    low < high; /* NOP */) {
					mid = (low + high) / 2;
					p = map_of + (pair_size * mid);
					for (i = 0, result = 0;
					    i < source_len;
					    i++, p++) {
						if (*(q + i) < *p) {
							result = -1;
							break;
						}
						if (*p < *(q + i)) {
							result = 1;
							break;
						}
					}
					if (result < 0) {
						high = mid;
					} else if (0 < result) {
						low = mid + 1;
					} else { /* 0 == result */
						TRACE_MESSAGE('G', ("(h=%d): "
						    "find data on out of "
						    "hashtable with CONFLICT\n",
						    hash_value));
						break;
					}
				}
			}
		}
		if (0 != result) {
			if (map_hdr->default_error < 0) {
				p = q;
			} else if (0 == map_hdr->default_error) {
				p = map_of + map_hdr->hash_of_size;
			} else if (0 < map_hdr->default_error) {
				TRACE_MESSAGE('G', ("(h=%d): NO PAIR\n",
				    hash_value));
				errno = EILSEQ;
				TRACE_MESSAGE('e',
				    ("map_h_l:error=%d\n", errno));
				return ((size_t)(-1));
			}
		} else {
			if (0 != (*p)) {
				errno = EILSEQ;
				TRACE_MESSAGE('G', ("	      : error pair\n"));
				TRACE_MESSAGE('e', ("map_l_f:error\n", errno));
				return ((size_t)(-1));
			}
			p++;
		}

		if (*outbytesleft < result_len) {
			errno = E2BIG;
			TRACE_MESSAGE('e', ("map_h_l:error=%d\n", errno));
			return ((size_t)(-1));
		}
		DISCARD(source_len);

		for (i = 0; i < result_len; i++) {
			PUT(*(p + i));
		}
	} while ((0 < *inbytesleft) && (0 == once));

	return ((size_t)(0));
}


/*
 * map-dense_encoding-lookup
 */
static size_t
map_d_e_l(
	itm_tbl_hdr_t		*tbl_hdr,
	const unsigned char	**inbuf,
	size_t			*inbytesleft,
	unsigned char		**outbuf,
	size_t			*outbytesleft,
	long			once)
{
	itm_map_dense_enc_hdr_t	*map_hdr;
	long			i;
	itm_num_t		j;
	const unsigned char	*p;
	unsigned char		*map_ptr;
	unsigned char		*map_error;
	unsigned char		*byte_seq_min;
	unsigned char		*byte_seq_max;

	TRACE_MESSAGE('i', ("map_d_e_l\n"));

	map_hdr = (itm_map_dense_enc_hdr_t *)(tbl_hdr + 1);
	map_ptr = ((unsigned char *)(map_hdr + 1) + map_hdr->source_len +
	    map_hdr->source_len);
	map_error = (map_ptr + (tbl_hdr->number * map_hdr->result_len));
	if (0 == map_hdr->default_error) {
		map_error = (void *)(map_error + map_hdr->result_len);
	}
	byte_seq_min = (unsigned char *)(map_hdr + 1);
	byte_seq_max = byte_seq_min + map_hdr->source_len;

	do {
		if (*inbytesleft < map_hdr->source_len) {
			errno = EINVAL;
			TRACE_MESSAGE('e', ("map_d_e_l:error=%d\n", errno));
			return ((size_t)(-1));
		}

		j = hash_dense_encoding(*inbuf, map_hdr->source_len,
		    byte_seq_min, byte_seq_max);

		if (((j < 0) || (tbl_hdr->number < j)) &&
		    (0 < map_hdr->default_error)) {
			errno = EILSEQ;
			TRACE_MESSAGE('e', ("map_d_e_l:error=%d\n", errno));
			return ((size_t)(-1));
		}

		if (*outbytesleft < map_hdr->result_len) {
			errno = E2BIG;
			TRACE_MESSAGE('e', ("map_d_e_l:error=%d\n", errno));
			return ((size_t)(-1));
		}

		if ((j < 0) || (tbl_hdr->number < j)) {
			if (0 == map_hdr->default_error) {
				p = (map_ptr + (tbl_hdr->number *
				    map_hdr->result_len));
				for (i = 0; i < map_hdr->result_len; i++) {
					PUT(*(p + i));
				}
			} else {
				p = *inbuf;
				for (i = 0; i < map_hdr->source_len; i++) {
					PUT(*(p + i));
				}
			}
		} else {
			if ((1 == map_hdr->default_error) ||
			    (0 < map_hdr->error_num)) {
				if (0 != *(map_error + j)) {
					errno = EILSEQ;
					TRACE_MESSAGE('e',
					    ("map_d_e_l:error=%d\n", errno));
					return ((size_t)(-1));
				}
			}
			p = (map_ptr + (map_hdr->result_len * j));
			for (i = 0; i < map_hdr->result_len; i++) {
				PUT(*(p + i));
			}
		}
		DISCARD(map_hdr->source_len);
	} while ((0 < *inbytesleft) && (0 == once));

	return ((size_t)(0));
}



/*
 * Evaluate condition table
 *
 */
static size_t
eval_cond_tbl(icv_state_t *ist, itm_place_t cond_place,
    const unsigned char **inbuf, size_t *inbytesleft, size_t outbytesleft,
    itm_direc_t *direc)
{
	itm_tbl_hdr_t		*cond_hdr;
	itm_cond_t		*cond;
	long			i;
	long			j;
	long			k;
	size_t			retval;
	itm_tbl_hdr_t		*rth;
	itm_range_hdr_t		*rtsh;
	unsigned char		*p;
	itm_tbl_hdr_t		*eth;
	itm_escapeseq_hdr_t	*eh;
	itm_data_t		*d;
	const unsigned char	*ip;
	size_t			ileft;

	retval = 0;
	ip =	*inbuf;
	ileft = *inbytesleft;
	cond_hdr = ADDR(cond_place);
	cond = (itm_cond_t *)(cond_hdr + 1);
	for (i = 0; i < cond_hdr->number; i++, cond++) {
		switch (cond->type) {
		case ITM_COND_BETWEEN:
			rth = ADDR(cond->operand.place);
			rtsh = (itm_range_hdr_t *)(rth + 1);
			if (ileft < rtsh->len) {
				errno = EINVAL;
				TRACE_MESSAGE('e', ("eval_cond_tbl:error=%d\n",
				    errno));
				retval = ((size_t)(-1));
				goto eval_cond_return;
			}
			p = (unsigned char *)(rtsh + 1);
			retval = 0;
			for (j = 0; j < rth->number;
			    j++,  p = (void *)(p + (2 * rtsh->len))) {
				retval = 1;
				for (k = 0; k < rtsh->len; k++) {
					if ((*(ip + k) < *(p + k)) ||
					    (*(p + rtsh->len + k) <
					    *(ip + k))) {
						retval = 0;
						break;
					}
				}
				if (1 == retval) {
					break;
				}
			}
			if (0 == retval) {
				TRACE_MESSAGE('b',
				    ("out of between (%p) len= rtsh=%ld\n",
				    *ip, rtsh->len));
				goto eval_cond_return;
			}
			break; /* continue */
		case ITM_COND_ESCAPESEQ:
			/*
			 * if escape sequence occur,
			 * change ist->default_action and return 2.
			 * never return 1.
			 */
			retval = 0;
			eth = ADDR(cond->operand.place);
			eh = (itm_escapeseq_hdr_t *)(eth + 1);
			if (0 == ist->default_action.itm_ptr) {
				ist->default_action = direc->action;
				TRACE_MESSAGE('E',
				    ("escape seq (default action=%6p, "
				    "type=%ld) set\n",
				    direc->action.itm_ptr, ((itm_tbl_hdr_t *)
				    (ADDR(direc->action)))->type));
			}
			retval = 0;
			if (*inbytesleft < eh->len_min) {
				break;
			}
			for (j = 0, d = (itm_data_t *)(eh + 1);
			    j < eth->number;
			    j++, d++) {
				if (*inbytesleft < d->size) {
					continue;
				}
				if (0 == memcmp(*inbuf, DADDR(d), d->size)) {
					TRACE_MESSAGE('E',
					    ("escape seq: discard=%ld chars\n",
					    d->size));
					TRACE_MESSAGE('E',
					    ("escape seq (default "
					    "action=%6p, type=%ld) set\n",
					    direc->action.itm_ptr,
					    ((itm_tbl_hdr_t *)
					    (ADDR(direc->action)))->type));
					ist->default_action = direc->action;
					DISCARD(d->size);
					retval = 2;
					goto eval_cond_return;
				}
			}
			if (0 == retval) {
				goto eval_cond_return;
			}
			break; /* continue */
		case ITM_COND_EXPR:
			retval = eval_expr(ist, cond->operand.place,
			    *inbytesleft, ip, outbytesleft);
			if (0 == retval) {
				goto eval_cond_return;
			} else {
				retval = 1;
			}
			break; /* continue */
		default:
			TRACE_MESSAGE('e', ("eval_cond_tbl:illegal cond=%d\n",
			    cond->type));
			retval = (size_t)-1;
			goto eval_cond_return;
		}
	}

eval_cond_return:
	return (retval);
}

/*
 * Evaluate operation table
 *
 */
static size_t
eval_op_tbl(
	icv_state_t	*ist,
	itm_place_t	op_tbl_place,
	const unsigned char	**inbuf,
	size_t		*inbytesleft,
	unsigned char	**outbuf,
	size_t		*outbytesleft)
{
	itm_tbl_hdr_t	*op_hdr;
	itm_op_t	*operation;
	itm_place2_t	op_place;
	size_t		retval;
	long		i;

	retval = 0;

#if defined(OP_DEPTH_MAX)
	if (OP_DEPTH_MAX <= ist->op_depth) {
		errno = ELIBBAD;
		TRACE_MESSAGE('e', ("eval_op_tbl:error=%d\n", errno));
		return	(RETVALERR);
	}
	ist->op_depth += 1;
#endif /* OP_DEPTH_MAX */

	op_hdr = ADDR(op_tbl_place);
	operation = (itm_op_t *)(op_hdr + 1);

	op_place = op_tbl_place.itm_ptr + (sizeof (itm_tbl_hdr_t));
	for (i = 0; i < op_hdr->number; i++, operation++,
	    op_place += (sizeof (itm_op_t))) {
		TRACE_MESSAGE('O', ("eval_op_tbl: %ld %p\n", i, op_place));
		retval = eval_op(ist, op_place, inbuf, inbytesleft,
		    outbuf, outbytesleft);
		if (((long)(retval)) < 0) {
#if defined(OP_DEPTH_MAX)
			ist->op_depth -= 1;
#endif /* OP_DEPTH_MAX */
			switch (retval) {
			case RETVALERR:
				return	(retval);
			case RETVALRET:
				if (0 == op_hdr->name.itm_ptr) {
					return	(RETVALRET);
				} else {
					return (0);
				}
			}
		}
	}
#if defined(OP_DEPTH_MAX)
	ist->op_depth -= 1;
#endif /* OP_DEPTH_MAX */
	return	(retval);
}


/*
 * Evaluate single operation
 *
 */
static size_t
eval_op(
	icv_state_t		*ist,
	itm_place2_t		op_place,
	const unsigned char	**inbuf,
	size_t			*inbytesleft,
	unsigned char		**outbuf,
	size_t			*outbytesleft)
{
	size_t			retval;
	itm_num_t		num;
	itm_op_t		*operation;
	itm_expr_t		*expr;
	itm_num_t		c;
	itm_num_t		i;
	itm_size_t		z;
	unsigned char		*p;
	itm_expr_t		*expr0;
	itm_tbl_hdr_t		*h;
	itm_type_t		t;

#define	EVAL_EXPR(n)							\
	(expr0 = ADDR(operation->data.operand[(n)]),			\
		(itm_num_t)((expr0->type == ITM_EXPR_INT) ?		\
		expr0->data.itm_exnum :					\
		((expr0->type == ITM_EXPR_REG) ?			\
		REG(expr0->data.itm_exnum) :				\
		((expr0->type == ITM_EXPR_IN_VECTOR_D) ?		\
		((expr0->data.itm_exnum < 0) ?				\
		(((-1) == expr0->data.itm_exnum) ? *inbytesleft : 0) :	\
		((expr0->data.itm_exnum < *inbytesleft) ?		\
		(*(uchar_t *)(*inbuf + expr0->data.itm_exnum)) : 0)):	\
		eval_expr(ist, operation->data.operand[(n)],		\
		*inbytesleft, *inbuf, *outbytesleft)))))

	retval = 0;

	operation = (itm_op_t *)ADDR2(op_place);

	switch (operation->type) {
	case ITM_OP_EXPR:
		num = eval_expr(ist, operation->data.operand[0],
		    *inbytesleft, *inbuf, *outbytesleft);
		TRACE_MESSAGE('o', ("ITM_OP_EXPR: %ld\n", retval));
		break;
	case ITM_OP_ERROR:
		num = eval_expr(ist, operation->data.operand[0],
		    *inbytesleft, *inbuf, *outbytesleft);
		errno = (int)num;
		TRACE_MESSAGE('o', ("ITM_OP_ERROR: %ld\n", num));
		retval = (size_t)(-1);
		break;
	case ITM_OP_ERROR_D:
		errno = (int)operation->data.itm_opnum;
		TRACE_MESSAGE('o', ("ITM_OP_ERROR_D: %d\n", errno));
		retval = (size_t)(-1);
		break;
	case ITM_OP_OUT:
		expr = ADDR(operation->data.operand[0]);
		if ((*outbytesleft) == 0) {
			errno = E2BIG;
			TRACE_MESSAGE('e', ("eval_op:error=%d\n", errno));
			return ((size_t)(-1));
		}
		c = eval_expr(ist, operation->data.operand[0],
		    *inbytesleft, *inbuf, *outbytesleft);
		PUT((uchar_t)c);
		retval = *inbytesleft;
		TRACE_MESSAGE('o', ("ITM_OP_OUT: %ld %ld\n", c, *inbytesleft));
		break;
	case ITM_OP_OUT_D:
		expr = ADDR(operation->data.operand[0]);
		if ((*outbytesleft) == 0) {
			errno = E2BIG;
			TRACE_MESSAGE('e', ("eval_op:error=%d\n", errno));
			return ((size_t)(-1));
		}
		PUT(0xff & (expr->data.itm_exnum));
		break;
	case ITM_OP_OUT_S:
		expr = ADDR(operation->data.operand[0]);
		if ((*outbytesleft) == 0) {
			errno = E2BIG;
			TRACE_MESSAGE('e', ("eval_op:error=%d\n", errno));
			return ((size_t)(-1));
		}
		z = expr->data.value.size;
		if (*outbytesleft < z) {
			errno = E2BIG;
			TRACE_MESSAGE('e', ("eval_op:error=%d\n", errno));
			return ((size_t)(-1));
		}
		p = DADDR(&(expr->data.value));
		for (; 0 < z; --z, p++) {
			PUT(*p);
		}
		break;
	case ITM_OP_OUT_R:
		expr = ADDR(operation->data.operand[0]);
		if ((*outbytesleft) == 0) {
			errno = E2BIG;
			TRACE_MESSAGE('e', ("eval_op:error=%d\n", errno));
			return ((size_t)(-1));
		}
		c = REG(expr->data.itm_exnum);
		PUT((uchar_t)c);
		break;
	case ITM_OP_OUT_INVD:
		expr = ADDR(operation->data.operand[0]);
		if ((*outbytesleft) == 0) {
			errno = E2BIG;
			TRACE_MESSAGE('e', ("eval_op:error=%d\n", errno));
			return ((size_t)(-1));
		}
		z = (((0 <= expr->data.itm_exnum) &&
		    (expr->data.itm_exnum < *inbytesleft)) ?
		    (*((unsigned char *)(*inbuf + expr->data.itm_exnum))) :
		    (((-1) == expr->data.itm_exnum) ? *inbytesleft : 0));
		PUT((uchar_t)z);
		break;
	case ITM_OP_DISCARD:
#if defined(EVAL_EXPR)
		num = EVAL_EXPR(0);
#else /* !defined(EVAL_EXPR) */
		num = eval_expr(ist, operation->data.operand[0],
		    *inbytesleft, *inbuf, *outbytesleft);
#endif /* defined(EVAL_EXPR) */
		TRACE_MESSAGE('o', ("ITM_OP_DISCARD: %ld\n", num));
#if defined(DISCARD)
		DISCARD((num <= *inbytesleft) ? ((ulong_t)num) : *inbytesleft);
#else /* defined(DISCARD) */
		for (num = ((num <= *inbytesleft) ? num : *inbytesleft);
		    0 < num; --num) {
			GET(c);
		}
#endif /* defined(DISCARD) */
		break;
	case ITM_OP_DISCARD_D:
		num = operation->data.itm_opnum;
		TRACE_MESSAGE('o', ("ITM_OP_DISCARD_D: %ld\n", num));
#if defined(DISCARD)
		DISCARD((num <= *inbytesleft) ? num : *inbytesleft);
#else /* defined(DISCARD) */
		for (num = ((num <= *inbytesleft) ? num : *inbytesleft);
		    0 < num; --num) {
			GET(c);
		}
#endif /* defined(DISCARD) */
		break;
	case ITM_OP_IF:
		c = eval_expr(ist, operation->data.operand[0],
		    *inbytesleft, *inbuf, *outbytesleft);
		TRACE_MESSAGE('o', ("ITM_OP_IF: %ld\n", c));
		if (c) {
			retval = eval_op_tbl(ist, operation->data.operand[1],
			    inbuf, inbytesleft, outbuf, outbytesleft);
		}
		break;
	case ITM_OP_IF_ELSE:
		c = eval_expr(ist, operation->data.operand[0],
		    *inbytesleft, *inbuf, *outbytesleft);
		TRACE_MESSAGE('o', ("ITM_OP_IF_ELSE: %ld\n", c));
		if (c) {
			retval = eval_op_tbl(ist, operation->data.operand[1],
			    inbuf, inbytesleft, outbuf, outbytesleft);
		} else {
			retval = eval_op_tbl(ist, operation->data.operand[2],
			    inbuf, inbytesleft, outbuf, outbytesleft);
		}
		break;
	case ITM_OP_DIRECTION:
		TRACE_MESSAGE('o', ("ITM_OP_DIRECTION: %p\n",
		    operation->data.operand[0].itm_ptr));
		ist->direc = ADDR(operation->data.operand[0]);
		return ((size_t)(-2));
	case ITM_OP_MAP:
		TRACE_MESSAGE('o', ("ITM_OP_MAP: %p\n",
		    operation->data.operand[0].itm_ptr));
		i = 0;
		if (0 != operation->data.operand[1].itm_ptr) {
#if defined(EVAL_EXPR)
			i = EVAL_EXPR(1);
#else /* !defined(EVAL_EXPR) */
			i = eval_expr(ist, operation->data.operand[1],
			    *inbytesleft, *inbuf, *outbytesleft);
#endif /* defined(EVAL_EXPR) */
			(*inbytesleft) -= i;
			(*inbuf) += i;
		}

		/*
		 * Based on what is the maptype, we call the corresponding
		 * mapping function.
		 */
		h = ADDR(operation->data.operand[0]);
		t = h->type;
		switch (t) {
		case ITM_TBL_MAP_INDEX_FIXED:
		case ITM_TBL_MAP_INDEX_FIXED_1_1:
			retval = map_i_f(h, inbuf, inbytesleft,
			    outbuf, outbytesleft, 1);
			break;
		case ITM_TBL_MAP_HASH:
			retval = map_h_l(h, inbuf, inbytesleft,
			    outbuf, outbytesleft, 1);
			break;
		case ITM_TBL_MAP_DENSE_ENC:
			retval = map_d_e_l(h, inbuf, inbytesleft,
			    outbuf, outbytesleft, 1);
			break;
		case ITM_TBL_MAP_LOOKUP:
			retval = map_l_f(h, inbuf, inbytesleft,
			    outbuf, outbytesleft, 1);
			break;
		default:
			/*
			 * This should not be possible, but in case we
			 * have an incorrect maptype, don't fall back to
			 * map_i_f(). Instead, because it is an error, return
			 * an error. See CR 6622765.
			 */
			errno = EBADF;
			TRACE_MESSAGE('e', ("eval_op:error=%d\n", errno));
			retval = (size_t)-1;
			break;
		}

		if ((size_t)(-1) == retval) {
			(*outbytesleft) += i;
			(*outbuf) -= i;
		}
		break;
	case ITM_OP_OPERATION:
		TRACE_MESSAGE('o', ("ITM_OP_OPERATION: %p\n",
		    operation->data.operand[0].itm_ptr));
		retval = eval_op_tbl(ist, operation->data.operand[0],
		    inbuf, inbytesleft, outbuf, outbytesleft);

		break;
	case ITM_OP_INIT:
		TRACE_MESSAGE('o', ("ITM_OP_INIT: %p\n",
		    ist->itm_hdr->op_init_tbl));
		if (0 != ist->itm_hdr->op_init_tbl.itm_ptr) {
			retval = eval_op_tbl(ist, ist->itm_hdr->op_init_tbl,
			    inbuf, inbytesleft, outbuf, outbytesleft);
		} else {
			op_init_default(ist);
			retval = (size_t)-2;
		}
		break;
	case ITM_OP_RESET:
		TRACE_MESSAGE('o', ("ITM_OP_RESET: %p\n",
		    ist->itm_hdr->op_reset_tbl));
		if (0 != ist->itm_hdr->op_reset_tbl.itm_ptr) {
			retval = eval_op_tbl(ist, ist->itm_hdr->op_reset_tbl,
			    inbuf, inbytesleft, outbuf, outbytesleft);
		} else {
			op_reset_default(ist);
			retval = (size_t)-2;
		}
		break;
	case ITM_OP_BREAK:
		TRACE_MESSAGE('o', ("ITM_OP_BREAK\n"));
		return	(RETVALBRK);
	case ITM_OP_RETURN:
		TRACE_MESSAGE('o', ("ITM_OP_RETURN\n"));
		return	(RETVALRET);
	case ITM_OP_PRINTCHR:
		c = eval_expr(ist, operation->data.operand[0], *inbytesleft,
		    *inbuf, *outbytesleft);
		(void) fputc((uchar_t)c, stderr);
		TRACE_MESSAGE('o', ("ITM_OP_PRINTCHR: %ld %ld\n",
		    c, *inbytesleft));
		break;
	case ITM_OP_PRINTHD:
		c = eval_expr(ist, operation->data.operand[0], *inbytesleft,
		    *inbuf, *outbytesleft);
		(void) fprintf(stderr, "%lx", c);
		TRACE_MESSAGE('o', ("ITM_OP_PRINTHD: %ld %ld\n",
		    c, *inbytesleft));
		break;
	case ITM_OP_PRINTINT:
		c = eval_expr(ist, operation->data.operand[0], *inbytesleft,
		    *inbuf, *outbytesleft);
		(void) fprintf(stderr, "%ld", c);
		TRACE_MESSAGE('o', ("ITM_OP_PRINTINT: %ld %ld\n",
		    c, *inbytesleft));
		break;
	default: /* never */
		errno = ELIBBAD;
		TRACE_MESSAGE('e', ("eval_op:error=%d\n", errno));
		return (size_t)(-1);
	}
	return	(retval);

#undef EVAL_EXPR
}


/*
 * Evaluate expression
 */
static itm_num_t
eval_expr(
	icv_state_t		*ist,
	itm_place_t		expr_place,
	size_t			inbytesleft,
	const unsigned char	*inbuf,
	size_t			outbytesleft)
{
	itm_expr_t		*expr;
	itm_expr_t		*expr_op;
	itm_num_t		num;
	unsigned char		*p;
	long			i;
	itm_expr_t		*expr0;
	itm_num_t		num00;
	itm_num_t		num01;

#define	EVAL_EXPR_E(n) (eval_expr(ist, expr->data.operand[(n)],		\
	inbytesleft, inbuf, outbytesleft))
#define	EVAL_EXPR_D(n)	((itm_num_t)(expr->data.operand[(n)].itm_ptr))
#define	EVAL_EXPR_R(n)	(REG((itm_num_t)(expr->data.operand[(n)].itm_ptr)))
#define	EVAL_EXPR_INVD(n)						\
	((num0 ## n) = ((itm_num_t)(expr->data.operand[(n)].itm_ptr)),	\
		((num0 ## n) < 0) ?					\
		(((-1) == (num0 ## n)) ? inbytesleft : 0) :		\
		(((num0 ## n) < inbytesleft) ?				\
		(*(unsigned char *)(inbuf + (num0 ## n))) : 0))
#define	EVAL_EXPR(n)							\
	(expr0 = ADDR(expr->data.operand[(n)]),				\
		(itm_num_t)((expr0->type == ITM_EXPR_INT) ?		\
		expr0->data.itm_exnum :					\
		((expr0->type == ITM_EXPR_REG) ?			\
		REG(expr0->data.itm_exnum) :				\
		((expr0->type == ITM_EXPR_IN_VECTOR_D) ?		\
		((expr0->data.itm_exnum < 0) ?				\
		(((-1) == expr0->data.itm_exnum) ? inbytesleft : 0) :	\
		((expr0->data.itm_exnum < inbytesleft) ?		\
		(*(uchar_t *)(inbuf + expr0->data.itm_exnum)) : 0)) :	\
		eval_expr(ist, expr->data.operand[(n)],			\
		inbytesleft, inbuf, outbytesleft)))))

#define	EVAL_OP_BIN_PROTO(op, name, name0, name1)			\
	case ITM_EXPR_##name##_##name0##_##name1:			\
		return (EVAL_EXPR_##name0(0) op EVAL_EXPR_##name1(1));

#define	EVAL_OP_BIN1(op, name)					\
		EVAL_OP_BIN_PROTO(op, name, E, E)		\
		EVAL_OP_BIN_PROTO(op, name, E, D)		\
		EVAL_OP_BIN_PROTO(op, name, E, R)		\
		EVAL_OP_BIN_PROTO(op, name, E, INVD)

#define	EVAL_OP_BIN2(op, name)					\
		EVAL_OP_BIN_PROTO(op, name, D, E)		\
		EVAL_OP_BIN_PROTO(op, name, D, D)		\
		EVAL_OP_BIN_PROTO(op, name, D, R)		\
		EVAL_OP_BIN_PROTO(op, name, D, INVD)

#define	EVAL_OP_BIN3(op, name)					\
		EVAL_OP_BIN_PROTO(op, name, R, E)		\
		EVAL_OP_BIN_PROTO(op, name, R, D)		\
		EVAL_OP_BIN_PROTO(op, name, R, R)		\
		EVAL_OP_BIN_PROTO(op, name, R, INVD)

#define	EVAL_OP_BIN4(op, name)					\
		EVAL_OP_BIN_PROTO(op, name, INVD, E)		\
		EVAL_OP_BIN_PROTO(op, name, INVD, D)		\
		EVAL_OP_BIN_PROTO(op, name, INVD, R)		\
		EVAL_OP_BIN_PROTO(op, name, INVD, INVD)

#define	EVAL_OP_BIN_PROTECT_PROTO(op, name, name0, name1)	\
	case ITM_EXPR_##name##_##name0##_##name1:		\
		num = EVAL_EXPR_##name1(1);			\
		if (0 != num) {					\
			return (EVAL_EXPR_##name0(0) op num);	\
		} else {					\
			return (0);				\
		}

#define	EVAL_OP_BIN_PROTECT1(op, name)				\
		EVAL_OP_BIN_PROTECT_PROTO(op, name, E, E)	\
		EVAL_OP_BIN_PROTECT_PROTO(op, name, E, D)	\
		EVAL_OP_BIN_PROTECT_PROTO(op, name, E, R)	\
		EVAL_OP_BIN_PROTECT_PROTO(op, name, E, INVD)

#define	EVAL_OP_BIN_PROTECT2(op, name)				\
		EVAL_OP_BIN_PROTECT_PROTO(op, name, D, E)	\
		EVAL_OP_BIN_PROTECT_PROTO(op, name, D, D)	\
		EVAL_OP_BIN_PROTECT_PROTO(op, name, D, R)	\
		EVAL_OP_BIN_PROTECT_PROTO(op, name, D, INVD)

#define	EVAL_OP_BIN_PROTECT3(op, name)				\
		EVAL_OP_BIN_PROTECT_PROTO(op, name, R, E)	\
		EVAL_OP_BIN_PROTECT_PROTO(op, name, R, D)	\
		EVAL_OP_BIN_PROTECT_PROTO(op, name, R, R)	\
		EVAL_OP_BIN_PROTECT_PROTO(op, name, R, INVD)

#define	EVAL_OP_BIN_PROTECT4(op, name)				\
		EVAL_OP_BIN_PROTECT_PROTO(op, name, INVD, E)	\
		EVAL_OP_BIN_PROTECT_PROTO(op, name, INVD, D)	\
		EVAL_OP_BIN_PROTECT_PROTO(op, name, INVD, R)	\
		EVAL_OP_BIN_PROTECT_PROTO(op, name, INVD, INVD)

	expr = ADDR(expr_place);

	switch (expr->type) {
	case ITM_EXPR_NONE:		/* not used */
		return (0);
	case ITM_EXPR_NOP:		/* not used */
		return (0);
	case ITM_EXPR_NAME:		/* not used */
		return (0);
	case ITM_EXPR_INT:		/* integer */
		return (expr->data.itm_exnum);
	case ITM_EXPR_SEQ:		/* byte sequence */
		if ((sizeof (itm_place_t)) < expr->data.value.size) {
			p = (unsigned char *)ADDR(expr->data.value.place);
		} else {
			p = (unsigned char *)&(expr->data.value.place);
		}
		for (i = 0, num = 0; i < expr->data.value.size; i++, p++) {
			num = ((num << 8) | *p);
		}
		return	(num);
	case ITM_EXPR_REG:		/* register */
		return (REG(expr->data.itm_exnum));
	case ITM_EXPR_IN_VECTOR:	/* in[expr] */
		num = EVAL_EXPR(0);
		if ((0 <= num) && (num < inbytesleft)) {
			return (*((unsigned char *)(inbuf + num)));
		} else if ((-1) == num) {
			return	(inbytesleft);
		} else {
			return (0);
		}
	case ITM_EXPR_IN_VECTOR_D:	/* in[DECIMAL] */
		num = expr->data.itm_exnum;
		if ((0 <= num) && (num < inbytesleft)) {
			return (*((unsigned char *)(inbuf + num)));
		} else if ((-1) == num) {
			return	(inbytesleft);
		} else {
			return (0);
		}
	case ITM_EXPR_OUT:		/* out */
		return	(outbytesleft);
	case ITM_EXPR_TRUE:		/* true */
		return (1);
	case ITM_EXPR_FALSE:		/* false */
		return (0);
	case ITM_EXPR_UMINUS:		/* unary minus */
		return ((-1) * EVAL_EXPR(0));
#define	PLUS_FOR_CSTYLE_CLEAN +
#define	MINUS_FOR_CSTYLE_CLEAN -
#define	MUL_FOR_CSTYLE_CLEAN *
#define	DIV_FOR_CSTYLE_CLEAN /
#define	MOD_FOR_CSTYLE_CLEAN %
#define	SHIFT_L_FOR_CSTYLE_CLEAN <<
#define	SHIFT_R_FOR_CSTYLE_CLEAN >>
#define	OR_FOR_CSTYLE_CLEAN |
#define	XOR_FOR_CSTYLE_CLEAN ^
#define	AND_FOR_CSTYLE_CLEAN &
#define	EQ_FOR_CSTYLE_CLEAN ==
#define	NE_FOR_CSTYLE_CLEAN !=
#define	GT_FOR_CSTYLE_CLEAN >
#define	GE_FOR_CSTYLE_CLEAN >=
#define	LT_FOR_CSTYLE_CLEAN <
#define	LE_FOR_CSTYLE_CLEAN <=
	EVAL_OP_BIN1(PLUS_FOR_CSTYLE_CLEAN, PLUS)	/* A + B */
	EVAL_OP_BIN2(PLUS_FOR_CSTYLE_CLEAN, PLUS)	/* A + B */
	EVAL_OP_BIN3(PLUS_FOR_CSTYLE_CLEAN, PLUS)	/* A + B */
	EVAL_OP_BIN4(PLUS_FOR_CSTYLE_CLEAN, PLUS)	/* A + B */

	EVAL_OP_BIN1(MINUS_FOR_CSTYLE_CLEAN, MINUS)	/* A - B */
	EVAL_OP_BIN2(MINUS_FOR_CSTYLE_CLEAN, MINUS)	/* A - B */
	EVAL_OP_BIN3(MINUS_FOR_CSTYLE_CLEAN, MINUS)	/* A - B */
	EVAL_OP_BIN4(MINUS_FOR_CSTYLE_CLEAN, MINUS)	/* A - B */

	EVAL_OP_BIN1(MUL_FOR_CSTYLE_CLEAN, MUL)		/* A * B */
	EVAL_OP_BIN2(MUL_FOR_CSTYLE_CLEAN, MUL)		/* A * B */
	EVAL_OP_BIN3(MUL_FOR_CSTYLE_CLEAN, MUL)		/* A * B */
	EVAL_OP_BIN4(MUL_FOR_CSTYLE_CLEAN, MUL)		/* A * B */

	EVAL_OP_BIN_PROTECT1(DIV_FOR_CSTYLE_CLEAN, DIV)	/* A / B */
	EVAL_OP_BIN_PROTECT2(DIV_FOR_CSTYLE_CLEAN, DIV)	/* A / B */
	EVAL_OP_BIN_PROTECT3(DIV_FOR_CSTYLE_CLEAN, DIV)	/* A / B */
	EVAL_OP_BIN_PROTECT4(DIV_FOR_CSTYLE_CLEAN, DIV)	/* A / B */

	EVAL_OP_BIN_PROTECT1(MOD_FOR_CSTYLE_CLEAN, MOD)	/* A % B */
	EVAL_OP_BIN_PROTECT2(MOD_FOR_CSTYLE_CLEAN, MOD)	/* A % B */
	EVAL_OP_BIN_PROTECT3(MOD_FOR_CSTYLE_CLEAN, MOD)	/* A % B */
	EVAL_OP_BIN_PROTECT4(MOD_FOR_CSTYLE_CLEAN, MOD)	/* A % B */

	EVAL_OP_BIN1(SHIFT_L_FOR_CSTYLE_CLEAN, SHIFT_L)	/* A << B */
	EVAL_OP_BIN2(SHIFT_L_FOR_CSTYLE_CLEAN, SHIFT_L)	/* A << B */
	EVAL_OP_BIN3(SHIFT_L_FOR_CSTYLE_CLEAN, SHIFT_L)	/* A << B */
	EVAL_OP_BIN4(SHIFT_L_FOR_CSTYLE_CLEAN, SHIFT_L)	/* A << B */

	EVAL_OP_BIN1(SHIFT_R_FOR_CSTYLE_CLEAN, SHIFT_R)	/* A >> B */
	EVAL_OP_BIN2(SHIFT_R_FOR_CSTYLE_CLEAN, SHIFT_R)	/* A >> B */
	EVAL_OP_BIN3(SHIFT_R_FOR_CSTYLE_CLEAN, SHIFT_R)	/* A >> B */
	EVAL_OP_BIN4(SHIFT_R_FOR_CSTYLE_CLEAN, SHIFT_R)	/* A >> B */

	EVAL_OP_BIN1(OR_FOR_CSTYLE_CLEAN, OR)		/* A |	B */
	EVAL_OP_BIN2(OR_FOR_CSTYLE_CLEAN, OR)		/* A |	B */
	EVAL_OP_BIN3(OR_FOR_CSTYLE_CLEAN, OR)		/* A |	B */
	EVAL_OP_BIN4(OR_FOR_CSTYLE_CLEAN, OR)		/* A |	B */

	EVAL_OP_BIN1(XOR_FOR_CSTYLE_CLEAN, XOR)		/* A ^	B */
	EVAL_OP_BIN2(XOR_FOR_CSTYLE_CLEAN, XOR)		/* A ^	B */
	EVAL_OP_BIN3(XOR_FOR_CSTYLE_CLEAN, XOR)		/* A ^	B */
	EVAL_OP_BIN4(XOR_FOR_CSTYLE_CLEAN, XOR)		/* A ^	B */

	EVAL_OP_BIN1(AND_FOR_CSTYLE_CLEAN, AND)		/* A &	B */
	EVAL_OP_BIN2(AND_FOR_CSTYLE_CLEAN, AND)		/* A &	B */
	EVAL_OP_BIN3(AND_FOR_CSTYLE_CLEAN, AND)		/* A &	B */
	EVAL_OP_BIN4(AND_FOR_CSTYLE_CLEAN, AND)		/* A &	B */

	EVAL_OP_BIN1(EQ_FOR_CSTYLE_CLEAN, EQ)		/* A == B */
	EVAL_OP_BIN2(EQ_FOR_CSTYLE_CLEAN, EQ)		/* A == B */
	EVAL_OP_BIN3(EQ_FOR_CSTYLE_CLEAN, EQ)		/* A == B */
	EVAL_OP_BIN4(EQ_FOR_CSTYLE_CLEAN, EQ)		/* A == B */

	EVAL_OP_BIN1(NE_FOR_CSTYLE_CLEAN, NE)		/* A != B */
	EVAL_OP_BIN2(NE_FOR_CSTYLE_CLEAN, NE)		/* A != B */
	EVAL_OP_BIN3(NE_FOR_CSTYLE_CLEAN, NE)		/* A != B */
	EVAL_OP_BIN4(NE_FOR_CSTYLE_CLEAN, NE)		/* A != B */

	EVAL_OP_BIN1(GT_FOR_CSTYLE_CLEAN, GT)		/* A >	B */
	EVAL_OP_BIN2(GT_FOR_CSTYLE_CLEAN, GT)		/* A >	B */
	EVAL_OP_BIN3(GT_FOR_CSTYLE_CLEAN, GT)		/* A >	B */
	EVAL_OP_BIN4(GT_FOR_CSTYLE_CLEAN, GT)		/* A >	B */

	EVAL_OP_BIN1(GE_FOR_CSTYLE_CLEAN, GE)		/* A >= B */
	EVAL_OP_BIN2(GE_FOR_CSTYLE_CLEAN, GE)		/* A >= B */
	EVAL_OP_BIN3(GE_FOR_CSTYLE_CLEAN, GE)		/* A >= B */
	EVAL_OP_BIN4(GE_FOR_CSTYLE_CLEAN, GE)		/* A >= B */

	EVAL_OP_BIN1(LT_FOR_CSTYLE_CLEAN, LT)		/* A <	B */
	EVAL_OP_BIN2(LT_FOR_CSTYLE_CLEAN, LT)		/* A <	B */
	EVAL_OP_BIN3(LT_FOR_CSTYLE_CLEAN, LT)		/* A <	B */
	EVAL_OP_BIN4(LT_FOR_CSTYLE_CLEAN, LT)		/* A <	B */

	EVAL_OP_BIN1(LE_FOR_CSTYLE_CLEAN, LE)		/* A <= B */
	EVAL_OP_BIN2(LE_FOR_CSTYLE_CLEAN, LE)		/* A <= B */
	EVAL_OP_BIN3(LE_FOR_CSTYLE_CLEAN, LE)		/* A <= B */
	EVAL_OP_BIN4(LE_FOR_CSTYLE_CLEAN, LE)		/* A <= B */

	case ITM_EXPR_NOT:		/*   !A	  */
		return (!(EVAL_EXPR(0)));
	case ITM_EXPR_NEG:		/*   ~A	  */
		return (~(EVAL_EXPR(0)));
	case ITM_EXPR_LOR:		/* A || B */
		if (0 != (num = EVAL_EXPR(0)))
			return	(num);
		if (0 != (num = EVAL_EXPR(1)))
			return	(num);
		return (0);
	case ITM_EXPR_LAND:		/* A && B */
		if (0 == EVAL_EXPR(0))
			return (0);
		if (0 == (num = EVAL_EXPR(1)))
			return (0);
		return	(num);
	case ITM_EXPR_ASSIGN:		/* A  = B */
		num = EVAL_EXPR(1);
		if (expr->data.operand[0].itm_ptr < ist->itm_hdr->reg_num) {
			return (*(ist->regs + expr->data.operand[0].itm_ptr)
			    = num);
		} else {
			return (0);
		}
	case ITM_EXPR_IN_EQ:		/* in == A */
		expr_op = ADDR(expr->data.operand[0]);
		switch (expr_op->type) {
		case ITM_EXPR_SEQ:
			if (inbytesleft < expr_op->data.value.size) {
				return (0);
			}
			p = DADDR(&(expr_op->data.value));
			for (i = 0; i < expr_op->data.value.size; i++, p++) {
				if (*p != *(inbuf + i)) {
					return (0);
				}
			}
			return (1);
		default:
			num = EVAL_EXPR(0);
			return (num == *((unsigned char *)inbuf));
		}
	default:
		break;
	}

	return (0);

#undef EVAL_EXPR_E
#undef EVAL_EXPR_D
#undef EVAL_EXPR_R
#undef EVAL_EXPR_INVD
#undef EVAL_EXPR
}


/*
 * maintain ITM reference information
 */
static void
itm_ref_free(int fd, void *ptr0, void *ptr1, void *ptr2, size_t len)
{
	int	r;
	r = errno;
	if (0 <= fd) {
		(void) close(fd);
	}
	free(ptr0);
	free(ptr1);
	if (0 < len) {
		(void) munmap(ptr2, len);
	}
	errno = r;
}

static itm_ref_t *
itm_ref_inc(const char		*itm)
{
	itm_ref_t	*ref;
	itm_hdr_t	*hdr;
	struct stat	st;
	int		fd;

	fd = open(itm, O_RDONLY, 0);
	if (fd == -1) {
		itm_ref_free(-1, NULL, NULL, NULL, 0);
		return	(NULL);
	}

	if (fstat(fd, &st) == -1) {
		itm_ref_free(fd, NULL, NULL, NULL, 0);
		return	(NULL);
	}
	hdr = (void *) mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (MAP_FAILED == hdr) {
		itm_ref_free(fd, NULL, NULL, NULL, 0);
		return	(NULL);
	}

	(void) close(fd);

	ref = malloc(sizeof (itm_ref_t));
	if (NULL == ref) {
		itm_ref_free(-1, NULL, NULL, hdr, st.st_size);
		return	(NULL);
	}
	ref->name = malloc(strlen(itm) + 1);
	if (NULL == ref->name) {
		itm_ref_free(-1, ref, NULL, hdr, st.st_size);
		return	(NULL);
	}
	(void) strcpy(ref->name, itm);
	ref->hdr = hdr;
	ref->len = st.st_size;

	if ((hdr->ident[0] != ITM_IDENT_0) ||
	    (hdr->ident[1] != ITM_IDENT_1) ||
	    (hdr->ident[2] != ITM_IDENT_2) ||
	    (hdr->ident[3] != ITM_IDENT_3) ||
	    (hdr->spec[0] != ITM_SPEC_0) ||
	    (hdr->spec[1] != ITM_SPEC_1) ||
	    (hdr->spec[2] != ITM_SPEC_2) ||
#if defined(_LITTLE_ENDIAN)
#if defined(_LP64)
	    ((hdr->spec[3] != ITM_SPEC_3_32_LITTLE_ENDIAN) &&
	    (hdr->spec[3] != ITM_SPEC_3_64_LITTLE_ENDIAN)) ||
#else
	    (hdr->spec[3] != ITM_SPEC_3_32_LITTLE_ENDIAN) ||
#endif
#else
#if defined(_LP64)
	    ((hdr->spec[3] != ITM_SPEC_3_32_BIG_ENDIAN) &&
	    (hdr->spec[3] != ITM_SPEC_3_64_BIG_ENDIAN)) ||
#else
	    (hdr->spec[3] != ITM_SPEC_3_32_BIG_ENDIAN) ||
#endif
#endif
	    (hdr->version[0] != ITM_VER_0) ||
	    (hdr->version[1] != ITM_VER_1) ||
	    (hdr->version[2] != ITM_VER_2) ||
	    (hdr->version[3] != ITM_VER_3) ||
	    (((size_t)(hdr->itm_size.itm_ptr)) != st.st_size)) {
		itm_ref_free(-1, ref, ref->name, ref->hdr, ref->len);
		errno = ELIBBAD;
		TRACE_MESSAGE('e', ("itm_ref_inc:error=%d\n", errno));
		return	(NULL);
	}

	return	(ref);
}


static void
itm_ref_dec(itm_ref_t	*ref)
{
	(void) munmap((char *)(ref->hdr), ref->len);
	free(ref->name);
	free(ref);
}


static void
op_init_default(icv_state_t	*ist)
{
	ist->direc = ADDR(ist->itm_hdr->direc_init_tbl);
	regs_init(ist);
}


static void
op_reset_default(icv_state_t	*ist)
{
	ist->direc = ADDR(ist->itm_hdr->direc_init_tbl);
	regs_init(ist);
}


static void
regs_init(icv_state_t	*ist)
{
	if (0 < ist->itm_hdr->reg_num) {
		(void) memset(ist->regs, 0,
		    (sizeof (itm_num_t)) * ist->itm_hdr->reg_num);
	}
}


#if defined(DEBUG)
static void
trace_init()
{
	char	*env_val;
	char	*p;

	env_val = getenv("ITM_INT_TRACE");
	if (NULL == env_val)
		return;

	for (p = env_val; *p; p++) {
		trace_option[(*p) & 0x007f] = 1;
	}
}

static void
trace_message(char	*format, ...)
{
	va_list	ap;

	va_start(ap, format);

	(void) vfprintf(stderr, format, ap);

	va_end(ap);
}
#endif /* DEBUG */
