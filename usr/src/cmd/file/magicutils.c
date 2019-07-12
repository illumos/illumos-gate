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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*	Copyright (c) 1987, 1988 Microsoft Corporation	*/
/*	  All Rights Reserved	*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <inttypes.h>
#include <sys/types.h>
#include <libintl.h>

/*
 *	Types
 */

#define	BYTE	1
#define	SHORT	2
#define	LONG	4
#define	LLONG	8
#define	UBYTE	16
#define	USHORT	32
#define	ULONG	64
#define	ULLONG	128
#define	STR	256

/*
 *	Opcodes
 */

#define	EQ	0
#define	GT	1
#define	LT	2
#define	STRC	3	/* string compare */
#define	ANY	4
#define	AND	5
#define	NSET	6	/* True if bit is not set */
#define	SUB	64	/* or'ed in, SUBstitution string, for example */
			/* %ld, %s, %lo mask: with bit 6 on, used to locate */
			/* print formats */
/*
 *	Misc
 */

#define	BSZ	128
#define	NENT	200

/*
 *	Structure of magic file entry
 */

struct	entry	{
	char		e_level;	/* 0 or 1 */
	off_t		e_off;		/* in bytes */
	uint32_t	e_type;		/* BYTE, SHORT, STR, et al */
	char		e_opcode;	/* EQ, GT, LT, ANY, AND, NSET */
	uint64_t	e_mask;		/* if non-zero, mask value with this */
	union	{
		uint64_t	num;
		char		*str;
	}	e_value;
	const char	*e_str;
};

/* Non-localized string giving name of command.  Defined in file.c */
extern const char	*File;

typedef	struct entry	Entry;

static Entry	*mtab1;	/* 1st magic table, applied before default tests */

	/*
	 * 2nd magic table, includes default tests and magic entries
	 * to be applied after default position-sensitive tests
	 */
static Entry	*mtab2;

static Entry	*mend1;	/* one past last-allocated entry in mtab1 */
static Entry	*mend2;	/* one past last-allocated entry in mtab2 */

static Entry	*ep1;	/* current entry in mtab1 */
static Entry	*ep2;	/* current entry in mtab2 */

static char *
getstr(char *p, char *file)
{
	char	*newstr;
	char	*s;
	long	val;
	int	base;

	newstr = (char *)malloc((strlen(p) + 1) * sizeof (char));
	if (newstr == NULL) {
		int err = errno;
		(void) fprintf(stderr, gettext("%s: malloc failed: %s\n"),
		    File, strerror(err));
		return (NULL);
	}

	s = newstr;
	while (*p != '\0') {
		if (*p != '\\') {
			*s++ = *p++;
			continue;
		}
		p++;
		if (*p == '\0')
			break;
		if (isdigit(*p)) {
			if (*p == '0' && (*(p+1) == 'x' || *(p+1) == 'X')) {
				/* hex */
				base = 16;
			} else {
				base = 8;
			}
			errno = 0;
			val = strtol(p, &p, base);
			if (val > UCHAR_MAX || val < 0 || errno != 0) {
				(void) fprintf(stderr, gettext("%s: %s: magic "
				    "table invalid string value\n"), File,
				    file);
				return (NULL);
			}
			*s++ = (char)val;
		} else {
			/* escape the character */
			switch (*p) {
			case 'n':
				*s = '\n';
				break;
			case 'r':
				*s = '\r';
				break;
			case 'a':
				*s = '\a';
				break;
			case 'b':
				*s = '\b';
				break;
			case 'f':
				*s = '\f';
				break;
			case 't':
				*s = '\t';
				break;
			case 'v':
				*s = '\v';
				break;
			default:
				*s = *p;
				break;
			}
			p++;
			s++;
		}
	}
	*s = '\0';
	return (newstr);
}

/*
 * f_mkmtab - fills mtab array of magic table entries with
 *	values from the file magfile.
 *	May be called more than once if multiple magic
 *	files were specified.
 *	Stores entries sequentially in one of two magic
 *	tables: mtab1, if first = 1; mtab2 otherwise.
 *
 *	If -c option is specified, cflg is non-zero, and
 *	f_mkmtab() reports on errors in the magic file.
 *
 *	Two magic tables may need to be created.  The first
 *	one (mtab1) contains magic entries to be checked before
 *	the programmatic default position-sensitive tests in
 *	def_position_tests().
 *	The second one (mtab2) should start with the default
 *	/etc/magic file entries and is to be checked after
 *	the programmatic default position-sensitive tests in
 *	def_position_tests().  The parameter "first" would
 *	be 1 for the former set of tables, 0 for the latter
 *	set of magic tables.
 *	No mtab2 should be created if file will not be
 *	applying default tests; in that case, all magic table
 *	entries should be in mtab1.
 *
 *	f_mkmtab returns 0 on success, -1 on error.  The calling
 *	program is not expected to proceed after f_mkmtab()
 *	returns an error.
 */

int
f_mkmtab(char *magfile, int cflg, int first)
{
	Entry	*mtab;	/* generic magic table pointer */
	Entry	*ep;	/* current magic table entry */
	Entry	*mend;	/* one past last-allocated entry of mtab */
	FILE	*fp;
	int	lcnt = 0;
	char	buf[BSZ];
	size_t	tbsize;
	size_t	oldsize;

	if (first) {
		mtab = mtab1;
		mend = mend1;
		ep = ep1;
	} else {
		mtab = mtab2;
		mend = mend2;
		ep = ep2;
	}

	/* mtab may have been allocated on a previous f_mkmtab call */
	if (mtab == (Entry *)NULL) {
		if ((mtab = calloc(NENT, sizeof (Entry))) == NULL) {
			int err = errno;
			(void) fprintf(stderr, gettext("%s: malloc "
			    "failed: %s\n"), File, strerror(err));
			return (-1);
		}

		ep = mtab;
		mend = &mtab[NENT];
	}

	errno = 0;
	if ((fp = fopen(magfile, "r")) == NULL) {
		int err = errno;
		(void) fprintf(stderr, gettext("%s: %s: cannot open magic "
		    "file: %s\n"), File, magfile, err ? strerror(err) : "");
		return (-1);
	}
	while (fgets(buf, BSZ, fp) != NULL) {
		char	*p = buf;
		char	*p2;
		char	*p3;
		char	opc;

		/*
		 * ensure we have one extra entry allocated
		 * to mark end of the table, after the while loop
		 */
		if (ep >= (mend - 1)) {
			oldsize = mend - mtab;
			tbsize = (NENT + oldsize) * sizeof (Entry);
			if ((mtab = realloc(mtab, tbsize)) == NULL) {
				int err = errno;
				(void) fprintf(stderr, gettext("%s: malloc "
				    "failed: %s\n"), File, strerror(err));
				return (-1);
			} else {
				(void) memset(mtab + oldsize, 0,
				    sizeof (Entry) * NENT);
				mend = &mtab[tbsize / sizeof (Entry)];
				ep = &mtab[oldsize-1];
			}
		}

		lcnt++;
		if (*p == '\n' || *p == '#')
			continue;


			/* LEVEL */
		if (*p == '>') {
			ep->e_level = 1;
			p++;
		}
			/* OFFSET */
		p2 = strchr(p, '\t');
		if (p2 == NULL) {
			if (cflg)
				(void) fprintf(stderr, gettext("%s: %s: format "
				    "error, no tab after %s on line %d\n"),
				    File, magfile, p, lcnt);
			continue;
		}
		*p2++ = '\0';
		ep->e_off = strtol((const char *)p, (char **)NULL, 0);
		while (*p2 == '\t')
			p2++;
			/* TYPE */
		p = p2;
		p2 = strchr(p, '\t');
		if (p2 == NULL) {
			if (cflg)
				(void) fprintf(stderr, gettext("%s: %s: format "
				    "error, no tab after %s on line %d\n"),
				    File, magfile, p, lcnt);
			continue;
		}
		*p2++ = '\0';
		p3 = strchr(p, '&');
		if (p3 != NULL) {
			*p3++ = '\0';
			ep->e_mask = strtoull((const char *)p3, (char **)NULL,
			    0);	/* returns 0 or ULLONG_MAX on error */
		} else {
			ep->e_mask = 0ULL;
		}
		switch (*p) {
			case 'd':
				if (*(p+1) == '\0') {
					/* d */
					ep->e_type = LONG;
				} else if (*(p+2) == '\0') {	/* d? */
					switch (*(p+1)) {
						case 'C':
						case '1':
							/* dC, d1 */
							ep->e_type = BYTE;
							break;
						case 'S':
						case '2':
							/* dS, d2 */
							ep->e_type = SHORT;
							break;
						case 'I':
						case 'L':
						case '4':
							/* dI, dL, d4 */
							ep->e_type = LONG;
							break;
						case '8':
							/* d8 */
							ep->e_type = LLONG;
							break;
						default:
							ep->e_type = LONG;
							break;
					}
				}
				break;
			case 'l':
				if (*(p+1) == 'l') {	/* llong */
					ep->e_type = LLONG;
				} else {		/* long */
					ep->e_type = LONG;
				}
				break;
			case 's':
				if (*(p+1) == 'h') {
					/* short */
					ep->e_type = SHORT;
				} else {
					/* s or string */
					ep->e_type = STR;
				}
				break;
			case 'u':
				if (*(p+1) == '\0') {
					/* u */
					ep->e_type = ULONG;
				} else if (*(p+2) == '\0') {	/* u? */
					switch (*(p+1)) {
						case 'C':
						case '1':
							/* uC, u1 */
							ep->e_type = UBYTE;
							break;
						case 'S':
						case '2':
							/* uS, u2 */
							ep->e_type = USHORT;
							break;
						case 'I':
						case 'L':
						case '4':
							/* uI, uL, u4 */
							ep->e_type = ULONG;
							break;
						case '8':
							/* u8 */
							ep->e_type = ULLONG;
							break;
						default:
							ep->e_type = ULONG;
							break;
					}
				} else { /* u?* */
					switch (*(p+1)) {
					case 'b':	/* ubyte */
						ep->e_type = UBYTE;
						break;
					case 's':	/* ushort */
						ep->e_type = USHORT;
						break;
					case 'l':
						if (*(p+2) == 'l') {
							/* ullong */
							ep->e_type = ULLONG;
						} else {
							/* ulong */
							ep->e_type = ULONG;
						}
						break;
					default:
						/* default, same as "u" */
						ep->e_type = ULONG;
						break;
					}
				}
				break;
			default:
				/* retain (undocumented) default type */
				ep->e_type = BYTE;
				break;
		}
		if (ep->e_type == 0) {
			ep->e_type = BYTE;	/* default */
		}
		while (*p2 == '\t')
			p2++;
			/* OP-VALUE */
		p = p2;
		p2 = strchr(p, '\t');
		if (p2 == NULL) {
			if (cflg)
				(void) fprintf(stderr, gettext("%s: %s: format "
				    "error, no tab after %s on line %d\n"),
				    File, magfile, p, lcnt);
			continue;
		}
		*p2++ = '\0';
		if (ep->e_type != STR) {
			opc = *p++;
			switch (opc) {
			case '=':
				ep->e_opcode = EQ;
				break;

			case '>':
				ep->e_opcode = GT;
				break;

			case '<':
				ep->e_opcode = LT;
				break;

			case 'x':
				ep->e_opcode = ANY;
				break;

			case '&':
				ep->e_opcode = AND;
				break;

			case '^':
				ep->e_opcode = NSET;
				break;
			default:	/* EQ (i.e. 0) is default	*/
				p--;	/* since global ep->e_opcode=0	*/
			}
		}
		if (ep->e_opcode != ANY) {
			if (ep->e_type != STR) {
				ep->e_value.num = strtoull((const char *)p,
				    (char **)NULL, 0);
			} else if ((ep->e_value.str =
			    getstr(p, magfile)) == NULL) {
				return (-1);
			}
		}
		p2 += strspn(p2, "\t");
			/* STRING */
		if ((ep->e_str = strdup(p2)) == NULL) {
			int err = errno;
			(void) fprintf(stderr, gettext("%s: malloc "
			    "failed: %s\n"), File, strerror(err));
			return (-1);
		} else {
			if ((p = strchr(ep->e_str, '\n')) != NULL)
				*p = '\0';
			if (strchr(ep->e_str, '%') != NULL)
				ep->e_opcode |= SUB;
		}
		ep++;
	}	/* end while (fgets) */

	ep->e_off = -1L;	/* mark end of table */
	if (first) {
		mtab1 = mtab;
		mend1 = mend;
		ep1 = ep;
	} else {
		mtab2 = mtab;
		mend2 = mend;
		ep2 = ep;
	}
	if (fclose(fp) != 0) {
		int err = errno;
		(void) fprintf(stderr, gettext("%s: fclose failed: %s\n"),
		    File, strerror(err));
		return (-1);
	}
	return (0);
}

/*
 * Check for Magic Table entries in the file.
 *
 * Since there may be two sets of magic tables, first = 1
 * for the first magic table (mtab1) and 0 for the second magic
 * table (mtab2).
 */
int
f_ckmtab(char *buf, int bufsize, int first)
{
	int		result;
	Entry		*mtab;
	Entry		*ep;
	char		*p;
	int		lev1 = 0;

	uint16_t	u16_val;
	uint32_t	u32_val;
	uint64_t	u64_val;

	if (first) {
		mtab = mtab1;
	} else {
		mtab = mtab2;
	}

	if (mtab == (Entry *)NULL) {
		return (0);	/* no magic file tests in this table */
	}

	for (ep = mtab; ep->e_off != -1L; ep++) {  /* -1 offset marks end of */
		if (lev1) {			/* valid magic file entries */
			if (ep->e_level != 1)
				break;
		} else if (ep->e_level == 1) {
			continue;
		}
		if (ep->e_off > (off_t)bufsize)
			continue;
		p = &buf[ep->e_off];
		switch (ep->e_type) {
		case STR:
		{
			if (strncmp(p, ep->e_value.str,
			    strlen(ep->e_value.str)))
				continue;
			if (lev1) {
				(void) putchar(' ');
			}
			if (ep->e_opcode & SUB)
				(void) printf(ep->e_str,
				    ep->e_value.str);
			else
				(void) printf(ep->e_str);
			lev1 = 1;
			continue;
			/*
			 * We've matched the string and printed the message;
			 * no STR processing occurs beyond this point.
			 */
		}

		case BYTE:
		case UBYTE:
			u64_val = (uint64_t)(uint8_t)(*p);
			break;

		case SHORT:
		case USHORT:
			(void) memcpy(&u16_val, p, sizeof (uint16_t));
			u64_val = (uint64_t)u16_val;
			break;

		case LONG:
		case ULONG:
			(void) memcpy(&u32_val, p, sizeof (uint32_t));
			u64_val = (uint64_t)u32_val;
			break;

		case LLONG:
		case ULLONG:
			(void) memcpy(&(u64_val), p, sizeof (uint64_t));
			break;

		}

		if (ep->e_mask) {
			u64_val &= ep->e_mask;
		}

		/*
		 * Compare the values according to the size and sign
		 * of the type.  For =, &, and ^ operators, the sign
		 * does not have any effect, so these are always compared
		 * unsigned.  Only for < and > operators is the
		 * sign significant.
		 * If the file value was masked, the compare should
		 * be unsigned.
		 */
		switch (ep->e_opcode & ~SUB) {
		case EQ:
			switch (ep->e_type) {
			case BYTE:
			case UBYTE:
				if ((uint8_t)u64_val !=
				    (uint8_t)(ep->e_value.num))
					continue;
				break;
			case SHORT:
			case USHORT:
				if ((uint16_t)u64_val !=
				    (uint16_t)(ep->e_value.num))
					continue;
				break;
			case LONG:
			case ULONG:
				if ((uint32_t)u64_val !=
				    (uint32_t)(ep->e_value.num))
					continue;
				break;
			case LLONG:
			case ULLONG:
				if (u64_val != ep->e_value.num)
					continue;
				break;
			default:
				continue;
			}
			break;
		case GT:
			switch (ep->e_type) {
			case BYTE:
				if (ep->e_mask == 0) {
					if ((int8_t)u64_val <=
					    (int8_t)(ep->e_value.num))
						continue;
					break;
				}
				/*FALLTHROUGH*/
			case UBYTE:
				if ((uint8_t)u64_val <=
				    (uint8_t)(ep->e_value.num))
					continue;
				break;
			case SHORT:
				if (ep->e_mask == 0) {
					if ((int16_t)u64_val <=
					    (int16_t)(ep->e_value.num))
						continue;
					break;
				}
				/*FALLTHROUGH*/
			case USHORT:
				if ((uint16_t)u64_val <=
				    (uint16_t)(ep->e_value.num))
					continue;
				break;
			case LONG:
				if (ep->e_mask == 0) {
					if ((int32_t)u64_val <=
					    (int32_t)(ep->e_value.num))
						continue;
					break;
				}
				/*FALLTHROUGH*/
			case ULONG:
				if ((uint32_t)u64_val <=
				    (uint32_t)(ep->e_value.num))
					continue;
				break;
			case LLONG:
				if (ep->e_mask == 0) {
					if ((int64_t)u64_val <=
					    (int64_t)(ep->e_value.num))
						continue;
					break;
				}
				/*FALLTHROUGH*/
			case ULLONG:
				if (u64_val <= ep->e_value.num)
					continue;
				break;
			default:
				continue;
			}
			break;
		case LT:
			switch (ep->e_type) {
			case BYTE:
				if (ep->e_mask == 0) {
					if ((int8_t)u64_val >=
					    (int8_t)(ep->e_value.num))
						continue;
					break;
				}
				/*FALLTHROUGH*/
			case UBYTE:
				if ((uint8_t)u64_val >=
				    (uint8_t)(ep->e_value.num))
					continue;
				break;
			case SHORT:
				if (ep->e_mask == 0) {
					if ((int16_t)u64_val >=
					    (int16_t)(ep->e_value.num))
						continue;
					break;
				}
				/*FALLTHROUGH*/
			case USHORT:
				if ((uint16_t)u64_val >=
				    (uint16_t)(ep->e_value.num))
					continue;
				break;
			case LONG:
				if (ep->e_mask == 0) {
					if ((int32_t)u64_val >=
					    (int32_t)(ep->e_value.num))
						continue;
					break;
				}
				/*FALLTHROUGH*/
			case ULONG:
				if ((uint32_t)u64_val >=
				    (uint32_t)(ep->e_value.num))
					continue;
				break;
			case LLONG:
				if (ep->e_mask == 0) {
					if ((int64_t)u64_val >=
					    (int64_t)(ep->e_value.num))
						continue;
					break;
				}
				/*FALLTHROUGH*/
			case ULLONG:
				if (u64_val >= ep->e_value.num)
					continue;
				break;
			default:
				continue;
			}
			break;
		case AND:
			switch (ep->e_type) {
			case BYTE:
			case UBYTE:
				if (((uint8_t)u64_val &
				    (uint8_t)(ep->e_value.num)) ==
				    (uint8_t)(ep->e_value.num))
					break;
				continue;
			case SHORT:
			case USHORT:
				if (((uint16_t)u64_val &
				    (uint16_t)(ep->e_value.num)) ==
				    (uint16_t)(ep->e_value.num))
					break;
				continue;
			case LONG:
			case ULONG:
				if (((uint32_t)u64_val &
				    (uint32_t)(ep->e_value.num)) ==
				    (uint32_t)(ep->e_value.num))
					break;
				continue;
			case LLONG:
			case ULLONG:
				if ((u64_val & ep->e_value.num) ==
				    ep->e_value.num)
					break;
				continue;
			default:
				continue;
			}
			break;
		case NSET:
			switch (ep->e_type) {
			case BYTE:
			case UBYTE:
				if (((uint8_t)u64_val &
				    (uint8_t)(ep->e_value.num)) !=
				    (uint8_t)(ep->e_value.num))
					break;
				continue;
			case SHORT:
			case USHORT:
				if (((uint16_t)u64_val &
				    (uint16_t)(ep->e_value.num)) !=
				    (uint16_t)(ep->e_value.num))
					break;
				continue;
			case LONG:
			case ULONG:
				if (((uint32_t)u64_val &
				    (uint32_t)(ep->e_value.num)) !=
				    (uint32_t)(ep->e_value.num))
					break;
				continue;
			case LLONG:
			case ULLONG:
				if ((u64_val & ep->e_value.num) !=
				    ep->e_value.num)
					break;
				continue;
			default:
				continue;
			}
			break;
		case ANY:	/* matches anything */
			break;
		default:	/* shouldn't occur; ignore it */
			continue;
		}
		if (lev1)
			(void) putchar(' ');
		if (ep->e_opcode & SUB) {
			switch (ep->e_type) {
			case LLONG:
#ifdef XPG4
				if (ep->e_mask == 0) {
					(void) printf(ep->e_str,
					    (int64_t)u64_val);
					break;
				}
#endif	/* XPG4 */
				/*FALLTHROUGH*/
			case ULLONG:
				(void) printf(ep->e_str, u64_val);
				break;
			case LONG:
#ifdef XPG4
				if (ep->e_mask == 0) {
					(void) printf(ep->e_str,
					    (int32_t)u64_val);
					break;
				}
#endif	/* XPG4 */
				/*FALLTHROUGH*/
			case ULONG:
				(void) printf(ep->e_str,
				    (uint32_t)u64_val);
				break;
			case SHORT:
#ifdef XPG4
				if (ep->e_mask == 0) {
					(void) printf(ep->e_str,
					    (int16_t)u64_val);
					break;
				}
#endif	/* XPG4 */
				/*FALLTHROUGH*/
			case USHORT:
				(void) printf(ep->e_str,
				    (uint16_t)u64_val);
				break;
			case BYTE:
#ifdef XPG4
				if (ep->e_mask == 0) {
					(void) printf(ep->e_str,
					    (int8_t)u64_val);
					break;
				}
#endif	/* XPG4 */
				/*FALLTHROUGH*/
			case UBYTE:
				(void) printf(ep->e_str,
				    (uint8_t)u64_val);
				break;
			case STR:
				/*
				 * Note: Currently can't get type
				 * STR here because we already
				 * did a 'continue' out of the
				 * loop earlier for case STR
				 */
				break;
			}
		} else
			(void) printf(ep->e_str);
		lev1 = 1;
	}
	result = lev1 ? (int)(1 + ep - mtab) : 0;

	return (result);
}

static void
showstr(char *s, int width)
{
	char c;

	while ((c = *s++) != '\0')
		if (c >= 040 && c < 0176) {
			(void) putchar(c);
			width--;
		} else {
			(void) putchar('\\');
			switch (c) {

			case '\n':
				(void) putchar('n');
				width -= 2;
				break;

			case '\r':
				(void) putchar('r');
				width -= 2;
				break;

			case '\a':
				(void) putchar('a');
				width -= 2;
				break;

			case '\b':
				(void) putchar('b');
				width -= 2;
				break;

			case '\t':
				(void) putchar('t');
				width -= 2;
				break;

			case '\f':
				(void) putchar('f');
				width -= 2;
				break;

			case '\v':
				(void) putchar('v');
				width -= 2;
				break;

			default:
				(void) printf("%.3o", c & 0377);
				width -= 4;
				break;
			}
		}
	while (width >= 0) {
		(void) putchar(' ');
		width--;
	};
}

static char *
type_to_name(Entry *ep)
{
	static char buf[20];
	char	*s;

	switch (ep->e_type) {
	case BYTE:
		s = "byte";
		break;
	case SHORT:
		s = "short";
		break;
	case LONG:
		s = "long";
		break;
	case LLONG:
		s = "llong";
		break;
	case UBYTE:
		s = "ubyte";
		break;
	case USHORT:
		s = "ushort";
		break;
	case ULONG:
		s = "ulong";
		break;
	case ULLONG:
		s = "ullong";
		break;
	case STR:
		return ("string");
	default:
		/* more of an emergency measure .. */
		(void) sprintf(buf, "%d", ep->e_type);
		return (buf);
	}
	if (ep->e_mask) {
		(void) snprintf(buf, sizeof (buf), "%s&0x%llx", s, ep->e_mask);
		return (buf);
	} else
		return (s);
}

static char
op_to_name(char op)
{
	char c;

	switch (op & ~SUB) {

	case EQ:
	case STRC:
		c = '=';
		break;

	case GT:
		c = '>';
		break;

	case LT:
		c = '<';
		break;

	case ANY:
		c = 'x';
		break;

	case AND:
		c = '&';
		break;

	case NSET:
		c = '^';
		break;

	default:
		c = '?';
		break;
	}

	return (c);
}

/*
 * f_prtmtab - Prints out a header, then entries from both magic
 *	tables, mtab1 and mtab2, if any exist.
 */
void
f_prtmtab(void)
{
	Entry	*mtab;
	Entry	*ep;
	int	count;

	(void) printf("%-7s %-7s %-10s %-7s %-11s %s\n",
	    "level", "off", "type", "opcode", "value", "string");
	for (mtab = mtab1, count = 1; count <= 2; count++, mtab = mtab2) {
		if (mtab == (Entry *)NULL) {
			continue;
		}
		for (ep = mtab; ep->e_off != -1L; ep++) {
			(void) printf("%-7d %-7ld %-10s %-7c ",
			    ep->e_level,
			    ep->e_off, type_to_name(ep),
			    op_to_name(ep->e_opcode));
			if (ep->e_type == STR) {
				showstr(ep->e_value.str, 10);
			} else {	/* numeric */
				(void) printf("%-#11llo", ep->e_value.num);
			}
			(void) printf(" %s", ep->e_str);
			if (ep->e_opcode & SUB)
				(void) printf("\tsubst");
			(void) printf("\n");
		}
	}
}

intmax_t
f_getmaxoffset(int first)
{
	Entry *mtab;
	Entry *ep;
	intmax_t cur;
	intmax_t max = 0;

	if (first) {
		mtab = mtab1;
	} else {
		mtab = mtab2;
	}
	if (mtab == (Entry *)NULL) {
		return (0);
	}
	for (ep = mtab; ep->e_off != -1L; ep++) {
		cur = ep->e_off;
		switch (ep->e_type) {
		case STR:
			cur += strlen(ep->e_value.str);
			break;
		case BYTE:
		case UBYTE:
			cur += sizeof (uchar_t);
			break;
		case SHORT:
		case USHORT:
			cur += sizeof (uint16_t);
			break;
		case LONG:
		case ULONG:
			cur += sizeof (uint32_t);
			break;
		case LLONG:
		case ULLONG:
			cur += sizeof (uint64_t);
			break;
		}
		if (cur <= INT_MAX && cur > max) {
			max = cur;
		}
	}

	return (max);
}
