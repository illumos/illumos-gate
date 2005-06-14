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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "gnu_msgfmt.h"

#define	OPT_L	0x01
#define	OPT_l	0x02
#define	OPT_ll	0x04
#define	OPT_w	0x08
#define	OPT_h	0x10
#define	OPT_hh	0x20
#define	OPT_j	0x40

static int
extract_format(char *norm, const char *sfmt, size_t sz)
{
	const unsigned char	*fmt = (const unsigned char *)sfmt;
	unsigned char	c;
	int	t, arg, ap;
	int	dotseen;
	char	flag, conv;
	int	lastarg = -1;
	int	prevarg;
	int	max = 0;
	int	lflag;

	for (; *fmt; fmt++) {
		if (*fmt == '%') {
			if (*++fmt == '%')
				continue;
			if (!*fmt)
				break;
			prevarg = lastarg;
			arg = ++lastarg;

			t = 0;
			while (*fmt && isdigit(*fmt))
				t = t * 10 + *fmt++ - '0';

			if (*fmt == '$') {
				lastarg = arg = t - 1;
				fmt++;
			}

			if (!*fmt)
				goto end;

			dotseen = 0;
			flag = 0;
			lflag = 0;
again:
			/* Skip flags */
			while ((c = *fmt) != '\0') {
				if (c == '\'' || c == '+' || c == '-' ||
					c == ' ' || c == '#' || c == '0') {
					fmt++;
					continue;
				}
				break;
			}

			while (*fmt && isdigit(*fmt))
				fmt++;

			if (*fmt == '*') {
				if (isdigit(*(fmt + 1))) {
					fmt++;
					t = 0;
					while (*fmt && isdigit(*fmt))
						t = t * 10 + *fmt++ - '0';

					if (*fmt == '$') {
						/*
						 * %*4$
						 */
						ap = t - 1;
						if ((ap * 2 + 1 >= sz) ||
							(norm[ap * 2] &&
							norm[ap * 2] != '*')) {
							/* error in format */
							return (-1);
						} else {
							if (ap >= max)
								max = ap + 1;
							norm[ap * 2] = '*';
						}
					}
					/*
					 * If digits follow a '*', it is
					 * not loaded as an argument, the
					 * digits are used instead.
					 */
				} else {
					/*
					 * %*
					 */
					if (*(fmt + 1) == '$') {
						fmt++;
					} else {
						ap = arg;
						prevarg = arg;
						lastarg = ++arg;
						if ((ap * 2 + 1 >= sz) ||
							(norm[ap * 2] &&
							norm[ap * 2] != '*')) {
							/* error in format */
							return (-1);
						} else {
							if (ap >= max)
								max = ap + 1;
							norm[ap * 2] = '*';
						}
					}
				}
				fmt++;
			}

			if ((*fmt == '.') || (*fmt == '*')) {
				if (dotseen)
					return (-1);
				dotseen = 1;
				fmt++;
				goto again;
			}

			if (!*fmt)
				goto end;

			while (*fmt) {
				switch (*fmt) {
				case 'l':
					if (!(flag & OPT_ll)) {
						if (lflag) {
							flag &= ~OPT_l;
							flag |= OPT_ll;
						} else {
							flag |= OPT_l;
						}
					}
					lflag++;
					break;
				case 'L':
					flag |= OPT_L;
					break;
				case 'w':
					flag |= OPT_w;
					break;
				case 'h':
					if (flag & (OPT_h|OPT_hh))
						flag |= OPT_hh;
					else
						flag |= OPT_h;
					break;
				case 'j':
					flag |= OPT_j;
					break;
				case 'z':
				case 't':
					if (!(flag & OPT_ll)) {
						flag |= OPT_l;
					}
					break;
				case '\'':
				case '+':
				case '-':
				case ' ':
				case '#':
				case '.':
				case '*':
					goto again;
				default:
					if (isdigit(*fmt))
						goto again;
					else
						goto done;
				}
				fmt++;
			}
done:
			if (!*fmt)
				goto end;

			if ((c = *fmt) == 'C') {
				flag |= OPT_l;
				conv = 'c';
			} else if (c == 'd') {
				conv = 'd';
			} else if (c == 'S') {
				flag |= OPT_l;
				conv = 's';
			} else if (c == 's') {
				conv = 's';
			} else if (c == 'i') {
				conv = 'i';
			} else if (c == 'o') {
				conv = 'o';
			} else if (c == 'u') {
				conv = 'u';
			} else if (c == 'c') {
				conv = 'c';
			} else if (c == 'x') {
				conv = 'x';
			} else if (c == 'X') {
				conv = 'X';
			} else if (c == 'e') {
				conv = 'e';
			} else if (c == 'E') {
				conv = 'E';
			} else if (c == 'f') {
				conv = 'f';
			} else if (c == 'F') {
				conv = 'F';
			} else if (c == 'a') {
				conv = 'a';
			} else if (c == 'A') {
				conv = 'A';
			} else if (c == 'g') {
				conv = 'g';
			} else if (c == 'G') {
				conv = 'G';
			} else if (c == 'p') {
				conv = 'p';
			} else if (c == 'n') {
				conv = 'n';
			} else {
				lastarg = prevarg;
				continue;
			}

			if ((arg * 2 + 1 >= sz) ||
				(norm[arg * 2] &&
				(norm[arg * 2] != conv))) {
				return (-1);
			} else {
				if (arg >= max)
					max = arg + 1;
				norm[arg * 2] = conv;
			}
			norm[arg * 2 + 1] = flag;
		}
	}

end:
	for (arg = 0; arg < max; arg++) {
		if (norm[arg * 2] == '\0')
			return (-1);
	}

	return (max);
}


void
check_format(struct entry *id, struct entry *str, int is_c_format)
{
	int	i, n;
	int	id_b_newline, id_e_newline;
	int	plural_b_newline, plural_e_newline;
	int	str_b_newline, str_e_newline;
	int	id_fmt, plural_fmt, str_fmt;
	int	*pstr_fmt;
	char	*msgid, *plural, *msgstr;
	char	*id_norm, *plural_norm, *str_norm;
	char	**pstr_norm;
	size_t	id_len, id_num;
	size_t	plural_off, plural_len, plural_num;
	size_t	str_len, str_num;
	size_t	osz, nsz;
	struct loc	*p;

	if (id->len == 1) {
		/*
		 * null string: header entry
		 * no check is performed
		 */
		return;
	}

	msgid = id->str;
	id_num = id->num;
	msgstr = str->str;
	if (id->no > 1) {
		/* plural */
		id_len = id->pos[0].len;
		plural_off = id->pos[1].off;
		plural_len = id->pos[1].len;
		plural_num = id->pos[1].num;
		plural = msgid + plural_off;
	} else {
		/* no plural form */
		id_len = id->len;
		str_len = str->len;
		str_num = str->num;
		plural = NULL;
	}

	/*
	 * First checking the newline
	 */

	if (!plural) {
		/* no plural form */
		id_b_newline = (msgid[0] == '\n');
		id_e_newline = (msgid[id_len - 1 - 1] == '\n');

		str_b_newline = (msgstr[0] == '\n');
		str_e_newline = (msgstr[str_len - 1 - 1] == '\n');
		if (id_b_newline && !str_b_newline) {
			diag(gettext(ERR_BEGIN_NEWLINE_1),
				id_num, str_num, cur_po);
			po_error++;
		} else if (!id_b_newline && str_b_newline) {
			diag(gettext(ERR_BEGIN_NEWLINE_2),
				id_num, str_num, cur_po);
			po_error++;
		}
		if (id_e_newline && !str_e_newline) {
			diag(gettext(ERR_END_NEWLINE_1),
				id_num, str_num, cur_po);
			po_error++;
		} else if (!id_e_newline && str_e_newline) {
			diag(gettext(ERR_END_NEWLINE_2),
				id_num, str_num, cur_po);
			po_error++;
		}
	} else {
		/* plural form */
		id_b_newline = (msgid[0] == '\n');
		id_e_newline = (msgid[id_len - 1 - 1] == '\n');

		plural_b_newline = (plural[0] == '\n');
		plural_e_newline = (plural[plural_len - 1 -1 ] == '\n');

		/* between msgid and msgid_plural */
		if (id_b_newline && !plural_b_newline) {
			diag(gettext(ERR_BEGIN_NEWLINE_3),
				id_num, plural_num, cur_po);
			po_error++;
		} else if (!id_b_newline && plural_b_newline) {
			diag(gettext(ERR_BEGIN_NEWLINE_4),
				id_num, plural_num, cur_po);
			po_error++;
		}
		if (id_e_newline && !plural_e_newline) {
			diag(gettext(ERR_END_NEWLINE_3),
				id_num, plural_num, cur_po);
			po_error++;
		} else if (!id_e_newline && plural_e_newline) {
			diag(gettext(ERR_END_NEWLINE_4),
				id_num, plural_num, cur_po);
			po_error++;
		}

		for (i = 0; i < str->no; i++) {
			p = str->pos + i;
			str_b_newline = (msgstr[p->off] == '\n');
			str_e_newline =
				(msgstr[p->off + p->len - 1 - 1] == '\n');

			if (id_b_newline && !str_b_newline) {
				diag(gettext(ERR_BEGIN_NEWLINE_5),
					id_num, p->num, cur_po, i);
				po_error++;
			} else if (!id_b_newline && str_b_newline) {
				diag(gettext(ERR_BEGIN_NEWLINE_6),
					id_num, p->num, cur_po, i);
				po_error++;
			}

			if (id_e_newline && !str_e_newline) {
				diag(gettext(ERR_END_NEWLINE_5),
					id_num, p->num, cur_po, i);
				po_error++;
			} else if (!id_e_newline && str_e_newline) {
				diag(gettext(ERR_END_NEWLINE_6),
					id_num, p->num, cur_po, i);
				po_error++;
			}
		}
	}

	/*
	 * if c-format is not specified, no printf-format check
	 * is performed.
	 */
	if (!is_c_format) {
		return;
	}

	osz = id_len * 2;
	id_norm = (char *)Xcalloc(1, osz);
	id_fmt = extract_format(id_norm, msgid, osz);
	if (id_fmt == -1) {
		diag(gettext(ERR_INVALID_FMT), id_num, cur_po);
		po_error++;
	}

	if (!plural) {
		/* no plural */

		nsz = str_len * 2;
		str_norm = (char *)Xcalloc(1, nsz);
		str_fmt = extract_format(str_norm, msgstr, nsz);
		if (str_fmt == -1) {
			diag(gettext(ERR_INVALID_FMT), str_num, cur_po);
			po_error++;
		}

		if (id_fmt != str_fmt) {
			diag(gettext(ERR_INCMP_FMT),
				id_num, str_num, cur_po);
			diag(gettext(ERR_INCMP_FMT_DIFF_1),
				id_fmt, str_fmt);
			po_error++;
		} else {
			for (n = 0; n < id_fmt; n++) {
				if ((id_norm[n * 2] !=
					str_norm[n * 2]) ||
					(id_norm[n * 2 + 1] !=
					str_norm[n * 2 + 1])) {
					diag(gettext(ERR_INCMP_FMT),
						id_num, str_num, cur_po);
					diag(gettext(ERR_INCMP_FMT_DIFF_2),
						n + 1);
					po_error++;
				}
			}
		}
		free(str_norm);
		free(id_norm);

		return;
	}

	/* plural */
	nsz = plural_len * 2;
	plural_norm = (char *)Xcalloc(1, nsz);
	plural_fmt = extract_format(plural_norm, plural, nsz);
	if (plural_fmt == -1) {
		diag(gettext(ERR_INVALID_FMT), plural_num, cur_po);
		po_error++;
	}

	pstr_norm = (char **)Xcalloc(str->no, sizeof (char *));
	pstr_fmt = (int *)Xcalloc(str->no, sizeof (int));
	for (i = 0; i < str->no; i++) {
		p = str->pos + i;
		nsz = p->len * 2;
		pstr_norm[i] = (char *)Xcalloc(1, nsz);
		pstr_fmt[i] = extract_format(pstr_norm[i],
			msgstr + p->off, nsz);
		if (pstr_fmt[i] == -1) {
			diag(gettext(ERR_INVALID_FMT),
				p->num, cur_po);
			po_error++;
		}
	}

	/* between msgid and msgid_plural */
	if (id_fmt != plural_fmt) {
		diag(gettext(ERR_INCMP_FMT),
			id_num, plural_num, cur_po);
		diag(gettext(ERR_INCMP_FMT_DIFF_1),
			id_fmt, plural_fmt);
		po_error++;
	} else {
		for (n = 0; n < id_fmt; n++) {
			if ((id_norm[n * 2] !=
				plural_norm[n * 2]) ||
				(id_norm[n * 2 + 1] !=
				plural_norm[n * 2 + 1])) {
				diag(gettext(ERR_INCMP_FMT),
					id_num, plural_num, cur_po);
				diag(gettext(ERR_INCMP_FMT_DIFF_2),
					n + 1);
				po_error++;
			}
		}
	}
	free(plural_norm);

	/* between msgid and msgstr */
	for (i = 0; i < str->no; i++) {
		p = str->pos + i;
		if (id_fmt != pstr_fmt[i]) {
			diag(gettext(ERR_INCMP_FMT),
				id_num, p->num, cur_po);
			diag(gettext(ERR_INCMP_FMT_DIFF_1),
				id_fmt, pstr_fmt[i]);
			po_error++;
		} else {
			for (n = 0; n < id_fmt; n++) {
				if ((id_norm[n * 2] !=
					pstr_norm[i][n * 2]) ||
					(id_norm[n * 2 + 1] !=
					pstr_norm[i][n * 2 + 1])) {
					diag(gettext(ERR_INCMP_FMT),
						id_num, p->num, cur_po);
					diag(gettext(ERR_INCMP_FMT_DIFF_2),
						n + 1);
					po_error++;
				}
			}
		}
		free(pstr_norm[i]);
	}
	free(pstr_norm);
	free(pstr_fmt);
	free(id_norm);
}
