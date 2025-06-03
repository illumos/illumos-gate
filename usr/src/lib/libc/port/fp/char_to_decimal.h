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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file contains the common part of the functions string_to_decimal,
 * func_to_decimal, and file_to_decimal.  Much of this code has been dupli-
 * cated in wstring_to_decimal (see wstod.c) with some simplifications and
 * appropriate modifications for wide characters.  DO NOT fix a bug here
 * without fixing the same bug in wstring_to_decimal, if it applies.
 *
 * The code below makes the following assumptions.
 *
 * 1. The first six parameters to the function are declared with the
 *    following names and types:
 *
 *    char **ppc;
 *    int nmax;
 *    int fortran_conventions;
 *    decimal_record *pd;
 *    enum decimal_string_form *pform;
 *    char **pechar;
 *
 * 2. Before this file is #included, the following variables have been
 *    defined and initialized as shown:
 *
 *    char *cp;
 *    char *good = *ppc - 1;
 *    int current;
 *    int nread;
 *    locale_t loc;
 *
 *    If the first character can be read successfully, then current is set
 *    to the value of the first character, cp is set to *ppc, (char)current
 *    is stored at *cp, and nread = 1.  If the first character cannot be
 *    read successfully, then current = EOF and nread = 0.
 *    loc should be set to the desired locale in which to perform the
 *    conversion.
 *
 * 3. The macro NEXT is defined to expand to code that implements
 *    the following logic:
 *
 *      if (nread < nmax) {
 *          current = <next character>;
 *          if (current != EOF) {
 *             *++cp = (char)current;
 *             nread++;
 *          }
 *      } else
 *          current = EOF;
 *
 *    Note that nread always reflects the number of characters successfully
 *    read, the buffer pointed to by *ppc gets filled only with characters
 *    that have been successfully read, and cp always points to the location
 *    in the buffer that was filled by the last character successfully read.
 *    current == EOF if and only if we can't read any more, either because
 *    we've reached the end of the input file or the buffer is full (i.e.,
 *    we've read nmax characters).
 *
 * 4. After this file is #included, the following variables may be used
 *    and will have the specified values:
 *
 *    *ppc, *pd, *pform, and *pechar will be set as documented in the
 *      manual page;
 *    nmax and fortran_conventions will be unchanged;
 *    nread will be the number of characters actually read;
 *    cp will point to the last character actually read, provided at least
 *      one character was read successfully (in which case cp >= *ppc).
 */

#define	UCASE(c) ((('a' <= c) && (c <= 'z'))? c - 32 : c)

#define	NZDIGIT(c)	(('1' <= c && c <= '9') || ((int)form < 0 && \
			(('a' <= c && c <= 'f') || ('A' <= c && c <= 'F'))))

{
	static const char    *infstring = "INFINITY";
	static const char    *nanstring = "NAN";

	int	sigfound, spacefound = 0;
	int	ids = 0;
	int	i, agree;
	int	nzbp = 0; /* number of zeros before point */
	int	nzap = 0; /* number of zeros after point */
	char	decpt;
	int	nfast, nfastlimit;
	char	*pfast;
	int	e, esign;
	int	expshift = 0;
	enum decimal_string_form	form;

	/*
	 * This routine assumes that the radix point is a single
	 * ASCII character, so that following this assignment, the
	 * condition (current == decpt) will correctly detect it.
	 */
	if (fortran_conventions > 0)
		decpt = '.';
	else
		decpt = *(localeconv_l(loc)->decimal_point);

	/* input is invalid until we find something */
	pd->fpclass = fp_signaling;
	pd->sign = 0;
	pd->exponent = 0;
	pd->ds[0] = '\0';
	pd->more = 0;
	pd->ndigits = 0;
	*pform = form = invalid_form;
	*pechar = NULL;

	/* skip white space */
	while (isspace_l(current, loc)) {
		spacefound = 1;
		NEXT;
	}

	if (fortran_conventions >= 2 && spacefound) {
		/*
		 * We found at least one white space character.  For
		 * Fortran formatted input, accept this; if we don't
		 * find anything else, we'll interpret it as a valid zero.
		 */
		pd->fpclass = fp_zero;
		form = whitespace_form;
		sigfound = 0;		/* 0 = only zeros found so far */
		if (current == EOF) {
			good = cp;
			goto done;
		} else {
			good = cp - 1;
		}
	} else {
		sigfound = -1;		/* -1 = no digits found yet */
	}

	/* look for optional leading sign */
	if (current == '+') {
		NEXT;
	} else if (current == '-') {
		pd->sign = 1;
		NEXT;
	}

	/*
	 * Admissible first non-white-space, non-sign characters are
	 * 0-9, i, I, n, N, or the radix point.
	 */
	if ('1' <= current && current <= '9') {
		good = cp;
		pd->fpclass = fp_normal;
		form = fixed_int_form;
		sigfound = 1;		/* 1 = significant digits found */
		pd->ds[ids++] = (char)current;
		NEXT;
	} else {
		switch (current) {
		case ' ':
			if (fortran_conventions < 2)
				goto done;
			/*
			 * When fortran_conventions >= 2, treat leading
			 * blanks the same as leading zeroes.
			 */
			/*FALLTHRU*/

		case '0':
			/*
			 * Accept the leading zero and set pd->fpclass
			 * accordingly, but don't set sigfound until we
			 * determine that this isn't a "fake" hex string
			 * (i.e., 0x.p...).
			 */
			good = cp;
			pd->fpclass = fp_zero;
			if (fortran_conventions < 0) {
				/* look for a hex fp string */
				NEXT;
				if (current == 'X' || current == 'x') {
					/* assume hex fp form */
					form = (enum decimal_string_form)-1;
					expshift = 2;
					NEXT;
					/*
					 * Only a digit or radix point can
					 * follow "0x".
					 */
					if (NZDIGIT(current)) {
						pd->fpclass = fp_normal;
						good = cp;
						sigfound = 1;
						pd->ds[ids++] = (char)current;
						NEXT;
						break;
					} else if (current == decpt) {
						NEXT;
						goto afterpoint;
					} else if (current != '0') {
						/* not hex fp after all */
						form = fixed_int_form;
						expshift = 0;
						goto done;
					}
				} else {
					form = fixed_int_form;
				}
			} else {
				form = fixed_int_form;
			}

			/* skip all leading zeros */
			while (current == '0' || (current == ' ' &&
			    fortran_conventions >= 2)) {
				NEXT;
			}
			sigfound = 0;	/* 0 = only zeros found so far */
			if (current == EOF) {
				good = cp;
				goto done;
			} else {
				good = cp - 1;
			}
			break;

		case 'i':
		case 'I':
			/* look for inf or infinity */
			NEXT;
			agree = 1;
			while (agree <= 7 &&
			    UCASE(current) == infstring[agree]) {
				NEXT;
				agree++;
			}
			if (agree < 3)
				goto done;
			/* found valid infinity */
			pd->fpclass = fp_infinity;
			sigfound = 1;
			__inf_read = 1;
			if (agree < 8) {
				good = (current == EOF)? cp + 3 - agree :
				    cp + 2 - agree;
				form = inf_form;
			} else {
				good = (current == EOF)? cp : cp - 1;
				form = infinity_form;
			}
			/*
			 * Accept trailing blanks if no extra characters
			 * intervene.
			 */
			if (fortran_conventions >= 2 && (agree == 3 ||
			    agree == 8)) {
				while (current == ' ') {
					NEXT;
				}
				good = (current == EOF)? cp : cp - 1;
			}
			goto done;

		case 'n':
		case 'N':
			/* look for nan or nan(string) */
			NEXT;
			agree = 1;
			while (agree <= 2 &&
			    UCASE(current) == nanstring[agree]) {
				NEXT;
				agree++;
			}
			if (agree < 3)
				goto done;
			/* found valid NaN */
			good = (current == EOF)? cp : cp - 1;
			pd->fpclass = fp_quiet;
			form = nan_form;
			sigfound = 1;
			__nan_read = 1;
			if (current == '(') {
				/* accept parenthesized string */
				NEXT;
				if (fortran_conventions < 0) {
					while ((isalnum_l(current, loc) ||
					    current == '_') &&
					    ids < DECIMAL_STRING_LENGTH - 1) {
						pd->ds[ids++] = (char)current;
						NEXT;
					}
					while (isalnum_l(current, loc) ||
					    current == '_') {
						pd->more = 1;
						NEXT;
					}
				} else {
					while (current > 0 && current != ')' &&
					    ids < DECIMAL_STRING_LENGTH - 1) {
						pd->ds[ids++] = (char)current;
						NEXT;
					}
					while (current > 0 && current != ')') {
						pd->more = 1;
						NEXT;
					}
				}
				if (current != ')')
					goto done;
				good = cp;
				form = nanstring_form;
				/* prepare for loop below */
				if (fortran_conventions >= 2) {
					NEXT;
				}
			}
			/* accept trailing blanks */
			if (fortran_conventions >= 2) {
				while (current == ' ') {
					NEXT;
				}
				good = (current == EOF)? cp : cp - 1;
			}
			goto done;

		default:
			if (current == decpt) {
				/*
				 * Don't accept the radix point just yet;
				 * we need to see at least one digit.
				 */
				NEXT;
				goto afterpoint;
			}
			goto done;
		}
	}

nextnumber:
	/*
	 * Admissible characters after the first digit are a valid digit,
	 * an exponent delimiter (E or e for any decimal form; +, -, D, d,
	 * Q, or q when fortran_conventions >= 2; P or p for hex form),
	 * or the radix point.  (Note that we can't get here unless we've
	 * already found a digit.)
	 */
	if (NZDIGIT(current)) {
		/*
		 * Found another nonzero digit.  If there's enough room
		 * in pd->ds, store any intervening zeros we've found so far
		 * and then store this digit.  Otherwise, stop storing
		 * digits in pd->ds and set pd->more.
		 */
		if (ids + nzbp + 2 < DECIMAL_STRING_LENGTH) {
			for (i = 0; i < nzbp; i++)
				pd->ds[ids++] = '0';
			pd->ds[ids++] = (char)current;
		} else {
			pd->exponent += (nzbp + 1) << expshift;
			pd->more = 1;
			if (ids < DECIMAL_STRING_LENGTH) {
				pd->ds[ids] = '\0';
				pd->ndigits = ids;
				/* don't store any more digits */
				ids = DECIMAL_STRING_LENGTH;
			}
		}
		pd->fpclass = fp_normal;
		sigfound = 1;
		nzbp = 0;
		NEXT;

		/*
		 * Use an optimized loop to grab a consecutive sequence
		 * of nonzero digits quickly.
		 */
		nfastlimit = DECIMAL_STRING_LENGTH - 3 - ids;
		for (nfast = 0, pfast = &(pd->ds[ids]);
		    nfast < nfastlimit && NZDIGIT(current);
		    nfast++) {
			*pfast++ = (char)current;
			NEXT;
		}
		ids += nfast;
		if (current == '0')
			goto nextnumberzero;	/* common case */
		/* advance good to the last accepted digit */
		good = (current == EOF)? cp : cp - 1;
		goto nextnumber;
	} else {
		switch (current) {
		case ' ':
			if (fortran_conventions < 2)
				goto done;
			if (fortran_conventions == 2) {
				while (current == ' ') {
					NEXT;
				}
				good = (current == EOF)? cp : cp - 1;
				goto nextnumber;
			}
			/*
			 * When fortran_conventions > 2, treat internal
			 * blanks the same as zeroes.
			 */
			/*FALLTHRU*/

		case '0':
nextnumberzero:
			/*
			 * Count zeros before the radix point.  Later we
			 * will either put these zeros into pd->ds or add
			 * nzbp to pd->exponent to account for them.
			 */
			while (current == '0' || (current == ' ' &&
			    fortran_conventions > 2)) {
				nzbp++;
				NEXT;
			}
			good = (current == EOF)? cp : cp - 1;
			goto nextnumber;

		case '+':
		case '-':
		case 'D':
		case 'd':
		case 'Q':
		case 'q':
			/*
			 * Only accept these as the start of the exponent
			 * field if fortran_conventions is positive.
			 */
			if (fortran_conventions <= 0)
				goto done;
			/*FALLTHRU*/

		case 'E':
		case 'e':
			if ((int)form < 0)
				goto done;
			goto exponent;

		case 'P':
		case 'p':
			if ((int)form > 0)
				goto done;
			goto exponent;

		default:
			if (current == decpt) {
				/* accept the radix point */
				good = cp;
				if (form == fixed_int_form)
					form = fixed_intdot_form;
				NEXT;
				goto afterpoint;
			}
			goto done;
		}
	}

afterpoint:
	/*
	 * Admissible characters after the radix point are a valid digit
	 * or an exponent delimiter.  (Note that it is possible to get
	 * here even though we haven't found any digits yet.)
	 */
	if (NZDIGIT(current)) {
		/* found a digit after the point; revise form */
		if (form == invalid_form || form == whitespace_form)
			form = fixed_dotfrac_form;
		else if (form == fixed_intdot_form)
			form = fixed_intdotfrac_form;
		good = cp;
		if (sigfound < 1) {
			/* no significant digits found until now */
			pd->fpclass = fp_normal;
			sigfound = 1;
			pd->ds[ids++] = (char)current;
			pd->exponent = (-(nzap + 1)) << expshift;
		} else {
			/* significant digits have been found */
			if (ids + nzbp + nzap + 2 < DECIMAL_STRING_LENGTH) {
				for (i = 0; i < nzbp + nzap; i++)
					pd->ds[ids++] = '0';
				pd->ds[ids++] = (char)current;
				pd->exponent -= (nzap + 1) << expshift;
			} else {
				pd->exponent += nzbp << expshift;
				pd->more = 1;
				if (ids < DECIMAL_STRING_LENGTH) {
					pd->ds[ids] = '\0';
					pd->ndigits = ids;
					/* don't store any more digits */
					ids = DECIMAL_STRING_LENGTH;
				}
			}
		}
		nzbp = 0;
		nzap = 0;
		NEXT;

		/*
		 * Use an optimized loop to grab a consecutive sequence
		 * of nonzero digits quickly.
		 */
		nfastlimit = DECIMAL_STRING_LENGTH - 3 - ids;
		for (nfast = 0, pfast = &(pd->ds[ids]);
		    nfast < nfastlimit && NZDIGIT(current);
		    nfast++) {
			*pfast++ = (char)current;
			NEXT;
		}
		ids += nfast;
		pd->exponent -= nfast << expshift;
		if (current == '0')
			goto zeroafterpoint;
		/* advance good to the last accepted digit */
		good = (current == EOF)? cp : cp - 1;
		goto afterpoint;
	} else {
		switch (current) {
		case ' ':
			if (fortran_conventions < 2)
				goto done;
			if (fortran_conventions == 2) {
				/*
				 * Treat a radix point followed by blanks
				 * but no digits as zero so we'll pass FCVS.
				 */
				if (sigfound == -1) {
					pd->fpclass = fp_zero;
					sigfound = 0;
				}
				while (current == ' ') {
					NEXT;
				}
				good = (current == EOF)? cp : cp - 1;
				goto afterpoint;
			}
			/*
			 * when fortran_conventions > 2, treat internal
			 * blanks the same as zeroes
			 */
			/*FALLTHRU*/

		case '0':
			/* found a digit after the point; revise form */
			if (form == invalid_form || form == whitespace_form)
				form = fixed_dotfrac_form;
			else if (form == fixed_intdot_form)
				form = fixed_intdotfrac_form;
			if (sigfound == -1) {
				pd->fpclass = fp_zero;
				sigfound = 0;
			}
zeroafterpoint:
			/*
			 * Count zeros after the radix point.  If we find
			 * any more nonzero digits later, we will put these
			 * zeros into pd->ds and decrease pd->exponent by
			 * nzap.
			 */
			while (current == '0' || (current == ' ' &&
			    fortran_conventions > 2)) {
				nzap++;
				NEXT;
			}
			if (current == EOF) {
				good = cp;
				goto done;
			} else {
				good = cp - 1;
			}
			goto afterpoint;

		case '+':
		case '-':
		case 'D':
		case 'd':
		case 'Q':
		case 'q':
			/*
			 * Only accept these as the start of the exponent
			 * field if fortran_conventions is positive.
			 */
			if (fortran_conventions <= 0)
				goto done;
			/*FALLTHRU*/

		case 'E':
		case 'e':
			/* don't accept exponent without preceding digits */
			if (sigfound == -1 || (int)form < 0)
				goto done;
			break;

		case 'P':
		case 'p':
			/* don't accept exponent without preceding digits */
			if (sigfound == -1 || (int)form > 0)
				goto done;
			break;

		default:
			goto done;
		}
	}

exponent:
	/*
	 * Set *pechar to point to the character that looks like the
	 * beginning of the exponent field, then attempt to parse it.
	 */
	*pechar = cp;
	if (current != '+' && current != '-') {
		/* skip the exponent character and following blanks */
		NEXT;
		if (fortran_conventions >= 2 && current == ' ') {
			while (current == ' ') {
				NEXT;
			}
			if (fortran_conventions > 2)
				good = (current == EOF)? cp : cp - 1;
		}
	}

	e = 0;
	esign = 0;

	/* look for optional exponent sign */
	if (current == '+') {
		NEXT;
	} else if (current == '-') {
		esign = 1;
		NEXT;
	}

	/*
	 * Accumulate explicit exponent.  Note that if we don't find at
	 * least one digit, good won't be updated and e will remain 0.
	 * Also, we keep e from getting too large so we don't overflow
	 * the range of int (but notice that the threshold is large
	 * enough that any larger e would cause the result to underflow
	 * or overflow anyway).
	 */
	while (('0' <= current && current <= '9') || current == ' ') {
		if (current == ' ') {
			if (fortran_conventions < 2)
				break;
			if (fortran_conventions == 2) {
				NEXT;
				continue;
			}
			current = '0';
		}
		good = cp;
		if (e <= 1000000)
			e = 10 * e + current - '0';
		NEXT;
		if (fortran_conventions == 2 && current == ' ') {
			/* accept trailing blanks */
			while (current == ' ') {
				NEXT;
			}
			good = (current == EOF)? cp : cp - 1;
		}
	}
	if (esign == 1)
		pd->exponent -= e;
	else
		pd->exponent += e;

	/*
	 * If we successfully parsed an exponent field, update form
	 * accordingly.  If we didn't, don't set *pechar.
	 */
	if (good >= *pechar) {
		switch (form) {
		case whitespace_form:
		case fixed_int_form:
			form = floating_int_form;
			break;

		case fixed_intdot_form:
			form = floating_intdot_form;
			break;

		case fixed_dotfrac_form:
			form = floating_dotfrac_form;
			break;

		case fixed_intdotfrac_form:
			form = floating_intdotfrac_form;
			break;
		}
	} else {
		*pechar = NULL;
	}

done:
	/*
	 * If we found any zeros before the radix point that were not
	 * accounted for earlier, adjust the exponent.  (This is only
	 * relevant when pd->fpclass == fp_normal, but it's harmless
	 * in all other cases.)
	 */
	pd->exponent += nzbp << expshift;

	/* terminate pd->ds if we haven't already */
	if (ids < DECIMAL_STRING_LENGTH) {
		pd->ds[ids] = '\0';
		pd->ndigits = ids;
	}

	/*
	 * If we accepted any characters, advance *ppc to point to the
	 * first character we didn't accept; otherwise, pass back a
	 * signaling nan.
	 */
	if (good >= *ppc) {
		*ppc = good + 1;
	} else {
		pd->fpclass = fp_signaling;
		pd->sign = 0;
		form = invalid_form;
	}

	*pform = form;
}
