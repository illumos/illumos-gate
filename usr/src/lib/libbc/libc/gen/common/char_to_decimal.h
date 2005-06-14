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
 * Copyright (c) 1990-1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma	ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains the common part of string_to_decimal, func_to_decimal,
 * and file_to_decimal. NEXT must be defined to cause CURRENT to contain the
 * next input character.   ATEOF must be defined to be == EOF if an input
 * file is at EOF, != EOF otherwise.
 */

{
	int             sigfound;
	int             ids = 0;
	int             i;
	int             nzbp = 0, nzap = 0;	/* Length of zero substring
						 * before point, after point. */
	char            decpt;
	int             nfast, nfastlimit;
	char           *pfast;

	*pform = invalid_form;	/* Invalid until we find something. */
	*pechar = NULL;		/* No exponent field assumed. */
	pd->fpclass = fp_normal;/* Defaults. */
	pd->sign = 0;		/* Positive. */
	pd->exponent = 0;
	pd->more = 0;		/* Assume no overflow of digits on NaN
				 * string. */
	if (fortran_conventions != 0)
		decpt = '.';
	else
#ifdef PRE41
		decpt = '.';
#else
		decpt = *(localeconv()->decimal_point);
#endif
	while (isspace(CURRENT)) {
		NEXT;
	}			/* Skip white space. */
	if (fortran_conventions >= 2) {
		/*
		 * All white space - valid zero for Fortran formatted input.
		 */
		*pform = whitespace_form;
		if (isspace(*cp))
			good = cp;
		else
			good = cp - 1;
		if ((nread >= nmax) && (CURRENT == NULL)) {	/* Used up field width. */
			pd->fpclass = fp_zero;
			goto done;
		}
	}
	if (CURRENT == '+') {
		NEXT;
	} else if (CURRENT == '-') {	/* Negative. */
		pd->sign = 1;
		NEXT;
	}
	sigfound = -1;		/* -1 = no digits found yet. */

	if (('1' <= CURRENT) && (CURRENT <= '9')) {
		good = cp;
		*pform = fixed_int_form;
		sigfound = 1;	/* 1 = significant digits found. */
		pd->ds[ids++] = CURRENT;
		NEXT;
		goto number;
	} else
		switch (CURRENT) {
		case ' ':
			if (fortran_conventions < 2)
				goto firstdefault;
		case '0':
			*pform = fixed_int_form;
			while ((CURRENT == '0') || ((fortran_conventions >= 2) && (CURRENT == ' '))) {
				NEXT;
			}	/* Ignore leading zeros. */
			if ((*cp == '0') || ((fortran_conventions >= 2) && (*cp == ' ')))
				good = cp;
			else
				good = cp - 1;
			sigfound = 0;	/* 0 = only zeros found yet. */
			goto number;
		case 'i':
		case 'I':
			{	/* Try infinity. */
				static char    *infstring = "INFINITY";
				int             is, iagree;

#define UCASE(c) ( (('a' <= c) && (c <= 'z')) ? c - 32 : c )

				NEXT;
				is = 1;
				while (is <= 7 &&
					UCASE(CURRENT) == infstring[is]) {
					NEXT;
					is++;
				}
					iagree = is;
				if (CURRENT != NULL) {
					is++;	/* To account for infstring
						 * indexing starting at 0.
						 */
				}
				if (iagree >= 3) {	/* Found syntactically
							 * valid infinity. */
					if (iagree < 8) {	/* INFxxxx */
						if (iagree > 3) {
							nmax++;	/* 1083219 */
							CURRENT = EOF;	/* 1083219 */
						}
						good = cp - (is - 3);
						*pform = inf_form;
					} else {	/* INFINITYxxx */
						good = cp - (is - 8);
						*pform = infinity_form;
					}
					pd->fpclass = fp_infinity;
					sigfound = iagree;
				}
				else {
					nmax++;			/* 1083219 */
					CURRENT = EOF;		/* 1083219 */
				}
				goto done;
			}
		case 'n':
		case 'N':
			{	/* Try NaN. */
				static char    *nanstring = "NAN(";
				int             is;

				NEXT;
				is = 1;
				while (is <= 3 &&
					UCASE(CURRENT) == nanstring[is]) {
					NEXT;
					is++;
				}
				if ((is == 3)) {	/* Found syntactically
							 * valid NaN. */
					*pform = nan_form;
					good = CURRENT == NULL ? cp : cp - 1;
					pd->fpclass = fp_quiet;
					sigfound = 1;
				}
				else if (is == 4) {	/* Found NaN followed by
						 * parenthesis. */
					good = CURRENT == NULL ? cp - 1 : cp - 2;
					*pform = nan_form;
					pd->fpclass = fp_quiet;
					sigfound = 1;
					while ((CURRENT != 0) && (CURRENT != ')') && (ids < (DECIMAL_STRING_LENGTH - 1))) {
						pd->ds[ids++] = CURRENT;
						NEXT;
					}
					while ((CURRENT != 0) && (CURRENT != ')') && (ATEOF != EOF)) {	/* Pick up rest of
													 * string. */
						pd->more = 1;
						NEXT;
					}
					if (CURRENT == ')') {
						good = cp;
						NEXT;
					*pform = nanstring_form;
				}
					else {
						nmax++;		/* 1083219 */
						CURRENT = EOF;	/* 1083219 */
					}
				}
				else {
					nmax++;		/* 1083219 */
					CURRENT = EOF;	/* 1083219 */
				}
				goto done;
			}
		default:
			if (CURRENT == decpt) {
				NEXT;	/* Try number. */
				goto afterpoint;
			}
	firstdefault:
			goto done;
		}

number:

nextnumber:
	if (('1' <= CURRENT) && (CURRENT <= '9')) {
		if ((ids + nzbp + 2) >= DECIMAL_STRING_LENGTH) {	/* Not enough room to
									 * store it all:  fake
									 * end of string. */
			pd->exponent += nzbp + 1;
			pd->more = 1;
			pd->ds[ids] = 0;	/* Actual string termination. */
			ids = DECIMAL_STRING_LENGTH - 1;	/* To allow end of
								 * program to terminate
								 * again. */
		} else {
			for (i = 0; (i < nzbp); i++)
				pd->ds[ids++] = '0';
			pd->ds[ids++] = CURRENT;
		}
		*pform = fixed_int_form;
		sigfound = 1;
		nzbp = 0;
		NEXT;
		nfastlimit = DECIMAL_STRING_LENGTH - 3 - ids;
		if ((0 < nfastlimit) && ('1' <= CURRENT) && (CURRENT <= '9')) {	/* Special handling for
										 * common case. */
			nfast = 0;
			pfast = &(pd->ds[ids]);
			do {
				pfast[nfast++] = CURRENT;
				NEXT;
			}
			while (('1' <= CURRENT) && (CURRENT <= '9') && (nfast < nfastlimit));
			ids += nfast;
		}
		if (CURRENT == '0')
			goto nextnumberzero;	/* common case */
		good = cp;
		if (('1' > *good) || (*good > '9'))
			good--;	/* look out if we fell off end */
		goto nextnumber;
	} else
		switch (CURRENT) {
		case ' ':
			if (fortran_conventions < 2)
				goto numberdefault;
			if (fortran_conventions == 2) {
				NEXT;
				goto nextnumber;
			}
		case '0':
			*pform = fixed_int_form;
	nextnumberzero:
			while ((CURRENT == '0') || (CURRENT == ' ')) {	/* Accumulate zero
									 * substring. */
				if (CURRENT == ' ') {
					if (fortran_conventions < 2) {
						good = cp - 1;
						goto numberdefault;
					}
					if (fortran_conventions == 2) {
						nzbp--;	/* Undo effect of
							 * following nzbp++ */
					}
				}
				good = cp;
				nzbp++;
				NEXT;
			}
			goto nextnumber;

		case 'E':
		case 'e':
	efound:
			*pechar = cp;
			if (sigfound == -1)	/* exp following no digits?
						 * bad format */
				goto done;
			if (sigfound > 0)
				pd->exponent += nzbp;
			goto exponent;
		case '+':
		case '-':
		case 'D':
		case 'd':
		case 'Q':
		case 'q':
			if (fortran_conventions != 0)
				goto efound;
		default:
			if (CURRENT == decpt) {
				NEXT;
				goto afterpoint;
			}
	numberdefault:
			if (sigfound > 0)
				pd->exponent += nzbp;
			goto done;
		}

afterpoint:
	if (sigfound >= 0) {	/* Better accept the point as good, but don't
				 * accept the next character after.  */
		good = cp - 1;	/* Assume cp points past. */
		if (*good != decpt)	/* If not, bump good. */
			good++;
	}
	switch (*pform) {	/* Revise *pform now that point has been
				 * found. */
	case invalid_form:
	case whitespace_form:
		*pform = fixed_dotfrac_form;
		break;
	case fixed_int_form:
		*pform = fixed_intdot_form;
		break;
	}
switchafterpoint:
	if (('1' <= CURRENT) && (CURRENT <= '9')) {
		if (*pform == fixed_intdot_form)
			*pform = fixed_intdotfrac_form;
		good = cp;
		if (sigfound < 1) {	/* No significant digits found so
					 * far. */
			sigfound = 1;
			pd->ds[ids++] = CURRENT;
			pd->exponent = -(nzap + 1);
		} else {	/* Significant digits have begun. */
			if ((ids + nzbp + nzap + 2) >= DECIMAL_STRING_LENGTH) {	/* Not enough room to
										 * store it all:  fake
										 * end of string. */
				pd->exponent += nzbp;
				pd->more = 1;
				pd->ds[ids] = 0;	/* Actual string
							 * termination. */
				ids = DECIMAL_STRING_LENGTH - 1;	/* To allow end of
									 * program to terminate
									 * again. */
			} else {
				for (i = 0; (i < (nzbp + nzap)); i++)
					pd->ds[ids++] = '0';
				pd->ds[ids++] = CURRENT;
				pd->exponent -= nzap + 1;
			}
		}
		nzbp = 0;
		nzap = 0;
		NEXT;
		nfastlimit = DECIMAL_STRING_LENGTH - 3 - ids;
		if ((0 < nfastlimit) && ('1' <= CURRENT) && (CURRENT <= '9')) {	/* Special handling for
										 * common case. */
			nfast = 0;
			pfast = &(pd->ds[ids]);
			do {
				pfast[nfast++] = CURRENT;
				NEXT;
			}
			while (('1' <= CURRENT) && (CURRENT <= '9') && (nfast < nfastlimit));
			good = cp;
			if (('1' > *good) || (*good > '9'))
				good--;	/* look out if we fell off end */
			ids += nfast;
			pd->exponent -= nfast;
		}
		if (CURRENT == '0')
			goto zeroafterpoint;
		goto switchafterpoint;
	} else
		switch (CURRENT) {
		case ' ':
			if (fortran_conventions < 2)
				goto afterpointdefault;
			if (fortran_conventions == 2) {
				/*
				 * To pass FCVS, all blanks after point must
				 * count as if zero seen.
				 */
				if (sigfound == -1)
					sigfound = 0;
				NEXT;
				goto switchafterpoint;
			}
		case '0':
			if (*pform == fixed_intdot_form)
				*pform = fixed_intdotfrac_form;
			if (sigfound == -1)
				sigfound = 0;
	zeroafterpoint:
			good = cp;
			nzap++;
			NEXT;
			while ((CURRENT == '0') || (CURRENT == ' ')) {
				if (CURRENT == ' ') {	/* Handle blanks and
							 * Fortran. */
					if (fortran_conventions < 2) {
						good = cp - 1;
						goto afterpointdefault;
					}
					if (fortran_conventions == 2) {
						nzap--;	/* Undo following nzap++ */
					}
				}
				nzap++;
				NEXT;
			}
			good = cp;
			if (*good != '0')
				good--;
			goto switchafterpoint;

		case 'E':
		case 'e':
	efound2:
			*pechar = cp;
			if (sigfound == -1)	/* exp following no digits?
						 * bad! */
				goto done;
			if (sigfound > 0)
				pd->exponent += nzbp;
			goto exponent;
		case '+':
		case '-':
		case 'D':
		case 'd':
		case 'Q':
		case 'q':
			if (fortran_conventions != 0)
				goto efound2;

		default:
	afterpointdefault:
			if (sigfound > 0)
				pd->exponent += nzbp;
			goto done;
		}
exponent:
	{
		unsigned        explicitsign = 0, explicitexponent = 0;

		if ((CURRENT != '+') && (CURRENT != '-')) {	/* Skip EeDd and
								 * following blanks. */
			NEXT;	/* Pass the EeDd. */
			if (fortran_conventions >= 2)
				while (CURRENT == ' ') {
					NEXT;
				}
		}
		if (CURRENT == '+') {
			NEXT;
		} else if (CURRENT == '-') {	/* Negative explicit
						 * exponent. */
			NEXT;
			explicitsign = 1;
		}
		while ((('0' <= CURRENT) && (CURRENT <= '9')) || (CURRENT == ' ')) {	/* Accumulate explicit
											 * exponent. */
			if (CURRENT == ' ') {	/* Handle blanks and Fortran. */
				if (fortran_conventions < 2)
					goto doneexp;
				if (fortran_conventions == 2) {
					NEXT;
					goto exploop;
				}
				CURRENT = '0';
			}
			good = cp;
			if (explicitexponent <= 400000000) {
				explicitexponent = 10 * explicitexponent + CURRENT - '0';
			}
			NEXT;
			switch (*pform) {
			case whitespace_form:
			case fixed_int_form:
				*pform = floating_int_form;
				break;
			case fixed_intdot_form:
				*pform = floating_intdot_form;
				break;
			case fixed_dotfrac_form:
				*pform = floating_dotfrac_form;
				break;
			case fixed_intdotfrac_form:
				*pform = floating_intdotfrac_form;
				break;
			}
	exploop:	;
		}
doneexp:
		if (explicitsign == 1)
			pd->exponent -= explicitexponent;
		else
			pd->exponent += explicitexponent;
	}

done:
	if (fortran_conventions >= 2) {	/* Fill up field width with extra
					 * blanks found. */
		if (good == (cp - 1))
			good = NULL;	/* Flag that whole field was good up
					 * to now. */
		while (CURRENT == ' ') {
			NEXT;
		}
		if (good == NULL) {
			good = CURRENT == NULL ? cp : cp - 1;
		}
	}
	if (sigfound < 1)
		pd->fpclass = fp_zero;	/* True zero found. */

	pd->ds[ids] = 0;	/* Terminate decimal string. */
	pd->ndigits = ids;	/* Save string length in ndigits. */
	if (good >= cp0) {	/* Valid token found. */
		*ppc = good + 1;/* token found - point one past. */
	} else {		/* No valid token found. */
		*pform = invalid_form;
		*ppc = cp0;	/* No token found - revert to original value. */
		pd->sign = 0;
		pd->fpclass = fp_signaling;	/* If anyone looks, x will be
						 * nan. */
	}
}
