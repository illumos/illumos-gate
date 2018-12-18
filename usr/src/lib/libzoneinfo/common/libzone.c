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
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <tzfile.h>
#include <fcntl.h>
#include <regex.h>
#include <errno.h>
#include <libintl.h>
#include <libzoneinfo.h>

#define	DEFINIT		"/etc/default/init"
#define	ZONEINFOTABDIR	"/usr/share/lib/zoneinfo/tab/"
#define	CONTINENT_TAB	ZONEINFOTABDIR "continent.tab"
#define	COUNTRY_TAB	ZONEINFOTABDIR "country.tab"
#define	ZONE_SUN_TAB	ZONEINFOTABDIR "zone_sun.tab"

#define	NEWLINE		"\n"
#define	SLASH		"/"
#define	WHITESPACE	"\t "
#define	WHITESPACE_NL	"\t \n"
#define	DIGITS		"0123456789"
#define	BUFFLEN		1024

#define	CCLEN		2		/* country code length */

#define	GMT_MAX		(12*60*60)	/* The maximum GMT offset */
#define	GMT_MIN		(-13*60*60)	/* The minimum GMT offset */
#define	GMT_FMT_Q	"<GMT%c%d>%c%d"
#define	GMT_FMT_Q_LEN	(11)		/* "<GMT+dd>+dd" - maximum 11 chars */
#define	GMT0_FMT	"GMT0"		/* backwards compatibility name */
#define	GMT_FMT_ZONE	":Etc/GMT%c%d"	/* ":Etc/GMT+dd" */
#define	GMT_FMT_ZONE_LEN	(11)	/* ":Etc/GMT+dd" - maximum 11 chars */

#define	TZ_FMT		"TZ=%s\n"	/* format TZ entry init file */
#define	TZ_FMT_Q	"TZ=\"%s\"\n"	/* format quoted TZ entry init file */

#define	COORD_FMTLEN1	(sizeof ("+DDMM+DDDMM") - 1)
#define	COORD_FMTLEN2	(sizeof ("+DDMMSS+DDDMMSS") - 1)
#define	COORD_FMT1		(1)	/* flag for format 1 */
#define	COORD_FMT2		(2)	/* flag for format 2 */
#define	COORD_DLEN_LAT		(2)	/* length of DD for latitude */
#define	COORD_DLEN_LONG		(3)	/* length of DDD for longtitude */
#define	COORD_MLEN		(2)	/* length of MM */
#define	COORD_SLEN		(2)	/* length of SS */

#define	TRAILER		"/XXXXXX"
#define	TR_LEN		(sizeof (TRAILER) -1)

/* Internal Declarations */
static char *skipwhite(char *);
static int skipline(char *);
static int trav_link(char **);
static void remove_component(char *);
static void strip_quotes(char *, char *);
static int compar(struct tz_country *, struct tz_country *);
static int get_coord(struct tz_timezone *, char *, size_t);
static int _tz_match(const char *, const char *);
static char *_conv_gmt_zoneinfo(int);
static char *_conv_gmt_posix(int);

/*
 * get_tz_continents() reads the continent.tab file, and
 * returns a list of continents.
 */
int
get_tz_continents(struct tz_continent **cont)
{
	FILE *fp;
	char buff[BUFFLEN];
	char *lp;		/* line pointer */
	char *lptr, *ptr;	/* temp pointer */
	struct tz_continent *head = NULL, *lcp, *prev = NULL;
	int sav_errno = 0, ncount, status;
	size_t len;

	/* open continents file */
	if ((fp = fopen(CONTINENT_TAB, "r")) == NULL) {
		/* fopen() sets errno */
		return (-1);
	}
	/* read and count continents */
	ncount = 0;
	/*CONSTANTCONDITION*/
	while (1) {
		if (fgets(buff, sizeof (buff), fp) == NULL) {
			if (feof(fp) == 0) {
				/* fgets() sets errno */
				sav_errno = errno;
				ncount = -1;
			}
			break;
		}
		/* Skip comments or blank/whitespace lines */
		if ((status = skipline(buff)) != 0) {
			if (status == 1)
				continue;
			else {
				sav_errno = EINVAL;
				ncount = -1;
				break;
			}
		}
		/* Get continent name */
		lp = skipwhite(&buff[0]);
		if ((len = strcspn(lp, WHITESPACE)) > _TZBUFLEN -1) {
			sav_errno = ENAMETOOLONG;
			ncount = -1;
			break;
		}
		/* create continent struct */
		if ((lcp = (struct tz_continent *)
			calloc(1, sizeof (struct tz_continent))) == NULL) {
			sav_errno = ENOMEM;
			ncount = -1;
			break;
		}
		(void) strncpy(lcp->ctnt_name, lp, len);
		lcp->ctnt_name[len] = '\0';

		/* Get continent description */
		lp = skipwhite(lp + len);
		len = strcspn(lp, NEWLINE);
		if ((ptr = malloc(len + 1)) == NULL) {
			(void) free_tz_continents(lcp);
			sav_errno = ENOMEM;
			ncount = -1;
			break;
		}
		(void) strncpy(ptr, lp, len);
		*(ptr + len) = '\0';
		lcp->ctnt_id_desc = ptr;

		/* Get localized continent description */
		lptr = dgettext(TEXT_DOMAIN, lcp->ctnt_id_desc);
		if ((ptr = strdup(lptr)) == NULL) {
			(void) free_tz_continents(lcp);
			sav_errno = ENOMEM;
			ncount = -1;
			break;
		}
		lcp->ctnt_display_desc = ptr;

		if (head == NULL) {
			head = lcp;
		} else {
			prev->ctnt_next = lcp;
		}
		prev = lcp;
		ncount++;
	}
	(void) fclose(fp);
	if (ncount == -1) {
		if (head != NULL) {
			(void) free_tz_continents(head);
		}
		if (sav_errno)
			errno = sav_errno;
	} else {
		*cont = head;
	}
	return (ncount);
}

/*
 * get_tz_countries() finds the list of countries from the zone_sun.tab
 * file, for the input continent, and retrieves the country
 * names from the country.tab file.  It also retrieves the localized
 * country names.  The returned list of countries is sorted by the
 * countries' localized name fields.
 */
int
get_tz_countries(struct tz_country **country, struct tz_continent *cont)
{
	FILE *fp_zone, *fp_cc;
	char buff[BUFFLEN], ccbuf[_CCBUFLEN], *ptr;
	char *lp, *lptr, *lp_coord, *lp_cc, *lp_tz;	/* line pointer */
	struct tz_country *head = NULL, *prev = NULL, *next, *cp, *cp2;
	int sav_errno = 0, ncount, i;
	int cmp, status;
	size_t len, len_coord, len_ctnt;

	len_ctnt = strlen(cont->ctnt_name);
	ccbuf[0] = '\0';

	/* open zone_sun.tab and country.tab files */
	if ((fp_zone = fopen(ZONE_SUN_TAB, "r")) == NULL) {
		/* fopen() sets errno */
		return (-1);
	}
	if ((fp_cc = fopen(COUNTRY_TAB, "r")) == NULL) {
		/* fopen() sets errno */
		(void) fclose(fp_zone);
		return (-1);
	}

	/* read timezones to match continents, and get countries */
	ncount = 0;
	/*CONSTANTCONDITION*/
	while (1) {
		if (fgets(buff, sizeof (buff), fp_zone) == NULL) {
			if (feof(fp_zone) == 0) {
				/* fgets() error - errno set */
				sav_errno = errno;
				ncount = -1;
			}
			break;
		}
		/* Skip comments or blank/whitespace lines */
		if ((status = skipline(buff)) != 0) {
			if (status == 1)
				continue;
			else {
				sav_errno = EINVAL;
				ncount = -1;
				break;
			}
		}
		/*
		 * If country matches previously *matched* country, skip
		 * entry, since zone.tab is alphabetized by country code
		 * (It should be a *matched* country, because the same country
		 * can be in different continents.)
		 */
		/* Get country code */
		lp_cc = skipwhite(&buff[0]);
		if (strcspn(lp_cc, WHITESPACE) != CCLEN) {
			ncount = -1;
			sav_errno = EINVAL;
			break;
		}
		/* Check country code cache; skip if already found */
		if (strncmp(ccbuf, lp_cc, CCLEN) == 0) {
			continue;
		}
		/* Get coordinates */
		lp_coord = skipwhite(lp_cc + CCLEN);
		if (((len_coord = strcspn(lp_coord, WHITESPACE)) !=
				COORD_FMTLEN1) &&
				(len_coord != COORD_FMTLEN2)) {
			ncount = -1;
			sav_errno = EINVAL;
			break;
		}

		/* Get timezone name (Skip timezone description) */
		lp_tz = skipwhite(lp_coord + len_coord);
		if ((len = strcspn(lp_tz, SLASH)) == 0) {
			ncount = -1;
			sav_errno = EINVAL;
			break;
		}
		/* If continents match, allocate a country struct */
		if ((len == len_ctnt) &&
				(strncmp(cont->ctnt_name, lp_tz, len) == 0)) {
			if ((cp = (struct tz_country *)
			    calloc(1, sizeof (struct tz_country))) == NULL) {
				sav_errno = ENOMEM;
				ncount = -1;
				break;
			}
			/* Copy and save country code (len already checked) */
			(void) strncpy(cp->ctry_code, lp_cc, CCLEN);
			cp->ctry_code[CCLEN] = '\0';
			(void) strncpy(ccbuf, lp_cc, CCLEN);
			ccbuf[CCLEN] = '\0';

			/* Create linked list */
			if (head == NULL) {
				head = cp;
			} else {
				prev->ctry_next = cp;
			};
			prev = cp;
			ncount++;
		}
	}	/* while */

	if (ncount == -1)
		goto error;

	/* Get country name from country.tab; get localized country name */
	/* Read country list, match country codes to process entry */
	cp = head;
	/*CONSTANTCONDITION*/
	while (1) {
		if (fgets(buff, sizeof (buff), fp_cc) == NULL) {
			if (feof(fp_cc) == 0) {
				/* fgets() sets errno */
				ncount = -1;
				sav_errno = errno;
			}
			break;
		}
		/* Skip comments or blank/whitespace lines */
		if ((status = skipline(buff)) != 0) {
			if (status == 1)
				continue;
			else {
				sav_errno = EINVAL;
				ncount = -1;
				break;
			}
		}
		/* Match country codes */
		if ((len = strcspn(buff, WHITESPACE)) != CCLEN) {
			sav_errno = EINVAL;
			ncount = -1;
			break;
		}
		if ((cmp = strncmp(cp->ctry_code, buff, CCLEN)) == 0) {
			/* Get country description, and localized desc. */
			/* Skip to country description */
			lp = &buff[CCLEN];
			if ((len = strspn(lp, WHITESPACE)) == 0) {
				sav_errno = EINVAL;
				ncount = -1;
				break;
			}
			lp += len;		/* lp points to country desc. */
			len = strcspn(lp, NEWLINE);
			if ((ptr = calloc(len + 1, 1)) == NULL) {
				ncount = -1;
				errno = ENOMEM;
				break;
			}
			(void) strncpy(ptr, lp, len);
			*(ptr + len) = '\0';
			cp->ctry_id_desc = ptr;

			/* Get localized country description */
			lptr = dgettext(TEXT_DOMAIN, ptr);
			if ((ptr = strdup(lptr)) == NULL) {
				ncount = -1;
				errno = ENOMEM;
				break;
			}
			cp->ctry_display_desc = ptr;
		} else if (cmp > 0) {
			/* Keep searching country.tab */
			continue;
		} else {
			/* Not found - should not happen */
			ncount = -1;
			errno = EILSEQ;
			break;
		}
		if (cp->ctry_next == NULL) {
			/* done with countries list */
			break;
		} else {
			cp = cp->ctry_next;
		}
	}		/* while */

	/* Now sort the list by ctry_display_desc field */
	if ((ncount != -1) &&
		((cp2 = calloc(ncount, sizeof (struct tz_country))) != NULL)) {
		/*
		 * First copy list to a static array for qsort() to use.
		 * Use the cnt_next field to point back to original structure.
		 */
		cp = head;
		for (i = 0; i < ncount; i++) {
			next = cp->ctry_next;
			cp->ctry_next = cp;
			(void) memcpy(&cp2[i], cp, sizeof (struct tz_country));
			cp = next;
		}

		/* Next, call qsort() using strcoll() to order */
		qsort(cp2, ncount, sizeof (struct tz_country),
			(int (*)(const void *, const void *))compar);

		/* Rearrange the country list according to qsort order */
		head = cp2->ctry_next; /* ctry_next is pointer to orig struct */
		cp = head;
		for (i = 0; i < ncount; i++) {
			prev = cp;
			cp = cp2[i].ctry_next;
			prev->ctry_next = cp;
		}
		cp->ctry_next = NULL;

		/* Last, free the static buffer */
		free(cp2);

	} else {
		if (ncount != -1)
			ncount = -1;
	}

error:
	(void) fclose(fp_zone);
	(void) fclose(fp_cc);
	if (ncount == -1) {
		/* free the linked list */
		if (head != NULL)
			(void) free_tz_countries(head);
		if (sav_errno)
			errno = sav_errno;
	} else {
		*country = head;
	}
	return (ncount);
}

/*
 * get_timezones_by_country() finds the list of timezones from the
 * zone_sun.tab file, for the input country.
 */
int
get_timezones_by_country(struct tz_timezone **tmzone,
	struct tz_country *country)
{
	FILE *fp_zone;		/* zone.tab */
	int match = 0, ncount = 0, sav_errno = 0, status;
	char buff[1024];
	char *lp_cc, *lp_tz, *lp_otz, *lp_coord, *lp_tzdesc, *ptr, *lptr;
	size_t len_tz, len_otz, len_coord, len_tzdesc;
	struct tz_timezone *head = NULL, *prev = NULL, *tp;

	/* open zone.tab file */
	if ((fp_zone = fopen(ZONE_SUN_TAB, "r")) == NULL)
		return (-1);

	/* Read through zone.tab until countries match */
	/*CONSTANTCONDITION*/
	while (1) {
		if (fgets(buff, sizeof (buff), fp_zone) == NULL) {
			if (feof(fp_zone)) {
				break;
			} else {
				/* fgets() sets errno */
				ncount = -1;
				sav_errno = errno;
				break;
			}
		}
		/* Skip comments or blank/whitespace lines */
		if ((status = skipline(buff)) != 0) {
			if (status == 1)
				continue;
			else {
				sav_errno = EINVAL;
				ncount = -1;
				break;
			}
		}
		/*
		 * Find country entries, or detect if no country matches.
		 */
		lp_cc = skipwhite(&buff[0]);
		if (strcspn(lp_cc, WHITESPACE) != CCLEN) {
			sav_errno = EINVAL;
			ncount = -1;
			break;
		}
		if (strncmp(country->ctry_code, lp_cc, CCLEN) == 0) {
			match = 1;

			/* Get coordinates */
			lp_coord = skipwhite(lp_cc + CCLEN);
			if (((len_coord = strcspn(lp_coord, WHITESPACE)) !=
					COORD_FMTLEN1) &&
					(len_coord != COORD_FMTLEN2)) {
				ncount = -1;
				sav_errno = EINVAL;
				break;
			}
			/* Get Olson timezone name */
			lp_otz = skipwhite(lp_coord + len_coord);
			len_otz = strcspn(lp_otz, WHITESPACE);

			/* Get Solaris compatible timezone name */
			lp_tz = skipwhite(lp_otz + len_otz);
			len_tz = strcspn(lp_tz, WHITESPACE_NL);
			if (*(lp_tz + len_tz - 1) == '\n') {
				/* No timezone description */
				len_tz--;
				lp_tzdesc = NULL;
				len_tzdesc = 0;
			} else {
				/* Get timezone description */
				lp_tzdesc = skipwhite(lp_tz +
					len_tz);
				len_tzdesc = strcspn(lp_tzdesc,
					NEWLINE);
			}
			/*
			 * Check tz name lengths.  This check assumes the
			 * tz_oname and tz_name fields are the same size.
			 * (since tz_name may be written with lp_otz, if
			 * lp_tz is "-".)
			 */
			if ((len_otz > _TZBUFLEN - 1) ||
				(len_tz > _TZBUFLEN - 1)) {
				sav_errno = ENAMETOOLONG;
				ncount = -1;
				break;
			}
			/* Create timezone struct */
			if ((tp =  (struct tz_timezone *)
				calloc(1, sizeof (struct tz_timezone))) ==
					NULL) {
				sav_errno = ENOMEM;
				ncount = -1;
				break;
			}
			/*
			 * Copy the timezone names - use the Solaris
			 * compatible timezone name if one exists,
			 * otherwise use the current Olson timezone
			 * name.
			 */
			(void) strncpy(tp->tz_oname, lp_otz, len_otz);
			tp->tz_oname[len_otz] = '\0';
			if (strncmp("-", lp_tz, len_tz) == 0) {
				lp_tz = lp_otz;
				len_tz = len_otz;
			}
			/* If name has numeric digits, prefix ':' */
			if (strcspn(lp_tz, DIGITS) < len_tz) {
				if (len_tz > _TZBUFLEN - 2) {
					free(tp);
					sav_errno = ENAMETOOLONG;
					ncount = -1;
					break;
				}
				tp->tz_name[0] = ':';
				(void) strncpy(tp->tz_name + 1, lp_tz, len_tz);
				tp->tz_name[len_tz + 1] = '\0';
			} else {
				(void) strncpy(tp->tz_name, lp_tz, len_tz);
				tp->tz_name[len_tz] = '\0';
			}
			/* Process timezone description, if one exists */
			if ((lp_tzdesc != NULL) && (*lp_tzdesc != '\n')) {
				if ((ptr = calloc(1, len_tzdesc + 1))
						== NULL) {
					sav_errno = ENOMEM;
					ncount = -1;
					(void) free_timezones(tp);
					break;
				}
				(void) strncpy(ptr, lp_tzdesc, len_tzdesc);
				*(ptr + len_tzdesc) = '\0';
				tp->tz_id_desc = ptr;

				/* Get localized country description */
				lptr = dgettext(TEXT_DOMAIN, ptr);
				if ((ptr = strdup(lptr)) == NULL) {
					sav_errno = ENOMEM;
					ncount = -1;
					(void) free_timezones(tp);
					break;
				}
				tp->tz_display_desc = ptr;

			} else {
				tp->tz_id_desc = NULL;
				tp->tz_display_desc = NULL;
			}
			/* Get coordinate information */
			if (get_coord(tp, lp_coord, len_coord) == -1) {
				sav_errno = EILSEQ;
				ncount = -1;
				(void) free_timezones(tp);
				break;
			}
			/* Store timezone struct in a linked list */
			if (head == NULL) {
				head = tp;
			} else {
				prev->tz_next = tp;
			}
			prev = tp;
			ncount++;
		} else {
			if (match == 1) {
				/*
				 * At this point, since zone_sun.tab is ordered,
				 * if we've already found timezone entries for
				 * the input country, then we've found all of
				 * the desired timezone entries (since we will
				 * be past that country's section in
				 * zone_sun.tab), and we are done.
				 */
				break;
			}
		}
	}

	/* Finish up */
	(void) fclose(fp_zone);
	if (ncount == -1) {
		if (head != NULL)
			(void) free_timezones(head);
		if (sav_errno)
			errno = sav_errno;
	} else {
		*tmzone = head;
	}
	return (ncount);
}

int
free_tz_continents(struct tz_continent *cont)
{
	struct tz_continent *cptr, *cprev;

	cptr = cont;
	while (cptr != NULL) {
		if (cptr->ctnt_id_desc != NULL)
			free(cptr->ctnt_id_desc);
		if (cptr->ctnt_display_desc != NULL)
			free(cptr->ctnt_display_desc);
		cprev = cptr;
		cptr = cptr->ctnt_next;
		free(cprev);
	}
	return (0);
}

int
free_tz_countries(struct tz_country *country)
{
	struct tz_country *cptr, *cprev;

	cptr = country;
	while (cptr != NULL) {
		if (cptr->ctry_id_desc != NULL)
			free(cptr->ctry_id_desc);
		if (cptr->ctry_display_desc != NULL)
			free(cptr->ctry_display_desc);
		cprev = cptr;
		cptr = cptr->ctry_next;
		free(cprev);
	}
	return (0);
}

int
free_timezones(struct tz_timezone *timezone)
{
	struct tz_timezone *tzptr, *tzprev;

	tzptr = timezone;
	while (tzptr != NULL) {
		if (tzptr->tz_id_desc != NULL)
			free(tzptr->tz_id_desc);
		if (tzptr->tz_display_desc != NULL)
			free(tzptr->tz_display_desc);
		tzprev = tzptr;
		tzptr = tzptr->tz_next;
		free(tzprev);
	}
	return (0);
}

/*
 *  conv_gmt() returns a GMT-offset style timezone
 *    If flag = 0, return Quoted POSIX timezone like: <GMT+8>+8
 *    If flag = 1, return zoneinfo timezone like:  :Etc/GMT+8
 */
char *
conv_gmt(int seconds, int flag)
{
	int hour;
	char *cp;

	if ((seconds < _GMT_MIN) || (seconds > _GMT_MAX)) {
		errno = EINVAL;
		return (NULL);
	}
	hour = (seconds / 60) / 60;

	if (flag == 0) {
		cp = _conv_gmt_posix(hour);
	} else if (flag == 1) {
		cp = _conv_gmt_zoneinfo(hour);
	} else {
		errno = EINVAL;
		return (NULL);
	}
	return (cp);
}

static char *
_conv_gmt_posix(int hour)
{
	char *cp;
	char xsign;

	if (hour == 0) {
		if ((cp = strdup(GMT0_FMT)) == NULL) {
			errno = ENOMEM;
			return (NULL);
		}
	} else {
		if (hour < 0) {
			xsign = '-';
			/* make hour positive for snprintf() */
			hour = -hour;
		} else {
			xsign = '+';
		}
		if ((cp = malloc(GMT_FMT_Q_LEN + 1)) == NULL) {
			errno = ENOMEM;
			return (NULL);
		}
		(void) snprintf(cp, GMT_FMT_Q_LEN + 1, GMT_FMT_Q,
			xsign, hour, xsign, hour);
	}
	return (cp);
}

static char *
_conv_gmt_zoneinfo(int hour)
{
	char *cp;
	char xsign;

	if (hour < 0) {
		xsign = '-';
		/* make hour positive for snprintf() */
		hour = -hour;
	} else {
		xsign = '+';
	}
	if ((cp = malloc(GMT_FMT_ZONE_LEN + 1)) == NULL) {
		errno = ENOMEM;
		return (NULL);
	}
	(void) snprintf(cp, GMT_FMT_ZONE_LEN + 1, GMT_FMT_ZONE,
		xsign, hour);
	return (cp);
}

/* Regular expression for POSIX GMT-offset timezone */
#define	_GMT_EXPR	"(" _GMT_EXPR_U "|" _GMT_EXPR_Q ")"
#define	_GMT_EXPR_U	"^[gG][mM][tT][-+]?[0-2]?[0-9]$"
#define	_GMT_EXPR_Q	"^<[gG][mM][tT][-+]?[0-2]?[0-9]>[-+]?[0-2]?[0-9]$"

/*
 * Regular expression for quoted POSIX timezone.
 */
/* Avoid alphabetic ranges (eg, a-z) due to effect of LC_COLLATE */
#define	_ALPHA	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define	_NUM	"0123456789"    /* for safe */
#define	_STD_Q_ELM	"[-+" _ALPHA _NUM "]"
#define	_STD_Q		"<" _STD_Q_ELM _STD_Q_ELM _STD_Q_ELM "+>"

/* Regular expression for unquoted POSIX timezone */
#define	_STD_U_ELM_1	"[^-+,<" _NUM "]"
#define	_STD_U_ELM	"[^-+,"  _NUM "]"
#define	_STD_U		_STD_U_ELM_1 _STD_U_ELM _STD_U_ELM "+"

/* Regular expression for POSIX timezone */
#define	_STD		"(" _STD_U "|" _STD_Q ")"
#define	_DST		_STD
#define	_OFFSET		"[-+]?" _TIME
#define	_START		"(" _DATEJ "|" _DATEn "|" _DATEM ")"
#define	_DATEJ		"J(([0-2]?[0-9]?[0-9])|3[0-5][0-9]|36[0-5])"
#define	_DATEn		"(([0-2]?[0-9]?[0-9])|3[0-5][0-9]|36[0-5])"
#define	_DATEM		"M([0-9]|10|11|12)\\.[1-5]\\.[0-6]"
#define	_END		_START
#define	_TIME		_HH "(:" _MM "(:" _SS ")?" ")?"
#define	_HH		"(([0-1]?[0-9])|20|21|22|23|24)"
#define	_MM		"[0-5]?[0-9]"
#define	_SS		_MM
#define	_POSIX_EXPR	"^" _STD _OFFSET "(" _DST "(" _OFFSET ")?" \
				"(," _START "(/" _TIME ")?" \
				"," _END "(/" _TIME ")?" ")?" ")?" "$"

#define	LEN_TZDIR	(sizeof (TZDIR) - 1)

/*
 *  isvalid_tz() checks if timezone is a valid POSIX or zoneinfo
 *  timezone, depending on the value of flag.  For flag = _VTZ_INSTALL,
 *  isvalid_tz() behaves according to the behavior of Solaris Install
 *  in Solaris 9 and earlier, where timezones under /usr/share/lib/zoneinfo
 *  were validated.  isvalid_tz() has a special check for GMT+-* timezones
 *  because Solaris Install validated /usr/share/lib/zoneinfo/GMT+-*.
 *  However, when /usr/share/lib/zoneinfo/GMT+-* are EOF'd, that check
 *  no longer works.
 *
 *  isvalid_tz() returns 1 if a valid timezone is detected.
 */
int
isvalid_tz(char *timezone, char *root, int flag)
{
	char path[MAXPATHLEN];
	char buf[sizeof (struct tzhead)];
	int fid, ret;

	if ((timezone == NULL) || (*timezone == '\0')) {
		return (0);
	}

	/* First check if timezone is a valid POSIX timezone */
	switch (flag) {
	case _VTZ_INSTALL:
		/*
		 * Special check for POSIX GMT timezone.
		 * If no match, check for zoneinfo timezone below
		 */
		if (_tz_match(_GMT_EXPR, timezone) == 0) {
			/* Valid GMT timezone */
			return (1);
		}
		break;
	case _VTZ_POSIX:
		/* Check for generic POSIX timezone */
		if (_tz_match(_POSIX_EXPR, timezone) == 0) {
			/* Valid POSIX timezone */
			return (1);
		}
		/* Invalid POSIX timezone */
		return (0);
	case _VTZ_ALL:
		/* Check for generic POSIX timezone */
		if (_tz_match(_POSIX_EXPR, timezone) == 0) {
			/* Valid POSIX timezone */
			return (1);
		}
		break;
	case _VTZ_ZONEINFO:
		break;
	default:
		return (0);
	}

	/*
	 * Check for valid zoneinfo timezone -
	 * open zoneinfo file and check for magic number
	 */

	/* skip prepended ':' if one exists */
	if (*timezone == ':') {
		timezone++;
	}
	/* Construct full zoneinfo pathname */
	if ((root != NULL) && (*root != '\0')) {
		ret = snprintf(path, sizeof (path),
		    "%s%s/%s", root, TZDIR, timezone);
		if (ret >= sizeof (path)) {
			/* too long */
			return (0);
		}
	} else {
		ret = snprintf(path, sizeof (path),
		    "%s/%s", TZDIR, timezone);
		if (ret >= sizeof (path)) {
			/* too long */
			return (0);
		}
	}
	if ((fid = open(path, O_RDONLY)) == -1) {
		return (0);
	}
	if (read(fid, buf, sizeof (struct tzhead)) !=
	    sizeof (struct tzhead)) {
		(void) close(fid);
		return (0);
	}
	if (strncmp(buf, TZ_MAGIC, sizeof (TZ_MAGIC) - 1) != 0) {
		(void) close(fid);
		return (0);
	}
	if (close(fid) == -1) {
		return (0);
	}
	/* Valid zoneinfo timezone */
	return (1);
}

#define	N_MATCH		1

int
_tz_match(const char *expr, const char *string)
{
	regex_t reg;
	regmatch_t pmatch[N_MATCH];
	int ret;

	ret = regcomp(&reg, expr, REG_EXTENDED);
	if (ret != 0) {
		return (-1);
	}

	ret = regexec((const regex_t *)&reg, string, N_MATCH, pmatch, 0);
	if (ret == 0) {
#ifdef DEBUG
		printf("OK matched - %s\n", string);
#endif
		regfree(&reg);
		return (0);
	}
#ifdef DEBUG
	printf("NOT matched - %s\n", string);
#endif
	regfree(&reg);
	return (-1);
}

char *
get_system_tz(char *root)
{
	FILE *ifp;
	char buff[512];
	int serrno, ret;
	char *sp, *ptr, *p;
	char fname[MAXPATHLEN];

	if ((ret = snprintf(fname, sizeof (fname), "%s/%s", root, DEFINIT)) >=
			sizeof (fname)) {
		errno = ENAMETOOLONG;
		return (NULL);
	} else if (ret < 0) {
		return (NULL);
	}
	if ((ifp = fopen(fname, "r")) == NULL)
		return (NULL);
	while (fgets(buff, sizeof (buff), ifp) != NULL) {
		if (strncmp(buff, "TZ=", 3) == 0) {
			(void) fclose(ifp);
			p = &buff[3];
			if ((sp = strchr(p, ';')) != NULL) {
				*sp = '\0';
			} else if ((sp = strchr(p, '\n')) != NULL) {
				*sp = '\0';
			}
			if (strpbrk(p, "\"'") != NULL) {
				strip_quotes(p, p);
			}
			ptr = strdup(p);
			if (ptr == NULL) {
				errno = ENOMEM;
				return (NULL);
			}
			return (ptr);
		}
	}

	/* Either reached EOF with no TZ= entry, or got fgets() error */
	serrno = errno;
	if (feof(ifp) != 0) {
		/* No "TZ=" entry found */
		serrno = EINVAL;
	}
	(void) fclose(ifp);
	errno = serrno;
	return (NULL);
}

int
set_system_tz(char *tz, char *root)
{
	FILE *ifp, *ofp;	/* Input & output files */
	char *tmpdir, *tmp;	/* Temp file name and location */
	char buff[1024];
	int replaced = 0, ret, serrno;
	char *tdb;
	struct stat sb;
	char fname[MAXPATHLEN];
	const char *tzfmt;
	int len, fd;

	if (tz == NULL || root == NULL)
		return (-1);

	if (strchr(tz, '<')) {
		tzfmt = TZ_FMT_Q;
	} else {
		tzfmt = TZ_FMT;
	}

	if ((ret = snprintf(fname, sizeof (fname), "%s/%s", root, DEFINIT)) >=
			sizeof (fname)) {
		errno = ENAMETOOLONG;
		return (-1);
	} else if (ret < 0) {
		return (-1);
	}

	/*
	 * Generate temporary file name to use.  We make sure it's in the same
	 * directory as the db we're processing so that we can use rename to
	 * do the replace later.  Otherwise we run the risk of being on the
	 * wrong filesystem and having rename() fail for that reason.
	 */
	tdb = fname;
	if (trav_link(&tdb) == -1)
		return (-1);
	if ((tmpdir = strdup(tdb)) == NULL) {
		errno = ENOMEM;
		return (-1);
	}
	remove_component(tmpdir);
	if ((len = strlen(tmpdir)) == 0) {
		(void) strcpy(tmpdir, ".");
		len = 1;
	}

	if ((tmp = malloc(len + TR_LEN + 1)) == NULL) {
		free(tmpdir);
		errno = ENOMEM;
		return (-1);
	}
	(void) strcpy(tmp, tmpdir);
	(void) strcpy(tmp + len, TRAILER);
	free(tmpdir);
	if ((fd = mkstemp(tmp)) == -1) {
		free(tmp);
		return (-1);
	}
	if ((ofp = fdopen(fd, "w")) == NULL) {
		serrno = errno;
		(void) close(fd);
		free(tmp);
		errno = serrno;
		return (-1);
	}

	/* Preserve permissions of current file if it exists */
	if (stat(tdb, &sb) == 0) {
		if (fchmod(fileno(ofp), sb.st_mode) == -1) {
			serrno = errno;
			(void) fclose(ofp);
			(void) unlink(tmp);
			free(tmp);
			errno = serrno;
			return (-1);
		}
		if (fchown(fileno(ofp), sb.st_uid, sb.st_gid) == -1) {
			serrno = errno;
			(void) fclose(ofp);
			(void) unlink(tmp);
			free(tmp);
			errno = serrno;
			return (-1);
		}
	} else if (errno != ENOENT) {
		serrno = errno;
		(void) fclose(ofp);
		(void) unlink(tmp);
		free(tmp);
		errno = serrno;
		return (-1);
	}

	if ((ifp = fopen(fname, "r+")) != NULL) {
		while (fgets(buff, sizeof (buff), ifp) != NULL) {
			if (!replaced && (strncmp(buff, "TZ=", 3) == 0)) {
				ret = snprintf(buff, sizeof (buff), tzfmt,
							tz);
				if ((ret >= sizeof (buff)) || (ret < 0)) {
					if (ret >= sizeof (buff))
						serrno = EINVAL;
					(void) fclose(ofp);
					(void) fclose(ifp);
					(void) unlink(tmp);
					free(tmp);
					errno = serrno;
					return (-1);
				}
				replaced = 1;
			}
			if (fputs(buff, ofp) == EOF) {
				serrno = errno;
				(void) fclose(ofp);
				(void) fclose(ifp);
				(void) unlink(tmp);
				free(tmp);
				errno = serrno;
				return (-1);
			}
		}
		(void) fclose(ifp);

	} else if (errno != ENOENT) {
		serrno = errno;
		(void) fclose(ofp);
		(void) unlink(tmp);
		free(tmp);
		errno = serrno;
		return (-1);
	}

	/*
	 * no $(ROOT)/etc/default/init found, or
	 * no "TZ=" entry found in the init file.
	 */
	if (!replaced &&
	    (fprintf(ofp, tzfmt, tz) == EOF)) {
		serrno = errno;
		(void) fclose(ofp);
		(void) unlink(tmp);
		free(tmp);
		errno = serrno;
		return (-1);
	}

	if (fsync(fileno(ofp))) {
		serrno = errno;
		(void) unlink(tmp);
		free(tmp);
		errno = serrno;
		return (-1);
	}

	(void) fclose(ofp);
	if (rename(tmp, tdb) != 0) {
		serrno = errno;
		(void) unlink(tmp);
		free(tmp);
		errno = serrno;
		return (-1);
	} else {
		free(tmp);
		return (0);
	}
}

/*
 * Function to traverse a symlink path to find the real file at the end of
 * the rainbow.
 */
int
trav_link(char **path)
{
	static char newpath[MAXPATHLEN];
	char lastpath[MAXPATHLEN];
	int len, ret;
	char *tp;

	(void) strcpy(lastpath, *path);
	while ((len = readlink(*path, newpath, sizeof (newpath))) != -1) {
		newpath[len] = '\0';
		if (newpath[0] != '/') {
			if ((tp = strdup(newpath)) == NULL) {
				errno = ENOMEM;
				return (-1);
			}
			remove_component(lastpath);
			ret = snprintf(newpath, sizeof (newpath),
				"%s/%s", lastpath, tp);
			free(tp);
			if ((ret >= sizeof (newpath)) || (ret < 0))
				return (-1);
		}
		(void) strcpy(lastpath, newpath);
		*path = newpath;
	}

	/*
	 * ENOENT or EINVAL is the normal exit case of the above loop.
	 */
	if ((errno == ENOENT) || (errno == EINVAL))
		return (0);
	else
		return (-1);
}

void
remove_component(char *path)
{
	char *p;

	p = strrchr(path, '/'); 		/* find last '/' 	*/
	if (p == NULL) {
		*path = '\0';			/* set path to null str	*/
	} else {
		*p = '\0';			/* zap it 		*/
	}
}

/*
 *  get_coord() fills in the tz_coord structure of the tz_timezone
 *  struct.  It returns 0 on success, or -1 on error.
 *  The format of p_coord is:
 *
 *	Latitude and longitude of the zone's principal location
 *	in ISO 6709 sign-degrees-minutes-seconds format,
 *	either +-DDMM+-DDDMM or +-DDMMSS+-DDDMMSS,
 *	first latitude (+ is north), then longitude (+ is east).
 */
static int
get_coord(struct tz_timezone *tp, char *p_coord, size_t len_coord)
{
	int i, fmt_flag, nchar;
	int *signp, *degp, *minp, *secp;
	struct tz_coord *tcp;
	char buff[512], *endp;

	tcp = &(tp->tz_coord);

	/* Figure out which format to use */
	if (len_coord == COORD_FMTLEN1) {
		/* "+-DDMM+-DDDMM" */
		fmt_flag = COORD_FMT1;
	} else if (len_coord == COORD_FMTLEN2) {
		/* "+-DDMMSS+-DDDMMSS" */
		fmt_flag = COORD_FMT2;
	} else {
		/* error */
		return (-1);
	}
	/*
	 * First time through, get values for latitude;
	 * second time through, get values for longitude.
	 */
	for (i = 0; i < 2; i++) {
		/* Set up pointers */
		if (i == 0) {
			/* Do latitude */
			nchar = COORD_DLEN_LAT;
			signp = (int *)&(tcp->lat_sign);
			degp = (int *)&(tcp->lat_degree);
			minp = (int *)&(tcp->lat_minute);
			secp = (int *)&(tcp->lat_second);
		} else {
			/* Do longitude */
			nchar = COORD_DLEN_LONG;
			signp = (int *)&(tcp->long_sign);
			degp = (int *)&tcp->long_degree;
			minp = (int *)&tcp->long_minute;
			secp = (int *)&tcp->long_second;
		}
		/* Get latitude/logitude sign */
		if (*p_coord == '+') {
			*signp = 1;
		} else if (*p_coord == '-') {
			*signp = -1;
		} else {
			return (-1);
		}
		p_coord++;

		/* Get DD latitude, or DDD longitude */
		(void) strncpy(buff, p_coord, nchar);
		buff[nchar] = '\0';
		errno = 0;
		*degp = (int)strtol(buff, &endp, 10);
		if ((endp != &buff[nchar]) || ((*degp == 0) && (errno != 0)))
			return (-1);
		p_coord += nchar;

		/* Get MM latitude/longitude */
		(void) strncpy(buff, p_coord, COORD_MLEN);
		buff[COORD_MLEN] = '\0';
		errno = 0;
		*minp = (int)strtol(buff, &endp, 10);
		if ((endp != &buff[COORD_MLEN]) ||
				((*degp == 0) && (errno != 0)))
			return (-1);
		p_coord += COORD_MLEN;

		/* If FMT2, then get SS latitude/longitude */
		if (fmt_flag == COORD_FMT2) {
			(void) strncpy(buff, p_coord, COORD_SLEN);
			buff[COORD_SLEN] = '\0';
			errno = 0;
			*secp = (int)strtol(buff, &endp, 10);
			if ((endp != &buff[COORD_SLEN]) ||
					((*degp == 0) && (errno != 0)))
				return (-1);
			p_coord += COORD_SLEN;
		} else {
			*secp = 0;
		}
	}
	return (0);
}

static char *
skipwhite(char *cp)
{
	while (*cp && ((*cp == ' ') || (*cp == '\t'))) {
		cp++;
	}

	return (cp);
}

/*
 *  skipline() checks if the line begins with a comment
 *  comment character anywhere in the line, or if the
 *  line is only whitespace.
 *  skipline() also checks if the line read is too long to
 *  fit in the buffer.
 *  skipline() returns 1 if the line can be skipped, -1 if
 *  the line read is too long, and 0 if the line should not be skipped.
 */
static int
skipline(char *line)
{
	size_t len;

	len = strlen(line);
	if (line[len - 1] != '\n')
		return (-1);
	if (line[0] == '#' || line[0] == '\0' ||
		(len = strspn(line, " \t\n")) == strlen(line) ||
		strchr(line, '#') == line + len)

		return (1);
	else
		return (0);
}

/*
 * strip_quotes -- strip double (") or single (') quotes
 */
static void
strip_quotes(char *from, char *to)
{
	char *strip_ptr = NULL;

	while (*from != '\0') {
		if ((*from == '"') || (*from == '\'')) {
			if (strip_ptr == NULL)
				strip_ptr = to;
		} else {
			if (strip_ptr != NULL) {
				*strip_ptr = *from;
				strip_ptr++;
			} else {
				*to = *from;
				to++;
			}
		}
		from++;
	}
	if (strip_ptr != NULL) {
		*strip_ptr = '\0';
	} else {
		*to = '\0';
	}
}

/*
 * Compare function used by get_tz_countries() - uses strcoll()
 * for locale-sensitive comparison for the localized country names.
 */
static int
compar(struct tz_country *p1, struct tz_country *p2)
{
	int ret;

	ret = strcoll(p1->ctry_display_desc, p2->ctry_display_desc);
	return (ret);
}
