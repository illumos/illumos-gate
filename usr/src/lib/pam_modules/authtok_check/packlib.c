/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * This program is copyright Alec Muffett 1993. The author disclaims all
 * responsibility or liability with respect to it's usage or its effect
 * upon hardware or computer systems, and maintains copyright as set out
 * in the "LICENCE" document which accompanies distributions of Crack v4.0
 * and upwards.
 */

#include "packer.h"

void
PWRemove(char *path)
{
	char fname[PATH_MAX];

	(void) snprintf(fname, sizeof (fname), "%s/%s", path,
	    DICT_DATABASE_PWI);
	(void) unlink(fname);
	(void) snprintf(fname, sizeof (fname), "%s/%s", path,
	    DICT_DATABASE_PWD);
	(void) unlink(fname);
	(void) snprintf(fname, sizeof (fname), "%s/%s", path,
	    DICT_DATABASE_HWM);
	(void) unlink(fname);
}

PWDICT *
PWOpen(char *path, char *mode)
{
	PWDICT *pdesc;
	char iname[PATH_MAX];
	char dname[PATH_MAX];
	char wname[PATH_MAX];
	int fd_d;
	int fd_i;
	int fd_w;
	FILE *dfp;
	FILE *ifp;
	FILE *wfp;

	if ((pdesc = calloc(1, sizeof (PWDICT))) == NULL)
		return ((PWDICT *) 0);

	if (pdesc->header.pih_magic == PIH_MAGIC) {
		return ((PWDICT *) 0);
	}
	(void) memset(pdesc, '\0', sizeof (pdesc));

	(void) snprintf(iname, sizeof (iname), "%s/%s", path,
	    DICT_DATABASE_PWI);
	(void) snprintf(dname, sizeof (dname), "%s/%s", path,
	    DICT_DATABASE_PWD);
	(void) snprintf(wname, sizeof (wname), "%s/%s", path,
	    DICT_DATABASE_HWM);

	if ((fd_d = open(dname, O_RDWR|O_CREAT, 0600)) == -1)
		syslog(LOG_ERR, "PWopen: can't open %s: %s", dname,
		    strerror(errno));
	if ((fd_i = open(iname, O_RDWR|O_CREAT, 0600)) == -1)
		syslog(LOG_ERR, "PWopen: can't open %s: %s", iname,
		    strerror(errno));
	if ((fd_w = open(wname, O_RDWR|O_CREAT, 0600)) == -1)
		syslog(LOG_ERR, "PWopen: can't open %s: %s", wname,
		    strerror(errno));

	if (!(pdesc->dfp = fdopen(fd_d, mode))) {
		return ((PWDICT *) 0);
	}

	if (!(pdesc->ifp = fdopen(fd_i, mode))) {
		(void) fclose(pdesc->dfp);
		return ((PWDICT *) 0);
	}

	if (pdesc->wfp = fdopen(fd_w, mode)) {
		pdesc->flags |= PFOR_USEHWMS;
	}

	ifp = pdesc->ifp;
	dfp = pdesc->dfp;
	wfp = pdesc->wfp;

	if (mode[0] == 'w') {
		pdesc->flags |= PFOR_WRITE;
		pdesc->header.pih_magic = PIH_MAGIC;
		pdesc->header.pih_blocklen = NUMWORDS;
		pdesc->header.pih_numwords = 0;

		(void) fwrite((char *)&(pdesc->header), sizeof (pdesc->header),
		    1, ifp);
	} else {
		pdesc->flags &= ~PFOR_WRITE;

		if (!fread((char *)&(pdesc->header), sizeof (pdesc->header),
		    1, ifp)) {
			pdesc->header.pih_magic = 0;
			(void) fclose(ifp);
			(void) fclose(dfp);
			return ((PWDICT *) 0);
		}

		if (pdesc->header.pih_magic != PIH_MAGIC) {
			pdesc->header.pih_magic = 0;
			(void) fclose(ifp);
			(void) fclose(dfp);
			return ((PWDICT *) 0);
		}

		if (pdesc->header.pih_blocklen != NUMWORDS) {
			pdesc->header.pih_magic = 0;
			(void) fclose(ifp);
			(void) fclose(dfp);
			return ((PWDICT *) 0);
		}

		if (pdesc->flags & PFOR_USEHWMS) {
			if (fread(pdesc->hwms, 1, sizeof (pdesc->hwms), wfp) !=
			    sizeof (pdesc->hwms)) {
				pdesc->flags &= ~PFOR_USEHWMS;
			}
		}
	}
	return (pdesc);
}

int
PWClose(PWDICT *pwp)
{
	if (pwp->header.pih_magic != PIH_MAGIC) {
		return (-1);
	}

	if (pwp->flags & PFOR_WRITE) {
		pwp->flags |= PFOR_FLUSH;
		(void) PutPW(pwp, (char *)0);	/* flush last index if necess */

		if (fseek(pwp->ifp, 0L, 0)) {
			return (-1);
		}

		if (!fwrite((char *)&pwp->header, sizeof (pwp->header),
		    1, pwp->ifp)) {
			return (-1);
		}

		if (pwp->flags & PFOR_USEHWMS) {
			int i;
			for (i = 1; i <= 0xff; i++) {
				if (!pwp->hwms[i]) {
					pwp->hwms[i] = pwp->hwms[i-1];
				}
			}
			(void) fwrite(pwp->hwms, 1, sizeof (pwp->hwms),
			    pwp->wfp);
		}
	}

	(void) fclose(pwp->ifp);
	(void) fclose(pwp->dfp);
	(void) fclose(pwp->wfp);

	pwp->header.pih_magic = 0;

	free(pwp);

	return (0);
}

int
PutPW(PWDICT *pwp, char *string)
{
	if (!(pwp->flags & PFOR_WRITE)) {
		return (-1);
	}

	if (string) {
		(void) strncpy(pwp->data[pwp->count], string, MAXWORDLEN);
		pwp->data[pwp->count][MAXWORDLEN - 1] = '\0';

		pwp->hwms[string[0] & 0xff] = pwp->header.pih_numwords;

		++(pwp->count);
		++(pwp->header.pih_numwords);

	} else if (!(pwp->flags & PFOR_FLUSH)) {
		return (-1);
	}

	if ((pwp->flags & PFOR_FLUSH) || !(pwp->count % NUMWORDS)) {
		int i;
		uint32_t datum;
		register char *ostr;

		datum = (uint32_t)ftell(pwp->dfp);

		(void) fwrite((char *)&datum, sizeof (datum), 1, pwp->ifp);

		(void) fputs(pwp->data[0], pwp->dfp);
		(void) putc(0, pwp->dfp);

		ostr = pwp->data[0];

		for (i = 1; i < NUMWORDS; i++) {
			register int j;
			register char *nstr;

			nstr = pwp->data[i];

			if (nstr[0]) {
				for (j = 0; ostr[j] && nstr[j] &&
				    (ostr[j] == nstr[j]); j++)
					;
				(void) putc(j & 0xff, pwp->dfp);
				(void) fputs(nstr + j, pwp->dfp);
			}
			(void) putc(0, pwp->dfp);

			ostr = nstr;
		}

		(void) memset(pwp->data, '\0', sizeof (pwp->data));
		pwp->count = 0;
	}
	return (0);
}

char *
GetPW(PWDICT *pwp, uint32_t number)
{
	uint32_t datum;
	register int i;
	register char *ostr;
	register char *nstr;
	register char *bptr;
	char buffer[NUMWORDS * MAXWORDLEN];
	static char data[NUMWORDS][MAXWORDLEN];
	static uint32_t prevblock = 0xffffffff;
	uint32_t thisblock;

	thisblock = number / NUMWORDS;

	if (prevblock == thisblock) {
		return (data[number % NUMWORDS]);
	}

	if (fseek(pwp->ifp, sizeof (struct pi_header) +
	    (thisblock * sizeof (uint32_t)), 0)) {
		return (NULL);
	}

	if (!fread((char *)&datum, sizeof (datum), 1, pwp->ifp)) {
		return (NULL);
	}

	if (fseek(pwp->dfp, datum, 0)) {
		return (NULL);
	}

	if (!fread(buffer, 1, sizeof (buffer), pwp->dfp)) {
		return (NULL);
	}

	prevblock = thisblock;

	bptr = buffer;

	for (ostr = data[0]; *(ostr++) = *(bptr++); /* nothing */)
		;

	ostr = data[0];

	for (i = 1; i < NUMWORDS; i++) {
		nstr = data[i];
		(void) strcpy(nstr, ostr);
		ostr = nstr + *(bptr++);
		while (*(ostr++) = *(bptr++))
			;

		ostr = nstr;
	}

	return (data[number % NUMWORDS]);
}

uint32_t
FindPW(PWDICT *pwp, char *string)
{
	int lwm;
	int hwm;
	int idx;

	if (string == NULL)
		return (PW_WORDS(pwp));

	if (pwp->flags & PFOR_USEHWMS) {
		idx = string[0] & 0xff;
		lwm = idx ? pwp->hwms[idx - 1] : 0;
		hwm = pwp->hwms[idx];
	} else {
		lwm = 0;
		hwm = PW_WORDS(pwp) - 1;
	}

	for (;;) {
		int cmp;
		int pivot;
		char *this;

		pivot = lwm + ((hwm+1)-lwm)/2;

		if (feof(pwp->ifp) && feof(pwp->dfp) && feof(pwp->wfp))
			break;

		if ((this = GetPW(pwp, pivot)) == NULL)
			break;

		cmp = strcmp(string, this);		/* INLINE ? */

		if (cmp == 0)
			return (pivot);
		else if (cmp < 0)
			hwm = pivot-1;
		else
			lwm = pivot+1;

		if (lwm > hwm)	/* searched all; not found */
			break;
	}

	/* not found */
	return (PW_WORDS(pwp));
}
