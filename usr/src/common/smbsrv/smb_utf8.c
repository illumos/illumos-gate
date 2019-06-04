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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Multibyte/wide-char conversion routines. SMB uses UTF-16 on the wire
 * (smb_wchar_t) and we use UTF-8 internally (our multi-byte, or mbs).
 */

#if defined(_KERNEL) || defined(_FAKE_KERNEL)
#include <sys/types.h>
#include <sys/sunddi.h>
#else	/* _KERNEL || _FAKE_KERNEL */
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <iconv.h>
#include <assert.h>
#endif	/* _KERNEL || _FAKE_KERNEL */
#include <sys/u8_textprep.h>
#include <smbsrv/string.h>


/*
 * mbstowcs
 *
 * The mbstowcs() function converts a multibyte character string
 * mbstring into a wide character string wcstring. No more than
 * nwchars wide characters are stored. A terminating null wide
 * character is appended if there is room.
 *
 * Returns the number of wide characters converted, not counting
 * any terminating null wide character. Returns -1 if an invalid
 * multibyte character is encountered.
 */
size_t
smb_mbstowcs(smb_wchar_t *wcs, const char *mbs, size_t nwchars)
{
	size_t mbslen, wcslen;
	int err;

	/* NULL or empty input is allowed. */
	if (mbs == NULL || *mbs == '\0') {
		if (wcs != NULL && nwchars > 0)
			*wcs = 0;
		return (0);
	}

	/*
	 * Traditional mbstowcs(3C) allows wcs==NULL to get the length.
	 * SMB never calls it that way, but let's future-proof.
	 */
	if (wcs == NULL) {
		return ((size_t)-1);
	}

	mbslen = strlen(mbs);
	wcslen = nwchars;
	err = uconv_u8tou16((const uchar_t *)mbs, &mbslen,
	    wcs, &wcslen, UCONV_OUT_LITTLE_ENDIAN);
	if (err != 0)
		return ((size_t)-1);

	if (wcslen < nwchars)
		wcs[wcslen] = 0;

	return (wcslen);
}


/*
 * mbtowc
 *
 * The mbtowc() function converts a multibyte character mbchar into
 * a wide character and stores the result in the object pointed to
 * by wcharp. Up to nbytes bytes are examined.
 *
 * If mbchar is NULL, mbtowc() returns zero to indicate that shift
 * states are not supported.  Shift states are used to switch between
 * representation modes using reserved bytes to signal shifting
 * without them being interpreted as characters.  If mbchar is null
 * mbtowc should return non-zero if the current locale requires shift
 * states.  Otherwise it should be return 0.
 *
 * If mbchar is non-null, returns the number of bytes processed in
 * mbchar.  If mbchar is null, convert the null (wcharp=0) but
 * return length zero.  If mbchar is invalid, returns -1.
 */
int /*ARGSUSED*/
smb_mbtowc(uint32_t *wcharp, const char *mbchar, size_t nbytes)
{
	uint32_t wide_char;
	int count, err;
	size_t mblen;
	size_t wclen;

	if (mbchar == NULL)
		return (0); /* no shift states */

	/*
	 * How many bytes in this symbol?
	 */
	count = u8_validate((char *)mbchar, nbytes, NULL, 0, &err);
	if (count < 0)
		return (-1);

	mblen = count;
	wclen = 1;
	err = uconv_u8tou32((const uchar_t *)mbchar, &mblen,
	    &wide_char, &wclen, UCONV_OUT_SYSTEM_ENDIAN);
	if (err != 0)
		return (-1);
	if (wclen == 0) {
		wide_char = 0;
		count = 0;
	}

	if (wcharp)
		*wcharp = wide_char;

	return (count);
}


/*
 * wctomb
 *
 * The wctomb() function converts a wide character wchar into a multibyte
 * character and stores the result in mbchar. The object pointed to by
 * mbchar must be large enough to accommodate the multibyte character.
 *
 * Returns the numberof bytes written to mbchar.
 * Note: handles null like any 1-byte char.
 */
int
smb_wctomb(char *mbchar, uint32_t wchar)
{
	char junk[MTS_MB_CUR_MAX+1];
	size_t mblen;
	size_t wclen;
	int err;

	if (mbchar == NULL)
		mbchar = junk;

	mblen = MTS_MB_CUR_MAX;
	wclen = 1;
	err = uconv_u32tou8(&wchar, &wclen, (uchar_t *)mbchar, &mblen,
	    UCONV_IN_SYSTEM_ENDIAN | UCONV_IGNORE_NULL);
	if (err != 0)
		return (-1);

	return ((int)mblen);
}


/*
 * wcstombs
 *
 * The wcstombs() function converts a wide character string wcstring
 * into a multibyte character string mbstring. Up to nbytes bytes are
 * stored in mbstring. Partial multibyte characters at the end of the
 * string are not stored. The multibyte character string is null
 * terminated if there is room.
 *
 * Returns the number of bytes converted, not counting the terminating
 * null byte. Returns -1 if an invalid WC sequence is encountered.
 */
size_t
smb_wcstombs(char *mbs, const smb_wchar_t *wcs, size_t nbytes)
{
	size_t mbslen, wcslen;
	int err;

	/* NULL or empty input is allowed. */
	if (wcs == NULL || *wcs == 0) {
		if (mbs != NULL && nbytes > 0)
			*mbs = '\0';
		return (0);
	}

	/*
	 * Traditional wcstombs(3C) allows mbs==NULL to get the length.
	 * SMB never calls it that way, but let's future-proof.
	 */
	if (mbs == NULL) {
		return ((size_t)-1);
	}

	/*
	 * Compute wcslen
	 */
	wcslen = 0;
	while (wcs[wcslen] != 0)
		wcslen++;

	mbslen = nbytes;
	err = uconv_u16tou8(wcs, &wcslen,
	    (uchar_t *)mbs, &mbslen, UCONV_IN_LITTLE_ENDIAN);
	if (err != 0)
		return ((size_t)-1);

	if (mbslen < nbytes)
		mbs[mbslen] = '\0';

	return (mbslen);
}


/*
 * Returns the number of bytes that would be written if the multi-
 * byte string mbs was converted to a wide character string, not
 * counting the terminating null wide character.
 */
size_t
smb_wcequiv_strlen(const char *mbs)
{
	uint32_t	wide_char;
	size_t bytes;
	size_t len = 0;

	while (*mbs) {
		bytes = smb_mbtowc(&wide_char, mbs, MTS_MB_CHAR_MAX);
		if (bytes == ((size_t)-1))
			return ((size_t)-1);
		mbs += bytes;

		len += sizeof (smb_wchar_t);
		if (bytes > 3) {
			/*
			 * Extended unicode, so TWO smb_wchar_t
			 */
			len += sizeof (smb_wchar_t);
		}
	}

	return (len);
}


/*
 * Returns the number of bytes that would be written if the multi-
 * byte string mbs was converted to an OEM character string,
 * (smb_mbstooem) not counting the terminating null character.
 */
size_t
smb_sbequiv_strlen(const char *mbs)
{
	size_t nbytes;
	size_t len = 0;

	while (*mbs) {
		nbytes = smb_mbtowc(NULL, mbs, MTS_MB_CHAR_MAX);
		if (nbytes == ((size_t)-1))
			return ((size_t)-1);
		if (nbytes == 0)
			break;

		if (nbytes == 1) {
			/* ASCII */
			len++;
		} else if (nbytes < 8) {
			/* Compute OEM length */
			char mbsbuf[8];
			uint8_t oembuf[8];
			int oemlen;
			(void) strlcpy(mbsbuf, mbs, nbytes+1);
			oemlen = smb_mbstooem(oembuf, mbsbuf, 8);
			if (oemlen < 0)
				return ((size_t)-1);
			len += oemlen;
		} else {
			return ((size_t)-1);
		}

		mbs += nbytes;
	}

	return (len);
}

/*
 * Convert OEM strings to/from internal (UTF-8) form.
 *
 * We rarely encounter these anymore because all modern
 * SMB clients use Unicode (UTF-16). The few cases where
 * this IS still called are normally using ASCII, i.e.
 * tag names etc. so short-cut those cases.  If we get
 * something non-ASCII we have to call iconv.
 *
 * If we were to really support OEM code pages, we would
 * need to have a way to set the OEM code page from some
 * configuration value.  For now it's always CP850.
 * See also ./smb_oem.c
 */
static char smb_oem_codepage[32] = "CP850";

/*
 * smb_oemtombs
 *
 * Convert a null terminated OEM string 'string' to a UTF-8 string
 * no longer than max_mblen (null terminated if space).
 *
 * If the input string contains invalid OEM characters, a value
 * of -1 will be returned. Otherwise returns the length of 'mbs',
 * excluding the terminating null character.
 *
 * If either mbstring or string is a null pointer, -1 is returned.
 */
int
smb_oemtombs(char *mbs, const uint8_t *oems, int max_mblen)
{
	uchar_t *p;
	int	oemlen;
	int	rlen;
	boolean_t need_iconv = B_FALSE;

	if (mbs == NULL || oems == NULL)
		return (-1);

	/*
	 * Check if the oems is all ASCII (and get the length
	 * while we're at it) so we know if we need to iconv.
	 * We usually can avoid the iconv calls.
	 */
	oemlen = 0;
	p = (uchar_t *)oems;
	while (*p != '\0') {
		oemlen++;
		if (*p & 0x80)
			need_iconv = B_TRUE;
		p++;
	}

	if (need_iconv) {
		int	rc;
		char	*obuf = mbs;
		size_t	olen = max_mblen;
		size_t	ilen = oemlen;
#if defined(_KERNEL) || defined(_FAKE_KERNEL)
		char *ibuf = (char *)oems;
		kiconv_t ic;
		int	err;

		ic = kiconv_open("UTF-8", smb_oem_codepage);
		if (ic == (kiconv_t)-1)
			goto just_copy;
		rc = kiconv(ic, &ibuf, &ilen, &obuf, &olen, &err);
		(void) kiconv_close(ic);
#else	/* _KERNEL || _FAKE_KERNEL */
		const char *ibuf = (char *)oems;
		iconv_t	ic;
		ic = iconv_open("UTF-8", smb_oem_codepage);
		if (ic == (iconv_t)-1)
			goto just_copy;
		rc = iconv(ic, &ibuf, &ilen, &obuf, &olen);
		(void) iconv_close(ic);
#endif	/* _KERNEL || _FAKE_KERNEL */
		if (rc < 0)
			return (-1);
		/* Return val. is output bytes. */
		rlen = (max_mblen - olen);
	} else {
	just_copy:
		rlen = oemlen;
		if (rlen > max_mblen)
			rlen = max_mblen;
		bcopy(oems, mbs, rlen);
	}
	if (rlen < max_mblen)
		mbs[rlen] = '\0';

	return (rlen);
}

/*
 * smb_mbstooem
 *
 * Convert a null terminated multi-byte string 'mbs' to an OEM string
 * no longer than max_oemlen (null terminated if space).
 *
 * If the input string contains invalid multi-byte characters, a value
 * of -1 will be returned. Otherwise returns the length of 'oems',
 * excluding the terminating null character.
 *
 * If either mbstring or string is a null pointer, -1 is returned.
 */
int
smb_mbstooem(uint8_t *oems, const char *mbs, int max_oemlen)
{
	uchar_t *p;
	int	mbslen;
	int	rlen;
	boolean_t need_iconv = B_FALSE;

	if (oems == NULL || mbs == NULL)
		return (-1);

	/*
	 * Check if the mbs is all ASCII (and get the length
	 * while we're at it) so we know if we need to iconv.
	 * We usually can avoid the iconv calls.
	 */
	mbslen = 0;
	p = (uchar_t *)mbs;
	while (*p != '\0') {
		mbslen++;
		if (*p & 0x80)
			need_iconv = B_TRUE;
		p++;
	}

	if (need_iconv) {
		int	rc;
		char	*obuf = (char *)oems;
		size_t	olen = max_oemlen;
		size_t	ilen = mbslen;
#if defined(_KERNEL) || defined(_FAKE_KERNEL)
		char *ibuf = (char *)mbs;
		kiconv_t ic;
		int	err;

		ic = kiconv_open(smb_oem_codepage, "UTF-8");
		if (ic == (kiconv_t)-1)
			goto just_copy;
		rc = kiconv(ic, &ibuf, &ilen, &obuf, &olen, &err);
		(void) kiconv_close(ic);
#else	/* _KERNEL || _FAKE_KERNEL */
		const char *ibuf = mbs;
		iconv_t	ic;
		ic = iconv_open(smb_oem_codepage, "UTF-8");
		if (ic == (iconv_t)-1)
			goto just_copy;
		rc = iconv(ic, &ibuf, &ilen, &obuf, &olen);
		(void) iconv_close(ic);
#endif	/* _KERNEL || _FAKE_KERNEL */
		if (rc < 0)
			return (-1);
		/* Return val. is output bytes. */
		rlen = (max_oemlen - olen);
	} else {
	just_copy:
		rlen = mbslen;
		if (rlen > max_oemlen)
			rlen = max_oemlen;
		bcopy(mbs, oems, rlen);
	}
	if (rlen < max_oemlen)
		oems[rlen] = '\0';

	return (rlen);
}
