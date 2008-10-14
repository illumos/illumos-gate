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

/*
 *	The SPCS status support kernel utilities
 *	See header spcs_s_k.h for functional spec
 */
#include <sys/types.h>
#include <sys/ksynch.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/varargs.h>

#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_k.h>
#include <sys/unistat/spcs_s_impl.h>
#include <sys/unistat/spcs_errors.h>

#ifdef DS_DDICT
#include <sys/nsctl/contract.h>
#endif
/*
 *	Debug support to allow testing in userspace
 */

#if	UNISTAT_ASSERTIONS
#define	_CELEVEL CE_PANIC
#else
#define	_CELEVEL CE_WARN
#endif


/*
 *	Unistat state data
 */

/*
 * This flag is made nonzero to indicate the bytestream transport mechanism
 * is initalized.
 */

static int bytestream_transport_initialized = 0;

/*
 *	Common code for status init
 *
 */

static void init_status(spcs_s_pinfo_t *p)
{
#ifdef UNISTAT_TRACE
	cmn_err(CE_WARN, "init_status entry");
#endif
	p->major = SPCS_S_MAJOR_REV;
	p->minor = SPCS_S_MINOR_REV;
	p->icount = 0;
	p->scount = 0;
	p->tcount = 0;
#ifdef UNISTAT_TRACE
	cmn_err(CE_WARN, "init_status exit");
#endif
}

/*
 *	Create and initialize local ioctl status.
 *
 */

spcs_s_info_t
spcs_s_kcreate()
{
	spcs_s_pinfo_t *kstatus;
#ifdef UNISTAT_TRACE
	cmn_err(CE_WARN, "spcs_s_kcreate entry");
#endif
	kstatus = (spcs_s_pinfo_t *)
			kmem_alloc(sizeof (spcs_s_pinfo_t), KM_SLEEP);

	if (kstatus)
		init_status(kstatus);
#ifdef UNISTAT_TRACE
	cmn_err(CE_WARN, "spcs_s_kcreate exit");
#endif
	return ((spcs_s_info_t)kstatus);
}

/*
 *	Initialize existing ioctl status.
 */

void
spcs_s_kinit(spcs_s_info_t kstatus)
{
#ifdef UNISTAT_TRACE
	cmn_err(CE_WARN, "spcs_s_kinit called");
#endif
	init_status((spcs_s_pinfo_t *)kstatus);
}

/*
 *	Release (free) ioctl status storage.
 *	BUG: this should take an spcs_s_info_t** or else the userspace
 *	version shoud just take a pointer. Could hopefully fix up Simon and
 *	Phil's code without too much trouble to fix this. Being inconsistent
 *	over the long term is bad.
 */

void
spcs_s_kfree(spcs_s_info_t kstatus)
{
#ifdef UNISTAT_TRACE
	cmn_err(CE_WARN, "spcs_s_kfree entry");
#endif
	kmem_free((void *)kstatus, sizeof (spcs_s_pinfo_t));
#ifdef UNISTAT_TRACE
	cmn_err(CE_WARN, "spcs_s_kfree exit");
#endif
}

/*
 *	Delete one error code and its supplemental info
 *	The "oldest" error code is removed.
 *	The assumption is that there is at least one status code present.
 *	Neither sdata nor tdata space is reclaimed
 */

static void
spcs_delete(spcs_s_pinfo_t *p)
{
	int i;
	int d;
#ifdef UNISTAT_TRACE
	cmn_err(CE_WARN, "spcs_s_delete entry");
#endif
	d = p->idata[0].f.sup_count + 1;

	for (i = 0; i < (p->icount - d); i++)
		p->idata[i] = p->idata[i+d];
	p->icount -= d;
#ifdef UNISTAT_TRACE
	cmn_err(CE_WARN, "spcs_s_delete exit");
#endif
}

/*
 * 	Common code for adding a status code
 *	Return 1 if overflow detected, 0 if enough space for code and support
 *      info.
 */

static boolean_t
add_code(spcs_s_pinfo_t *p, spcs_s_status_t stcode)
{
	spcs_s_udata_t c;
	c.s = stcode;
#ifdef UNISTAT_TRACE
	cmn_err(CE_WARN, "add_code entry");
#endif

	if ((p->icount + c.f.sup_count + 1) > SPCS_S_IDSIZE) {
		if (p->icount == SPCS_S_IDSIZE)
			spcs_delete(p);
		p->idata[p->icount++].s = SPCS_EOVERFLOW;

		cmn_err(_CELEVEL, "SPCS Unistat: not enough room in idata!");
#ifdef UNISTAT_TRACE
		cmn_err(CE_WARN, "add_code exit 1");
#endif

		return (B_TRUE);
	} else
		p->idata[p->icount++] = c;
#ifdef UNISTAT_TRACE
	cmn_err(CE_WARN, "add_code exit 2");
#endif
	return (B_FALSE);
}

/*
 * 	Common code for adding a string as supplemental info.
 *	Add_code is assumed to have been called already to ensure enough space
 *      idata. The string is copied into the sdata array and the index to the
 *	first character is put in idata along with the datatype indicator.
 */

static void
add_item(spcs_s_pinfo_t *p, char *string)
{
	int len;
	char *nullstr = "XXXXXXXX";
#ifdef UNISTAT_TRACE
	cmn_err(CE_WARN, "add_item entry");
#endif
	len = strlen(string);

/*
 * The following HACK is for RDC which is somewhat careless about
 * it's usage of strings. It does not make sense to panic the machine
 * because we botched an informational message. Print something
 * usefull so we can go back and fix it.
 * This can be removed when everyone has played by the correct unistat rules
 */
	if (len == 0) {
		string = nullstr;
		len = strlen(nullstr);
#ifdef LATER
		cmn_err(_CELEVEL,
		"SPCS: Unistat zero length string passed to add_item");
#endif
	}
	if ((len + 1) > (SPCS_S_SDSIZE - p->scount))
		cmn_err(_CELEVEL,
		"SPCS: Unistat sdata array too small: needed %d bytes",
			len + 1);

	p->idata[p->icount].su.type = SU_STRING;
	p->idata[p->icount++].su.offset = p->scount;
	(void) strcpy(&(p->sdata[p->scount]), string);
	p->scount += len + 1;
}

/*
 *	Check the rev level of the userspace status structure
 *	and spew some chunks if it doesn't match the kernel's unistat rev.
 *	Some day something more intelligent should happen to try to provide
 *	backward compatiblity with some mismatches (see the impl header file).
 *	Returns true if the revisions are compatible, false otherwise.
 */

static boolean_t
check_revision(spcs_s_info_t ustatus)
{
	char *m;
	char buf[SPCS_S_REVSIZE];
	spcs_s_pinfo_t *p = (spcs_s_pinfo_t *)buf;
	int mode = 0;

#ifdef UNISTAT_TRACE
	cmn_err(CE_WARN, "check_revision entry");
#endif

	m =
	"SPCS Unistat failure (product packaging error): data struct mismatch";
	(void) ddi_copyin((void *) ustatus, (void *) p, SPCS_S_REVSIZE, mode);

	if ((p->major == SPCS_S_MAJOR_REV) && (p->minor == SPCS_S_MINOR_REV)) {
		/* Both match */
#ifdef UNISTAT_TRACE
		cmn_err(CE_WARN, "check_revision exit 1");
#endif
		return (B_TRUE);
	}

	/*
	 * We have a major and/or minor version mismatch.
	 * Deal with each case individually.
	 */

#ifdef DEBUG
	cmn_err(CE_WARN, "unistat kernel v%d.%d, user v%d.%d\n",
		SPCS_S_MAJOR_REV, SPCS_S_MINOR_REV,
		(int)p->major, (int)p->minor);
#endif

	if (p->major > SPCS_S_MAJOR_REV) {
		/*
		 * couldn't guess what to do if the userspace version is ahead
		 * of the kernel version, so issue a warning
		 */
		cmn_err(CE_WARN, m);
	} else if (p->major < SPCS_S_MAJOR_REV) {
		/*
		 * kernel's major version is ahead of userspace version: do
		 * something extremely clever here some day instead of the
		 * warning
		 */
		cmn_err(CE_WARN, m);
	} else if (p->minor < SPCS_S_MINOR_REV) {

		/*
		 * kernel's minor version is ahead of userspace version: do
		 * something clever here some day instead of the warning
		 */

		cmn_err(CE_WARN, m);
	} else {
		/*
		 * couldn't guess what to do if the userspace version is ahead
		 * of the kernel's minor version, so issue a warning
		 */

		cmn_err(CE_WARN, m);
	}
#ifdef UNISTAT_TRACE
	cmn_err(CE_WARN, "check_revision exit 2");
#endif
	return (B_FALSE);
}

/*
 *	Add a code and optional support information to status
 *
 *	The support info can only consist of char pointers.
 *
 *	Varargs doesn't provide a means of detecting too few supplemental
 *	values...
 */

void
spcs_s_add(spcs_s_info_t kstatus, spcs_s_status_t stcode, ...)
{
	va_list ap;
	spcs_s_udata_t c;
	spcs_s_pinfo_t *p;
	char *sp;

#ifdef UNISTAT_TRACE
	cmn_err(CE_WARN, "spcs_s_add entry");
#endif
	p = (spcs_s_pinfo_t *)kstatus;
	c.s = stcode;

	if (add_code(p, stcode) == B_TRUE) {
#ifdef UNISTAT_TRACE
		cmn_err(CE_WARN, "spcs_s_add exit 1");
#endif
		return;
	}

	va_start(ap, stcode);

	while (c.f.sup_count--) {
		sp = va_arg(ap, caddr_t);
		if (sp != (char *)NULL)
			add_item(p, sp);
	}

	va_end(ap);
#ifdef UNISTAT_TRACE
	cmn_err(CE_WARN, "spcs_s_add exit 2");
#endif
}

/*
 *	Common code to copy status to userspace
 *
 *	Only "used" data is copied to minimize overhead.
 */

static void
scopyout(spcs_s_pinfo_t *kstatus, spcs_s_pinfo_t *ustatus)
{
	int mode = 0;
#ifdef UNISTAT_TRACE
	cmn_err(CE_WARN, "scopyout entry");
#endif

	/*
	 * If tdata is in use, blow up: asynch data is not intended for ioctls.
	 * How would we ship it back? (the user hasn't given us any place to
	 * put it!)
	 */

	if (kstatus->tcount)
		cmn_err(_CELEVEL, "SPCS: Unistat asynch data in ioctl status!");

	/*
	 * Gently, Bentley
	 * Have to copy all the header stuff even though there is no need for
	 * some items like the revisions. This is unavoidable without making
	 * the structure more complex or guessing about alignment and the true
	 * size of the part of the structure sitting ahead of the {i,s,t}data
	 * arrays.
	 */

	(void) ddi_copyout((void *) kstatus, (void *) ustatus,
		sizeof (spcs_s_pinfo_t) - (sizeof (kstatus->idata) +
		sizeof (kstatus->sdata) + sizeof (kstatus->tdata)), mode);
	(void) ddi_copyout((void *)kstatus->idata, (void *) ustatus->idata,
		(kstatus->icount * sizeof (kstatus->idata[0])), mode);
	(void) ddi_copyout((void *)kstatus->sdata, (void *) ustatus->sdata,
		(kstatus->scount * sizeof (kstatus->sdata[0])), mode);
	(void) ddi_copyout((void *)kstatus->tdata, (void *) ustatus->tdata,
		(kstatus->tcount * sizeof (kstatus->tdata[0])), mode);
#ifdef UNISTAT_TRACE
	cmn_err(CE_WARN, "scopyout exit");
#endif
}

/*
 *	Copy the ioctl status info to userspace
 */

void
spcs_s_copyout(spcs_s_info_t *kstatus_a, spcs_s_info_t ustatus)
{
#ifdef UNISTAT_TRACE
	cmn_err(CE_WARN, "spcs_s_copyout entry");
#endif
	if (check_revision(ustatus) == B_TRUE)
		scopyout((spcs_s_pinfo_t *)*kstatus_a,
		    (spcs_s_pinfo_t *)ustatus);
#ifdef UNISTAT_TRACE
	cmn_err(CE_WARN, "spcs_s_copyout exit");
#endif
}


/*
 *	Copy the ioctl status info to userspace
 *      Free the status info storage.
 */

void
spcs_s_copyoutf(spcs_s_info_t *kstatus_a, spcs_s_info_t ustatus)
{
#ifdef UNISTAT_TRACE
	cmn_err(CE_WARN, "spcs_s_copyoutf entry");
#endif
	if (check_revision(ustatus) == B_TRUE)
		scopyout((spcs_s_pinfo_t *)*kstatus_a,
		    (spcs_s_pinfo_t *)ustatus);
	spcs_s_kfree(*kstatus_a);
	*kstatus_a = NULL;
#ifdef UNISTAT_TRACE
	cmn_err(CE_WARN, "spcs_s_copyoutf exit");
#endif
}

/*
 *	Return the oldest status code from the status info or SPCS_S_OK if
 *      there is none.
 */

spcs_s_status_t
spcs_s_oldest_status(spcs_s_info_t kstatus)
{
	spcs_s_pinfo_t *p;
#ifdef UNISTAT_TRACE
	cmn_err(CE_WARN, "spcs_s_oldest_status entry");
#endif
	p = (spcs_s_pinfo_t *)kstatus;

#ifdef UNISTAT_TRACE
	cmn_err(CE_WARN, "spcs_s_oldest_status exit");
#endif
	return (p->icount ? p->idata[0].s : SPCS_S_OK);
}

/*
 *      Return the idata index of the last status code in the array (i.e.
 *      the "youngest" code present). The assumption is that the caller has
 *      checked to see that pcount is nonzero.
 */

static int
last_code_idx(spcs_s_pinfo_t *p)
{
	int last = 0;
	int idx = 0;
#ifdef UNISTAT_TRACE
	cmn_err(CE_WARN, "last_code_idx entry");
#endif

	while (idx < p->icount) {
		last = idx;
		idx += p->idata[idx].f.sup_count + 1;
	}
#ifdef UNISTAT_TRACE
	cmn_err(CE_WARN, "last_code_idx exit");
#endif
	return (last);
}

/*
 *	Return the youngest status code form the status info or SPCS_S_OK if
 *      there is none.
 */

spcs_s_status_t
spcs_s_youngest_status(spcs_s_info_t kstatus)
{
	spcs_s_pinfo_t *p;
	spcs_s_status_t temp;
#ifdef UNISTAT_TRACE
	cmn_err(CE_WARN, "spcs_s_youngest_status entry");
#endif
	p = (spcs_s_pinfo_t *)kstatus;

	if (p->icount)
		temp = p->idata[last_code_idx(p)].s;
	else
		temp = SPCS_S_OK;

#ifdef UNISTAT_TRACE
	cmn_err(CE_WARN, "spcs_s_youngest_status exit");
#endif
	return (temp);
}

/*
 *      Insert a new status code or NULL if there is none.
 *      Copy the status info to userspace.
 *      return a value to use as an return value (e.g. ioctl return).
 */

spcs_s_status_t
spcs_s_ocopyout(spcs_s_info_t *kstatus_a,
			spcs_s_info_t ustatus, spcs_s_status_t stcode, ...)
{
	spcs_s_udata_t ret;
	va_list ap;
	spcs_s_udata_t c;
	spcs_s_pinfo_t *p;
	char *sp;

#ifdef UNISTAT_TRACE
	cmn_err(CE_WARN, "spcs_s_ocopyout entry");
#endif
	p  = (spcs_s_pinfo_t *)*kstatus_a;
	c.s = stcode;

	if (check_revision(ustatus) == B_FALSE)
		ret.s = EINVAL;
	else {
		if (stcode) {
			if (add_code(p, stcode) == B_FALSE) {
				va_start(ap, stcode);

				while (c.f.sup_count--) {
					sp = va_arg(ap, caddr_t);
					if (sp != (char *)NULL)
						add_item(p, sp);
				}

				va_end(ap);
			}
		}
		ret.s = p->icount ? p->idata[last_code_idx(p)].s: SPCS_S_OK;
		scopyout(p, (spcs_s_pinfo_t *)ustatus);
	}
#ifdef UNISTAT_TRACE
	cmn_err(CE_WARN, "spcs_s_ocopyout exit");
#endif
	return (ret.s);
}


/*
 *      Insert a new status code or NULL if there is none.
 *      Copy the status info to userspace.
 *      Free the kernel status info storage
 *      return a value to use as an operatiion return value (e.g. ioctl return)
 */

spcs_s_status_t
spcs_s_ocopyoutf(spcs_s_info_t *kstatus_a,
		spcs_s_info_t ustatus, spcs_s_status_t stcode, ...)
{
	spcs_s_udata_t ret;
	va_list ap;
	spcs_s_udata_t c;
	spcs_s_pinfo_t *p;
	char *sp;

#ifdef UNISTAT_TRACE
	cmn_err(CE_WARN, "spcs_s_ocopyoutf entry");
#endif
	p = *(spcs_s_pinfo_t **)kstatus_a;
	c.s = stcode;

	if (check_revision(ustatus) == B_FALSE) {
		ret.s = EINVAL;
	} else {
		if (stcode) {
			if (add_code(p, stcode) == B_FALSE) {
				va_start(ap, stcode);

				while (c.f.sup_count--) {
					sp = va_arg(ap, caddr_t);
					if (sp != (char *)NULL)
						add_item(p, sp);
				}

				va_end(ap);
			}
		}

		ret.s = p->icount ? p->idata[last_code_idx(p)].s: SPCS_S_OK;
		scopyout(p, (spcs_s_pinfo_t *)ustatus);
	}
	spcs_s_kfree((spcs_s_info_t)p);
	*kstatus_a = NULL;
#ifdef UNISTAT_TRACE
	cmn_err(CE_WARN, "spcs_s_ocopyoutf exit");
#endif
	return (ret.s);
}

/*
 * Return true if a status code is a Solaris error code
 */

boolean_t
spcs_s_is_solaris(spcs_s_status_t error)
{
	spcs_s_udata_t c;
#ifdef UNISTAT_TRACE
	cmn_err(CE_WARN, "spcs_s_is_solaris called");
#endif
	c.s = error;
	return (c.f.module == 0 ? B_TRUE : B_FALSE);
}

/*
 * Edit a value into a numeric string
 */

char
*spcs_s_inttostring(int val, char *buf, int buflen, int hex)
{
	char tempbuf[20];

#ifdef UNISTAT_TRACE
	cmn_err(CE_WARN, "spcs_s_inttostring entry 0x%x", val);
#endif
	if (buflen) {
		if (hex)
			(void) sprintf(tempbuf, "0x%0X", val);
		else
			(void) sprintf(tempbuf, "%d", val);
		if (strlen(tempbuf) < (size_t)buflen)
			(void) strcpy(buf, tempbuf);
		else
			(void) strcpy(buf, "***");
	} else  {
		(void) strcpy(buf, "***");
	}
#ifdef UNISTAT_TRACE
		cmn_err(CE_WARN, "spcs_s_inttostring exit: %s", buf);
#endif
	return (buf);
}

/*
 *	Initialize the bytestream mechanism.
 *	This is a prototype. Specification TBD. Not in 10/22 commitment
 */

int
spcs_s_start_bytestream()
{
#ifdef UNISTAT_TRACE
		cmn_err(CE_WARN, "spcs_s_start_bytestream called");
#endif
	bytestream_transport_initialized = 1;
	return (SPCS_S_OK);
}

/*
 *	Stop (shut off) the bytestream mechanism.
 *
 *	This is a prototype. Specification TBD. Not in 10/22 commitment
 */

int
spcs_s_stop_bytestream()
{
#ifdef UNISTAT_TRACE
		cmn_err(CE_WARN, "spcs_s_stop_bytestream called");
#endif
	bytestream_transport_initialized = 0;
	return (SPCS_S_OK);
}

/*
 *	Add a status code and the address and length of arbitrary binary
 *	data to be held (possibly with other status) for later transmission to
 *	userspace via a pipe facility (i.e. NOT via ioctl return). This is a
 *	means of getting arbitrary information with or without other status
 *	info shipped out as an alternative to cmn_err and/or trace file
 *	mechanisms.
 *	@param kstatus  The status info pointer
 *	@param stcode   The status code to annotate the data
 *	@param address  The starting address of the data
 *	@param length   The byte length of the data
 *	This is a prototype. Specification TBD. Not in the 10/22/98 unistat
 *	commitment
 */

void
spcs_s_add_bytestream(spcs_s_info_t kstatus, spcs_s_status_t stcode,
	spcs_s_bytestream_ptr_t data, int size)
{
	spcs_s_pinfo_t *p;
#ifdef UNISTAT_TRACE
		cmn_err(CE_WARN, "spcs_s_add_bytestream entry");
#endif
	p = (spcs_s_pinfo_t *)kstatus;

	if (p->tcount == SPCS_S_TDSIZE)
		cmn_err(CE_PANIC,
		"SPCS: Unistat too many calls to spcs_s_add_bytestream");
	if ((p->icount + 2) >= SPCS_S_TDSIZE)
		cmn_err(CE_PANIC,
		"SPCS: Unistat idata array too small in spcs_s_add_bytestream");
	p->idata[p->icount].s = stcode;
	if (p->idata[p->icount++].f.sup_count != 1)
		cmn_err(CE_PANIC,
		"SPCS: Unistat wrong sup_count in spcs_s_add_bytestream");
	p->idata[p->icount].su.type = SU_BYTESTREAM;
	p->idata[p->icount].su.offset = p->tcount++;
	p->tdata[p->idata[p->icount].su.offset].size = size;
	p->tdata[p->idata[p->icount++].su.offset].u_p.data = data;
#ifdef UNISTAT_TRACE
		cmn_err(CE_WARN, "spcs_s_add_bytestream exit");
#endif
}

/*
 *	Asynchronously output unistat info and possibly bytestreams to
 *	userspace. The bytestream mechanism must have been initialized.
 *	@param kstatus  The status info pointer
 *	@return SPCS_S_OK for normal completion, SPCS_S_ERROR otherwise
 *	This is a prototype. Specification TBD. Not in the 10/22/98 unistat
 *	commitment
 */

int
spcs_s_asynch_status(spcs_s_info_t kstatus)
{
	spcs_s_pinfo_t *p;
	int i, s, b, suppcount;
	uchar_t *bp;
#ifdef UNISTAT_TRACE
		cmn_err(CE_WARN, "spcs_s_asynch_status entry");
#endif
	p = (spcs_s_pinfo_t *)kstatus;

	/*
	 * Any real code would have to go through and process the
	 * address/length pairs in the tdata array. The lengths would be
	 * valid but the addresses would be meaningless. Instead, for a
	 * stream transport mechanism the bytestream(s) would follow the
	 * spcs_s_pinfo_t structure. So after the last call to
	 * spcs_s_add_bytestream things the spcs_pinfo_t would look like this:
	 * |-------------|
	 * | preamble	 |
	 * |-------------|
	 * | idata	 |
	 * |(sup offset) |-----------------|
	 * |(sup offset) |--|		   | bytestream reference (index)
	 * |-------------|  | string	   |
	 * | sdata	 |  | ref (offset) |
	 * | (strings)   |<-|		   |
	 * |-------------|		   |
	 * | tdata	 |		   |
	 * |		 |<----------------|
	 * | (length)    |
	 * | (address)   |-------------------->byte data "out there somewhere"
	 * |-------------|
	 *
	 * After processing in this function the data headed for a pipe or
	 * other sequention stream would look like this:
	 *
	 * |-------------|
	 * | preamble    |
	 * |-------------|
	 * | idata	 |
	 * |		 |-----------------|
	 * |		 |--|		   | bytestream reference (index)
	 * |-------------|  | string	   |
	 * | sdata	 |  | ref (offset) |
	 * | (strings)	 |<-|		   |
	 * |-------------|		   |
	 * | tdata	 |		   |
	 * |		 |<----------------|
	 * | (length)    |
	 * | (null addr) |
	 * |-------------|
	 * |first	 |
	 * |bytestream	 |
	 * |group	 |
	 * |-------------|
	 * |second	 |
	 * |bytestream   |
	 * |group	 |
	 * |-------------|
	 * | . . .	 |
	 * |-------------|
	 *
	 * For the prototype we just dump the stuff out so we can see the
	 * functions work.
	 */

	if (! bytestream_transport_initialized) {
#ifdef UNISTAT_TRACE
		cmn_err(CE_WARN, "spcs_s_asynch_status exit 1");
#endif
		return (SPCS_S_ERROR);
	}

	cmn_err(CE_NOTE, "SPCS Unistat Asynchronous Status Dump");
	cmn_err(CE_NOTE, "This is a test fixture waiting for a pipe or");
	cmn_err(CE_NOTE, "shared memory");

	/*
	 * I'd like nothing more than to code up a really cool pipe or mmap'd
	 * shared memory scheme to shovel this stuff up to a daemon that feeds
	 * Java events out to listener threads belonging to both management
	 * software, coresw product code and developer code. As it is I just
	 * have time to spew stuff out via cmn_err. Have to make believe this
	 * is an alternative to cmn_err and not just another dang client!
	 */

	i = 0;

	while (i < p->icount) {

		/*
		 * can't access the status text or anything else proper and
		 * pretty from here in the kernel, have to just dump it. Put
		 * the status codes out as decimal to make them look as weird
		 * as possible so we see that the point of this is not for
		 * anybody to actually pay attention to them but to use this
		 * as a means of testing the rest of the prototype and
		 * suggesting potental functionality. We also put the oldest
		 * stuff out first, backwards from ioctl status. That's
		 * because there are only minutes to implement this and the
		 * point is to see the potential, etc.
		 */

		suppcount = p->idata[i].f.sup_count;

		cmn_err(CE_NOTE, "Status item %d value %x supplements %d",
			i, p->idata[i].s, suppcount);
		i++;

		for (s = 0; s < suppcount; s++) {
			if (p->idata[i+s].su.type == SU_STRING)
				cmn_err(CE_NOTE,
				"Supplement %d string value: %s", s,
				(char *)(p->sdata + p->idata[i+s].su.offset));
			else {
				cmn_err(CE_NOTE,
				"Supplement %d bytestream dump:", s);
				cmn_err(CE_NOTE, "offset data");
				bp = p->tdata[p->idata[i+s].su.offset].u_p.data;
				/* The SunSoft mandated 8 character tabstops */
				/* really BITE MY BUTT */
				for (b = 0;
				    b < p->tdata[p->idata[i+s].su.offset].size;
				    b++)
					cmn_err(CE_NOTE, "%6d   %2x", b, *bp++);
			}
		}

		i += suppcount;
	}

#ifdef UNISTAT_TRACE
		cmn_err(CE_WARN, "spcs_s_asynch_status exit 2");
#endif
	return (SPCS_S_OK);
}
