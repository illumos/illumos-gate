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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/modctl.h>
#include <sys/kobj.h>
#include <sys/kobj_impl.h>
#include <sys/promif.h>
#include <sys/promimpl.h>
#include <sys/reboot.h>
#include <sys/bootconf.h>
#include <sys/systm.h>		/* strstr */
#include <sys/machsystm.h>	/* obpdebug */

#define	FDEBUGFILE	"misc/forthdebug"
#define	INSTALL_DBP	"kdbg-words dbp-install previous"
#define	SYMBOL_END	"END OF SYMBOL"

#ifdef DEBUG
static int forthdebug	= 1;
#else
static int forthdebug	= 0;
#endif /* DEBUG */

static int forthdebug_dbp = 0;
int forthdebug_supported = 1;
int modreloc_flag = KOBJ_RELOCATED;

/*
 * basic_sym[] holds all essential symbols the symbol lookup
 * service requires. Forthdebug stub names appears in forthdebug
 * as place holders. They are replaced with the value of corresponding
 * kernel variables. For example, "modules-val-here" in forthdebug
 * is replaced with the address of "modules" variable.
 *
 * To improve performance, we mandate the records be in the same
 * sequence they appear in forthdebug, i.e "modules-val-here" is
 * ahead of "primaries-v-here" in misc/forthdebug.
 *
 * The last record must be all 0 to indicate end of the array.
 */
static char *basic_sym[] = {
	/* kernel variable */	/* forthdebug stub name - must be 16 chars */
	"modules",		"modules-val-here",
	"primaries",		"primaries-v-here",
	"modreloc_flag",	"modreloc-flagval",
	0,			0
};

static void fdbp_hook() {} /* null function for defer breakpoint operation */

/*ARGSUSED*/
static void fdbp_snoop(unsigned int i, struct modctl *modctl_p)
{
	promif_preprom();
	fdbp_hook();
	promif_postprom();
}

static kobj_notify_list_t knl_load = {
	fdbp_snoop, KOBJ_NOTIFY_MODLOADED, 0, 0
};

static kobj_notify_list_t knl_unload = {
	fdbp_snoop, KOBJ_NOTIFY_MODUNLOADING, 0, 0
};

void
forthdebug_init(void)
{
	char *fth_buf, *buf_p;
	ulong_t modsym;
	int i, sz;
	struct bootstat bstat;
	struct _buf *file;

	if (!forthdebug_supported) {
		if (obpdebug)
			(void) modload("misc", "obpsym");
		return;
	}

	forthdebug_dbp |= boothowto & RB_FORTHDEBUGDBP;
	forthdebug |= (boothowto & RB_FORTHDEBUG) | forthdebug_dbp;

	file = kobj_open_path(FDEBUGFILE, 1, 1);
	if (file == (struct _buf *)-1) {
		cmn_err(CE_CONT, "Can't open %s\n", FDEBUGFILE);
		return;
	}

	i = BOP_FSTAT(bootops, file->_fd, &bstat);
	if (i || !bstat.st_size) {
		cmn_err(CE_CONT, "Can't stat %s stat=%x sz=%llx\n",
		    FDEBUGFILE, i, (long long)bstat.st_size);
		goto err_stat;
	}

	fth_buf = (char *)kobj_zalloc(bstat.st_size + 1, KM_SLEEP);
	sz = kobj_read_file(file, fth_buf, bstat.st_size, 0); /* entire file */
	if (sz < 0) {
		cmn_err(CE_CONT, "Error(%d) reading %s\n", sz, FDEBUGFILE);
		goto done;
	}
	ASSERT(bstat.st_size == sz);
	fth_buf[sz] = 0;

	/* resolve all essential symbols in basic_sym[] */
	for (i = 0; basic_sym[i]; i += 2) {
		buf_p = strstr(fth_buf, basic_sym[i + 1]);
		modsym = kobj_getsymvalue(basic_sym[i], 0);
		if (buf_p && modsym) {
			(void) sprintf(buf_p, "%16p", (void *)modsym);
			buf_p += 16;
			*buf_p++ = ' ';	/* erase null char by sprintf */
		} else {
			cmn_err(CE_CONT,
			    "forthdebug_init: No %s symbol(%p,%p), aborted\n",
			    basic_sym[i], (void *)buf_p, (void *)modsym);
			goto done;
		}
	}
	if (!forthdebug) {	/* symbol lookup services only */
		if (!(buf_p = strstr(fth_buf, SYMBOL_END))) {
			cmn_err(CE_CONT, "No %s in forthdebug\n", SYMBOL_END);
			goto done;
		}
		*buf_p = '\0';
#ifdef DEBUG
		cmn_err(CE_CONT, "symbol lookup service (%ld bytes)\n",
		    (long)(buf_p - fth_buf));
#endif /* DEBUG */
		prom_interpret(fth_buf, 0, 0, 0, 0, 0);
		goto done;
	}

	cmn_err(CE_CONT, "%s (%d bytes) ", FDEBUGFILE, sz);
	prom_interpret(fth_buf, 0, 0, 0, 0, 0);
	cmn_err(CE_CONT, "loaded\n");
	obpdebug = 1;	/* backward compatibility */

	if (forthdebug_dbp) {
#ifdef NO_KOBJ_NOTIFY
		modsym = kobj_getsymvalue("kobj_notify_add", 0);
		(void) ((int (*)(kobj_notify_list_t *))modsym)(&knl_load);
		(void) ((int (*)(kobj_notify_list_t *))modsym)(&knl_unload);
#else
		(void) kobj_notify_add(&knl_load);
		(void) kobj_notify_add(&knl_unload);
#endif	/* NO_KOBJ_NOTIFY */
		prom_interpret(INSTALL_DBP, 0, 0, 0, 0, 0);
		debug_enter("Defer breakpoint enabled. Add breakpoints, then");
	}
done:
	kobj_free(fth_buf, bstat.st_size + 1);
err_stat:
	kobj_close_file(file);

	if (boothowto & RB_HALT)
		debug_enter("forthdebug: halt flag (-h) is set.\n");
}
