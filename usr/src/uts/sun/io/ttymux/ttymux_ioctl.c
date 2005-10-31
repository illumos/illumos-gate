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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * DESCRIPTION
 *
 * ttymux_ioctl - Handler for ttymux specific ioctl calls.
 *
 */

#include <sys/types.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/termio.h>
#include <sys/mkdev.h>
#include <sys/sunddi.h>
#include <sys/esunddi.h>
#include <sys/consdev.h>
#include <sys/promif.h>

#include <sys/ttymux.h>
#include "ttymux_impl.h"

/*
 * Extern declarations
 */
extern mblk_t *mkiocb(uint_t);
extern int nulldev();
extern uintptr_t space_fetch(char *key);
extern void prom_interpret(char *, uintptr_t, uintptr_t, uintptr_t,
    uintptr_t, uintptr_t);

/*
 * Imported ttymux routines
 */
extern void sm_debug(char *, ...);
extern void sm_log(char *, ...);
extern sm_lqi_t *get_lqi_byid(int);
extern sm_lqi_t *get_lqi_bydevt(dev_t);
extern int sm_associate(int, sm_lqi_t *, ulong_t, uint_t, char *);
extern int sm_disassociate(int, sm_lqi_t *, ulong_t);

/*
 * Exported ttymux routines
 */
int ttymux_abort_ioctl(mblk_t *);
int ttymux_device_init(sm_lqi_t *);
int ttymux_device_fini(sm_lqi_t *);
int sm_ioctl_cmd(sm_uqi_t *, mblk_t *);

/*
 * Imported ttymux variables
 */
extern sm_ss_t	*sm_ssp;

static int
mblk2assoc(mblk_t *mp, ttymux_assoc_t *assoc)
{
	struct iocblk *iobp = (struct iocblk *)mp->b_rptr;

	sm_dbg('M', ("mblk2assoc:\n"));
	if (mp->b_cont == NULL)
		return (EINVAL);

#ifdef _SYSCALL32_IMPL
	if ((iobp->ioc_flag & IOC_MODELS) != IOC_NATIVE) {
		ttymux_assoc32_t *assoc32;

		sm_dbg('I', ("mblk2assoc: b_cont 0x%p count %d (sz %d)\n",
		    mp->b_cont, iobp->ioc_count, sizeof (*assoc32)));

		if (iobp->ioc_count < sizeof (ttymux_assoc32_t))
			return (EINVAL);

		assoc32 = (ttymux_assoc32_t *)mp->b_cont->b_rptr;
		assoc->ttymux_udev = expldev(assoc32->ttymux32_udev);
		assoc->ttymux_ldev = expldev(assoc32->ttymux32_ldev);
		assoc->ttymux_linkid = assoc32->ttymux32_linkid;
		assoc->ttymux_tag = assoc32->ttymux32_tag;
		assoc->ttymux_ioflag = assoc32->ttymux32_ioflag;
		(void) strncpy(assoc->ttymux_path, assoc32->ttymux32_path,
				MAXPATHLEN);

	} else
#endif
	if (iobp->ioc_count < sizeof (*assoc)) {
		return (EINVAL);
	} else {
		*assoc = *(ttymux_assoc_t *)mp->b_cont->b_rptr;
	}
	sm_dbg('M', ("mblk2assoc (%d): dev %d:%d not found\n",
	    assoc->ttymux_linkid, getmajor(assoc->ttymux_ldev),
			getminor(assoc->ttymux_ldev)));
	return (0);
}

/*
 * Given a device path return an OBP alias for it if it exists.
 */
static char *
val2alias(pnode_t node, char *path)
{
	char *buf1;
	char *buf2;
	char *propname, *propval;
	int proplen;

	if (node == OBP_BADNODE)
		return (NULL);

	sm_dbg('A', ("Looking for an alias for: %s (len %d)\n",
	    path, strlen(path)));

	/*
	 * Ask for first property by passing a NULL string
	 */
	buf1 = kmem_alloc(OBP_MAXPROPNAME, KM_SLEEP);
	buf2 = kmem_zalloc(OBP_MAXPROPNAME, KM_SLEEP);
	buf1[0] = '\0';

	while (propname = (char *)prom_nextprop(node, buf1, buf2)) {
		if (strlen(propname) == 0)
			break;	  /* end of prop list */

		(void) strcpy(buf1, propname);

		proplen = prom_getproplen(node, propname);
		if (proplen == 0)
			continue;
		propval = kmem_zalloc(proplen + 1, KM_SLEEP);
		(void) prom_getprop(node, propname, propval);

		if (strcmp(propval, path) == 0) {
			kmem_free(propval, proplen + 1);
			kmem_free(buf1, OBP_MAXPROPNAME);
			sm_dbg('A', ("Alias is : %s\n", buf2));
			return (buf2);
		}

		kmem_free(propval, proplen + 1);
		bzero(buf2, OBP_MAXPROPNAME);
	}

	kmem_free(buf1, OBP_MAXPROPNAME);
	kmem_free(buf2, OBP_MAXPROPNAME);

	return (NULL);
}

/*
 * Tell OBP that this device is now usable
 */
static void
enable_device(sm_mux_state_t *ms, sm_console_t *cn)
{
	char *enb_str = "\" enable-device\" rot $call-method";

	if (!cn->sm_obp_con)
		return;

	sm_dbg('A', ("ttymux: enabling %d:%d\n",
		getmajor(cn->sm_dev), getminor(cn->sm_dev)));

	if (cn->sm_i_ihdl != 0)
		prom_interpret(enb_str, (caddr32_t)ms->sm_cons_stdin.sm_i_ihdl,
			(caddr32_t)cn->sm_i_ihdl, 0, 0, 0);

	if (cn->sm_o_ihdl != 0 && cn->sm_o_ihdl != cn->sm_i_ihdl)
		prom_interpret(enb_str, (caddr32_t)ms->sm_cons_stdout.sm_o_ihdl,
			(caddr32_t)cn->sm_o_ihdl, 0, 0, 0);
}

/*
 * Tell OBP that this device is no longer usable
 */
static void
disable_device(sm_mux_state_t *ms, sm_console_t *cn)
{
	char *dis_str = "\" disable-device\" rot $call-method";

	if (!cn->sm_obp_con)
		return;

	sm_dbg('A', ("ttymux: disabling %d:%d\n",
		getmajor(cn->sm_dev), getminor(cn->sm_dev)));

	if (cn->sm_i_ihdl != 0)
		prom_interpret(dis_str, (caddr32_t)ms->sm_cons_stdin.sm_i_ihdl,
			(caddr32_t)cn->sm_i_ihdl, 0, 0, 0);
	if (cn->sm_o_ihdl != 0 && cn->sm_o_ihdl != cn->sm_i_ihdl)
		prom_interpret(dis_str, (caddr32_t)ms->sm_cons_stdout.sm_o_ihdl,
			(caddr32_t)cn->sm_o_ihdl, 0, 0, 0);
}

static void
device_init_impl(sm_mux_state_t *ms, sm_console_t *cn, sm_lqi_t *plqi)
{
	uint_t		flags = 0;
	dev_info_t	*ldip;

	sm_dbg('I', ("device_init_impl:\n"));

	if (plqi == NULL || cn == NULL)
		return;

	flags = (uint_t)cn->sm_mode;
	sm_dbg('I', ("device_init_impl: flgs %d con %d\n", flags,
			cn->sm_obp_con));
	if (ldip = e_ddi_hold_devi_by_dev(cn->sm_dev, 0)) {

		/*
		 * Indicate to the linked device that it is
		 * providing a multiplexed console.
		 */
		if (flags & (uint_t)FORINPUT)
			(void) e_ddi_prop_create(cn->sm_dev, ldip,
			    DDI_PROP_CANSLEEP, "obp-input-console", 0, 0);
		if (flags & (uint_t)FOROUTPUT)
			(void) e_ddi_prop_create(cn->sm_dev, ldip,
			    DDI_PROP_CANSLEEP, "obp-output-console", 0, 0);

		ddi_release_devi(ldip);
	}

	if (flags) {
		plqi->sm_ioflag = flags;
		if (cn->sm_obp_con)
			plqi->sm_uqflags |= SM_OBPCNDEV;
		plqi->sm_ctrla_abort_on = sm_ssp->sm_ctrla_abort_on;
		plqi->sm_break_abort_on = sm_ssp->sm_break_abort_on;
	}

	/*
	 * Tell OBP that its ok to use this console
	 */
	enable_device(ms, cn);
}

static void
device_fini_impl(sm_mux_state_t *ms, sm_console_t *cn, sm_lqi_t *plqi)
{
	dev_info_t	*ldip;

	if (plqi == NULL || cn == NULL)
		return;
	/*
	 * Indicate to the linked device that it is no longer
	 * providing a multiplexed console.
	 */
	if (ldip = e_ddi_hold_devi_by_dev(plqi->sm_dev, 0)) {
		if (plqi->sm_ioflag & (uint_t)FORINPUT)
			(void) e_ddi_prop_remove(plqi->sm_dev,
			    ldip, "obp-input-console");
		if (plqi->sm_ioflag & (uint_t)FOROUTPUT)
			(void) e_ddi_prop_remove(plqi->sm_dev,
			    ldip, "obp-output-console");

		ddi_release_devi(ldip);
	}
	plqi->sm_ioflag = 0;
	plqi->sm_uqflags &= ~SM_OBPCNDEV;
	disable_device(ms, cn);
}

static int
read_prop(pnode_t node, char *propname, char **propval)
{
	int	proplen = prom_getproplen(node, propname);

	if (proplen < 0)
		return (proplen);
	*propval = kmem_zalloc(proplen + 1, KM_SLEEP);
	if (proplen > 0)
		(void) prom_getprop(node, propname, *propval);
	else
		*propval = 0;

	return (proplen);
}

/*
 * Parse a list of tokens
 */
static char *
sm_strtok_r(char *p, char *sep, char **lasts)
{
	char    *e, *tok = NULL;

	if (p == 0 || *p == 0)
		return (NULL);

	e = p + strlen(p);

	do {
		if (strchr(sep, *p) != NULL) {
			if (tok != NULL) {
				*p = 0;
				*lasts = p + 1;
				return (tok);
			}
		} else if (tok == NULL) {
			tok = p;
		}
	} while (++p < e);

	*lasts = NULL;
	if (tok != NULL)
		return (tok);
	return (NULL);
}

/*
 * Add or remove an alias from a property list of aliases:
 * path:	an OBP device path
 * pname:	property name containing a space separated list of aliases
 * append:	if true include the alias for path in the property list
 *		otherwise remove the alias from the list.
 */
static int
upd_config(boolean_t append, char *pname, char *path)
{
	pnode_t		onode, anode;
	size_t		plen;		/* length of property name */
	char		*pval;		/* value of property */
	char		*tok, *lasts;
	char		*aliases[TTYMUX_MAX_LINKS];
	size_t		i, cnt, len;
	boolean_t	found;
	char		*nval, *alias = NULL;

	if ((anode = prom_alias_node()) == OBP_BADNODE ||
	    (onode = prom_optionsnode()) == OBP_BADNODE) {
		sm_dbg('I', ("upd_config: no alias or options node.\n"));
		return (1);
	}

	if ((plen = read_prop(onode, pname, &pval)) < 0)
		return (1);

	sm_dbg('I', ("upd_config: %s=%s (%s)\n", pname, pval, path));
	found = B_FALSE;
	for (len = 0, cnt = 0, tok = sm_strtok_r(pval, " \t", &lasts);
	    tok != NULL && cnt < TTYMUX_MAX_LINKS;
	    tok = sm_strtok_r(lasts, " \t", &lasts)) {
		char	*aval;
		size_t	alen;

		if ((alen = read_prop(anode, tok, &aval)) < 0)
			continue;

		/* does this alias match the requested path */
		if (strcmp(aval, path) == 0 ||
		    (strstr(path, aval) != NULL &&
		    strchr(aval, ':') == NULL && strchr(path, ':') != NULL &&
		    strcmp(strchr(path, ':'), ":a") == 0)) {
			if (!found && append) {
				kmem_free(aval, alen + 1);
				goto out;
			}
			found = B_TRUE;
		} else {
			aliases[cnt++] = tok;
			len += strlen(tok) + 1;
		}
		kmem_free(aval, alen + 1);
	}

	sm_dbg('I', ("%d aliases\n", cnt));
	if (append) {
		if (cnt + 1 == TTYMUX_MAX_LINKS)
			goto out;

		if ((alias = val2alias(anode, path)) == NULL) {
			char *mnode = strstr(path, ":a");

			if (mnode != 0) {
				*mnode = '\0';
				alias = val2alias(anode, path);
				*mnode = ':';
			}
		}
		if (alias == NULL) {
			sm_dbg('I', ("No alias for %s\n", path));
			goto out;
		}
		aliases[cnt++] = alias;
		len += strlen(alias) + 1;
	} else if (!found) {
		goto out;
	}

	sm_dbg('I', ("%d aliases (len %d)\n", cnt, len));
	if (len == 0)
		goto out;
	ASSERT(len > 1 && cnt > 0);

	nval = kmem_zalloc(len, KM_SLEEP);
	for (i = 0; ; ) {
		ASSERT(strlen(nval) + strlen(aliases[i]) + 1 <= len);
		sm_dbg('I', ("alias %s\n", aliases[i]));
		(void) strcat(nval, aliases[i]);
		if (++i == cnt)
			break;
		(void) strcat(nval, " ");
	}

	sm_dbg('I', ("setprop: %s=%s (%d)\n", pname, nval, len));

	(void) prom_setprop(onode, pname, nval, len);

	kmem_free(nval, len);

	if (alias != NULL)
		kmem_free(alias, OBP_MAXPROPNAME);
out:
	sm_dbg('I', ("upd_config: returning.\n"));
	kmem_free(pval, plen + 1);
	return (0);
}

/*
 *
 */
static int
update_config(sm_mux_state_t *ms, char *path, io_mode_t mode, int cmd)
{
	sm_dbg('I', ("update_config: path %s io %d\n", path ? path : "", mode));
	if (path == 0 || *path == 0) {
		sm_dbg('I', ("update_config: EINVAL - no path\n"));
		return (1);
	}
	if (prom_is_openprom() == 0)
		return (0);

	if ((mode & FORINPUT) && ms->sm_ialias != NULL)
		(void) upd_config((cmd == TTYMUX_ASSOC), ms->sm_ialias, path);
	if ((mode & FOROUTPUT) && ms->sm_oalias != NULL)
		(void) upd_config((cmd == TTYMUX_ASSOC), ms->sm_oalias, path);
	return (0);
}

/*
 * Convert a dev_t to a device path
 */
static char *
sm_di_path(dev_t dev)
{
	char *p, *path;

	if (dev == NODEV)
		return (NULL);

	p = kmem_zalloc(MAXPATHLEN + 1, KM_SLEEP);
	if (ddi_dev_pathname(dev, S_IFCHR, p) == DDI_SUCCESS) {
		path = kmem_alloc(strlen(p) + 1, KM_SLEEP);
		(void) strcpy(path, p);
	}
	kmem_free(p, MAXPATHLEN + 1);

	return (path);
}

static int
console_cmd(int cmd, ttymux_assoc_t *assoc)
{
	sm_mux_state_t	*ms;
	sm_console_t	*cn;
	uint_t		j;

	sm_dbg('I', ("console_cmd ENTER: %s\n", cmd == TTYMUX_DISASSOC ?
		"TTYMUX_DISASSOC" : "TTYMUX_ASSOC"));

	if (assoc->ttymux_ldev == NODEV && *assoc->ttymux_path != '/') {
		sm_lqi_t *lqi = get_lqi_byid(assoc->ttymux_linkid);
		if (lqi == 0 || lqi->sm_dev == NODEV) {
			sm_dbg('I', ("console_cmd: no id link %d cmd %d\n",
			    assoc->ttymux_linkid, cmd));
			return (EINVAL);
		}
		assoc->ttymux_ldev = lqi->sm_dev;
	}

	sm_dbg('I', ("console_cmd: path %s\n", assoc->ttymux_path));

	if ((ms = (sm_mux_state_t *)space_fetch(TTYMUXPTR)) == 0) {
		sm_dbg('I', ("console_cmd: No muxstate\n"));
		return (0);
	}

	mutex_enter(&ms->sm_cons_mutex);

	for (cn = ms->sm_cons_links, j = 0;
	    j < ms->sm_cons_cnt; cn++, j++) {
		if (assoc->ttymux_ldev != NODEV && assoc->ttymux_ldev ==
				cn->sm_dev) {
			break;
		} else if (cn->sm_path != NULL &&
		    strncmp(cn->sm_path, assoc->ttymux_path, MAXPATHLEN) == 0) {
			break;
		}
	}

	assoc->ttymux_path[MAXPATHLEN - 1] = 0;
	if (cmd == TTYMUX_DISASSOC) {
		if (j == ms->sm_cons_cnt) {
			mutex_exit(&ms->sm_cons_mutex);
			return (0);
		}

		/*
		 * Disable the console in OBP and then delete this console
		 * this console - note that this also deletes OBP
		 * information - i.e. once it is disassociated it cannot
		 * be reused as an OBP console - roll on polled I/O!
		 */
		sm_dbg('I', ("console_cmd: cleaning up\n"));
		device_fini_impl(ms, cn, get_lqi_bydevt(assoc->ttymux_ldev));

		if (cn->sm_path == NULL) {
			if (assoc->ttymux_ldev != NODEV)
				cn->sm_path = sm_di_path(assoc->ttymux_ldev);
			else
				(void) update_config(ms, assoc->ttymux_path,
				    assoc->ttymux_ioflag, cmd);
		}
		if (cn->sm_path) {
			(void) update_config(ms, cn->sm_path, cn->sm_mode, cmd);
			kmem_free(cn->sm_path, strlen(cn->sm_path) + 1);
			cn->sm_path = NULL;
		}
		ms->sm_cons_cnt -= 1;
		if (ms->sm_cons_cnt > 0)
			*cn = ms->sm_cons_links[ms->sm_cons_cnt];

		sm_dbg('I', ("console_cmd: console %d removed (cnt %d)\n",
		    j, ms->sm_cons_cnt));

	} else if (cmd == TTYMUX_ASSOC) {

		if (j == ms->sm_cons_cnt) {

			if (j == TTYMUX_MAX_LINKS) {
				mutex_exit(&ms->sm_cons_mutex);
				return (ENOMEM);
			}

			ms->sm_cons_cnt += 1;

			bzero((caddr_t)cn, sizeof (*cn));
			cn->sm_dev = assoc->ttymux_ldev;
			cn->sm_muxid = assoc->ttymux_linkid;
			cn->sm_mode = assoc->ttymux_ioflag;
			device_init_impl(ms, cn,
				get_lqi_bydevt(assoc->ttymux_ldev));
		} else {
			cn->sm_dev = assoc->ttymux_ldev;
			cn->sm_muxid = assoc->ttymux_linkid;
			cn->sm_mode = assoc->ttymux_ioflag;
		}

		if (assoc->ttymux_ldev != NODEV) {
			cn->sm_path = sm_di_path(assoc->ttymux_ldev);
		} else {
			cn->sm_path = kmem_alloc(strlen(assoc->ttymux_path) + 1,
			    KM_SLEEP);
			(void) strcpy(cn->sm_path, assoc->ttymux_path);
		}
		if (cn->sm_path != NULL)
			(void) update_config(ms, cn->sm_path, cn->sm_mode, cmd);
		else
			sm_dbg('I', ("console_cmd: ASSOC No path info"));
	}
	mutex_exit(&ms->sm_cons_mutex);
	sm_dbg('I', ("console_cmd EXIT: %s\n", cmd == TTYMUX_DISASSOC ?
		"TTYMUX_DISASSOC" : "TTYMUX_ASSOC"));
	return (0);
}

static int
get_unconfigured_consoles(sm_mux_state_t *ms, ttymux_assoc_t *a)
{
	sm_console_t	*cn;
	int		j, cnt;

	if (ms == 0)
		return (0);

	mutex_enter(&ms->sm_cons_mutex);
	for (cn = ms->sm_cons_links, cnt = j = 0; j < ms->sm_cons_cnt;
							cn++, j++) {
		if (cn->sm_path && get_lqi_bydevt(cn->sm_dev) == NULL) {
			a->ttymux_linkid = cn->sm_muxid;
			a->ttymux_tag = (uint_t)0;
			a->ttymux_ioflag = cn->sm_mode;
			a->ttymux_udev = cn->sm_mode & FORINPUT ?
						ms->sm_cons_stdin.sm_dev :
						ms->sm_cons_stdout.sm_dev;
			a->ttymux_ldev = NODEV;
			(void) strncpy(a->ttymux_path, cn->sm_path, MAXPATHLEN);
			cnt++;
			a++;
		}
	}
	mutex_exit(&ms->sm_cons_mutex);
	return (cnt);
}

#ifdef _SYSCALL32_IMPL
/*
 * Look for any consoles that are not currently plumbed under the multiplexer.
 */
static int
get_unconfigured_consoles32(sm_mux_state_t *ms, ttymux_assoc32_t *a)
{
	sm_console_t	*cn;
	int		j, cnt;

	if (ms == 0)
		return (0);

	mutex_enter(&ms->sm_cons_mutex);
	for (cn = ms->sm_cons_links, cnt = j = 0; j < ms->sm_cons_cnt;
							cn++, j++) {
		sm_dbg('I', ("get_unconfigured_consoles: check %s (%d:%d)",
		    cn->sm_path ? cn->sm_path : "NULL",
		    getmajor(cn->sm_dev), getminor(cn->sm_dev)));
		if (cn->sm_path && get_lqi_bydevt(cn->sm_dev) == NULL) {
			a->ttymux32_linkid = 0;
			a->ttymux32_tag = (uint32_t)0;
			a->ttymux32_ioflag = (uint32_t)cn->sm_mode;
			a->ttymux32_ldev = NODEV32;
			(void) cmpldev(&a->ttymux32_udev, cn->sm_mode &
					FORINPUT ? ms->sm_cons_stdin.sm_dev :
					ms->sm_cons_stdout.sm_dev);

			(void) strncpy(a->ttymux32_path, cn->sm_path,
					MAXPATHLEN);
			cnt++;
			a++;
		}
	}
	mutex_exit(&ms->sm_cons_mutex);
	return (cnt);
}
#endif

static int
count_unconfigured_consoles(sm_mux_state_t *ms)
{
	sm_console_t	*cn;
	int		j, cnt;

	if (ms == 0)
		return (0);

	mutex_enter(&ms->sm_cons_mutex);
	for (cn = ms->sm_cons_links, cnt = j = 0; j < ms->sm_cons_cnt;
							cn++, j++) {
		sm_dbg('I', ("cnt_unconfigured_consoles: check %s (%d:%d)",
		    cn->sm_path ? cn->sm_path : "NULL",
		    getmajor(cn->sm_dev), getminor(cn->sm_dev)));
		if (cn->sm_path && get_lqi_bydevt(cn->sm_dev) == NULL)
			cnt++;
	}
	mutex_exit(&ms->sm_cons_mutex);
	return (cnt);
}

/*
 * Exported interfaces
 */

/*
 * A console device is no longer associated.
 */
int
ttymux_device_fini(sm_lqi_t *plqi)
{
	int		j;
	sm_mux_state_t	*ms;

	ms = (sm_mux_state_t *)space_fetch(TTYMUXPTR);

	if (plqi == NULL || ms == NULL)
		return (0);

	mutex_enter(&ms->sm_cons_mutex);

	for (j = 0; j < ms->sm_cons_cnt; j++) {

		if (ms->sm_cons_links[j].sm_dev == plqi->sm_dev) {

			device_fini_impl(ms, &ms->sm_cons_links[j], plqi);

			mutex_exit(&ms->sm_cons_mutex);
			return (0);
		}
	}
	mutex_exit(&ms->sm_cons_mutex);

	return (1);
}

/*
 * A console device is being introduced.
 */
int
ttymux_device_init(sm_lqi_t *plqi)
{
	int j;
	sm_mux_state_t *ms;

	ms = (sm_mux_state_t *)space_fetch(TTYMUXPTR);

	if (ms == NULL)
		return (0);

	mutex_enter(&ms->sm_cons_mutex);

	for (j = 0; j < ms->sm_cons_cnt; j++) {

		if (ms->sm_cons_links[j].sm_dev == plqi->sm_dev) {

			device_init_impl(ms, &ms->sm_cons_links[j], plqi);

			mutex_exit(&ms->sm_cons_mutex);
			return (0);
		}
	}
	mutex_exit(&ms->sm_cons_mutex);
	return (1);
}

/*
 * Process a TTYMUX_ASSOCIATE or TTYMUX_DISASSOCIATE ioctl.
 */
static int
ttymux_link_ioctl(mblk_t *mp)
{
	ttymux_assoc_t	assoc;
	int		err;
	sm_lqi_t		*lqi;
	struct iocblk	*iobp = (struct iocblk *)mp->b_rptr;
	dev_t		cidev, codev;

	sm_dbg('I', ("ttymux_link_ioctl:\n"));
	if ((err = mblk2assoc(mp, &assoc)) != 0)
		return (err);

	sm_dbg('I', ("uminor is %d\n", getminor(assoc.ttymux_udev)));

	if (assoc.ttymux_udev == NODEV)
		return (EINVAL);

	err = 0;

	if ((lqi = get_lqi_bydevt(assoc.ttymux_ldev)) == NULL) {
		if (assoc.ttymux_linkid < 0)
			err = EINVAL;
		else if ((lqi = get_lqi_byid(assoc.ttymux_linkid)) == 0)
			err = ENOLINK;
	}

	if (sm_ssp->sm_ms) {
		mutex_enter(&sm_ssp->sm_ms->sm_cons_mutex);
		cidev = sm_ssp->sm_ms->sm_cons_stdin.sm_dev;
		codev = sm_ssp->sm_ms->sm_cons_stdout.sm_dev;
		mutex_exit(&sm_ssp->sm_ms->sm_cons_mutex);
	} else {
		cidev = codev = NODEV;
	}

	if (err != 0) {
		if (assoc.ttymux_udev != cidev && assoc.ttymux_udev != codev)
			return (err);
		(void) console_cmd(iobp->ioc_cmd, &assoc);
		return (0);
	} else if (assoc.ttymux_udev == cidev || assoc.ttymux_udev == codev) {
		(void) console_cmd(iobp->ioc_cmd, &assoc);
	}

	if (iobp->ioc_cmd == TTYMUX_ASSOC)
		return (sm_associate(sm_dev2unit(assoc.ttymux_udev),
		    lqi, assoc.ttymux_tag, assoc.ttymux_ioflag,
			assoc.ttymux_path));
	else if (iobp->ioc_cmd == TTYMUX_DISASSOC)
		return (sm_disassociate(sm_dev2unit(assoc.ttymux_udev),
		    lqi, assoc.ttymux_tag));

	return (0);
}

/*
 * Process a TTYMUX_GETLINK ioctl.
 */
int
ttymux_query_link_ioctl(mblk_t *mp)
{
	sm_lqi_t		*lqi;

	struct iocblk *iobp = (struct iocblk *)mp->b_rptr;

	sm_dbg('I', ("ttymux_query_link_ioctl:\n"));

	if (mp->b_cont == NULL)
		return (EINVAL);

#ifdef _SYSCALL32_IMPL
	if ((iobp->ioc_flag & IOC_MODELS) != IOC_NATIVE) {
		ttymux_assoc32_t	*assoc32;
		ttymux_assoc_t	assoc;

		if (mblk2assoc(mp, &assoc) != 0)
			return (EINVAL);

		if ((lqi = get_lqi_bydevt(assoc.ttymux_ldev)) == NULL &&
		    (lqi = get_lqi_byid(assoc.ttymux_linkid)) == NULL) {
			sm_dbg('M', ("Query Link (%d): dev %d:%d not found\n",
			    assoc.ttymux_linkid,
			    getmajor(assoc.ttymux_ldev),
				getminor(assoc.ttymux_ldev)));
			return (ENOLINK);
		}
		assoc32 = (ttymux_assoc32_t *)mp->b_cont->b_rptr;
		LQI2ASSOC32(assoc32, lqi);
	} else
#endif
	{
		ttymux_assoc_t	*assoc;

		if (iobp->ioc_count < sizeof (ttymux_assoc_t))
			return (EINVAL);

		assoc = (ttymux_assoc_t *)mp->b_cont->b_rptr;
		if ((lqi = get_lqi_bydevt(assoc->ttymux_ldev)) == NULL &&
		    (lqi = get_lqi_byid(assoc->ttymux_linkid)) == NULL) {
			return (ENOLINK);
		}
		LQI2ASSOC(assoc, lqi);
	}
	return (0);
}

/*
 * Response to receiving an M_IOCDATA message for the TTYMUX_LIST ioctl.
 */
static int
sm_iocresp(mblk_t *mp)
{
	struct copyresp *csp = (struct copyresp *)mp->b_rptr;
	struct iocblk	*iobp = (struct iocblk *)mp->b_rptr;
	mblk_t		*pmp;

	sm_dbg('M', ("(M_IOCDATA: cmd %d)\n", csp->cp_cmd));

	if (csp->cp_cmd != TTYMUX_LIST) {
		sm_dbg('M', ("(M_IOCDATA: unknown cmd)\n"));
		DB_TYPE(mp) = M_IOCNAK;
		return (EINVAL);
	}
	if (csp->cp_rval) {
		if (csp->cp_private)
			freemsg((mblk_t *)csp->cp_private);

		sm_dbg('M', ("M_IOCDATA: result is %d\n", csp->cp_rval));
		DB_TYPE(mp) = M_IOCNAK;
		iobp->ioc_error = (int)(uintptr_t)csp->cp_rval;
		iobp->ioc_rval = 0;
		return (iobp->ioc_error);
	}

	pmp = (mblk_t *)csp->cp_private;

#ifdef _SYSCALL32_IMPL
	if ((csp->cp_flag & IOC_MODELS) != IOC_NATIVE) {
		iobp->ioc_count = sizeof (ttymux_assocs32_t);
		iobp->ioc_rval = pmp == NULL ? 0 :
		    ((ttymux_assocs32_t *)pmp->b_rptr)->ttymux32_nlinks;
	} else
#endif
	{
		iobp->ioc_count = sizeof (ttymux_assocs_t);
		iobp->ioc_rval = pmp == NULL ? 0 :
		    ((ttymux_assocs_t *)pmp->b_rptr)->ttymux_nlinks;

	}

	DB_TYPE(mp) = (pmp) ? M_IOCACK : M_IOCNAK;
	mp->b_wptr = mp->b_rptr + sizeof (struct iocblk);

	if (mp->b_cont)
		freemsg(unlinkb(mp));
	if (pmp)
		linkb(mp, pmp);
	else
		iobp->ioc_count = 0;

	iobp->ioc_error = 0;

	sm_dbg('M', ("(M_IOCDATA: rval %d cnt %d private 0x%p)\n",
	    iobp->ioc_rval, iobp->ioc_count, pmp));
	return (0);
}

/*
 * Process a TTYMUX_LIST ioctl.
 */
int
ttymux_query_links_ioctl(mblk_t *mp)
{
	struct iocblk	*iobp = (struct iocblk *)mp->b_rptr;
	struct copyreq	*cqp;
	int		unit;
	sm_lqi_t		*lqi;
	mblk_t		*nmp;
	int		cnt;
	void		*asl;
	void		*uaddr;
	size_t		sz;

	if (DB_TYPE(mp) == M_IOCDATA) {
		return (sm_iocresp(mp));
	}
	/*
	 * Is this a query for the number of linked devices?
	 */
	if (iobp->ioc_count == 0) {

		for (unit = 0, iobp->ioc_rval = 0;
		    unit < MAX_LQS && (lqi = get_lqi(sm_ssp, unit));
		    unit++)
			if (lqi->sm_linkid != 0)
				iobp->ioc_rval += 1;

		iobp->ioc_rval += count_unconfigured_consoles(sm_ssp->sm_ms);
		DB_TYPE(mp) = M_IOCACK;
		iobp->ioc_error = 0;

		return (0);
	}

	if (mp->b_cont == NULL) {
		sm_dbg('Y', ("TTYMUX_LIST: b_cont is NULL\n"));
		DB_TYPE(mp) = M_IOCNAK;
		iobp->ioc_error = EINVAL;
		return (EINVAL);
	}

	asl = mp->b_cont->b_rptr;

#ifdef _SYSCALL32_IMPL
	if ((iobp->ioc_flag & IOC_MODELS) != IOC_NATIVE) {
		cnt = ((ttymux_assocs32_t *)asl)->ttymux32_nlinks;
		sz = cnt * sizeof (ttymux_assoc32_t);
		uaddr = (void *)(uintptr_t)
		    ((ttymux_assocs32_t *)asl)->ttymux32_assocs;
	} else
#endif
	{
		cnt = ((ttymux_assocs_t *)asl)->ttymux_nlinks;
		sz = cnt * sizeof (ttymux_assoc_t);
		uaddr = (void *)((ttymux_assocs_t *)asl)->ttymux_assocs;
	}
	if ((nmp = sm_allocb(sz, BPRI_MED)) == NULL) {
		DB_TYPE(mp) = M_IOCNAK;
		iobp->ioc_error = EINVAL;
		return (EAGAIN);
	}

	sm_dbg('Y', ("TTYMUX_LIST: cnt %d sz %d uaddr 0x%p\n", cnt, sz, uaddr));

	iobp->ioc_rval = 0;

#ifdef _SYSCALL32_IMPL
	if ((iobp->ioc_flag & IOC_MODELS) != IOC_NATIVE) {
		ttymux_assoc32_t	*assoc;

		sm_dbg('Y', ("!Native: %d structures\n", cnt));
		assoc = (ttymux_assoc32_t *)nmp->b_rptr;

		for (unit = 0;
		    unit < MAX_LQS && (lqi = get_lqi(sm_ssp, unit));
		    unit++) {
			if (lqi->sm_linkid != 0) {
				if (cnt-- == 0)
					break;
				LQI2ASSOC32(assoc, lqi);
				assoc++;
				iobp->ioc_rval += 1;
			}
		}
		if (cnt > 0) {
			/* see if there are unconfigured consoles */
			iobp->ioc_rval +=
			    get_unconfigured_consoles32(sm_ssp->sm_ms, assoc);
			sm_dbg('I', ("%d unconfigured consoles\n",
			    iobp->ioc_rval));
		} else {
			sm_dbg('I', ("no more space in user addr\n"));
		}
		((ttymux_assocs32_t *)asl)->ttymux32_nlinks = iobp->ioc_rval;
	} else
#endif
	{
		ttymux_assoc_t	*assoc;

		sm_dbg('Y', ("!Native: %d structures\n", cnt));
		assoc = (ttymux_assoc_t *)nmp->b_wptr;

		for (unit = 0;
		    unit < MAX_LQS && (lqi = get_lqi(sm_ssp, unit));
		    unit++) {
			if (lqi->sm_linkid != 0) {
				if (cnt-- == 0)
					break;
				LQI2ASSOC(assoc, lqi);
				assoc++;
				iobp->ioc_rval += 1;
			}
		}
		if (cnt > 0) {
			/* see if there are unconfigured consoles */
			iobp->ioc_rval +=
			    get_unconfigured_consoles(sm_ssp->sm_ms, assoc);
			sm_dbg('I', ("%d unconfigured consoles\n",
			    iobp->ioc_rval));
		} else {
			sm_dbg('I', ("no more space in user addr\n"));
		}
		((ttymux_assocs_t *)asl)->ttymux_nlinks = iobp->ioc_rval;
	}

	cqp = (struct copyreq *)mp->b_rptr;
	cqp->cq_addr = uaddr;
	cqp->cq_size = sz;
	cqp->cq_flag = 0;
	cqp->cq_private = mp->b_cont;
	mp->b_cont = nmp;
	nmp->b_wptr = nmp->b_rptr + sz;

	DB_TYPE(mp) = M_COPYOUT;
	mp->b_wptr = mp->b_rptr + sizeof (struct copyreq);

	return (0);
}

/*
 * Process a TTYMUX_CONSDEV ioctl.
 */
static int
ttymux_console_ioctl(mblk_t *mp)
{
	struct iocblk *iobp = (struct iocblk *)mp->b_rptr;
	int	err = EINVAL;

	sm_dbg('I', ("ttymux_console_ioctl:\n"));
#ifdef _SYSCALL32_IMPL
	if ((iobp->ioc_flag & IOC_MODELS) != IOC_NATIVE) {
		if (mp->b_cont && iobp->ioc_count >= sizeof (dev32_t)) {
			dev32_t dev;

			(void) cmpldev(&dev, rconsdev);

			*(dev32_t *)mp->b_cont->b_rptr = dev;
			mp->b_cont->b_wptr = mp->b_cont->b_rptr + sizeof (dev);
			iobp->ioc_count = sizeof (dev);
			err = 0;
		} else {
			sm_dbg('I', ("TTYMUX_CONSDEV: b_cont 0x%p count %d\n",
			    mp->b_cont, iobp->ioc_count));
		}
	} else
#endif
	if (mp->b_cont && iobp->ioc_count >= sizeof (dev_t)) {
		*(dev_t *)mp->b_cont->b_rptr = rconsdev;
		mp->b_cont->b_wptr = mp->b_cont->b_rptr + sizeof (rconsdev);
		iobp->ioc_count = sizeof (rconsdev);
		err = 0;
	}
	return (err);
}

/*
 * Process a ioctl relating to aborting on the console.
 */
int
ttymux_abort_ioctl(mblk_t *mp)
{
	struct iocblk	*iobp;
	int		cmd, err = 0;
	sm_lqi_t		*lqi;
	ttymux_abort_t	*abreq;
#ifdef _SYSCALL32_IMPL
	struct ttymux_abort32 {
		dev32_t			ldev;
		enum ttymux_break_type  method;
		uint32_t		enable;
	} *abreq32;
#endif
	dev_t			ldev;
	enum ttymux_break_type  method;
	uint_t			enable;

	iobp = (struct iocblk *)mp->b_rptr;
	cmd = iobp->ioc_cmd;

	iobp->ioc_error = 0;
	iobp->ioc_rval = 0;
	sm_dbg('I', ("ttymux_abort_ioctl:\n"));
	switch (cmd) {
	case CONSSETABORTENABLE:
		lqi = (sm_ssp->sm_lconsole) ? sm_ssp->sm_lconsole->sm_lqs : 0;
		enable = (*(intptr_t *)mp->b_cont->b_rptr) ? 1 : 0;
		sm_ssp->sm_ctrla_abort_on = sm_ssp->sm_break_abort_on = enable;
		for (; lqi != 0; lqi = lqi->sm_nlqi) {
			lqi->sm_ctrla_abort_on = enable;
			lqi->sm_break_abort_on = enable;
		}
		break;
	case CONSGETABORTENABLE:
		if (mp->b_cont == 0 || iobp->ioc_count < sizeof (intptr_t)) {
			iobp->ioc_error = EINVAL;
			iobp->ioc_rval = -1;
		} else {
			*(intptr_t *)mp->b_cont->b_rptr =
			    (sm_ssp->sm_ctrla_abort_on ||
			    sm_ssp->sm_break_abort_on);
			mp->b_cont->b_wptr =
				mp->b_cont->b_rptr + sizeof (intptr_t);
			iobp->ioc_count = sizeof (intptr_t);
		}
		break;
	case TTYMUX_GETABORTSTR:

		if (iobp->ioc_count < strlen(sm_ssp->sm_abs) + 1 ||
		    mp->b_cont == 0 ||
		    mp->b_cont->b_cont) {
			iobp->ioc_error = EINVAL;
			iobp->ioc_rval = -1;
		} else {
			(void) strcpy((char *)mp->b_cont->b_rptr,
					sm_ssp->sm_abs);
			iobp->ioc_count = strlen(sm_ssp->sm_abs) + 1;
			mp->b_cont->b_wptr =
				mp->b_cont->b_rptr + iobp->ioc_count;
		}
		break;
	case TTYMUX_GETABORT:
	case TTYMUX_SETABORT:

		lqi = 0;
#ifdef _SYSCALL32_IMPL
		if ((iobp->ioc_flag & IOC_MODELS) != IOC_NATIVE) {
			if (iobp->ioc_count < sizeof (*abreq32) ||
			    mp->b_cont == 0) {
				err = EINVAL;
			} else {
				abreq32 = (struct ttymux_abort32 *)
				    mp->b_cont->b_rptr;
				ldev = expldev(abreq32->ldev);
				method = abreq32->method;
				enable = (uint_t)abreq32->enable;
				iobp->ioc_count = sizeof (*abreq32);
			}
		} else
#endif
		if (iobp->ioc_count < sizeof (*abreq) ||
		    mp->b_cont == 0) {
			err = EINVAL;
		} else {
			abreq = (ttymux_abort_t *)mp->b_cont->b_rptr;
			ldev = abreq->ttymux_ldev;
			method = abreq->ttymux_method;
			enable = abreq->ttymux_enable;
			iobp->ioc_count = sizeof (*abreq);
		}

		if (err != 0) {
			iobp->ioc_rval = -1;
			return ((iobp->ioc_error = err));
		}

		sm_dbg('Y', ("ttymux_abort_ioctl: type %d how %d ldev %d:%d\n",
		    method, enable, getmajor(ldev), getminor(ldev)));

		lqi = get_lqi_bydevt(ldev);
		if (ldev != NODEV && lqi == 0) {
			err = ENOLINK;
		} else if (cmd == TTYMUX_GETABORT && lqi == 0) {
			err = ENODEV;
		} else if (cmd == TTYMUX_GETABORT) {
			if (lqi->sm_break_abort_on == 0 &&
			    lqi->sm_ctrla_abort_on == 0) {
				method = SOFTHARD_BREAK;
				enable = 0;
			} else {
				enable = 1;
				if (lqi->sm_break_abort_on == 0)
					method = SOFTWARE_BREAK;
				else if (lqi->sm_ctrla_abort_on == 0)
					method = HARDWARE_BREAK;
				else
					method = SOFTHARD_BREAK;
			}

#ifdef _SYSCALL32_IMPL
			if ((iobp->ioc_flag & IOC_MODELS) != IOC_NATIVE) {
				abreq32->method = method;
				abreq32->enable = (uint32_t)enable;
			} else
#endif
			{
				abreq->ttymux_method = method;
				abreq->ttymux_enable = enable;
			}
		} else {
			iobp->ioc_count = 0;
			sm_dbg('I', ("lqi is 0x%p\n", lqi));
			if (lqi == 0) {
				if (method == HARDWARE_BREAK)
					sm_ssp->sm_break_abort_on = enable;
				else if (method == SOFTWARE_BREAK)
					sm_ssp->sm_ctrla_abort_on = enable;
				else if (method == SOFTHARD_BREAK) {
					sm_ssp->sm_break_abort_on = enable;
					sm_ssp->sm_ctrla_abort_on = enable;
				} else {
					sm_dbg('I', ("%d - invalid\n", method));
					iobp->ioc_rval = -1;
					return ((iobp->ioc_error = EINVAL));
				}

				if (sm_ssp->sm_lconsole) {
					sm_dbg('I', ("lconsole 0x%p (0x%p)\n",
					    sm_ssp->sm_lconsole,
					    sm_ssp->sm_lconsole->sm_lqs));
				} else {
					sm_dbg('I', ("lconsole is null\n"));
				}

				lqi = (sm_ssp->sm_lconsole) ?
				    sm_ssp->sm_lconsole->sm_lqs : 0;
			}
			while (lqi) {
				if (method == HARDWARE_BREAK)
					lqi->sm_break_abort_on = enable;
				else if (method == SOFTWARE_BREAK)
					lqi->sm_ctrla_abort_on = enable;
				else if (method == SOFTHARD_BREAK) {
					lqi->sm_break_abort_on = enable;
					lqi->sm_ctrla_abort_on = enable;
				} else {
					sm_dbg('I', ("%d: invalid\n", method));
					iobp->ioc_rval = -1;
					return ((iobp->ioc_error = EINVAL));
				}

				lqi = (ldev == NODEV) ? lqi->sm_nlqi : 0;
			}
		}
		iobp->ioc_rval = err ? -1 : 0;
		iobp->ioc_error = err;
		break;
	default:
		iobp->ioc_rval = -1;
		iobp->ioc_error = EINVAL;
	}
	return (iobp->ioc_error);
}

/*
 * Process ioctls specific to the ttymux driver.
 */
/*ARGSUSED*/
int
sm_ioctl_cmd(sm_uqi_t *uqi, mblk_t *mp)
{
	struct iocblk *iobp = (struct iocblk *)mp->b_rptr;

	iobp->ioc_rval = 0;

	/*
	 * This routine does not support transparent ioctls
	 */
	if (iobp->ioc_count == TRANSPARENT) {
		sm_dbg('Y', ("sm_ioctl_cmd: unsupported ioctl\n"));
		iobp->ioc_error = ENOTSUP;
		DB_TYPE(mp) = M_IOCNAK;
		if (mp->b_cont)
			freemsg(unlinkb(mp));
		return (ENOTSUP);
	}

	switch (iobp->ioc_cmd) {
	case TTYMUX_CONSDEV:
		iobp->ioc_error = ttymux_console_ioctl(mp);
		break;
	case TTYMUX_ASSOC:
	case TTYMUX_DISASSOC:
		iobp->ioc_error = ttymux_link_ioctl(mp);
		break;
	case TTYMUX_GETLINK:
		iobp->ioc_error = ttymux_query_link_ioctl(mp);
		break;
	case TTYMUX_LIST:
		return (ttymux_query_links_ioctl(mp));
	case TTYMUX_SETCTL:
	case TTYMUX_GETCTL:
		iobp->ioc_error = ENOTSUP;
		break;
	case TTYMUX_GETABORTSTR:
	case TTYMUX_SETABORT:
	case TTYMUX_GETABORT:
		iobp->ioc_error = ttymux_abort_ioctl(mp);
		break;
	default:
		iobp->ioc_error = EINVAL;
		break;
	}

	DB_TYPE(mp) = iobp->ioc_error ? M_IOCNAK : M_IOCACK;

	if ((iobp->ioc_error || iobp->ioc_count == 0) && mp->b_cont)
	    freemsg(unlinkb(mp));

	sm_dbg('I', ("TTYMUX IOCTL: err %d rval %d count %d\n",
	    iobp->ioc_error, iobp->ioc_rval, iobp->ioc_count));

	return (iobp->ioc_error);
}
