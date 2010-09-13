/*
 * Routines and structures which are used from CMU's 2.2 bootp implementation
 * are labelled as such. Code not labelled is:
 *
 * Copyright 1997-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	Copyright 1988, 1991 by Carnegie Mellon University
 *
 *			All Rights Reserved
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted, provided
 * that the above copyright notice appear in all copies and that both that
 * copyright notice and this permission notice appear in supporting
 * documentation, and that the name of Carnegie Mellon University not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission.
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
 * SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.
 * IN NO EVENT SHALL CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
 * THIS SOFTWARE.
 */

/*
 * in.dhcpd configuration file reading code.
 *
 * The routines in this file deal with reading, interpreting, and storing
 * the information found in the in.dhcpd configuration file (usually
 * /etc/dhcptab).
 */

/*
 * TODO: What's missing: Symbol code is very generic, but doesn't allow
 * per symbol granularity checking - ie, using goodname() to check the
 * hostname, for example. Perhaps each symbol should have a verifier
 * function possibly associated with it (null is ok), which would return
 * B_TRUE if ok, B_FALSE if not, and print out a nasty message.
 *
 * Option overload. If set, then NO BOOTFILE or SNAME values can exist.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/byteorder.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <dhcp_inittab.h>
#include <dhcp_symbol.h>
#include "netinet/dhcp.h"
#include "hash.h"
#include "dhcpd.h"
#include <locale.h>

/*
 * Local constants
 */
#define	OP_ADDITION		  1	/* Operations on tags */
#define	OP_DELETION		  2
#define	OP_BOOLEAN		  3

#define	MAXENTRYLEN		3072	/* Max size of an entire entry */
#define	MAX_ITEMS		16	/* Max number of items in entry */
#define	MAX_MACRO_NESTING	20	/* Max number of nested includes */

#define	DB_DHCP_MAC		'm'	/* Like TBL_DHCP_{MACRO,SYMBOL} */
#define	DB_DHCP_SYM		's'	/* But not strings! */

static time_t	mtable_time;		/* load time of hash table */

static uint_t	nentries;		/* Total number of entries */
static int	include_nest;		/* macro nesting counter */
static dt_rec_list_t **newtbl;		/* reordered Tbl. */
static dt_rec_list_t **oldtbl;		/* The original tbl. */
static hash_tbl	*mtable;
static mutex_t	mtable_mtx;		/* Reinitialization mutex */
static cond_t	mtable_cv;		/* Reinitialization cv */
static int	mtable_refcnt;		/* Current reference count */
static int	mtable_closing;		/* macros are going away */

#define	INCLUDE_SYM	"Include"	/* symbol for macro include */

/*
 * Forward declarations.
 */
static dhcp_symbol_t *sym_list;
static size_t sym_num_items;
static int check_includes(int, char *);
static MACRO *process_entry(dt_rec_list_t *);
static int eval_symbol(char **, MACRO *);
static char *get_string(char **, char *, uchar_t *);
static void adjust(char **);
static void eat_whitespace(char **);
static int first_macro_row(dt_rec_list_t **);
static void get_sym_name(char *, char **);
static void print_error_msg(int, uchar_t);
static boolean_t define_symbol(char **, char *);
static int scan_include(char **, char *);
static boolean_t free_macro(MACRO *, boolean_t);
static int macro_cmp(MACRO *, MACRO *);
static void add_vndlist(ENCODE *, MACRO *, dhcp_symbol_t *);

/*
 * Initialize the hash table.
 */
int
initmtab(void)
{
	/*
	 * Allocate hash table
	 */
	mtable = hash_Init(0, NULL, 0, B_FALSE);

	assert(mtable != NULL);

	(void) mutex_init(&mtable_mtx, USYNC_THREAD, NULL);
	(void) cond_init(&mtable_cv, USYNC_THREAD, 0);

	return (0);
}

/*
 * Check presence/access to dhcptab database file.
 */
int
checktab(void)
{
	int		err;
	dsvc_handle_t	dh;

	err = open_dd(&dh, &datastore, DSVC_DHCPTAB, DT_DHCPTAB, DSVC_READ);
	switch (err) {
	case DSVC_SUCCESS:
		(void) close_dd(&dh);
		break;
	case DSVC_ACCESS:
		dhcpmsg(LOG_ERR,
		    "No permission to access dhcptab in %s (%s)\n",
		    datastore.d_resource, datastore.d_location);
		err = EACCES;
		break;
	case DSVC_NOENT:
	case DSVC_NO_TABLE:
		dhcpmsg(LOG_INFO,
		    "Dhcptab table does not exist in %s (%s)\n",
		    datastore.d_resource, datastore.d_location);
		err = ENOENT;
		break;
	default:
		dhcpmsg(LOG_ERR,
			"Error checking status of dhcptab in %s (%s)\n",
			datastore.d_resource, datastore.d_location);
	}
	return (err);
}

/*
 * Read dhcptab database file.
 */
int
readtab(int preserve)
{
	int		err = 0, first_mac;
	MACRO		*mc;
	uint32_t	query;
	dt_rec_t	dt;
	dt_rec_list_t	**dhcptab = NULL;
	dt_rec_list_t	*dhcptab_list = NULL;
	dt_rec_list_t	*dtep;
	int		i;
	int		ind;
	uint_t		records;
	timestruc_t	tm;
	dsvc_handle_t	dh;
	boolean_t	tab_open = B_FALSE;

	(void) mutex_lock(&mtable_mtx);

	/*
	 * Wait for any current thread(s) to complete using macros.
	 */
	mtable_closing = 1;
	while (mtable_refcnt > 0) {
		tm.tv_sec = 1;
		tm.tv_nsec = 0;
		(void) cond_reltimedwait(&mtable_cv, &mtable_mtx, &tm);
	}

	/* Get the *entire* dhcptab. */
	while ((err = open_dd(&dh, &datastore, DSVC_DHCPTAB, DT_DHCPTAB,
	    DSVC_READ)) != DSVC_SUCCESS) {
		if (err == DSVC_BUSY) {
			continue;
		}
		if (err == DSVC_NOENT) {
			dhcpmsg(LOG_INFO, "Empty dhcptab macro database.\n");
			err = 0;	/* not a "real" error */
		} else
			dhcpmsg(LOG_ERR, "Error opening macro database: %s\n",
				dhcpsvc_errmsg(err));
		goto leave_readtab;
	}

	tab_open = B_TRUE;

	DSVC_QINIT(query);
	(void) memset(&dt, 0, sizeof (dt_rec_t));

	dhcptab_list = NULL;
	nentries = 0;
	err = lookup_dd(dh, B_FALSE, query, -1, (const void *)&dt,
			(void **)&dhcptab_list, &nentries);
	if (err != DSVC_SUCCESS) {
		if (verbose && err == DSVC_NOENT) {
			dhcpmsg(LOG_INFO, "Error access macro database: %s\n",
				dhcpsvc_errmsg(err));
		}
		goto leave_readtab;
	} else
		err = 0;
	if (nentries == 0) {
		dhcpmsg(LOG_INFO, "Empty dhcptab macro database.\n");
		err = 0;	/* not a "real" error */
		goto leave_readtab;
	}

	/*
	 * Because libdhcpsvc doesn't guarantee any order, we need to
	 * preprocess the macro list to guarantee that macros which are
	 * included in other macro definitions are already defined prior
	 * to their use. This means that macro processing is a two step process.
	 */
	dhcptab = (dt_rec_list_t **)smalloc((nentries + 1) *
		sizeof (dt_rec_list_t *));

	/* Extract symbols first. */
	ind = 0;
	for (i = 0, dtep = dhcptab_list; dtep != NULL;
		i++, dtep = dtep->dtl_next) {
		if (dtep->dtl_rec->dt_type == DT_SYMBOL) {
			dhcptab[ind++] = dtep;
		}
	}
	/* Copy macros */
	for (i = 0, dtep = dhcptab_list; dtep != NULL;
		i++, dtep = dtep->dtl_next) {
		if (dtep->dtl_rec->dt_type == DT_MACRO) {
			dhcptab[ind++] = dtep;
		}
	}

	first_mac = first_macro_row(dhcptab);
	include_nest = 0;
	if (first_mac >= 0) {
		oldtbl = dhcptab;
		newtbl = (dt_rec_list_t **)smalloc((nentries + 1) *
			sizeof (dt_rec_list_t *));
		for (i = 0; i < first_mac; i++)
			newtbl[i] = oldtbl[i];	/* copy symdefs */
		for (i = first_mac; i < nentries; i++) {
			if ((err = check_includes(first_mac,
			    oldtbl[i]->dtl_rec->dt_key)) != 0)
				break;
		}
		if (err != 0) {
			free(newtbl);
			free(dhcptab);
			goto leave_readtab;
		} else {
			free(dhcptab);
			dhcptab = newtbl;
		}
	}

	resettab(B_FALSE);

	/*
	 * Now table is reordered. process as usual.
	 */
	records = 0;
	for (i = 0; i < nentries; i++) {

		if ((mc = process_entry(dhcptab[i])) == (MACRO *)NULL)
			continue;

		if (hash_Insert(mtable, mc->nm, strlen(mc->nm), macro_cmp,
		    mc->nm, mc) == NULL) {
			dhcpmsg(LOG_WARNING,
			    "Duplicate macro definition: %s\n", mc->nm);
			continue;
		}
		records++;
	}

	mtable_time = time(NULL);

	if (verbose) {
		dhcpmsg(LOG_INFO,
		    "Read %d entries from DHCP macro database on %s",
		    records, ctime(&mtable_time));
	}

	free(dhcptab);

leave_readtab:

	if (dhcptab_list != NULL)
		free_dd_list(dh, dhcptab_list);

	if (tab_open)
		(void) close_dd(&dh);

	if (preserve && err != 0) {
		dhcpmsg(LOG_WARNING,
		    "DHCP macro database rescan failed %d, using scan: %s",
		    err, ctime(&mtable_time));
		err = 0;
	}

	mtable_closing = 0;
	(void) mutex_unlock(&mtable_mtx);
	return (err);
}

/*
 *  Reset the dhcptab hash table, free any dynamic symbol definitions.
 */
void
resettab(boolean_t lck)
{
	int		i;
	dhcp_symbol_t	tmp;
	timestruc_t	tm;

	if (lck == B_TRUE)
		(void) mutex_lock(&mtable_mtx);

	/*
	 * Wait for any current thread(s) to complete using macros.
	 */
	if (mtable_closing == 0) {
		mtable_closing = 1;
		while (mtable_refcnt > 0) {
			tm.tv_sec = 1;
			tm.tv_nsec = 0;
			(void) cond_reltimedwait(&mtable_cv, &mtable_mtx, &tm);
		}
	}

	/* Entirely erase all hash tables. */
	hash_Reset(mtable, free_macro);

	/*
	 * Dump any dynamically defined symbol definitions, and reinitialize.
	 */
	if (sym_list != NULL) {

		/*
		 * Free class resources for each symbol.
		 */
		for (i = 0; i < sym_num_items; i++) {
			dsym_free_classes(&sym_list[i].ds_classes);
		}

		free(sym_list);
		sym_list = NULL;
	}

	if (time_to_go) {
		if (lck == B_TRUE) {
			(void) mutex_unlock(&mtable_mtx);
			(void) mutex_destroy(&mtable_mtx);
			(void) cond_destroy(&mtable_cv);
		}
		return;
	}

	/* Allocate the inittab and class tables */
	sym_list = inittab_load(ITAB_CAT_STANDARD|ITAB_CAT_FIELD|
			ITAB_CAT_INTERNAL|ITAB_CAT_VENDOR,
			ITAB_CONS_SERVER, &sym_num_items);
	/*
	 * Allocate the internal INCLUDE_SYM macro include symbol.
	 * Since this is not part of inittab, it must be added
	 * manually to the list.
	 */
	sym_list = (dhcp_symbol_t *)realloc(sym_list,
		(sym_num_items + 1) * sizeof (dhcp_symbol_t));

	if (sym_num_items == 0 || sym_list == NULL) {
		dhcpmsg(LOG_ERR, "Cannot allocate inittab, exiting\n");
		(void) exit(1);
	}

	(void) memset(&sym_list[sym_num_items], 0, sizeof (dhcp_symbol_t));
	(void) strcpy(sym_list[sym_num_items].ds_name, INCLUDE_SYM);
	sym_list[sym_num_items].ds_type = DSYM_INCLUDE;
	sym_list[sym_num_items].ds_max = 32;
	sym_num_items++;

	/* Verify the inittab entries */
	for (i = 0; i < sym_num_items; i++) {
		if (inittab_verify(&sym_list[i], &tmp) == ITAB_FAILURE) {
			print_error_msg(ITAB_SYNTAX_ERROR, i);
			(void) memcpy(&sym_list[i], &tmp,
				sizeof (dhcp_symbol_t));
		}
	}

	mtable_closing = 0;
	if (lck == B_TRUE)
		(void) mutex_unlock(&mtable_mtx);
}

/*
 * Given an value field pptr, return the first INCLUDE_SYM value found in
 * include, updating pptr along the way. Returns nonzero if no INCLUDE_SYM
 * symbol is found (pptr is still updated).
 */
static int
scan_include(char **cpp, char *include)
{
	char	t_sym[DSVC_MAX_MACSYM_LEN + 1];
	uchar_t	ilen;

	while (*cpp && **cpp != '\0') {
		eat_whitespace(cpp);
		get_sym_name(t_sym, cpp);
		if (strcmp(t_sym, INCLUDE_SYM) == 0) {
			ilen = DHCP_SCRATCH;
			if (**cpp == '=')
				(*cpp)++;
			(void) get_string(cpp, include, &ilen);
			include[ilen] = '\0';
			return (0);
		} else
			adjust(cpp);
	}
	return (1);
}

/*
 * Return the first macro row in dhcptab. Returns -1 if no macros exist.
 */
static int
first_macro_row(dt_rec_list_t **tblp)
{
	int i;

	for (i = 0; i < nentries; i++) {
		if (tolower(tblp[i]->dtl_rec->dt_type) == (int)DT_MACRO)
			return (i);
	}
	return (-1);
}

/*
 * RECURSIVE function: Scans for included macros, and reorders Tbl to
 * ensure macro definitions occur in the correct order.
 *
 * Returns 0 for success, nonzero otherwise.
 */
static int
check_includes(int first, char *mname)
{
	char	include[DHCP_SCRATCH + 1];
	int	m, err = 0;
	dt_rec_list_t *current_rowp = NULL;
	char	*cp;

	include_nest++;

	if (include_nest > MAX_MACRO_NESTING) {
		dhcpmsg(LOG_ERR,
		    "Circular macro definition using: %s\n", mname);
		err = -1;
		goto leave_check_include;
	}

	for (m = first; m < nentries; m++) {
		if (newtbl[m] != NULL &&
		    strcmp(newtbl[m]->dtl_rec->dt_key, mname) == 0) {
			err = 0; /* already processed */
			goto leave_check_include;
		}
	}

	/*
	 * is it defined someplace?
	 */
	for (m = first; m < nentries; m++) {
		if (strcmp(oldtbl[m]->dtl_rec->dt_key, mname) == 0) {
			current_rowp = oldtbl[m];
			break;
		}
	}

	if (current_rowp == NULL) {
		dhcpmsg(LOG_ERR, "Undefined macro: %s\n", mname);
		err = -1;
		goto leave_check_include;
	}

	/*
	 * Scan value field, looking for includes.
	 */
	cp = current_rowp->dtl_rec->dt_value;
	while (cp) {
		adjust(&cp);
		if (scan_include(&cp, include) != 0) {
			/* find a free entry */
			for (m = first; m < nentries; m++) {
				if (newtbl[m] == NULL)
					break;
			}
			if (m >= nentries) {
				dhcpmsg(LOG_ERR,
				    "Macro expansion (Include=%s) error!\n",
				    mname);
				err = -1;
			} else {
				newtbl[m] = current_rowp;
				err = 0;
			}
			break;
		}

		if (*include == '\0') {
			/*
			 * Null value for macro name. We can safely ignore
			 * this entry. An error message will be generated
			 * later during encode processing.
			 */
			continue;
		}

		if (strcmp(mname, include) == 0) {
			dhcpmsg(LOG_ERR,
			    "Circular macro definition using: %s\n", mname);
			err = -1;
			break;
		}

		/* Recurse. */
		if ((err = check_includes(first, include)) != 0)
			break;
	}

leave_check_include:
	include_nest--;
	return (err);
}

/*
 * open_macros: open reference to macro table.
 */
void
open_macros(void) {
	(void) mutex_lock(&mtable_mtx);
	mtable_refcnt++;
	(void) mutex_unlock(&mtable_mtx);
}

/*
 * close_macros: close reference to macro table.
 */
void
close_macros(void) {
	(void) mutex_lock(&mtable_mtx);
	mtable_refcnt--;
	(void) cond_signal(&mtable_cv);
	(void) mutex_unlock(&mtable_mtx);
}

/*
 * Given a macro name, look it up in the hash table.
 * Returns ptr to MACRO structure, NULL if error occurs.
 */
MACRO *
get_macro(char *mnamep)
{
	if (mnamep == (char *)NULL)
		return ((MACRO *)NULL);

	return ((MACRO *)hash_Lookup(mtable, mnamep, strlen(mnamep), macro_cmp,
	    mnamep, B_FALSE));
}

/*ARGSUSED*/
static boolean_t
free_macro(MACRO *mp, boolean_t force)
{
	int i;

	if (mp) {
		free_encode_list(mp->head);
		for (i = 0; i < mp->classes; i++) {
			if (mp->list[i]->head != NULL)
				free_encode_list(mp->list[i]->head);
			free(mp->list[i]);
		}
		free(mp->list);
		free(mp);
	}
	return (B_TRUE);
}

static int
macro_cmp(MACRO *m1, MACRO *m2)
{
	if (!m1 || !m2)
		return (B_FALSE);

	if (strcmp(m1->nm, m2->nm) == 0)
		return (B_TRUE);
	else
		return (B_FALSE);
}

/*
 * Parse out all the various tags and parameters in the row entry pointed
 * to by "src".
 *
 * Returns 0 for success, nozero otherwise.
 */
static MACRO *
process_entry(dt_rec_list_t *src)
{
	char *cp;
	MACRO *mc, *retval = NULL;

	assert(src != NULL);

	if (strlen(src->dtl_rec->dt_key) > DSVC_MAX_MACSYM_LEN) {
		dhcpmsg(LOG_ERR,
		    "Token: %s is too long. Limit: %d characters.\n",
		    src->dtl_rec->dt_key, DSVC_MAX_MACSYM_LEN);
		return (retval);
	}

	switch (tolower(src->dtl_rec->dt_type)) {
	case DT_SYMBOL:
		/* New Symbol definition */
		cp = src->dtl_rec->dt_value;
		if (!define_symbol(&cp, src->dtl_rec->dt_key))
			dhcpmsg(LOG_ERR,
			    "Bad Runtime symbol definition: %s\n",
			    src->dtl_rec->dt_key);
		/* Success. Treat new symbol like the predefines. */
		break;
	case DT_MACRO:
		/* Macro definition */

		mc = (MACRO *)smalloc(sizeof (MACRO));
		(void) strcpy(mc->nm, src->dtl_rec->dt_key);

		cp = src->dtl_rec->dt_value;
		adjust(&cp);
		while (*cp != '\0') {
			if (eval_symbol(&cp, mc) != 0) {
				dhcpmsg(LOG_ERR,
				    "Error processing macro: %s\n", mc->nm);
				(void) free_macro(mc, B_TRUE);
				return (NULL);
			}
			adjust(&cp);
			eat_whitespace(&cp);
		}
		retval = mc;
		break;
	default:
		dhcpmsg(LOG_ERR, "Unrecognized token: %s.\n",
			src->dtl_rec->dt_key);
		break;
	}
	return (retval);
}

/*
 * This function processes the parameter name pointed to by "symbol" and
 * updates the appropriate ENCODE structure in data if one already exists,
 * or allocates a new one for this parameter.
 */
static int
eval_symbol(char **symbol, MACRO *mc)
{
	int	index, optype, i, j, err = 0;
	dhcp_symbol_t	*sp;
	char		**clp;
	ENCODE	*tmp;
	VNDLIST	**mpp, **ipp;
	MACRO	*ic;
	char	*cp;
	uchar_t	ilen;
	uint16_t len;
	char	t_sym[DSVC_MAX_MACSYM_LEN + 1];
	char	include[DHCP_SCRATCH + 1];
	/*
	 * The following buffer must be aligned on a int64_t boundary.
	 */
	uint64_t scratch[(UCHAR_MAX + sizeof (int64_t) - 1) /
	    sizeof (int64_t)];

	if ((*symbol)[0] == ':')
		return (0);

	eat_whitespace(symbol);
	get_sym_name(t_sym, symbol);

	for (index = 0; index < sym_num_items; index++) {
		if (strcmp(t_sym, sym_list[index].ds_name) == 0)
			break;
	}
	if (index >= sym_num_items) {
		dhcpmsg(LOG_ERR, "Unrecognized symbol name: '%s'\n", t_sym);
		return (-1);
	} else {
		sp = &sym_list[index];
		clp = sp->ds_classes.dc_names;
	}
	/*
	 * Determine the type of operation to be done on this symbol
	 */
	switch (**symbol) {
	case '=':
		optype = OP_ADDITION;
		(*symbol)++;
		break;
	case '@':
		optype = OP_DELETION;
		(*symbol)++;
		break;
	case ':':
	case '\0':
		optype = OP_BOOLEAN;
		break;
	default:
		dhcpmsg(LOG_ERR, "Syntax error: symbol: '%s' in macro: %s\n",
		    t_sym, mc->nm);
		return (-1);
	}

	switch (optype) {
	case OP_ADDITION:
		switch (sp->ds_type) {
		case DSYM_BOOL:
			err = -1;
			break;

		case DSYM_INCLUDE:
			/*
			 * If symbol type is INCLUDE, then walk the encode
			 * list, replacing any previous encodes with those
			 * from the INCLUDed macro. Vendor options are also
			 * merged, if their class and vendor codes match.
			 */
			ilen = DHCP_SCRATCH;
			(void) get_string(symbol, include, &ilen);
			include[ilen] = '\0';
			ic = get_macro(include);
			if (ic == (MACRO *)NULL) {
				dhcpmsg(LOG_ERR, "WARNING: No macro: '%1$s' \
defined for 'Include' symbol in macro: %2$s\n",
				    include, mc->nm);
				adjust(symbol);
				return (0);
			}

			mc->head = combine_encodes(mc->head, ic->head,
			    ENC_DONT_COPY);

			if (ic->list == NULL && mc->list == NULL)
				break;

			/* Vendor options. */
			if (mc->list == NULL) {
				/*
				 * No combining necessary. Just duplicate
				 * ic's vendor options - all classes.
				 */
				mc->list = (VNDLIST **)smalloc(
				    sizeof (VNDLIST **) * ic->classes);
				for (i = 0;  i < ic->classes; i++) {
					mc->list[i] = (VNDLIST *)smalloc(
					    sizeof (VNDLIST));
					(void) strcpy(mc->list[i]->class,
					    ic->list[i]->class);
					mc->list[i]->head = dup_encode_list(
					    ic->list[i]->head);
				}
				mc->classes = ic->classes;
			} else {
				/* Class and vendor code must match. */
				for (i = 0, ipp = ic->list;
				    ipp && i < ic->classes; i++) {
					for (j = 0, mpp = mc->list;
					    j < mc->classes; j++) {
						if (strcmp(mpp[j]->class,
						    ipp[i]->class) == 0) {
							mpp[j]->head =
							    combine_encodes(
							    mpp[j]->head,
							    ipp[i]->head,
							    ENC_DONT_COPY);
							break;
						}
					}
				}
			}
			break;

		default:
			/*
			 * Get encode associated with symbol value.
			 */
			tmp = (ENCODE *)smalloc(sizeof (ENCODE));

			if (sp->ds_type == DSYM_ASCII) {
				if (sp->ds_max)
					ilen = sp->ds_max;
				else
					ilen = UCHAR_MAX;
				(void) get_string(symbol, (char *)scratch,
					&ilen);
				include[ilen] = '\0';

				tmp->data = inittab_encode_e(sp,
					(char *)scratch, &len, B_TRUE, &err);
			} else {

				if ((cp = strchr(*symbol, ':')) != NULL)
					*cp = '\0';

				tmp->data = inittab_encode_e(sp, *symbol, &len,
					B_TRUE, &err);
				/*
				 * Advance symbol pointer to next encode.
				 */
				if (cp != NULL) {
					*cp = ':';
					*symbol = cp;
				} else {
					while (*symbol != '\0')
						symbol++;
				}
			}

			tmp->len = len;
			tmp->category = sp->ds_category;
			tmp->code = sp->ds_code;

			if (err != 0 || tmp->data == NULL) {
				if (err == 0)
					err = -1;
				free_encode(tmp);
			} else {
				/*
				 * Find/replace/add encode.
				 */
				if (sp->ds_category != DSYM_VENDOR) {
					replace_encode(&mc->head, tmp,
					    ENC_DONT_COPY);
				} else
					add_vndlist(tmp, mc, sp);
			}
			break;
		}
		break;

	case OP_DELETION:
		if (sp->ds_type == DSYM_INCLUDE)
			return (-1);

		if (sp->ds_category != DSYM_VENDOR) {
			tmp = find_encode(mc->head, sp->ds_category,
				sp->ds_code);
			if (tmp != (ENCODE *)NULL) {
				if (tmp->prev != (ENCODE *)NULL)
					tmp->prev->next = tmp->next;
				else
					mc->head = mc->head->next;
				free_encode(tmp);
			}
		} else {
			for (i = 0; i < sp->ds_classes.dc_cnt; i++) {
				for (j = 0; mc->list && j < mc->classes;
				    j++) {
					if (strcmp(clp[i],
					    mc->list[j]->class) == 0) {
						tmp = find_encode(
						    mc->list[j]->head,
						    sp->ds_category,
						    sp->ds_code);
						if (tmp == NULL)
							continue;
						if (tmp->prev != NULL) {
							tmp->prev->next =
							    tmp->next;
						} else {
							mc->list[j]->head =
							    mc->list[j]->
							    head->next;
						}
						free_encode(tmp);
					}
				}
			}
		}

		err = 0;
		break;

	case OP_BOOLEAN:
		if (sp->ds_type == DSYM_INCLUDE)
			return (-1);
		/*
		 * True signified by existence, false by omission.
		 */
		if (sp->ds_category != DSYM_VENDOR) {
			tmp = find_encode(mc->head, sp->ds_category,
				sp->ds_code);
			if (tmp == (ENCODE *)NULL) {
				tmp = make_encode(sp->ds_category, sp->ds_code,
					0, NULL, ENC_DONT_COPY);
				replace_encode(&mc->head, tmp,
				    ENC_DONT_COPY);
			}
		} else {
			for (i = 0; i < sp->ds_classes.dc_cnt; i++) {
				for (j = 0; mc->list && j < mc->classes;
				    j++) {
					if (strcmp((const char *)clp[i],
					    mc->list[j]->class) == 0) {
						tmp = find_encode(
						    mc->list[j]->head,
						    sp->ds_category,
						    sp->ds_code);
						if (tmp == NULL) {
							tmp = make_encode(
							    sp->ds_category,
							    sp->ds_code, 0,
							    NULL,
							    ENC_DONT_COPY);
							replace_encode(
							    &mc->list[j]->
							    head, tmp,
							    ENC_DONT_COPY);
						}
					}
				}
			}
		}

		err = 0;
		break;
	}
	if (err)
		print_error_msg(ITAB_SYNTAX_ERROR, index);
	return (err);
}

/*
 * Find/add option to appropriate client classes.
 */
static void
add_vndlist(ENCODE *vp, MACRO *mp, dhcp_symbol_t *sp)
{
	int	i, j, class_exists, copy;
	VNDLIST	**tmp;
	char **cp = sp->ds_classes.dc_names;

	copy = ENC_DONT_COPY;
	for (i = 0; i < sp->ds_classes.dc_cnt; i++) {
		class_exists = 0;
		for (j = 0; mp->list && j < mp->classes; j++) {
			if (strcmp(cp[i], mp->list[j]->class) == 0) {
				class_exists = 1;
				replace_encode(&mp->list[j]->head, vp, copy);
				if (copy == ENC_DONT_COPY)
					copy = ENC_COPY;
			}
		}
		if (!class_exists) {
			tmp = (VNDLIST **)realloc(mp->list,
			    sizeof (VNDLIST **) * (j + 1));
			if (tmp != NULL)
				mp->list = tmp;
			else {
				dhcpmsg(LOG_ERR, "Warning: ran out of \
memory adding vendor class: '%1$s' for symbol: '%2$s'\n",
				    cp[i], sp->ds_name);
				break;
			}
			mp->list[j] = (VNDLIST *)smalloc(sizeof (VNDLIST));
			(void) strcpy(mp->list[j]->class, cp[i]);
			if (copy == ENC_DONT_COPY) {
				mp->list[j]->head = vp;
				copy = ENC_COPY;
			} else
				mp->list[j]->head = dup_encode(vp);
			mp->classes++;
		}
	}
}

/*
 * CMU 2.2 routine.
 *
 * Read a string from the buffer indirectly pointed to through "src" and
 * move it into the buffer pointed to by "dest".  A pointer to the maximum
 * allowable length of the string (including null-terminator) is passed as
 * "length".  The actual length of the string which was read is returned in
 * the unsigned integer pointed to by "length".  This value is the same as
 * that which would be returned by applying the strlen() function on the
 * destination string (i.e the terminating null is not counted as a
 * character).  Trailing whitespace is removed from the string.  For
 * convenience, the function returns the new value of "dest".
 *
 * The string is read until the maximum number of characters, an unquoted
 * colon (:), or a null character is read.  The return string in "dest" is
 * null-terminated.
 */
static char *
get_string(char **src, char *dest, uchar_t *length)
{
	int n = 0, len, quoteflag;

	quoteflag = B_FALSE;
	len = *length - 1;
	while ((n < len) && (**src)) {
		if (quoteflag == B_FALSE && (**src == ':'))
			break;
		if (**src == '"') {
			(*src)++;
			quoteflag = !quoteflag;
			continue;
		}
		if (**src == '\\') {
			(*src)++;
			if (!**src)
				break;
		}
		*dest++ = *(*src)++;
		n++;
	}

	/*
	 * Remove that troublesome trailing whitespace. . .
	 */
	while ((n > 0) && isspace(*(char *)(dest - 1))) {
		dest--;
		n--;
	}

	*dest = '\0';
	*length = n;
	return (dest);
}

/*
 * This function adjusts the caller's pointer to point just past the
 * first-encountered colon.  If it runs into a null character, it leaves
 * the pointer pointing to it.
 */
static void
adjust(char **s)
{
	char *t;

	t = *s;
	while (*t && (*t != ':'))
		t++;

	if (*t)
		t++;
	*s = t;
}

/*
 * This function adjusts the caller's pointer to point to the first
 * non-whitespace character.  If it runs into a null character, it leaves
 * the pointer pointing to it.
 */
static void
eat_whitespace(char **s)
{
	char *t;

	t = *s;
	while (*t && isspace(*t))
		t++;
	*s = t;
}

/*
 *  Copy symbol name into buffer. Sym ends up pointing to the end of the
 * token.
 */
static void
get_sym_name(char *buf, char **sym)
{
	int i;

	for (i = 0; i < DSVC_MAX_MACSYM_LEN; i++) {
		if (**sym == ':' || **sym == '=' || **sym == '@' ||
		    **sym == '\0')
			break;
		*buf++ = *(*sym)++;
	}
	*buf = '\0';
}

static void
print_error_msg(int error, uchar_t index)
{
	switch (error) {
	case ITAB_BAD_IPADDR:
		dhcpmsg(LOG_ERR, "Error processing Internet address \
value(s) for symbol: '%s'\n", sym_list[index].ds_name);
		break;
	case ITAB_BAD_STRING:
		dhcpmsg(LOG_ERR, "Error processing ASCII string value for \
symbol: '%s'\n", sym_list[index].ds_name);
		break;
	case ITAB_BAD_OCTET:
		dhcpmsg(LOG_ERR, "Error processing OCTET string value for \
symbol: '%s'\n", sym_list[index].ds_name);
		break;
	case ITAB_BAD_NUMBER:
		dhcpmsg(LOG_ERR, "Error processing NUMBER value for \
symbol: '%s'\n", sym_list[index].ds_name);
		break;
	case ITAB_BAD_BOOLEAN:
		dhcpmsg(LOG_ERR,
		    "Error processing BOOLEAN value for symbol: '%s'\n",
		    sym_list[index].ds_name);
		break;
	case ITAB_SYNTAX_ERROR:
	/* FALLTHRU */
	default:
		dhcpmsg(LOG_ERR,
		    "Syntax error found processing value for symbol: '%s'\n",
		    sym_list[index].ds_name);
		break;
	}
}

/*
 * Define new symbols for things like site-wide and vendor options.
 */
static boolean_t
define_symbol(char **ptr, char *name)
{

	dhcp_symbol_t sym;
	char **fields;
	int last = 0;
	dsym_errcode_t ret = DSYM_SUCCESS;
	ushort_t min;
	ushort_t max;
	int i;

	/*
	 * Only permit new symbol definitions, not old ones. I suppose we
	 * could allow the administrator to redefine symbols, but what if
	 * they redefine subnetmask to be a new brownie recipe? Let's stay
	 * out of that rat hole for now.
	 */
	for (i = 0; i < sym_num_items; i++) {
		if (strcmp(name, sym_list[i].ds_name) == 0) {
			dhcpmsg(LOG_ERR, "Symbol: %s already defined. New "
			    "definition ignored.\n", name);
			adjust(ptr);
			return (0);
		}
	}

	ret = dsym_init_parser(name, *ptr, &fields, &sym);
	if (ret != DSYM_SUCCESS) {
		switch (ret) {
		case DSYM_NULL_FIELD:
			dhcpmsg(LOG_ERR,
			    "Item is missing in symbol definition: '%s'\n",
			    name);
			break;

		case DSYM_TOO_MANY_FIELDS:
			dhcpmsg(LOG_ERR,
			    "Too many items exist in symbol definition: %s\n",
			    name);
			break;
		case DSYM_NO_MEMORY:
			dhcpmsg(LOG_ERR,
			    "Ran out of memory processing symbol: '%s'\n",
			    name);
			break;
		default:
			dhcpmsg(LOG_ERR,
			    "Internal error processing symbol: '%s'\n",
			    name);
			break;

		}
		return (B_FALSE);
	}

	ret = dsym_parser(fields, &sym, &last, B_FALSE);
	if (ret != DSYM_SUCCESS) {
		switch (ret) {
		case DSYM_SYNTAX_ERROR:
			dhcpmsg(LOG_ERR,
			    "Syntax error parsing symbol definition: '%s'\n",
			    name);
			break;

		case DSYM_CODE_OUT_OF_RANGE:
			(void) dsym_get_code_ranges(fields[DSYM_CAT_FIELD],
			    &min, &max, B_TRUE);
			dhcpmsg(LOG_ERR, "Out of range (%d-%d) option code: "
			    "%d in symbol definition: '%s'\n",
			    min, max, sym.ds_code, name);
			break;

		case DSYM_VALUE_OUT_OF_RANGE:
			dhcpmsg(LOG_ERR,
			    "Bad item, %s, in symbol definition: '%s'\n",
			    fields[last], name);
			break;

		case DSYM_INVALID_CAT:
			dhcpmsg(LOG_ERR, "Missing/Incorrect Site/Vendor flag "
			    "in symbol definition: '%s'\n", name);
			break;

		case DSYM_INVALID_TYPE:
			dhcpmsg(LOG_ERR, "Unrecognized value descriptor: %s "
			    "in symbol definition: '%s'\n",
			    fields[DSYM_TYPE_FIELD], name);
			break;

		case DSYM_EXCEEDS_CLASS_SIZE:
			dhcpmsg(LOG_ERR, "Client class is too "
			    "long for vendor symbol: '%s'. Must be "
			    "less than: %d\n", name, DSYM_CLASS_SIZE);
			break;

		case DSYM_EXCEEDS_MAX_CLASS_SIZE:
			dhcpmsg(LOG_ERR, "Client class is too long for "
			    "vendor symbol: '%s'. Must be less than: %d\n",
			    name, DSYM_MAX_CLASS_SIZE);
			break;

		case DSYM_NO_MEMORY:
			dhcpmsg(LOG_ERR,
			    "Ran out of memory processing symbol: '%s'\n",
			    name);
			break;

		default:
			dhcpmsg(LOG_ERR,
			    "Internal error processing symbol: '%s'\n",
			    name);
			break;
		}
		dsym_close_parser(fields, &sym);
		return (B_FALSE);
	}

	/*
	 * Don't free the symbol structure resources, we need those.
	 * Just free the fields memory. We will free the symbol structure
	 * resources later.
	 */
	dsym_free_fields(fields);

	/*
	 * Now add it to the existing definitions, reallocating
	 * the dynamic symbol list.
	 */
	sym_list = (dhcp_symbol_t *)realloc(sym_list,
			(sym_num_items + 1) * sizeof (dhcp_symbol_t));
	if (sym_list != (dhcp_symbol_t *)NULL) {
		sym_num_items++;
		(void) memcpy(&sym_list[sym_num_items - 1], &sym,
		    sizeof (dhcp_symbol_t));
	} else {
		dhcpmsg(LOG_ERR,
		    "Cannot extend symbol table, using predefined table.\n");
		resettab(B_FALSE);
	}

	return (B_TRUE);
}
