/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * As of BIND 8.2.2, ISC (a) removed res_mkupdate(), res_update(), and
 * res_mkupdrec() from what they consider the supported interface. The
 * functions still exist, but their calling interface has changed, since
 * the ns_updrec structure has changed.
 *
 * It seems probable that res_mkupdate()  etc. will return, though possibly
 * with other changes, in some future BIND release. In order to avoid
 * going to PSARC twice (once to remove the functions, and then again to
 * add them back), we retain the old interface as a wrapper around the
 * new one.
 */

#include <port_before.h>

#include <malloc.h>
#include <strings.h>
#include <sys/types.h>
#include <netinet/in.h>

/* get the Solaris ns_updrec before any renaming happens */
#include <arpa/nameser.h>

/* get the __ISC_ns_updrec */
#include <res_update.h>

#include <port_after.h>

/* un-rename ns_updrec and res_* functions so we can wrap them */
#undef	ns_updrec
#undef	res_mkupdate
#undef	res_update
#undef	res_mkupdrec
#undef	res_freeupdrec
#undef	res_nmkupdate
#undef	res_nupdate

void	res_freeupdrec(ns_updrec *);

static int
old2new(ns_updrec *old, __ISC_ns_updrec *new) {

	if (old->r_dname != 0) {
		if ((new->r_dname = strdup(old->r_dname)) == 0)
			return (-1);
	} else {
		new->r_dname = 0;
	}

	new->r_glink.prev =
	new->r_glink.next =
	new->r_link.prev  =
	new->r_link.next  = 0;

	new->r_section	= old->r_section;
	new->r_class	= old->r_class;
	new->r_type	= old->r_type;
	new->r_ttl	= old->r_ttl;
	new->r_data	= old->r_data;
	new->r_size	= old->r_size;
	new->r_opcode	= old->r_opcode;
	new->r_dp	= old->r_dp;
	new->r_deldp	= old->r_deldp;
	new->r_zone	= old->r_zone;

	return (0);
}


static int
new2old(__ISC_ns_updrec *new, ns_updrec *old) {
	/* XXX r_prev and r_next unchanged */
	if (new->r_dname != 0) {
		if ((old->r_dname = strdup(new->r_dname)) == 0)
			return (-1);
	} else {
		old->r_dname = 0;
	}
	old->r_section	= new->r_section;
	old->r_class	= new->r_class;
	old->r_type	= new->r_type;
	old->r_ttl	= new->r_ttl;
	old->r_data	= new->r_data;
	old->r_size	= new->r_size;
	old->r_opcode	= new->r_opcode;
	old->r_grpnext	= 0;			/* XXX */
	old->r_dp	= new->r_dp;
	old->r_deldp	= new->r_deldp;
	old->r_zone	= new->r_zone;

	return (0);
}


static void
delete_list(__ISC_ns_updrec *list) {

	__ISC_ns_updrec	*next;

	for (; list != 0; list = next) {
		next = list->r_link.next;
		__ISC_res_freeupdrec(list);
	}
}


static __ISC_ns_updrec *
copy_list(ns_updrec *old, int do_glink) {

	__ISC_ns_updrec *list = 0, *r, *p;

	if (old == 0)
		return (0);

	for (p = 0; old != 0; old = old->r_next, p = r) {
		if ((r = calloc(1, sizeof (*r))) == 0 ||
			old2new(old, r) != 0) {
			free(r);
			delete_list(list);
			return (0);
		}
		r->r_link.prev = p;
		r->r_link.next = 0;
		/* res_update and res_nupdate want r_glink set up like this */
		if (do_glink) {
			r->r_glink.prev = p;
			r->r_glink.next = 0;
		} else {
			r->r_glink.prev = (void *)-1;
			r->r_glink.next = (void *)-1;
		}
		if (p != 0) {
			p->r_link.next = r;
			if (do_glink) {
				p->r_glink.next = r;
			}
		} else {
			list = r;
		}
	}
	return (list);
}


int
res_mkupdate(ns_updrec  *rrecp_in, uchar_t *buf, int length) {

	__ISC_ns_updrec	*r;
	int		ret;

	if ((r = copy_list(rrecp_in, 1)) == 0)
		return (-1);

	ret = __ISC_res_mkupdate(r, buf, length);

	delete_list(r);

	return (ret);
}

int
res_nmkupdate(res_state statp, ns_updrec  *rrecp_in, uchar_t *buf, int length) {

	__ISC_ns_updrec	*r;
	int		ret;

	if ((r = copy_list(rrecp_in, 1)) == 0)
		return (-1);

	ret = __ISC_res_nmkupdate(statp, r, buf, length);

	delete_list(r);

	return (ret);
}


int
res_update(ns_updrec *rrecp_in) {

	__ISC_ns_updrec	*r;
	int		ret;

	if ((r = copy_list(rrecp_in, 0)) == 0)
		return (-1);

	ret = __ISC_res_update(r);

	delete_list(r);

	return (ret);
}

int
res_nupdate(res_state statp, ns_updrec *rrecp_in, ns_tsig_key *key) {

	__ISC_ns_updrec	*r;
	int		ret;

	if ((r = copy_list(rrecp_in, 0)) == 0)
		return (-1);

	ret = __ISC_res_nupdate(statp, r, key);

	delete_list(r);

	return (ret);
}



ns_updrec *
res_mkupdrec(int section, const char *dname, uint_t class, uint_t type,
		uint_t ttl) {

	__ISC_ns_updrec	*n;
	ns_updrec	*o;

	n = __ISC_res_mkupdrec(section, dname, class, type, ttl);
	if (n == 0)
		return (0);

	if ((o = calloc(1, sizeof (*o))) != 0) {
		if (new2old(n, o) != 0) {
			res_freeupdrec(o);
			o = 0;
		}
	}

	__ISC_res_freeupdrec(n);

	return (o);
}


void
res_freeupdrec(ns_updrec *rrecp) {
	if (rrecp == 0)
		return;
	/* Note: freeing r_dp is the caller's responsibility. */
	if (rrecp->r_dname != NULL)
		free(rrecp->r_dname);
	free(rrecp);
}
