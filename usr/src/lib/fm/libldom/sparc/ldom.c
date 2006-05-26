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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <libnvpair.h>

#include <sys/processor.h>
#include <sys/stat.h>
#include <sys/mdesc.h>
#include <sys/param.h>
#include <sys/systeminfo.h>
#include <sys/mem.h>
#include <sys/bl.h>
#include <sys/fm/protocol.h>
#include <fm/fmd_fmri.h>

#include "ldom.h"
#include "ldmsvcs_utils.h"


static ssize_t
get_local_core_md(ldom_hdl_t *lhp, uint64_t **buf)
{
	int fh;
	size_t size;
	uint64_t *bufp;

	if ((fh = open("/devices/pseudo/mdesc@0:mdesc", O_RDONLY, 0)) < 0)
		return (-1);

	if (ioctl(fh, MDESCIOCGSZ, &size) < 0) {
		(void) close(fh);
		return (-1);
	}

	bufp = (uint64_t *)lhp->allocp(size);

	if (read(fh, bufp, size) < 0) {
		lhp->freep(bufp, size);
		(void) close(fh);
		return (-1);
	}
	(void) close(fh);

	*buf = bufp;

	return ((ssize_t)size);
}


static int
ldom_getinfo(struct ldom_hdl *lhp)
{
	static pthread_mutex_t mt = PTHREAD_MUTEX_INITIALIZER;
	static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
	static int major_version = -1;
	static int service_ldom = -1;
	static int busy_init = 0;

	int ier, rc = 0;

	(void) pthread_mutex_lock(&mt);

	while (busy_init == 1)
		(void) pthread_cond_wait(&cv, &mt);

	if (major_version != -1 && service_ldom != -1) {
		lhp->major_version = major_version;
		lhp->service_ldom = service_ldom;
		(void) pthread_mutex_unlock(&mt);
		return (0);
	}

	/*
	 * get to this point if major_version and service_ldom have not yet
	 * been determined
	 */
	busy_init = 1;
	(void) pthread_mutex_unlock(&mt);

	/*
	 * set defaults which correspond to the case of "LDOMS not
	 * available".  note that these can (and will) also apply to
	 * non-sun4v machines.
	 */
	major_version = 0;
	service_ldom = 1;

	/* figure out version */
	if ((ier = ldmsvcs_check_channel()) == 0) {
		/*
		 * get into this block if vldc exists.  LDOMS is available
		 * and we are on the service LDOM.
		 */
		major_version = 1;
		service_ldom = 1;
	} else if (ier == 1) {
		/*
		 * get into this block if vldc does not exist
		 *
		 * if we do not get into the following if() block [i.e.,
		 * if (bufsiz <= 0)] then we are on a non-sun4v machine.
		 */
		uint64_t *bufp;
		ssize_t bufsiz;

		if ((bufsiz = get_local_core_md(lhp, &bufp)) > 0) {
			md_t *mdp;

			if ((mdp = md_init_intern(bufp, lhp->allocp,
						    lhp->freep)) != NULL) {
				mde_cookie_t *listp;
				uint64_t dval;
				int num_nodes;

				num_nodes = md_node_count(mdp);
				listp = lhp->allocp(sizeof (mde_cookie_t) *
						    num_nodes);

				/*
				 * if we do not enter the following if block,
				 * we conclude that LDOMS is not available
				 */
				if (md_scan_dag(mdp, MDE_INVAL_ELEM_COOKIE,
					md_find_name(mdp, "platform"),
					md_find_name(mdp, "fwd"),
					listp) > 0 &&
				    md_get_prop_val(mdp, listp[0],
					"domaining-enabled", &dval) >= 0 &&
				    dval == 1) {
					/*
					 * LDOMS is available.  an earlier
					 * block detected the situation of
					 * being on a service LDOM, so
					 * we get to this point only if we
					 * are not on a service LDOM.
					 */
					major_version = 1;
					service_ldom = 0;
				}

				lhp->freep(listp, sizeof (mde_cookie_t) *
					    num_nodes);
				(void) md_fini(mdp);
			}

			lhp->freep(bufp, bufsiz);
		}
	} else {
		rc = 1;
	}

	(void) pthread_mutex_lock(&mt);
	lhp->major_version = major_version;
	lhp->service_ldom = service_ldom;
	busy_init = 0;
	(void) pthread_mutex_unlock(&mt);

	(void) pthread_cond_broadcast(&cv);

	return (rc);
}


/*
 * search the machine description for a "pid" entry (physical cpuid) and
 * return the corresponding "id" entry (virtual cpuid)
 */
static processorid_t
cpu_phys2virt(ldom_hdl_t *lhp, uint32_t cpuid)
{
	char isa[MAXNAMELEN];
	md_t *mdp;
	mde_cookie_t *listp;
	ssize_t bufsize;
	processorid_t vid;
	uint64_t *bufp;
	uint64_t pval;
	int num_nodes, ncpus, i;

	(void) sysinfo(SI_ARCHITECTURE, isa, MAXNAMELEN);

	if (strcmp(isa, "sun4v") != 0)
		return ((processorid_t)cpuid);

	/*
	 * convert the physical cpuid to a virtual cpuid
	 */
	if ((bufsize = ldom_get_core_md(lhp, &bufp)) < 1)
		return (-1);

	if ((mdp = md_init_intern(bufp, lhp->allocp, lhp->freep)) == NULL ||
	    (num_nodes = md_node_count(mdp)) < 1) {
		lhp->freep(bufp, bufsize);
		return (-1);
	}

	listp = (mde_cookie_t *)lhp->allocp(sizeof (mde_cookie_t) * num_nodes);
	ncpus = md_scan_dag(mdp, MDE_INVAL_ELEM_COOKIE,
			    md_find_name(mdp, "cpu"),
			    md_find_name(mdp, "fwd"), listp);

	vid = -1;
	for (i = 0; i < ncpus; i++) {
		if (md_get_prop_val(mdp, listp[i], "pid", &pval) >= 0 &&
		    pval == (uint64_t)cpuid) {
			if (md_get_prop_val(mdp, listp[i], "id", &pval) >= 0)
				vid = (processorid_t)pval;

			break;
		}
	}

	lhp->freep(listp, sizeof (mde_cookie_t) * num_nodes);
	(void) md_fini(mdp);
	lhp->freep(bufp, bufsize);

	return (vid);
}

/*
 * if checking for status of a retired page:
 *   0 - page is retired
 *   EAGAIN - page is scheduled for retirement
 *   EIO - page not scheduled for retirement
 *   EINVAL - error
 *
 * if retiring a page:
 *   0 - success in retiring page
 *   EIO - page is already retired
 *   EAGAIN - page is scheduled for retirement
 *   EINVAL - error
 *
 * the original decoder for ioctl() return values is
 * http://fma.eng/documents/engineering/cpumem/page_retire_api.txt
 */
static int
os_mem_page_retire(ldom_hdl_t *lhp, int cmd, nvlist_t *nvl)
{
	mem_page_t mpage;
	char *fmribuf;
	size_t fmrisz;
	int fd, rc;

	if ((fd = open("/dev/mem", O_RDONLY)) < 0)
		return (EINVAL);

	if ((errno = nvlist_size(nvl, &fmrisz, NV_ENCODE_NATIVE)) != 0 ||
	    fmrisz > MEM_FMRI_MAX_BUFSIZE ||
	    (fmribuf = lhp->allocp(fmrisz)) == NULL) {
		(void) close(fd);
		return (EINVAL);
	}

	if ((errno = nvlist_pack(nvl, &fmribuf, &fmrisz,
				    NV_ENCODE_NATIVE, 0)) != 0) {
		lhp->freep(fmribuf, fmrisz);
		(void) close(fd);
		return (EINVAL);
	}

	mpage.m_fmri = fmribuf;
	mpage.m_fmrisz = fmrisz;

	rc = ioctl(fd, cmd, &mpage);
	lhp->freep(fmribuf, fmrisz);
	(void) close(fd);

	if (rc < 0)
		return (EINVAL);

	if ((cmd == MEM_PAGE_RETIRE || cmd == MEM_PAGE_FMRI_RETIRE ||
	    cmd == MEM_PAGE_ISRETIRED || cmd == MEM_PAGE_FMRI_ISRETIRED) &&
	    (rc == 0 || rc == EIO || rc == EAGAIN))
			return (rc);

	return (EINVAL);
}

int
ldom_fmri_status(ldom_hdl_t *lhp, nvlist_t *nvl)
{
	char *name;
	int ret;

	if (nvlist_lookup_string(nvl, FM_FMRI_SCHEME, &name) != 0)
		return (EINVAL);

	switch (ldom_major_version(lhp)) {
	case 0:
		/*
		 * version == 0 means LDOMS support is not available
		 */
		if (strcmp(name, FM_FMRI_SCHEME_CPU) == 0) {
			processorid_t vid;
			uint32_t cpuid;

			if (nvlist_lookup_uint32(nvl, FM_FMRI_CPU_ID,
						    &cpuid) == 0 &&
			    (vid = cpu_phys2virt(lhp, cpuid)) != -1)
				return (p_online(vid, P_STATUS));
		} else if (strcmp(name, FM_FMRI_SCHEME_MEM) == 0) {
			return (os_mem_page_retire(lhp,
						MEM_PAGE_FMRI_ISRETIRED, nvl));
		}

		return (EINVAL);
		/*NOTREACHED*/
		break;
	case 1:
		/* LDOMS 1.0 */
		if (strcmp(name, FM_FMRI_SCHEME_CPU) == 0) {
			uint32_t cpuid;

			if (nvlist_lookup_uint32(nvl, FM_FMRI_CPU_ID,
						&cpuid) == 0)
				ret = ldmsvcs_cpu_req_status(lhp, cpuid);
		} else if (strcmp(name, FM_FMRI_SCHEME_MEM) == 0) {
			uint64_t pa;

			if (nvlist_lookup_uint64(nvl, FM_FMRI_MEM_PHYSADDR,
						&pa) == 0)
				ret = ldmsvcs_mem_req_status(lhp, pa);
			else
				ret = EINVAL;
		} else {
			ret = ENOTSUP;
		}
		return (ret);

		/*NOTREACHED*/
		break;
	default:
		break;
	}

	return (ENOTSUP);
}


int
ldom_fmri_retire(ldom_hdl_t *lhp, nvlist_t *nvl)
{
	char *name;
	int ret;

	if (nvlist_lookup_string(nvl, FM_FMRI_SCHEME, &name) != 0)
		return (EINVAL);

	switch (ldom_major_version(lhp)) {
	case 0:
		/*
		 * version == 0 means LDOMS support is not available
		 */
		if (strcmp(name, FM_FMRI_SCHEME_CPU) == 0) {
			processorid_t vid;
			uint32_t cpuid;

			if (nvlist_lookup_uint32(nvl, FM_FMRI_CPU_ID,
						    &cpuid) == 0 &&
			    (vid = cpu_phys2virt(lhp, cpuid)) != -1)
				return (p_online(vid, P_FAULTED));
		} else if (strcmp(name, FM_FMRI_SCHEME_MEM) == 0) {
			return (os_mem_page_retire(lhp,
						MEM_PAGE_FMRI_RETIRE, nvl));
		}

		return (EINVAL);
		/*NOTREACHED*/
		break;
	case 1:
		/* LDOMS 1.0 */
		if (strcmp(name, FM_FMRI_SCHEME_CPU) == 0) {
			uint32_t cpuid;

			if (nvlist_lookup_uint32(nvl, FM_FMRI_CPU_ID,
						&cpuid) == 0)
				ret = ldmsvcs_cpu_req_offline(lhp, cpuid);
		} else if (strcmp(name, FM_FMRI_SCHEME_MEM) == 0) {
			uint64_t pa;

			if (nvlist_lookup_uint64(nvl, FM_FMRI_MEM_PHYSADDR,
						&pa) == 0)
				ret = ldmsvcs_mem_req_retire(lhp, pa);
			else
				ret = EINVAL;
		} else {
			ret = ENOTSUP;
		}
		return (ret);

		/*NOTREACHED*/
		break;
	default:
		break;
	}

	return (ENOTSUP);
}


/*
 * blacklist cpus in a non-LDOMS environment
 */
int
ldom_fmri_blacklist(ldom_hdl_t *lhp, nvlist_t *nvl)
{
	char *name;

	if (ldom_major_version(lhp) != 0)
		return (0);

	if (nvlist_lookup_string(nvl, FM_FMRI_SCHEME, &name) != 0)
		return (EINVAL);

	if (strcmp(name, FM_FMRI_SCHEME_CPU) == 0) {
		bl_req_t blr;
		char *class;
		int fd, rc, err;

		if ((nvlist_lookup_string(nvl, FM_CLASS, &class) != 0) ||
		    (class == NULL) || (*class == '\0'))
			return (EINVAL);

		if ((fd = open("/dev/bl", O_RDONLY)) < 0)
			return (EIO);

		if (nvlist_size(nvl, &blr.bl_fmrisz, NV_ENCODE_NATIVE) != 0 ||
		    blr.bl_fmrisz == 0 ||
		    (blr.bl_fmri = (caddr_t)lhp->allocp(blr.bl_fmrisz)) ==
		    NULL) {
			(void) close(fd);
			return (EINVAL);
		}

		blr.bl_class = class;

		rc = ioctl(fd, BLIOC_INSERT, &blr);
		err = errno;

		lhp->freep((void *)&blr.bl_fmri, blr.bl_fmrisz);
		(void) close(fd);

		if (rc < 0 && err != ENOTSUP) {
			errno = err;
			return (-1);
		}
	}

	return (0);
}


ssize_t
ldom_get_core_md(ldom_hdl_t *lhp, uint64_t **buf)
{
	switch (ldom_major_version(lhp)) {
	case 0:
		return (get_local_core_md(lhp, buf));
		/*NOTREACHED*/
		break;
	case 1:
		/* LDOMS 1.0 */
		if (ldom_on_service(lhp) == 1)
			return (ldmsvcs_get_core_md(lhp, buf));
		else
			return (get_local_core_md(lhp, buf));

		/*NOTREACHED*/
		break;
	default:
		*buf = NULL;
		break;
	}

	return (-1);
}


/*
 * version 0 means no LDOMS
 */
int
ldom_major_version(ldom_hdl_t *lhp)
{
	if (lhp == NULL)
		return (-1);

	if (ldom_getinfo(lhp) == 0)
		return (lhp->major_version);
	else
		return (0);
}

/*
 * in the absence of ldoms we are on a single OS instance which is the
 * equivalent of the service ldom
 */
int
ldom_on_service(ldom_hdl_t *lhp)
{
	if (lhp == NULL)
		return (-1);

	if (ldom_getinfo(lhp) == 0)
		return (lhp->service_ldom);
	else
		return (1);
}


ldom_hdl_t *
ldom_init(void *(*allocp)(size_t size),
	void (*freep)(void *addr, size_t size))
{
	struct ldom_hdl *lhp;

	if ((lhp = allocp(sizeof (struct ldom_hdl))) == NULL)
		return (NULL);

	lhp->major_version = -1;	/* version not yet determined */
	lhp->allocp = allocp;
	lhp->freep = freep;

	ldmsvcs_init(lhp);

	return (lhp);
}


void
ldom_fini(ldom_hdl_t *lhp)
{
	if (lhp == NULL)
		return;

	ldmsvcs_fini(lhp);
	lhp->freep(lhp, sizeof (struct ldom_hdl));
}

/* end file */
