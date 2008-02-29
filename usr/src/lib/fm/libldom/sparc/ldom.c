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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <libnvpair.h>
#include <dlfcn.h>
#include <link.h>
#include <assert.h>

#include <sys/processor.h>
#include <sys/stat.h>
#include <sys/mdesc.h>
#include <sys/param.h>
#include <sys/systeminfo.h>
#include <sys/mem.h>
#include <sys/bl.h>
#include <sys/fm/protocol.h>
#include <fm/fmd_fmri.h>
#include <sys/pri.h>

#include "ldom.h"
#include "ldmsvcs_utils.h"

#define	MD_STR_PLATFORM		"platform"
#define	MD_STR_DOM_CAPABLE	"domaining-enabled"

static int ldom_ldmd_is_up = 0; /* assume stays up if ever seen up */

static void *ldom_dl_hp = (void *)NULL;
static const char *ldom_dl_path = "libpri.so.1";
static int ldom_dl_mode = (RTLD_NOW | RTLD_LOCAL);

static pthread_mutex_t ldom_pri_lock = PTHREAD_MUTEX_INITIALIZER;
static int ldom_pri_ref_cnt = 0; /* num of outstanding ldom_pri_init()s */
static int ldom_pri_init_done = 0; /* bool for real pri_init() done */
static int (*ldom_pri_fp_init)(void) = (int (*)(void))NULL;
static void (*ldom_pri_fp_fini)(void) = (void (*)(void))NULL;
static ssize_t (*ldom_pri_fp_get)(uint8_t wait, uint64_t *token, uint64_t **buf,
	void *(*allocp)(size_t), void (*freep)(void *, size_t)) =
	(ssize_t (*)(uint8_t wait, uint64_t *token, uint64_t **buf,
	void *(*allocp)(size_t), void (*freep)(void *, size_t)))NULL;

static void
ldom_pri_config(void)
{
	char isa[MAXNAMELEN];	/* used to see if machine is sun4v */

	if (sysinfo(SI_MACHINE, isa, MAXNAMELEN) < 0)
		return;
	if (strcmp(isa, "sun4v") != 0)
		return;
	if ((ldom_dl_hp = dlopen(ldom_dl_path, ldom_dl_mode)) == NULL)
		return;

	ldom_pri_fp_init = (int (*)(void))dlsym(ldom_dl_hp, "pri_init");
	ldom_pri_fp_fini = (void (*)(void))dlsym(ldom_dl_hp, "pri_fini");
	ldom_pri_fp_get = (ssize_t (*)(uint8_t wait, uint64_t *token,
	    uint64_t **buf, void *(*allocp)(size_t),
	    void (*freep)(void *, size_t)))dlsym(ldom_dl_hp, "pri_get");
}

static void
ldom_pri_unconfig(void)
{
	if (ldom_dl_hp == NULL)
		return;

	ldom_pri_fp_init = (int (*)(void))NULL;
	ldom_pri_fp_fini = (void (*)(void))NULL;
	ldom_pri_fp_get = (ssize_t (*)(uint8_t wait, uint64_t *token,
	    uint64_t **buf, void *(*allocp)(size_t),
	    void (*freep)(void *, size_t)))NULL;
	(void) dlclose(ldom_dl_hp);
	ldom_dl_hp = (void *)NULL;
}

/*
 * ldom_pri_lock is assumed already held by anyone accessing ldom_pri_ref_cnt
 */

static int
ldom_pri_init(void)
{
	if (ldom_pri_ref_cnt == 0) {
		ldom_pri_config();
		/*
		 * ldom_pri_init() is called before we know whether we
		 * have LDOMS FW or not; defer calling pri_init() via
		 * ldom_pri_fp_init until the first time we try to
		 * actually get a PRI
		 */
	}
	ldom_pri_ref_cnt++;

	assert(ldom_pri_ref_cnt > 0);

	return (0);
}

static void
ldom_pri_fini(void)
{
	assert(ldom_pri_ref_cnt > 0);

	ldom_pri_ref_cnt--;
	if (ldom_pri_ref_cnt == 0) {
		if (ldom_pri_init_done && (ldom_pri_fp_fini != NULL)) {
			(*ldom_pri_fp_fini)();
			ldom_pri_init_done = 0;
		}
		ldom_pri_unconfig();
	}
}

static ssize_t
ldom_pri_get(uint8_t wait, uint64_t *token, uint64_t **buf,
		void *(*allocp)(size_t), void (*freep)(void *, size_t))
{
	assert(ldom_pri_ref_cnt > 0);

	if ((!ldom_pri_init_done) && (ldom_pri_fp_init != NULL)) {
		if ((*ldom_pri_fp_init)() < 0)
			return (-1);
		ldom_pri_init_done = 1;
	}

	if (ldom_pri_fp_get != NULL)
		return ((*ldom_pri_fp_get)(wait, token, buf, allocp, freep));
	else
		return (-1);
}

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
get_local_md_prop_value(ldom_hdl_t *lhp, char *node, char *prop, uint64_t *val)
{
	int rc = 1;
	uint64_t *bufp;
	ssize_t bufsiz;

	if ((bufsiz = get_local_core_md(lhp, &bufp)) > 0) {
		md_t *mdp;

		if (mdp = md_init_intern(bufp, lhp->allocp, lhp->freep)) {
			int num_nodes;
			mde_cookie_t *listp;

			num_nodes = md_node_count(mdp);
			listp = lhp->allocp(sizeof (mde_cookie_t) * num_nodes);

			if (md_scan_dag(mdp, MDE_INVAL_ELEM_COOKIE,
			    md_find_name(mdp, node),
			    md_find_name(mdp, "fwd"), listp) > 0 &&
			    md_get_prop_val(mdp, listp[0], prop, val) >= 0) {
				/* found the property */
				rc = 0;
			}

			lhp->freep(listp, sizeof (mde_cookie_t) * num_nodes);
			(void) md_fini(mdp);
		}
		lhp->freep(bufp, bufsiz);
	}
	return (rc);
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
	uint64_t domain_capable;

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
	 * available".	note that these can (and will) also apply to
	 * non-sun4v machines.
	 */
	major_version = 0;
	service_ldom = 0;

	if (get_local_md_prop_value(lhp, MD_STR_PLATFORM, MD_STR_DOM_CAPABLE,
	    &domain_capable) == 0) {

		/*
		 * LDOMS capable FW is installed; it should be ok to
		 * try to communicate with ldmd and if that fails/timesout
		 * then use libpri
		 */
		major_version = 1;

		if ((ier = ldmsvcs_check_channel()) == 0) {
			/*
			 * control ldom
			 * ldmfma channel between FMA and ldmd only exists
			 * on the control domain.
			 */
			service_ldom = 1;
		} else if (ier == 1) {
			/*
			 * guest ldom
			 * non-control ldom such as guest and io service ldom
			 */
			service_ldom = 0;
		}
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
 * return the corresponding "id" entry (virtual cpuid).
 * return -1 if not found.
 * if the pid property does not exist in a cpu node, assume pid = id.
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
	uint64_t pval, pid, id;
	int num_nodes, ncpus, i;

	(void) sysinfo(SI_MACHINE, isa, MAXNAMELEN);

	if (strcmp(isa, "sun4v") != 0)
		return ((processorid_t)cpuid);

	/*
	 * convert the physical cpuid to a virtual cpuid
	 */
	if ((bufsize = get_local_core_md(lhp, &bufp)) < 1)
		return (-1);

	if ((mdp = md_init_intern(bufp, lhp->allocp, lhp->freep)) == NULL ||
	    (num_nodes = md_node_count(mdp)) < 1) {
		lhp->freep(bufp, bufsize);
		return (-1);
	}

	listp = (mde_cookie_t *)lhp->allocp(sizeof (mde_cookie_t) * num_nodes);
	ncpus = md_scan_dag(mdp, MDE_INVAL_ELEM_COOKIE,
	    md_find_name(mdp, "cpu"), md_find_name(mdp, "fwd"), listp);

	vid = -1;
	for (i = 0; i < ncpus; i++) {
		if (md_get_prop_val(mdp, listp[i], "id", &pval) < 0)
			pval = (uint64_t)-1;
		id = pval;

		/* if pid does not exist, assume pid=id */
		if (md_get_prop_val(mdp, listp[i], "pid", &pval) < 0)
			pval = id;
		pid = pval;

		if (pid == (uint64_t)cpuid) {
			/* Found the entry */
			vid = (processorid_t)id;
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
	int fd, rc, err;

	if (cmd != MEM_PAGE_RETIRE && cmd != MEM_PAGE_FMRI_RETIRE &&
	    cmd != MEM_PAGE_ISRETIRED && cmd != MEM_PAGE_FMRI_ISRETIRED &&
	    cmd != MEM_PAGE_UNRETIRE && cmd != MEM_PAGE_FMRI_UNRETIRE)
		return (EINVAL);

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
	err = errno;

	lhp->freep(fmribuf, fmrisz);
	(void) close(fd);

	if (rc < 0) {
		rc = err;
	}

	return (rc);
}


int
ldom_fmri_status(ldom_hdl_t *lhp, nvlist_t *nvl)
{
	char *name;
	int ret = ENOTSUP;

	if (nvlist_lookup_string(nvl, FM_FMRI_SCHEME, &name) != 0)
		return (EINVAL);

	/*
	 * ldom_ldmd_is_up can only be true if ldom_major_version()
	 * returned 1 earlier; the major version is constant for the
	 * life of the client process
	 */

	if (!ldom_ldmd_is_up) {
		/* Zeus is unavail; use local routines for status/retire */

		if (strcmp(name, FM_FMRI_SCHEME_CPU) == 0) {
			processorid_t vid;
			uint32_t cpuid;

			if (nvlist_lookup_uint32(nvl, FM_FMRI_CPU_ID, &cpuid)
			    == 0 && (vid = cpu_phys2virt(lhp, cpuid)) != -1)
				return (p_online(vid, P_STATUS));
		} else if (strcmp(name, FM_FMRI_SCHEME_MEM) == 0) {
			return (os_mem_page_retire(lhp,
			    MEM_PAGE_FMRI_ISRETIRED, nvl));
		}

		return (EINVAL);
	} else {
		/* Zeus is avail; use Zeus for status/retire */

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
		}
		return (ret);
	}
}


int
ldom_fmri_retire(ldom_hdl_t *lhp, nvlist_t *nvl)
{
	char *name;
	int ret = ENOTSUP;

	if (nvlist_lookup_string(nvl, FM_FMRI_SCHEME, &name) != 0)
		return (EINVAL);

	/*
	 * ldom_ldmd_is_up can only be true if ldom_major_version()
	 * returned 1 earlier; the major version is constant for the
	 * life of the client process
	 */

	if (!ldom_ldmd_is_up) {
		/* Zeus is unavail; use local routines for status/retire */

		if (strcmp(name, FM_FMRI_SCHEME_CPU) == 0) {
			processorid_t vid;
			uint32_t cpuid;

			if (nvlist_lookup_uint32(nvl, FM_FMRI_CPU_ID, &cpuid)
			    == 0 && (vid = cpu_phys2virt(lhp, cpuid)) != -1)
				return (p_online(vid, P_FAULTED));
		} else if (strcmp(name, FM_FMRI_SCHEME_MEM) == 0) {
			return (os_mem_page_retire(lhp,
			    MEM_PAGE_FMRI_RETIRE, nvl));
		}

		return (EINVAL);
	} else {
		/* Zeus is avail; use Zeus for status/retire */

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
		}
		return (ret);
	}
}

int
ldom_fmri_unretire(ldom_hdl_t *lhp, nvlist_t *nvl)
{
	char *name;
	int ret = ENOTSUP;

	if (nvlist_lookup_string(nvl, FM_FMRI_SCHEME, &name) != 0)
		return (EINVAL);

	/*
	 * ldom_ldmd_is_up can only be true if ldom_major_version()
	 * returned 1 earlier; the major version is constant for the
	 * life of the client process
	 */

	if (!ldom_ldmd_is_up) {
		/* Zeus is unavail; use local routines for status/retire */

		if (strcmp(name, FM_FMRI_SCHEME_CPU) == 0) {
			processorid_t vid;
			uint32_t cpuid;

			if (nvlist_lookup_uint32(nvl, FM_FMRI_CPU_ID, &cpuid)
			    == 0 && (vid = cpu_phys2virt(lhp, cpuid)) != -1)
				return (p_online(vid, P_ONLINE));
		} else if (strcmp(name, FM_FMRI_SCHEME_MEM) == 0) {
			return (os_mem_page_retire(lhp,
			    MEM_PAGE_FMRI_UNRETIRE, nvl));
		}

		return (EINVAL);
	} else {
		/* Zeus is avail; use Zeus for status/retire */

		if (strcmp(name, FM_FMRI_SCHEME_CPU) == 0) {
			uint32_t cpuid;

			if (nvlist_lookup_uint32(nvl, FM_FMRI_CPU_ID,
			    &cpuid) == 0)
				ret = ldmsvcs_cpu_req_online(lhp, cpuid);
		} else if (strcmp(name, FM_FMRI_SCHEME_MEM) == 0) {
			uint64_t pa;

			if (nvlist_lookup_uint64(nvl, FM_FMRI_MEM_PHYSADDR,
			    &pa) == 0)
				ret = ldmsvcs_mem_req_unretire(lhp, pa);
			else
				ret = EINVAL;
		}
		return (ret);
	}
}

static int
fmri_blacklist(ldom_hdl_t *lhp, nvlist_t *nvl, int cmd)
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

		rc = ioctl(fd, cmd, &blr);
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

/*
 * blacklist cpus in a non-LDOMS environment
 */
int
ldom_fmri_blacklist(ldom_hdl_t *lhp, nvlist_t *nvl)
{
	return (fmri_blacklist(lhp, nvl, BLIOC_INSERT));
}

/*
 * unblacklist cpus
 */
int
ldom_fmri_unblacklist(ldom_hdl_t *lhp, nvlist_t *nvl)
{
	return (fmri_blacklist(lhp, nvl, BLIOC_DELETE));
}


ssize_t
ldom_get_core_md(ldom_hdl_t *lhp, uint64_t **buf)
{
	ssize_t		rv;	/* return value */
	uint64_t	tok;	/* opaque PRI token */

	switch (ldom_major_version(lhp)) {
	case 0:
		/* pre LDOMS */
		rv = get_local_core_md(lhp, buf);
		break;
	case 1:
		/* LDOMS 1.0 - Zeus and libpri usable only on service dom */
		if (ldom_on_service(lhp) == 1) {
			if ((rv = ldmsvcs_get_core_md(lhp, buf)) < 1) {
				(void) pthread_mutex_lock(&ldom_pri_lock);
				rv = ldom_pri_get(PRI_GET, &tok,
				    buf, lhp->allocp, lhp->freep);
				(void) pthread_mutex_unlock(&ldom_pri_lock);
			} else {
				ldom_ldmd_is_up = 1;
			}
		} else {
			rv = get_local_core_md(lhp, buf);
		}
		break;
	default:
		rv = -1;
		break;
	}

	return (rv);
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

	(void) pthread_mutex_lock(&ldom_pri_lock);

	if (ldom_pri_init() < 0) {
		(void) pthread_mutex_unlock(&ldom_pri_lock);
		return (NULL);
	}

	if ((lhp = allocp(sizeof (struct ldom_hdl))) == NULL) {
		ldom_pri_fini();
		(void) pthread_mutex_unlock(&ldom_pri_lock);
		return (NULL);
	}

	(void) pthread_mutex_unlock(&ldom_pri_lock);

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

	(void) pthread_mutex_lock(&ldom_pri_lock);

	ldom_pri_fini();

	(void) pthread_mutex_unlock(&ldom_pri_lock);
}

/* end file */
