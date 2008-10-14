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
 * Routines for the Infinity Storage Device daemon
 */

#include <sys/types.h>
#include <sys/ksynch.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/buf.h>
#include <sys/kmem.h>
#include <sys/cred.h>
#include <sys/ddi.h>
#include <sys/nsc_thread.h>

#include "sd_bcache.h"
#include "sd_io.h"
#include "sd_bio.h"
#include "sd_ft.h"
#include "sd_misc.h"

#define	_INFSD_LOCAL_MEM

#define	_CD_VTRK_SIZE(cd)	(dev_tsize[GET_CD_STATE(cd)] * 1024)
#define	_CD_VTRK_NUM(cd, len)	((len)/_CD_VTRK_SIZE(cd))
#define	_CD_VTRK_OFF(cd, len)	((len)%(_CD_VTRK_SIZE(cd)))

#define	FILESIZE (1 << 27) 	/* 128 MB 	*/

#define	SIZEMASK 0x0000FFFF
#define	_INFSD_RECORD_SIZE(ndx) REC_SIZE
#define	GET_SEED(ndx) (gld[ndx] . seed & SIZEMASK)
#define	MAX_CD_STS	600
#define	MAX_TDAEMONS  128

static char devarray[MAX_TDAEMONS][MAX_TDAEMONS*2];
static int  dev_tsize[MAX_TDAEMONS*2];
static int  dev_flag[MAX_TDAEMONS*2];


/*
 * sd_test options
 */
#define	SD_TEST_CACHE_HIT    0x00000001
#define	SD_TEST_CACHE_MISS   0x00000002
#define	SD_TEST_CHECK_DATA   0x00000004
#define	SD_TEST_READ_ONLY    0x00000008
#define	SD_TEST_WRITE_ONLY   0x00000010
#define	SD_TEST_SEQUENTIAL   0x00000020

static struct cd_sts {
	volatile short  cd_state;
	volatile char waiting;
	volatile char inited;
	kcondvar_t cd_blk;
	volatile caddr_t asy_key;
} cd_test_sts[MAX_CD_STS];

#define	SET_CD_STATE(cd, i)	(cd_test_sts[(cd)].cd_state = (short)(i))
#define	GET_CD_STATE(cd)	(cd_test_sts[(cd)].cd_state)

static kmutex_t tdaemon_lock;
static kcondvar_t _wait_daemons;
dev_t	_test_async_fail;	/* fail async writes to cache dev_t */
static volatile int 	test_stop;

static int daemon_awake(int i);
static void wakeup_all_tdaemons(void);
static void _sd_idle_daemon(void);
static void _td_detach_cd(int cd);
static int _fork_test_daemon(int num_disks, int test_typ, int loop_cnt,
    int from, int seed);
static void _sd_test_rwloop_seq(int i, int loops, int seed, int forw);
static int _sd_copy_pattern_to_handle(_sd_buf_handle_t *handle,
    nsc_off_t fba_pos, nsc_size_t fba_len);
static int _sd_copy_handle(_sd_buf_handle_t *handle1, _sd_buf_handle_t *handle2,
    nsc_off_t fba_pos1, nsc_off_t fba_pos2, nsc_size_t fba_len, int skew);
static int _sd_compare_handle(_sd_buf_handle_t *handle1,
    _sd_buf_handle_t *handle2, nsc_off_t fba_pos1, nsc_off_t fba_pos2,
    nsc_size_t fba_len, int skew);
static void _sd_direct_test(int c, int loop, int seed, int type);
static void set_parameters(void);
static void test_dma_loop(int net, int seg);
static int _sd_hwrite(_sd_buf_handle_t *buf, nsc_off_t fba_pos,
    nsc_size_t fba_len, int flag);
static void myend(blind_t arg, nsc_off_t fba_pos, nsc_size_t fba_len,
    int error);
static int test_control(int typ, int cd, nsc_off_t fba_pos, nsc_size_t fba_len);

int
_sim_write(_sd_buf_handle_t *buf, int x)
{
	int rval;

	if (test_stop)
		return (EINVAL);
	rval = _sd_write(buf, buf->bh_fba_pos, buf->bh_fba_len, x);
	return (rval == NSC_HIT ? NSC_DONE : rval);
}

static int
_sd_hwrite(_sd_buf_handle_t *buf, nsc_off_t fba_pos, nsc_size_t fba_len,
    int flag)
{
	int rval;

	rval = _sd_write(buf, fba_pos, fba_len, flag);
	return (rval == NSC_HIT ? NSC_DONE : rval);
}

#define	_sd_allocate_buf _trk_allocate_buf
#define	_sd_write	 _sim_write

/*
 * INF SD daemon global data
 */

volatile int	test_created;
static int	_sd_daemon_created;
static int 	_sd_num_daemons;

static struct gld {
	volatile int type;
	volatile int loop;
	volatile int seed;
	volatile int asleep;
	kcondvar_t blk;
} gld[MAX_TDAEMONS];

/*
 * _sdbc_tdaemon_load: cache is being loaded, initialize any global state that
 * isn't configurable (lock/sv's).
 */
int
_sdbc_tdaemon_load(void)
{
	int i;

	for (i = 0; i < MAX_TDAEMONS; i++)
		cv_init(&gld[i].blk, NULL, CV_DRIVER, NULL);

	mutex_init(&tdaemon_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&_wait_daemons, NULL, CV_DRIVER, NULL);

	return (0);
}
/*
 * _sdbc_tdaemon_unload: cache is being unloaded.
 */
void
_sdbc_tdaemon_unload(void)
{
	int i;

	for (i = 0; i < MAX_TDAEMONS; i++) {
		cv_destroy(&gld[i].blk);
	}

	mutex_destroy(&tdaemon_lock);
	cv_destroy(&_wait_daemons);

}

/*
 * _sdbc_tdaemon_configure: configure the desired number of test daemons.
 */
int
_sdbc_tdaemon_configure(int num)
{
	int i;

	if (num >= MAX_TDAEMONS)
		return (-1);

	for (i = 0; i < num; i++) {
	    cv_init(&gld[i].blk, NULL, CV_DRIVER, NULL);
	}
	mutex_enter(&tdaemon_lock);
	test_created = 1;
	test_stop = 0;
	_sd_num_daemons = 0;
	mutex_exit(&tdaemon_lock);

	mutex_enter(&_sd_cache_lock);
	if (_sd_daemon_created == 1) {
		mutex_exit(&_sd_cache_lock);
		return (-1);
	}
	_sd_daemon_created = 1;
	mutex_exit(&_sd_cache_lock);

	for (i = 0; i < num; i++) {
		(void) nsc_create_process(
			(void (*)(void *))_sd_idle_daemon, 0, FALSE);
	}

#ifdef DEBUG
	if (num)
	    cmn_err(CE_NOTE, "Starting %d SDBC test daemon(s).", num);
#endif
	return (0);
}

void
_sdbc_tdaemon_deconfigure(void)
{
	int i, running, retry = 30;

	if (_sd_num_daemons) {
		_sd_daemon_created = 0;

		mutex_enter(&tdaemon_lock);
		test_created = 0;
		test_stop = 1;
		mutex_exit(&tdaemon_lock);

		wakeup_all_tdaemons();
		while (retry--) {
			delay(HZ);
			running = 0;
			for (i = 0; i < _sd_num_daemons; i++)
				if (daemon_awake(i))
					running++;
			if (running == 0) break;
		}
	}
	for (i = 0; i < MAX_CD_STS; i++) {
		cv_destroy(&cd_test_sts[i].cd_blk);
		cd_test_sts[i].inited = 0;
	}
	_sd_num_daemons = 0;
}


int sind = 0;

/*
 * Globals to change test parameters - Initially added for tests written
 * by Ajay
 */
#ifdef SD_TDAEMON_DEBUG
struct statis {
	int cd;
	nsc_size_t len;
	nsc_off_t offset;
	int type;
} statis[4000];

#define	add_statis(c, l, o, t) (statis[sind].cd = (c), \
				statis[sind].len = (l), \
				statis[sind].offset = (o), \
				statis[sind].type = (t), sind++)
int
statis_upd(caddr_t adr)
{
	(void) copyout(statis, adr, sizeof (struct statis) * sind);
	return (sind);
}
#endif /* SD_TDAEMON_DEBUG */

static int
daemon_awake(int i)
{
	if (gld[i].asleep == 2)
		return (1);
	return (0);
}

static int
daemon_nexist(int i)
{
	if (gld[i].asleep == 0)
		return (1);
	return (0);
}

static void
daemon_wakeup(int i)
{
#ifdef _SD_DEBUG
	cmn_err(CE_NOTE, "unblocking %d %x", i, gld[i].blk);
#endif
	mutex_enter(&tdaemon_lock);
	cv_broadcast(&gld[i].blk);
	mutex_exit(&tdaemon_lock);
}


static void
wakeup_all_tdaemons(void)
{
	int i;

	for (i = 0; i < _sd_num_daemons; i++)
		daemon_wakeup(i);
}


static void
_sd_idle_daemon(void)
{
	int who;	/* id of this daemon */

	mutex_enter(&_sd_cache_lock);
	_sd_cache_dem_cnt++;
	who = _sd_num_daemons++;
	mutex_exit(&_sd_cache_lock);

	/* CONSTCOND */
	while (1) {
		mutex_enter(&tdaemon_lock);
		gld[who].asleep = 1;
#ifdef DEBUG
		cmn_err(CE_NOTE, "%d daemon: sleeping %p", who,
		    (void *)&gld[who].blk);
#endif

		cv_signal(&_wait_daemons);
		if (test_created == 0) {
			gld[who].asleep = 0;
			mutex_exit(&tdaemon_lock);
			mutex_enter(&_sd_cache_lock);
			_sd_cache_dem_cnt--;
			mutex_exit(&_sd_cache_lock);
			return;
		} else {
			cv_wait(&gld[who].blk, &tdaemon_lock);
			mutex_exit(&tdaemon_lock);
		}

		_sd_print(0, "%d daemon awake type %d loop %d seed %d",
		    who, gld[who].type, gld[who].loop, GET_SEED(who));

		if (test_created == 0) {
			gld[who].asleep = 0;
			mutex_enter(&_sd_cache_lock);
			_sd_cache_dem_cnt--;
			mutex_exit(&_sd_cache_lock);
			return;
		}
		gld[who].asleep = 2;

		switch (gld[who].type) {

		case 210:
			test_dma_loop(gld[who].loop, gld[who].seed);
			break;
		case 323:
			_sd_direct_test(who, gld[who].loop, GET_SEED(who), 0);
			break;

		case 350:
			_sd_test_rwloop_seq(who, gld[who].loop, GET_SEED(who),
			    1);
			break;
		case 351:
			_sd_test_rwloop_seq(who, gld[who].loop, GET_SEED(who),
			    0);
			break;

#if 0
		case 400:
			if (gld[who].loop >= 6)
				numdevs = gld[who].loop;
			break;
#endif
		default:
			cmn_err(CE_WARN, "%d daemon %d type inval\n", who,
			    gld[who].type);
			break;
		}
		if (test_created == 0) {
			gld[who].asleep = 0;
			mutex_enter(&_sd_cache_lock);
			_sd_cache_dem_cnt--;
			mutex_exit(&_sd_cache_lock);
			return;
		}
	}
}


static void
_td_attach_cd(int cd)
{
	(void) nsc_reserve(_sd_cache_files[cd].cd_rawfd, NSC_MULTI);
}


static void
_td_detach_cd(int cd)
{
	nsc_release(_sd_cache_files[cd].cd_rawfd);
}


int
_sd_test_start(void *args, int *rvp)
{

	register struct a {
		long num;
		long type;
		long loop;
		long from;
		long seed;
	} *uap = (struct a *)args;

	*rvp = _fork_test_daemon(uap->num, uap->type, uap->loop,
					uap->from, uap->seed);

	return (0);
}

static int
test_control(int typ, int cd, nsc_off_t fba_pos, nsc_size_t fba_len)
/*
 * test_control - perform control operations outside of the range
 * of a test. This is typically called before/after a series of
 * tests to either check a result or to setup/free a device.
 */
{
	int rc = 0;

	if ((cd < 0) || (cd >= sdbc_max_devs))
		return (-1);
	switch (typ) {
	case 1:
		rc = _sdbc_io_attach_cd((blind_t)(unsigned long)cd);
		cmn_err(CE_NOTE, "_sdbc_io_attach_cd(%d): %d", cd, rc);
		break;
	case 2:
		rc = _sdbc_io_detach_cd((blind_t)(unsigned long)cd);
		cmn_err(CE_NOTE, "_sdbc_io_detach_cd(%d): %d", cd, rc);
		break;
	case 3:
		_test_async_fail = _sd_cache_files[cd].cd_crdev;
		cmn_err(CE_NOTE, "async fail dev %lu (cd=%d)", _test_async_fail,
		    cd);
		break;
	case 4:
		_test_async_fail = 0;
		cmn_err(CE_NOTE, "async fail cleared");
		break;
#if 0
	case 5:
		_trk_alloc_flag = NSC_PINNABLE;
		break;
	case 6:
		_trk_alloc_flag = 0;
		break;
#endif
	case 7:
		rc = _sd_get_pinned((blind_t)(unsigned long)cd);
		cmn_err(CE_NOTE, "get_pinned(%d): %d", cd, rc);
		break;
	case 8:
		rc = _sd_discard_pinned((blind_t)(unsigned long)cd, fba_pos,
		    fba_len);
		cmn_err(CE_NOTE, "discard_pinned(%d,%" NSC_SZFMT ",%" NSC_SZFMT
		    "): %d", cd, fba_pos, fba_len, rc);
		break;
	default:
		cmn_err(CE_WARN, "cache device command %d invalid\n", typ);
	}
	return (rc);
}


/*
 * _fork_sd_daemon(): Fork an nunix process that periodically flushes the
 *                    raw device buffer cache
 */

static int
_fork_test_daemon(int num_disks, int test_typ, int loop_cnt, int from, int seed)
{
	int i;
	int type;
	int dowait = 0, verify = 0;

	if (num_disks == -1) {
		return (test_control(test_typ, loop_cnt, from, seed));
	}

	type = test_typ;
	cmn_err(CE_NOTE,
	    "sd_test %d %d %d %d %d", num_disks, type, loop_cnt, from, seed);
	if (type == 100) {
		test_stop = 1;
		return (0);
	}

	if (type == 99) {
		/* Set some parameters for other tests */
		switch (num_disks) {
			/* Params set for this test */
#if 0
			case 302 :
				_sd_write_len = loop_cnt;
				break;
			case 303 :
				_sd_write_len = loop_cnt;
				break;
			case 304 :
				_sd_trk_zero = loop_cnt;
				_sd_trk_size = from;
				break;
			case 305 :
				_sd_min_blks = loop_cnt;
				_sd_max_blks = from;
				break;
#endif
			default :
				cmn_err(CE_WARN,
				    "Usage : sd_test <test_num> 99"
				    " <param1> <param2> <param3>");
				break;
		}
		return (0);
	}		/* type == 99 */

	if (type > 1000) {
		dowait = 1;
		type -= 1000;
	}
	if (type > 1000) {
		verify = 1;
		type -= 1000;
	}

again:
	set_parameters();

	for (i = from; i < (from+num_disks); i++) {
		if (daemon_awake(i)) {
			cmn_err(CE_WARN, "Daemon %d awake!?", i);
			return (-1);
		}
		if (daemon_nexist(i)) {
			cmn_err(CE_WARN, "Daemon %d nexist!?", i);
			return (-1);
		}

		gld[i].type = type;
		gld[i].loop = loop_cnt;
		gld[i].seed = seed;
		daemon_wakeup(i);
	}
	cmn_err(CE_CONT, "%d daemons woken (test %d)\n", num_disks, type);
	if (num_disks <= 0)
		return (0);

	if (dowait) {
	wait:
		mutex_enter(&tdaemon_lock);
		if (!cv_wait_sig(&_wait_daemons, &tdaemon_lock)) {
			mutex_exit(&tdaemon_lock);
			test_stop = 1;
			cmn_err(CE_WARN, "Interrupt: stopping tests");
			return (-1); /* interrupt */
		}
		mutex_exit(&tdaemon_lock);

		/* wait for all to stop */
		if (test_stop)
			return (-1);
		for (i = from; i < (from+num_disks); i++) {
			if (daemon_awake(i))
				goto wait;
		}
	}
	if (verify) {
		verify = 0;
		type++;		/* next test */
		goto again;
	}
	return (0);
}

int
_sd_test_end(void)
{
	test_created = 0;
	test_stop = 1;
	return (0);
}

int
_sd_test_init(void *args)
{
	register struct a {
		caddr_t addr;
		long ar;
		long len;
		long tsize;
		long flag;
	} *uap = (struct a *)args;

	if (copyin(uap->addr, devarray[uap->ar], uap->len)) {
		return (EFAULT);
	}
	dev_tsize[uap->ar] = (uap->tsize < 48) ? 48 : uap->tsize;
	dev_flag[uap->ar] = uap->flag;
	return (0);
}


typedef struct io_type {
	int cd, tsize;
	_sd_buf_handle_t *wbuf, *rbuf;
	int len, len2, rnet, wnet;
	int trk_num, trk_off;
	int offset, boff;
	char test_pattern;
} infnsc_io_t;

/* static spinlock_t INFSD_iolock = { SLK_IFS_SRVR, 0 }; */
#define	_INFSD_TRK_SIZE() (64*1024)
#define	_INFSD_BUF_ALIGN 512	/* Each read/write should be 512 aligned */

/*
 * _sd_test_rwloop_seq(i,loops, seed, forw):
 *
 * Sequential I/O test. Writes track records sequentially, either forwards
 * or backwards (forw = 1 or forw = 0), writing a fixed pattern with a
 * few unique bytes depending on loop id. Then reads back, checking
 * for data consistency.
 */

/* ARGSUSED */
static void
_sd_test_rwloop_seq(int i, int loops, int seed, int forw)
{
	int cd;
	int j, len;
	nsc_off_t offset;
	nsc_size_t fsize;
	int sts;
	_sd_buf_handle_t *fbuf, *buf;

	if (strlen(devarray[i]) == 0) {
		cmn_err(CE_WARN, "child %d devarray null", i);
		return;
	}
	if ((cd = _sd_open(devarray[i], dev_flag[i])) < 0) {
		cmn_err(CE_WARN, "Open error %s child %d", devarray[i], i);
		return;
	}
	SET_CD_STATE(cd, i);
	_td_attach_cd(cd);

	(void) _sd_get_partsize((blind_t)(unsigned long)cd, &fsize);
	len = 120;

	/*
	 * Write a base pattern into the first buffer
	 */
	fbuf = NULL;
	offset = 0;
	sts = _sd_alloc_buf((blind_t)(unsigned long)cd, 0, len, NSC_WRBUF,
	    &fbuf);
	if (sts > 0)  {
		cmn_err(CE_WARN, "Buffer alloc failed %d", sts);
		return;
	}
	(void) _sd_copy_pattern_to_handle(fbuf, 0, len);
	_td_detach_cd(cd);

	offset = 0;
	for (j = 0; j < loops; j++) {
		if (test_stop == 1) goto done;

		offset += len;
		if (offset + len > fsize)
			break;

		buf = NULL;
		_td_attach_cd(cd);
		sts = _sd_alloc_buf((blind_t)(unsigned long)cd, offset, len,
		    NSC_WRBUF, &buf);
		if (sts > 0) {
			cmn_err(CE_WARN, "ch %d getbuf error(WRBUF)%d", i, sts);
			goto done;
		}
		(void) _sd_copy_handle(fbuf, buf, 0, offset, len, j);

		sts = len;
		while (sts > 0) {
			if (forw && _sd_hwrite(buf, offset + len - sts,
			    12, 0) > 0) {
				cmn_err(CE_WARN, "ch %d fwwr err", i);
				test_stop = 1;
			}
			sts -= 12;
			if (!forw && _sd_hwrite(buf, offset + sts, 12, 0) > 0) {
				cmn_err(CE_WARN, "ch %d rvwr err", i);
				test_stop = 1;
			}
		}
		if (sts = _sd_free_buf(buf)) {
			cmn_err(CE_WARN, "ch %d freebuf error %d", i, sts);
			goto done;
		}
		_td_detach_cd(cd);
	}
	offset = 0;
	for (j = 0; j < loops; j++) {
		if (test_stop == 1) goto done;

		offset += len;
		if (offset + len > fsize)
			break;

		buf = NULL;
		_td_attach_cd(cd);
		sts = _sd_alloc_buf((blind_t)(unsigned long)cd, offset, len,
		    NSC_RDBUF, &buf);
		if (sts > 0) {
			cmn_err(CE_WARN, "ch %d getbuf error(WRBUF)%d", i, sts);
			goto done;
		}
		(void) _sd_compare_handle(fbuf, buf, 0, offset, len, j);

		if (sts = _sd_free_buf(buf)) {
			cmn_err(CE_WARN, "ch %d freebuf error %d", i, sts);
			goto done;
		}
		_td_detach_cd(cd);
	}
done:
	if (sts = _sd_free_buf(fbuf))
		cmn_err(CE_WARN, "child %d freebuf error %d", i, sts);
	cmn_err(1, "TEST OVER : rwloop_seq_%s() child %d",
	    forw ? "forw" : "rev", i);
}

static int
_sd_copy_pattern_to_handle(_sd_buf_handle_t *handle, nsc_off_t fba_pos,
    nsc_size_t fba_len)
{
	sdbc_cblk_fba_t st_cblk_len;	/* FBA len of starting cache block */
	sdbc_cblk_fba_t end_cblk_len;	/* FBA len of ending cache block */
	sdbc_cblk_fba_t st_cblk_off;	/* FBA offset into starting cblock */
	nsc_size_t cur_fba_len;
	int i;
	_sd_cctl_t *cc_ent;

	cc_ent = handle->bh_centry;
	while (CENTRY_BLK(cc_ent) != FBA_TO_BLK_NUM(fba_pos))
		cc_ent = cc_ent->cc_chain;

	cur_fba_len = fba_len;
	st_cblk_off = BLK_FBA_OFF(fba_pos);
	st_cblk_len = (BLK_FBAS - st_cblk_off);
	if ((nsc_size_t)st_cblk_len >= fba_len) {
		end_cblk_len = 0;
		st_cblk_len = (sdbc_cblk_fba_t)fba_len;
	} else
		end_cblk_len = BLK_FBA_OFF(fba_pos + fba_len);

	for (i = 0; i < (int)FBA_SIZE(st_cblk_len); i += 4)
		*((uint_t *)(void *)(cc_ent->cc_data + FBA_SIZE(st_cblk_off) +
		    i)) = nsc_usec();
	cur_fba_len -= st_cblk_len;
	cc_ent = cc_ent->cc_chain;

	while (cur_fba_len > (nsc_size_t)end_cblk_len) {
		for (i = 0; i < CACHE_BLOCK_SIZE; i += 4) {
			unsigned int usec = nsc_usec();
			bcopy(&usec, cc_ent->cc_data + i, 4);
		}
		cc_ent = cc_ent->cc_chain;
		cur_fba_len -= BLK_FBAS;
	}
	if (cur_fba_len) {
		for (i = 0; i < (int)FBA_SIZE(end_cblk_len); i += 4) {
			unsigned int usec = nsc_usec();
			bcopy(&usec, cc_ent->cc_data + i, 4);
		}
	}
	return (0);
}

static int
_sd_copy_handle(_sd_buf_handle_t *handle1,
		_sd_buf_handle_t *handle2,
		nsc_off_t fba_pos1,
		nsc_off_t fba_pos2,
		nsc_size_t fba_len,
		int skew)
{
	sdbc_cblk_fba_t st_cblk_len;	/* FBA len of starting cache block */
	sdbc_cblk_fba_t end_cblk_len;	/* FBA len of ending cache block */
	sdbc_cblk_fba_t st_cblk_off;	/* FBA offset into starting cblock */
	nsc_size_t cur_fba_len;
	_sd_cctl_t *cc_ent, *cc_ent1;
	unsigned char *skew_word;
	int skew_count = 0;

	ASSERT_HANDLE_LIMITS(handle1, fba_pos1, fba_len);
	ASSERT_HANDLE_LIMITS(handle2, fba_pos2, fba_len);

	cc_ent = handle1->bh_centry;
	while (CENTRY_BLK(cc_ent) != FBA_TO_BLK_NUM(fba_pos1))
		cc_ent = cc_ent->cc_chain;

	cc_ent1 = handle2->bh_centry;
	while (CENTRY_BLK(cc_ent1) != FBA_TO_BLK_NUM(fba_pos2))
		cc_ent1 = cc_ent1->cc_chain;


	if (BLK_FBA_OFF(fba_pos1) != BLK_FBA_OFF(fba_pos2)) {
		cmn_err(CE_WARN, "Cannot copy unaligned handles");
		return (0);
	}

	cur_fba_len = fba_len;
	st_cblk_off = BLK_FBA_OFF(fba_pos1);
	st_cblk_len = (BLK_FBAS - st_cblk_off);
	if ((nsc_size_t)st_cblk_len >= fba_len) {
		end_cblk_len = 0;
		st_cblk_len = (sdbc_cblk_fba_t)fba_len;
	} else
		end_cblk_len = BLK_FBA_OFF(fba_pos1 + fba_len);

	skew_word = cc_ent->cc_data + FBA_SIZE(st_cblk_off);
	*skew_word = skew | (++skew_count << 24);
	bcopy(cc_ent->cc_data + FBA_SIZE(st_cblk_off), cc_ent1->cc_data +
	    FBA_SIZE(st_cblk_off), FBA_SIZE(st_cblk_len));
	cur_fba_len -= st_cblk_len;
	cc_ent = cc_ent->cc_chain;
	cc_ent1 = cc_ent1->cc_chain;

	while (cur_fba_len > (nsc_size_t)end_cblk_len) {
		skew_word = cc_ent->cc_data;
		*skew_word = skew | (++skew_count << 24);
		bcopy(cc_ent->cc_data, cc_ent1->cc_data, CACHE_BLOCK_SIZE);
		cc_ent = cc_ent->cc_chain;
		cc_ent1 = cc_ent1->cc_chain;
		cur_fba_len -= BLK_FBAS;
	}
	if (cur_fba_len) {
		skew_word = cc_ent->cc_data;
		*skew_word = skew | (++skew_count << 24);
		bcopy(cc_ent->cc_data, cc_ent1->cc_data,
		    FBA_SIZE(end_cblk_len));
	}
	return (0);
}

static int
_sd_compare_handle(_sd_buf_handle_t *handle1, _sd_buf_handle_t *handle2,
    nsc_off_t fba_pos1, nsc_off_t fba_pos2, nsc_size_t fba_len, int skew)
{
	sdbc_cblk_fba_t st_cblk_len;	/* FBA len of starting cache block */
	sdbc_cblk_fba_t end_cblk_len;	/* FBA len of ending cache block */
	sdbc_cblk_fba_t st_cblk_off;	/* FBA offset into starting cblock */
	nsc_size_t cur_fba_len;
	_sd_cctl_t  *cc_ent, *cc_ent1;
	unsigned char *skew_word;
	int skew_count = 0;

	ASSERT_HANDLE_LIMITS(handle1, fba_pos1, fba_len);
	ASSERT_HANDLE_LIMITS(handle2, fba_pos2, fba_len);

	cc_ent = handle1->bh_centry;
	while (CENTRY_BLK(cc_ent) != FBA_TO_BLK_NUM(fba_pos1))
		cc_ent = cc_ent->cc_chain;

	cc_ent1 = handle2->bh_centry;
	while (CENTRY_BLK(cc_ent1) != FBA_TO_BLK_NUM(fba_pos2))
		cc_ent1 = cc_ent1->cc_chain;

	if (BLK_FBA_OFF(fba_pos1) != BLK_FBA_OFF(fba_pos2)) {
		cmn_err(CE_WARN, "Cannot compare unaligned handles");
		return (0);
	}

	cur_fba_len = fba_len;
	st_cblk_off = BLK_FBA_OFF(fba_pos1);
	st_cblk_len = (BLK_FBAS - st_cblk_off);
	if ((nsc_size_t)st_cblk_len >= fba_len) {
		end_cblk_len = 0;
		st_cblk_len = (sdbc_cblk_fba_t)fba_len;
	} else
		end_cblk_len = BLK_FBA_OFF(fba_pos1 + fba_len);

	skew_word = cc_ent->cc_data + FBA_SIZE(st_cblk_off);
	*skew_word = skew | (++skew_count << 24);
	if (bcmp(cc_ent->cc_data + FBA_SIZE(st_cblk_off),
	    cc_ent1->cc_data + FBA_SIZE(st_cblk_off),
	    FBA_SIZE(st_cblk_len)) != 0)
		cmn_err(CE_WARN, "Data mismatch fba_pos:%" NSC_SZFMT, fba_pos2);

	cur_fba_len -= st_cblk_len;
	cc_ent = cc_ent->cc_chain;
	cc_ent1 = cc_ent1->cc_chain;

	while (cur_fba_len > (nsc_size_t)end_cblk_len) {
		skew_word = cc_ent->cc_data;
		*skew_word = skew | (++skew_count << 24);
		if (bcmp(cc_ent->cc_data, cc_ent1->cc_data,
		    CACHE_BLOCK_SIZE) != 0)
			cmn_err(CE_WARN, "Data mismatch fba_pos:%" NSC_SZFMT,
			    fba_pos2);

		cc_ent = cc_ent->cc_chain;
		cc_ent1 = cc_ent1->cc_chain;
		cur_fba_len -= BLK_FBAS;
	}
	if (cur_fba_len) {
		skew_word = cc_ent->cc_data;
		*skew_word = skew | (++skew_count << 24);
		if (bcmp(cc_ent->cc_data, cc_ent1->cc_data,
		    FBA_SIZE(end_cblk_len)) != 0)
			cmn_err(CE_WARN, "Data mismatch fba_pos:%" NSC_SZFMT,
			    fba_pos2);
	}
	return (0);
}

/*
 * Macro definition for waiting for an IO buffer to be allocated or a read
 * to complete. Macro defined so code doesn't have to be typed each time
 */
#define	WAIT_IO(st, cd, buf, l) \
if ((st != NSC_DONE) && (st != NSC_HIT)) { \
	if (st != NSC_PENDING) \
		cmn_err(CE_WARN, "alloc sts: %d", st); \
	else { \
		buf = wait_io(cd, &st); \
		if (st) { \
			cmn_err(CE_WARN, "ch %d getbuf errpr %d\n", l, st); \
			if (buf) \
				(void) _sd_free_buf(buf); \
			return; \
		} \
	} \
}


#undef  _sd_write

static int tiodone, iosent, tioerr;

/* ARGSUSED */

static void
myend(blind_t arg, nsc_off_t fba_pos, nsc_size_t fba_len, int error)
{
	if (error)
		tioerr++;
	else 	tiodone++;
}

static int ckd_sskip = 3;

/* ARGSUSED3 */
static void
_sd_direct_test(int c, int loop, int seed, int type)
{
	nsc_size_t filesize;
	int loops;

	int cd;
	int ckd_hd, recs, rec_size, ckd_doz;
	int done_size;
	clock_t st_time;
	int i;

	int ckd_hd_sz, rec_bsz;
	int print_stuff;
	int throttle;
	struct buf *bp;
	nsc_off_t curpos;

	caddr_t caddr;
	iosent = 0;

	print_stuff = 0;
	seed = gld[c].seed;
	rec_size = (seed & 0xff);
	recs = (seed & 0xf00)>>8;
	ckd_hd = (seed & 0xf000)>>12;
	ckd_doz = (seed & 0xf0000)>>16;
	throttle = (seed & 0xff00000)>>20;
	ckd_hd_sz = ckd_hd * 512;
	rec_bsz = rec_size * 512;

	done_size = 0;
	tiodone = 0;
	curpos = 0;
	tioerr = 0;

	if (strlen(devarray[c]) == 0) {
		cmn_err(CE_WARN, "child %d devarray null\n", c);
		return;
	}
	if ((cd = _sd_open(devarray[c], dev_flag[c])) < 0) {
		cmn_err(CE_WARN, "Open error %s child %d\n", devarray[c], c);
		return;
	}

	caddr = (caddr_t)nsc_kmem_alloc(20 * 8192, KM_SLEEP, sdbc_local_mem);

	(void) _sd_get_partsize((blind_t)(unsigned long)cd, &filesize);
	filesize = FBA_SIZE(filesize);
	loops = ((nsc_size_t)loop > (filesize / (60 * 1024))) ?
	    (filesize / (60 * 1024)) : loop;

	st_time = nsc_usec();
	cmn_err(CE_CONT, "Test 100: %s file %d cd %d loops %x seed\n",
	    devarray[c], cd, loop, seed);
	cmn_err(CE_CONT,
	    "Test 100: %d recsize %d recs %d throttle %d hd %d doz\n",
	    rec_size, recs, throttle, ckd_hd, ckd_doz);

	for (i = 0; i < loops; i++) {
		curpos = i * 120;
		if (ckd_doz) {
			bp = sd_alloc_iob(_sd_cache_files[cd].cd_crdev,
					curpos, 20, B_WRITE);
			sd_add_mem(bp, caddr, ckd_hd_sz);
			(void) sd_start_io(bp,
			    _sd_cache_files[cd].cd_strategy, myend, NULL);
			iosent++;
			curpos += ckd_sskip;
		}
		if (ckd_doz == 2) {
			bp = sd_alloc_iob(_sd_cache_files[cd].cd_crdev,
					curpos, 20, B_WRITE);
			sd_add_mem(bp, caddr, 4096-ckd_sskip*512);
			(void) sd_start_io(bp,
			    _sd_cache_files[cd].cd_strategy, myend, NULL);
			iosent++;
			curpos += 4096-ckd_sskip*512;
		}
		bp = sd_alloc_iob(_sd_cache_files[cd].cd_crdev,
		    curpos, 20, B_WRITE);
		sd_add_mem(bp, caddr, recs * rec_bsz);
		(void) sd_start_io(bp,
		    _sd_cache_files[cd].cd_strategy, myend, NULL);
		iosent++;

		done_size += recs * rec_bsz;

		if (tiodone && ((tiodone / 300) > print_stuff)) {
			cmn_err(CE_CONT, "Done %d ios %d size in %lu time\n",
			    tiodone,
			    ckd_doz ? ((ckd_doz == 2) ?
			    (tiodone * (recs * rec_bsz + 4096)) / 3:
			    (tiodone * (recs * rec_bsz + ckd_hd_sz)) / 2) :
			    (tiodone * (recs * rec_bsz)),
			    (nsc_usec() - st_time) / 1000);
			print_stuff++;
		}
		while ((iosent - (tiodone + tioerr)) > throttle)
			;
	}
	while ((tiodone + tioerr) < iosent) {
		if (tiodone && ((tiodone / 300) > print_stuff)) {
			cmn_err(CE_CONT, "Done %d ios %d size in %lu time\n",
			    tiodone,
			    ckd_doz ? ((ckd_doz == 2) ?
			    (tiodone * (recs * rec_bsz + 4096)) / 3:
			    (tiodone * (recs * rec_bsz + ckd_hd_sz)) / 2) :
			    (tiodone * (recs * rec_bsz)),
			    (nsc_usec() - st_time) / 1000);
			print_stuff++;
		}
	}
	cmn_err(CE_CONT, "Done %d ios %d size in %lu time\n",
	    tiodone,
	    ckd_doz ? ((ckd_doz == 2) ?
	    (tiodone * (recs * rec_bsz + 4096)) / 3:
	    (tiodone * (recs * rec_bsz + ckd_hd_sz)) / 2) :
	    (tiodone * (recs * rec_bsz)),
	    (nsc_usec() - st_time) / 1000);

	print_stuff++;
	nsc_kmem_free(caddr, 20 * 8192);
}

static void
set_parameters(void)
{
	test_stop = 0;
}

static nsc_mem_t *dma_test = NULL;
static int *dma_mem = NULL;

static int
init_dmatest(void)
{
	dma_test = nsc_register_mem("dmatest:mem", NSC_MEM_GLOBAL, 0);
	dma_mem = (int *)nsc_kmem_zalloc(4096, 0, dma_test);
	if (!dma_mem) {
		cmn_err(CE_NOTE, "could not get rm mem\n");
		return (1);
	}
	cmn_err(CE_NOTE, "rm = 0x%p\n", (void *)dma_mem);
	return (0);
}

/*ARGSUSED*/
static void
release_dmatest(void)
{
	nsc_kmem_free(dma_mem, 1);
	nsc_unregister_mem(dma_test);
	dma_test = NULL;
	dma_mem = NULL;
}
/*ARGSUSED*/
static void
test_dma_loop(int net, int seg)
{
	delay(3*HZ);

	if (!dma_mem && init_dmatest()) {
		cmn_err(CE_WARN, "test_dma_loop: init failed");
		return;
	}

	/*
	 * The body of test loop is removed since we don't use any more
	 */

	release_dmatest();
}
