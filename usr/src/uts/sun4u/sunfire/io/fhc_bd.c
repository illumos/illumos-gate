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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/obpdefs.h>
#include <sys/promif.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/kstat.h>
#include <sys/debug.h>
#include <sys/fhc.h>
#include <sys/jtag.h>
#include <sys/sysctrl.h>

static fhc_bd_resizable_t boards; /* booted and hotplugged boards */
static fhc_bd_resizable_t clocks; /* clocks under central. */

static int fhc_bdmax;
/*
 * !! IMPORTANT !! fhc_bdlist_rwlock is implemented as a single
 * RW_WRITER lock with *no* RW_READERs -- and it should stay that
 * way.  The fhc_bdlist_rwlock should never be used with RW_READER.
 *
 * The lock was originally a mutex, but was changed to a
 * single-writer, zero-reader rwlock to force requesting threads
 * to block (sleep, not spin) when the RW_WRITER lock is already
 * held by a thread currently running.
 */
static krwlock_t fhc_bdlist_rwlock;
static sysc_evt_handle_t fhc_bd_evt;
static sysc_evt_handle_t *fbe = &fhc_bd_evt;

#define	fhc_bd_sc_evt(s, e)	(*fbe->update)(fbe->soft, s, e)
#define	FHC_INCREMENT 4
#define	FHC_B_SEARCH(in_array, board) \
	fhc_b_search(in_array.boards, board, 0, in_array.last);

static int	fhc_bd_disabled(int);
static void	fhc_check_array(int);
static void	fhc_shell_sort(fhc_bd_t **, int, int);
static int	fhc_b_search(fhc_bd_t **, int, int, int);
static void	fhc_check_size(fhc_bd_resizable_t *);
static void	fhc_resize(fhc_bd_t ***, int, int);


/*
 * fhc_bdmax gets set in fhc_bdlist_prime() and does not
 * change thereafter.
 */
int
fhc_max_boards()
{
	return (fhc_bdmax + 1);
}

static int
fhc_bd_disabled(int board)
{
	int index;

	ASSERT(boards.sorted);
	index = FHC_B_SEARCH(boards, board);
	ASSERT(index != -1);
	return (boards.boards[index]->flags & BDF_DISABLED);
}

static void
fhc_check_array(int btype)
{
	if (btype == FHC_BOARDS) {
		ASSERT(fhc_bdlist_locked());
		if (!boards.sorted) {
			fhc_shell_sort(boards.boards, 0, boards.last);
			boards.sorted = TRUE;
		}
	} else {
		ASSERT(fhc_bdlist_locked());
		if (!clocks.sorted) {
			fhc_shell_sort(clocks.boards, 0, clocks.last);
			clocks.sorted = TRUE;
		}
	}
}

static void
fhc_shell_sort(fhc_bd_t *a[], int lb, int ub)
{
	int n, h, i, j;
	fhc_bd_t *t;

	/* sort array a[lb..ub] */

	/* compute largest increment */
	n = ub - lb + 1;
	h = 1;
	if (n < 14)
		h = 1;
	else {
		while (h < n)
			h = 3 * h + 1;
		h /= 3;
		h /= 3;
	}

	while (h > 0) {
		/* sort-by-insertion in increments of h */
		for (i = lb + h; i <= ub; i++) {
			t = a[i];
			for (j = i - h;
			    j >= lb && a[j]->sc.board > t->sc.board;
			    j -= h) {
				a[j+h] = a[j];
			}
			a[j+h] = t;
		}

		/* compute next increment */
		h /= 3;
	}
}

static int
fhc_b_search(fhc_bd_t *in_array[], int board, int first, int last)
{
	int mid;

	/* Array of length 0 case. */
	if (in_array == NULL)
		return (-1);

	/* Array of length > 0 case. */
	while (first < last) {
		mid = (first + last) / 2;
		if (in_array[mid]->sc.board < board)
			first = mid + 1;
		else
			last = mid;
	}

	if (in_array[first]->sc.board == board) {
		return (first);
	} else {
		return (-1);
	}

}

static void
fhc_check_size(fhc_bd_resizable_t *resizable)
{
	int oldsize;
	int newsize;

	ASSERT(fhc_bdlist_locked());

	if (resizable->size == resizable->last + 1) {
		oldsize = sizeof (fhc_bd_t *) * resizable->size;
		resizable->size += FHC_INCREMENT;
		newsize = sizeof (fhc_bd_t *) * resizable->size;
		fhc_resize(&(resizable->boards), oldsize, newsize);
	}
}

int
fhc_bdlist_locked()
{
	if (panicstr)
		return (1);

	return (rw_owner(&fhc_bdlist_rwlock) == curthread);
}

int
fhc_bd_busy(int board)
{
	int index;

	ASSERT(boards.sorted);
	index = FHC_B_SEARCH(boards, board);
	ASSERT(index != -1);
	return (boards.boards[index]->sc.in_transition);
}

int
fhc_bd_is_jtag_master(int board)
{
	int index;

	ASSERT(boards.sorted);
	index = FHC_B_SEARCH(boards, board);
	ASSERT(index != -1);
	if (boards.boards[index]->softsp == NULL)
		return (FALSE);
	else
		return ((boards.boards[index]->softsp)->jt_master.is_master);
}

int
fhc_bd_is_plus(int board)
{
	int index;

	ASSERT(boards.sorted);
	index = FHC_B_SEARCH(boards, board);
	ASSERT(index != -1);
	if (boards.boards[index]->sc.plus_board)
		return (boards.boards[index]->sc.plus_board);
	else
		return (FALSE);
}

void
fhc_bdlist_init()
{
	ASSERT(!fhc_bdmax);
	rw_init(&fhc_bdlist_rwlock, NULL, RW_DEFAULT, NULL);
	boards.boards = NULL;
	boards.size = 0;
	boards.last = -1;
	boards.sorted = TRUE; /* Array of 0 elements is sorted. */

	clocks.boards = NULL;
	clocks.size = 0;
	clocks.last = -1;
	clocks.sorted = TRUE; /* Array of 0 elements is sorted. */
}

void
fhc_bdlist_fini()
{
	rw_destroy(&fhc_bdlist_rwlock);
}

fhc_bd_t *
fhc_bdlist_lock(int board)
{
	int index;

	ASSERT(!fhc_bdlist_locked());

	/* RW_WRITER *ONLY*.  Never use RW_READER! */
	rw_enter(&fhc_bdlist_rwlock, RW_WRITER);

	if (board == -1)
		return (NULL);
	else {
		ASSERT(boards.sorted);
		index = FHC_B_SEARCH(boards, board);
		ASSERT(index != -1);
		return (boards.boards[index]);
	}
}

void
fhc_bdlist_unlock()
{
	ASSERT(fhc_bdlist_locked());

	rw_exit(&fhc_bdlist_rwlock);
}

static void
fhc_resize(fhc_bd_t ***in_array, int oldsize, int newsize)
{
	fhc_bd_t **temp;

	/* This function only grows arrays. */
	ASSERT(newsize > oldsize);

	/* Allocate new array. */
	temp = kmem_alloc(newsize, KM_SLEEP);

	/* Bcopy old array and free it. */
	if (*in_array != NULL) {
		ASSERT(oldsize > 0);
		bcopy(*in_array, temp, oldsize);
		kmem_free(*in_array, oldsize);
	}
	*in_array = temp;
}

void
fhc_bd_init(struct fhc_soft_state *softsp, int board, enum board_type type)
{
	fhc_bd_t *bdp;
	int index;

	(void) fhc_bdlist_lock(-1);

	/* See if board already exists. */
	ASSERT(boards.sorted);
	ASSERT(clocks.sorted);
	if (softsp->is_central) {
		index = FHC_B_SEARCH(clocks, board);
	} else {
		index = FHC_B_SEARCH(boards, board);
	}

	/* If index == -1 board does not exist. */
	if (index != -1) {
		if (softsp->is_central) {
			bdp = clocks.boards[index];
		} else {
			bdp = boards.boards[index];
		}
	} else {
		if (softsp->is_central) {
			fhc_check_size(&clocks);
			clocks.boards[clocks.last + 1] =
			    kmem_zalloc(sizeof (fhc_bd_t), KM_SLEEP);
			bdp = clocks.boards[clocks.last + 1];
			clocks.last++;
			clocks.sorted = FALSE;
		} else {
			fhc_check_size(&boards);
			boards.boards[boards.last + 1] =
			    kmem_zalloc(sizeof (fhc_bd_t), KM_SLEEP);
			bdp = boards.boards[boards.last + 1];
			boards.last++;
			boards.sorted = FALSE;
		}
	}

	softsp->list = bdp;
	bdp->flags |= BDF_VALID;
	bdp->softsp = softsp;
	bdp->sc.type = type;
	bdp->sc.board = board;
	bdp->sc.plus_board = ISPLUSBRD(*softsp->bsr);

	/* Keep arrays sorted. */
	fhc_check_array(FHC_BOARDS);
	fhc_check_array(FHC_CLOCKS);

	fhc_bdlist_unlock();
}

fhc_bd_t *
fhc_bd(int board)
{
	int index;

	if (fhc_bdmax) {
		ASSERT(fhc_bdlist_locked());
	}
	ASSERT(boards.sorted);
	index = FHC_B_SEARCH(boards, board);
	ASSERT(index != -1);
	return (boards.boards[index]);
}

fhc_bd_t *
fhc_bd_clock(void)
{
	ASSERT(fhc_bdlist_locked());
	ASSERT(clocks.size != 0);

	return (clocks.boards[0]);
}

fhc_bd_t *
fhc_bd_first()
{
	ASSERT(fhc_bdlist_locked());
	if (boards.boards != NULL)
		return (boards.boards[0]);
	else
		return (NULL);
}

fhc_bd_t *
fhc_bd_next(fhc_bd_t *bdp)
{
	int index;

	ASSERT(boards.sorted);
	index = FHC_B_SEARCH(boards, bdp->sc.board);
	ASSERT(index != -1);
	if (index < boards.last)
		return (boards.boards[index + 1]);
	else
		return (NULL);
}

int
fhc_bd_valid(int bd)
{
	int index;

	ASSERT(bd >= 0);
	/* Untill fhc_bdlist_prime runs anything is valid. */
	if (!fhc_bdmax)
		return (TRUE);

	ASSERT(boards.sorted);
	index = FHC_B_SEARCH(boards, bd);
	if (index == -1)
		return (FALSE);
	else
		return (TRUE);
}

enum board_type
fhc_bd_type(int board)
{
	int index;

	ASSERT(boards.sorted);
	index = FHC_B_SEARCH(boards, board);
	if (index == -1)
		return (-1);

	return (boards.boards[index]->sc.type);
}

char *
fhc_bd_typestr(enum board_type type)
{
	char *type_str;

	switch (type) {
	case MEM_BOARD:
		type_str = MEM_BD_NAME;
		break;

	case CPU_BOARD:
		type_str = CPU_BD_NAME;
		break;

	case IO_2SBUS_BOARD:
		type_str = IO_2SBUS_BD_NAME;
		break;

	case IO_SBUS_FFB_BOARD:
		type_str = IO_SBUS_FFB_BD_NAME;
		break;

	case IO_2SBUS_SOCPLUS_BOARD:
		type_str = IO_2SBUS_SOCPLUS_BD_NAME;
		break;

	case IO_SBUS_FFB_SOCPLUS_BOARD:
		type_str = IO_SBUS_FFB_SOCPLUS_BD_NAME;
		break;

	case IO_PCI_BOARD:
		type_str = IO_PCI_BD_NAME;
		break;

	case DISK_BOARD:
		type_str = DISK_BD_NAME;
		break;

	case UNKNOWN_BOARD:
	default:
		type_str = "unknown";
		break;
	}

	return (type_str);
}

void
fhc_bd_env_set(int board, void *env)
{
	fhc_bd_t *bdp;

	bdp = fhc_bd(board);
	bdp->dev_softsp = env;
}

static void
fhc_bd_dlist_init()
{
	int i;
	int len;
	int board;
	pnode_t node;
	char *dlist;
	int index;

	/*
	 * Find the disabled board list property if present.
	 *
	 * The disabled board list is in the options node under root;
	 * it is a null terminated list of boards in a string.
	 * Each char represents a board. The driver must
	 * reject illegal chars in case a user places them in the
	 * property.
	 */
	if (((node = prom_finddevice("/options")) == OBP_BADNODE) ||
	    ((len = prom_getproplen(node, "disabled-board-list")) == -1))
		return;

	dlist = kmem_alloc(len, KM_SLEEP);
	(void) prom_getprop(node, "disabled-board-list", dlist);

	/*
	 * now loop thru the string, and create disabled board list
	 * entries for all legal boards in the list.
	 */
	for (i = 0; (i < len) && (dlist[i] != 0); i++) {
		char ch = dlist[i];

		if (ch >= '0' && ch <= '9')
			board = ch - '0';
		else if (ch >= 'A' && ch <= 'F')
			board = ch - 'A' + 10;
		else if (ch >= 'a' && ch <= 'f')
			board = ch - 'a' + 10;
		else
			/* junk entry */
			continue;

		index = FHC_B_SEARCH(boards, board);
		if (index != -1) {
			boards.boards[index]->flags |= BDF_DISABLED;
		}
	}
	kmem_free(dlist, len);
}

static struct bd_info fhc_bd_info;

static int
fhc_bd_ks_update(kstat_t *ksp, int rw)
{
	fhc_bd_t *bdp;
	sysc_cfga_stat_t *sc;
	struct bd_info *uip;
	enum board_state state;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	bdp = (fhc_bd_t *)ksp->ks_private;
	uip = &fhc_bd_info;
	sc = &bdp->sc;

	ASSERT(fhc_bd_valid(sc->board));

	uip->board = sc->board;
	uip->type = sc->type;
	uip->fhc_compid = sc->fhc_compid;
	uip->ac_compid = sc->ac_compid;
	bcopy((caddr_t)sc->prom_rev, uip->prom_rev, sizeof (uip->prom_rev));
	bcopy((caddr_t)&sc->bd, &uip->bd, sizeof (union bd_un));

	switch (sc->rstate) {
	case SYSC_CFGA_RSTATE_DISCONNECTED:
		switch (sc->condition) {
		case SYSC_CFGA_COND_OK:
		case SYSC_CFGA_COND_UNKNOWN:
			state = DISABLED_STATE;
			break;
		case SYSC_CFGA_COND_FAILING:
		case SYSC_CFGA_COND_FAILED:
		case SYSC_CFGA_COND_UNUSABLE:
			state = FAILED_STATE;
			break;
		default:
			state = UNKNOWN_STATE;
			break;
		}
		break;
	default:
		state = UNKNOWN_STATE;
		break;
	}

	uip->state = state;

	return (0);
}

void
fhc_bd_ks_alloc(fhc_bd_t *bdp)
{
	ASSERT(!bdp->ksp);

	bdp->ksp = kstat_create("unix", bdp->sc.board,
		BDLIST_KSTAT_NAME, "misc", KSTAT_TYPE_RAW,
		sizeof (struct bd_info), KSTAT_FLAG_VIRTUAL);

	if (bdp->ksp != NULL) {
		bdp->ksp->ks_data = &fhc_bd_info;
		bdp->ksp->ks_update = fhc_bd_ks_update;
		bdp->ksp->ks_private = (void *)bdp;
		kstat_install(bdp->ksp);
	}
}

static void
fhc_bdlist_dk_init()
{
	dev_info_t *dnode;

	/*
	 * Search the children of root to see if there are any
	 * disk boards in the tree.
	 */
	for (dnode = ddi_get_child(ddi_root_node());
	    dnode != NULL; dnode = ddi_get_next_sibling(dnode)) {
		if (strcmp(ddi_node_name(dnode), "disk-board") == 0) {
			int id;
			int board;
			fhc_bd_t *bdp;
			sysc_cfga_stat_t *sc;

			/*
			 * Get the board number property.
			 */
			if ((board = (int)ddi_getprop(DDI_DEV_T_ANY, dnode,
				DDI_PROP_DONTPASS, OBP_BOARDNUM, -1)) == -1) {
				cmn_err(CE_WARN,
					"Could not find board number");
				continue;
			}
			bdp = fhc_bd(board);
			sc = &bdp->sc;

			if ((id = (int)ddi_getprop(DDI_DEV_T_ANY, dnode,
			    DDI_PROP_DONTPASS, "disk0-scsi-id", -1)) != -1) {
				sc->bd.dsk.disk_pres[0] = 1;
				sc->bd.dsk.disk_id[0] = id;
			} else {
				sc->bd.dsk.disk_pres[0] = 0;
			}

			if ((id = (int)ddi_getprop(DDI_DEV_T_ANY, dnode,
			    DDI_PROP_DONTPASS, "disk1-scsi-id", -1)) != -1) {
				sc->bd.dsk.disk_pres[1] = 1;
				sc->bd.dsk.disk_id[1] = id;
			} else {
				sc->bd.dsk.disk_pres[1] = 0;
			}

		}
	}

}

struct jt_mstr *
jtag_master_lock(void)
{
	fhc_bd_t *bdp;
	struct jt_mstr *master = NULL;

	ASSERT(fhc_bdlist_locked());

	/*
	 * Now search for the JTAG master and place the addresses for
	 * command into the fhc soft state structure.
	 * Disk board do not have softsp set.
	 */
	for (bdp = fhc_bd_first(); bdp; bdp = fhc_bd_next(bdp))
		if (bdp->softsp && (bdp->softsp->jt_master.is_master == 1)) {
			master = &bdp->softsp->jt_master;
			mutex_enter(&master->lock);
			break;
		}

	return (master);
}

void
jtag_master_unlock(struct jt_mstr *mstr)
{
	ASSERT(fhc_bdlist_locked());
	ASSERT(mutex_owned(&mstr->lock));

	mutex_exit(&mstr->lock);
}

void
fhc_bdlist_prime(int first, int count, int incr)
{
	int board;
	fhc_bd_t *bdp;
	sysc_evt_t se;
	sysc_cfga_stat_t *sc;
	struct jt_mstr *jtm;
	int index;
	int nadded;

	ASSERT(fbe->update);

	(void) fhc_bdlist_lock(-1);
	nadded = 0;
	for (board = first; board < count; board += incr) {
		/*
		 * Search only subset of array. We hold mutex so
		 * noone can add new elements to it.
		 */
		index = fhc_b_search(boards.boards, board, 0,
		    boards.last - nadded);
		if (index == -1) {
			fhc_check_size(&boards);
			boards.boards[boards.last + 1] =
			    kmem_zalloc(sizeof (fhc_bd_t), KM_SLEEP);
			boards.boards[boards.last + 1]->sc.type = UNKNOWN_BOARD;
			boards.boards[boards.last + 1]->sc.board = board;
			boards.boards[boards.last + 1]->softsp = NULL;
			boards.last++;
			nadded++;
			boards.sorted = FALSE;
		}
	}
	fhc_check_array(FHC_BOARDS);
	fhc_bdlist_unlock();

	fhc_bdmax = count - 1;

	/*
	 * Initialize our copy of the disabled board list.
	 */
	fhc_bd_dlist_init();

	(void) fhc_bdlist_lock(-1);

	if ((jtm = jtag_master_lock()) == NULL)
		cmn_err(CE_PANIC, "fhc_bdlist_prime: no jtag master");

	/*
	 * Go through the board list, skipping illegal slots
	 * and initialize each slot.
	 */
	for (bdp = fhc_bd_first(); bdp; bdp = fhc_bd_next(bdp)) {
		sc = &bdp->sc;
		board = sc->board;

		se = SYSC_EVT_BD_PRESENT;

		if (sc->type == UNKNOWN_BOARD) {
			uint_t fhc_csr;
			uint_t fhc_bsr;
			enum board_type type;

			type = jtag_get_board_type(jtm->jtag_cmd, sc);
			switch (type) {
			case -1:
				fhc_bd_sc_evt(sc, SYSC_EVT_BD_EMPTY);
				continue;
			case DISK_BOARD:
				/*
				 * Disk boards are handled differently
				 * in that they don't fail POST and have
				 * no fhc attached.
				 */
				sc->type = DISK_BOARD;
				(void) jtag_init_disk_board(jtm->jtag_cmd,
				    board,
				    &fhc_csr, &fhc_bsr);
				fhc_bd_ks_alloc(bdp);
				break;
			default:
				/*
				 * Set the condition to FAILED if POST has
				 * failed. A failed board is physically
				 * present, is not on the disabled list and
				 * is of type UNKNOWN.
				 * NOTE: a non-present board which is
				 * (potentially) on the disabled board
				 * list has been ignored in the empty
				 * slot case.
				 */
				if (fhc_bd_disabled(board)) {
					fhc_bd_ks_alloc(bdp);
					se = SYSC_EVT_BD_DISABLED;
				} else
					se = SYSC_EVT_BD_FAILED;

				sc->type = type;
				break;
			}
		}

		fhc_bd_sc_evt(sc, se);
	}

	/*
	 * Do the disk specific initialization.  This routine scans
	 * for all disk boards, so we call it only once.
	 */
	fhc_bdlist_dk_init();

	jtag_master_unlock(jtm);

	fhc_bdlist_unlock();
}

struct cpu_speed {
	int cpu_freq;
	int sram_mode;
	int system_div;
	int system_dvd;
};

struct cpu_speed ultraI_speed_table[] = {
	{ 0,	0,	0,	0},
	{ 143,	1,	2,	1},
	{ 154,	1,	2,	1},
	{ 168,	1,	2,	1},
	{ 182,	1,	3,	1},
	{ 200,	1,	3,	1},
	{ 222,	1,	3,	1},
	{ 250,	1,	3,	1}
};

struct cpu_speed ultraII_speed_table[] = {
	{ 0,	0,	0,	0},
	{ 360,	2,	2,	1},
	{ 400,	2,	4,	1},
	{ 400,	2,	5,	2},
	{ 248,	2,	3,	2},
	{ 496,	2,	5,	2},
	{ 296,	2,	2,	1},
	{ 336,	2,	2,	1}
};

/*
 * set_cpu_info
 *
 * This routine extracts CPU module information used later for
 * determining hotplug compatibility.
 */
static void
set_cpu_info(sysc_cfga_stat_t *sc, uint_t fhc_bsr)
{
	int i;
	int speed_pins;
	struct cpu_speed *table;

	for (i = 0; i < 2; i++) {
		sc->bd.cpu[i].cpu_speed = 0;
		sc->bd.cpu[i].cpu_sram_mode = 0;

		if (!sc->bd.cpu[i].cpu_detected)
			continue;

		speed_pins = (i == 0) ? CPU_0_PINS(fhc_bsr) :
				CPU_1_PINS(fhc_bsr);

		switch (sc->bd.cpu[i].cpu_compid & CID_REV_MASK) {
			case ULTRAI_COMPID:
				table = ultraI_speed_table;
				break;
			case ULTRAII_COMPID:
				table = ultraII_speed_table;
				break;
			default:
				cmn_err(CE_WARN, "board %d, cpu module %c "
					"unknown type", sc->board,
					(i == 0) ? 'A' : 'B');
				sc->bd.cpu[i].cpu_speed = -1;
				continue;
		}

		sc->bd.cpu[i].cpu_speed = table[speed_pins].cpu_freq;
		sc->bd.cpu[i].cpu_sram_mode = table[speed_pins].sram_mode;
	}
}

int
fhc_bdlist_scan(sysc_cfga_rstate_t rstate, struct jt_mstr *jtm)
{
	int board;
	int error;
	int found = 0;
	uint_t fhc_csr;
	uint_t fhc_bsr;
	fhc_bd_t *bdp;
	sysc_cfga_stat_t *sc;
	enum board_type type;

	for (bdp = fhc_bd_first(); bdp; bdp = fhc_bd_next(bdp)) {

		sc = &bdp->sc;
		board = sc->board;

		/*
		 * Check the boards in EMPTY and DISCONNECTED
		 * states.  We need to check a board in the
		 * DISCONNECTED state in case it had been replugged.
		 */
		if (sc->in_transition || sc->rstate != rstate)
			continue;
		else if (sc->rstate == SYSC_CFGA_RSTATE_EMPTY) {
			type = jtag_get_board_type(jtm->jtag_cmd, sc);
			if (type == -1)
				continue;	/* no board present */
			sc->type = type;
		} else
			type = sc->type;

		if (type != UNKNOWN_BOARD)
			(void) jtag_get_board_info(jtm->jtag_cmd, sc);

		error = 0;

		if (type == DISK_BOARD)
			/*
			 * Scan the FHC to turn off the board insert
			 * interrupt and modify LEDs based on hotplug
			 * status.
			 */
			(void) jtag_init_disk_board(jtm->jtag_cmd, board,
					&fhc_csr, &fhc_bsr);
		else
			error = jtag_powerdown_board(jtm->jtag_cmd,
					board, type, &fhc_csr, &fhc_bsr, FALSE);

		if (error) {
			fhc_bd_sc_evt(sc, SYSC_EVT_BD_INS_FAILED);
			continue;
		}

		if (fhc_csr & FHC_NOT_BRD_PRES)
			continue;

		if (type == CPU_BOARD) {
			set_cpu_info(sc, fhc_bsr);
		}

		fhc_bd_sc_evt(sc, SYSC_EVT_BD_INSERTED);

		/*
		 * A replugged board will still have its kstat info.
		 */
		if (!bdp->ksp)
			fhc_bd_ks_alloc(bdp);

		found++;
		break;
	}

	return (found);
}

int
fhc_bd_insert_scan()
{
	struct jt_mstr *jtm;
	int found;

	ASSERT(fhc_bdlist_locked());

	if ((jtm = jtag_master_lock()) == NULL)
		cmn_err(CE_PANIC, "fhc_bd_insert_scan: no jtag master");

	/* first check empty then disconnected */
	found = fhc_bdlist_scan(SYSC_CFGA_RSTATE_EMPTY, jtm);
	if (!found)
		found |= fhc_bdlist_scan(SYSC_CFGA_RSTATE_DISCONNECTED, jtm);
	if (!found)
		cmn_err(CE_WARN, "Could not find hotplugged core system board");

	jtag_master_unlock(jtm);

	return (found);
}

int
fhc_bd_remove_scan()
{
	int poll = 0;
	fhc_bd_t *bdp;
	struct jt_mstr *jtm;
	sysc_cfga_stat_t *sc;

	ASSERT(fhc_bdlist_locked());

	if ((jtm = jtag_master_lock()) == NULL)
		cmn_err(CE_PANIC, "fhc_bd_remove_scan: no jtag master");

	for (bdp = fhc_bd_first(); bdp; bdp = fhc_bd_next(bdp)) {
		sc = &bdp->sc;

		if (sc->rstate != SYSC_CFGA_RSTATE_DISCONNECTED)
			continue;
		/*
		 * While there is a board in the disconnected state
		 * continue polling. When the last board is removed,
		 * we will get one last scan.
		 */
		poll++;

		if (sc->in_transition)
			continue;

		/*
		 * Scan to see if the board is still in.
		 */
		if (jtag_get_board_type(jtm->jtag_cmd, sc) == -1) {
			if (bdp->ksp) {
				kstat_delete(bdp->ksp);
				bdp->ksp = NULL;
			}
			fhc_bd_sc_evt(sc, SYSC_EVT_BD_REMOVED);
		}
	}

	jtag_master_unlock(jtm);

	return (poll);
}

int
fhc_bd_detachable(int board)
{
	fhc_bd_t *bdp = fhc_bd(board);

	if (bdp->softsp != NULL)
		return (bdp->flags & BDF_DETACH);
	else
		return (FALSE);
}

void
fhc_bd_sc_register(void (*f)(void *, sysc_cfga_stat_t *, sysc_evt_t), void *sp)
{
	fhc_bd_evt.update = f;
	fhc_bd_evt.soft = sp;
}

void
fhc_bd_update(int board, sysc_evt_t evt)
{
	fhc_bd_t *bdp;

	ASSERT(fhc_bd_valid(board));

	/*
	 * There is a window where this routine might be called
	 * as a result of the environ thread before sysctrl has
	 * attached and registered the callback.
	 */
	if (!(fbe->update))
		return;

	bdp = fhc_bdlist_lock(board);

	fhc_bd_sc_evt(&bdp->sc, evt);

	fhc_bdlist_unlock();
}

/* ARGSUSED */
int
fhc_bd_test(int board, sysc_cfga_pkt_t *pkt)
{
	uint_t fhc_csr, fhc_bsr;
	fhc_bd_t *bdp;
	struct jt_mstr *jtm;
	sysc_cfga_stat_t *sc;

	ASSERT(fhc_bdlist_locked());
	ASSERT(fhc_bd_busy(board));

	bdp = fhc_bd(board);
	sc = &bdp->sc;

	switch (sc->rstate) {
	case SYSC_CFGA_RSTATE_EMPTY:
		cmn_err(CE_NOTE, "fhc_bd_test: simulate board %d insertion",
		    board);

		jtm = jtag_master_lock();
		ASSERT(jtm);
		jtag_master_unlock(jtm);

		(void) jtag_powerdown_board(jtm->jtag_cmd, board,
			sc->type, &fhc_csr, &fhc_bsr, TRUE);
		break;
	case SYSC_CFGA_RSTATE_DISCONNECTED:
		cmn_err(CE_NOTE, "fhc_bd_test: simulate board %d removal",
		    board);

		if (bdp->ksp) {
			kstat_delete(bdp->ksp);
			bdp->ksp = NULL;
		}
		fhc_bd_sc_evt(sc, SYSC_EVT_BD_REMOVED);
		break;
	default:
		cmn_err(CE_NOTE,
			"fhc_bd_test: invalid board state: %d", board);
		break;
	}

	return (0);
}

/*
 * force a board condition for test purpose
 */
/* ARGSUSED */
int
fhc_bd_test_set_cond(int board, sysc_cfga_pkt_t *sysc_pkt)
{
	fhc_bd_t *bdp;
	sysc_cfga_stat_t *sc;
	sysc_cfga_cond_t cond;

	ASSERT(fhc_bdlist_locked());
	ASSERT(fhc_bd_busy(board));

	bdp = fhc_bd(board);
	sc = &bdp->sc;

	cond = (sysc_cfga_cond_t)sysc_pkt->cmd_cfga.arg;

	switch (cond) {
	case SYSC_CFGA_COND_UNKNOWN:
	case SYSC_CFGA_COND_OK:
	case SYSC_CFGA_COND_FAILING:
	case SYSC_CFGA_COND_FAILED:
	case SYSC_CFGA_COND_UNUSABLE:
		sc->condition = cond;
		return (0);
	default:
		return (EINVAL);
	}
}
