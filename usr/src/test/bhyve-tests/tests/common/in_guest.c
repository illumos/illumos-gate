/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2024 Oxide Computer Company
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <assert.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/segments.h>
#include <sys/psw.h>
#include <sys/controlregs.h>
#include <sys/sysmacros.h>
#include <sys/varargs.h>
#include <sys/debug.h>
#include <sys/mman.h>

#include <sys/vmm.h>
#include <sys/vmm_dev.h>
#include <vmmapi.h>

#include "in_guest.h"


#define	PT_VALID	0x01
#define	PT_WRITABLE	0x02
#define	PT_WRITETHRU	0x08
#define	PT_NOCACHE	0x10
#define	PT_PAGESIZE	0x80

#define	SEG_ACCESS_TYPE_MASK	0x1f
#define	SEG_ACCESS_DPL_MASK	0x60
#define	SEG_ACCESS_P		(1 << 7)
#define	SEG_ACCESS_AVL		(1 << 12)
#define	SEG_ACCESS_L		(1 << 13)
#define	SEG_ACCESS_D		(1 << 14)
#define	SEG_ACCESS_G		(1 << 15)
#define	SEG_ACCESS_UNUSABLE	(1 << 16)


/*
 * Keep the test name and VM context around so the consumer is not required to
 * pass either of them to us for subsequent test-related operations after the
 * initialization has been performed.
 *
 * The test code is not designed to be reentrant at this point.
 */
static struct vmctx *test_vmctx = NULL;
static const char *test_name = NULL;

static uint64_t test_msg_addr = 0;

static int
setup_rom(struct vmctx *ctx)
{
	const size_t seg_sz = 0x1000;
	const uintptr_t seg_addr = MEM_LOC_ROM;
	const int fd = vm_get_device_fd(ctx);
	int err;

	struct vm_memseg memseg = {
		.segid = VM_BOOTROM,
		.len = 0x1000,
	};
	(void) strlcpy(memseg.name, "testrom", sizeof (memseg.name));
	err = ioctl(fd, VM_ALLOC_MEMSEG, &memseg);
	if (err != 0) {
		return (err);
	}
	err = vm_mmap_memseg(ctx, seg_addr, VM_BOOTROM, 0, seg_sz,
	    PROT_READ | PROT_EXEC);
	return (err);
}

static void
populate_identity_table(struct vmctx *ctx)
{
	uint64_t gpa, pte_loc;

	/* Set up 2MiB PTEs for everything up through 0xffffffff */
	for (gpa = 0, pte_loc = MEM_LOC_PAGE_TABLE_2M;
	    gpa < 0x100000000;
	    pte_loc += PAGE_SIZE) {
		uint64_t *ptep = vm_map_gpa(ctx, pte_loc, PAGE_SIZE);

		for (uint_t i = 0; i < 512; i++, ptep++, gpa += 0x200000) {
			*ptep =  gpa | PT_VALID | PT_WRITABLE | PT_PAGESIZE;
			/* Make traditional MMIO space uncachable */
			if (gpa >= 0xc0000000) {
				*ptep |= PT_WRITETHRU | PT_NOCACHE;
			}
		}
	}
	assert(gpa == 0x100000000 && pte_loc == MEM_LOC_PAGE_TABLE_1G);

	uint64_t *pdep = vm_map_gpa(ctx, MEM_LOC_PAGE_TABLE_1G, PAGE_SIZE);
	pdep[0] = MEM_LOC_PAGE_TABLE_2M | PT_VALID | PT_WRITABLE;
	pdep[1] = (MEM_LOC_PAGE_TABLE_2M + PAGE_SIZE) | PT_VALID | PT_WRITABLE;
	pdep[2] =
	    (MEM_LOC_PAGE_TABLE_2M + 2 * PAGE_SIZE) | PT_VALID | PT_WRITABLE;
	pdep[3] =
	    (MEM_LOC_PAGE_TABLE_2M + 3 * PAGE_SIZE) | PT_VALID | PT_WRITABLE;

	pdep = vm_map_gpa(ctx, MEM_LOC_PAGE_TABLE_512G, PAGE_SIZE);
	pdep[0] = MEM_LOC_PAGE_TABLE_1G | PT_VALID | PT_WRITABLE;
}

static void
populate_desc_tables(struct vmctx *ctx)
{

}

void
test_cleanup(bool is_failure)
{
	if (test_vmctx != NULL) {
		bool keep_on_fail = false;

		const char *keep_var;
		if ((keep_var = getenv("KEEP_ON_FAIL")) != NULL) {
			if (strlen(keep_var) != 0 &&
			    strcmp(keep_var, "0") != 0) {
				keep_on_fail = true;
			}
		}

		/*
		 * Destroy the instance unless the test failed and it was
		 * requested that we keep it around.
		 */
		if (!is_failure || !keep_on_fail) {
			vm_destroy(test_vmctx);
		}
		test_name = NULL;
		test_vmctx = NULL;
	}
}

static void fail_finish(void)
{
	assert(test_name != NULL);
	(void) printf("FAIL %s\n", test_name);

	test_cleanup(true);
	exit(EXIT_FAILURE);
}

void
test_fail(void)
{
	fail_finish();
}

void
test_fail_errno(int err, const char *msg)
{
	const char *err_str = strerror(err);

	(void) fprintf(stderr, "%s: %s\n", msg, err_str);
	fail_finish();
}

void
test_fail_msg(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) vfprintf(stderr, fmt, ap);

	fail_finish();
}

void
test_fail_vmexit(const struct vm_exit *vexit)
{
	const char *hdr_fmt = "Unexpected %s exit:\n\t%%rip: %lx\n";

	switch (vexit->exitcode) {
	case VM_EXITCODE_INOUT:
		(void) fprintf(stderr, hdr_fmt, "IN/OUT", vexit->rip);
		(void) fprintf(stderr,
		    "\teax: %08x\n"
		    "\tport: %04x\n"
		    "\tbytes: %u\n"
		    "\tflags: %x\n",
		    vexit->u.inout.eax,
		    vexit->u.inout.port,
		    vexit->u.inout.bytes,
		    vexit->u.inout.flags);
		break;
	case VM_EXITCODE_RDMSR:
		(void) fprintf(stderr, hdr_fmt, "RDMSR", vexit->rip);
		(void) fprintf(stderr, "\tcode: %08x\n", vexit->u.msr.code);
		break;
	case VM_EXITCODE_WRMSR:
		(void) fprintf(stderr, hdr_fmt, "WRMSR", vexit->rip);
		(void) fprintf(stderr,
		    "\tcode: %08x\n"
		    "\twval: %016lx\n",
		    vexit->u.msr.code, vexit->u.msr.wval);
		break;
	case VM_EXITCODE_MMIO:
		(void) fprintf(stderr, hdr_fmt, "MMIO", vexit->rip);
		(void) fprintf(stderr,
		    "\tbytes: %u\n"
		    "\ttype: %s\n"
		    "\tgpa: %x\n"
		    "\tdata: %016x\n",
		    vexit->u.mmio.bytes,
		    vexit->u.mmio.read == 0 ? "write" : "read",
		    vexit->u.mmio.gpa,
		    vexit->u.mmio.data);
		break;
	case VM_EXITCODE_VMX:
		(void) fprintf(stderr, hdr_fmt, "VMX", vexit->rip);
		(void) fprintf(stderr,
		    "\tstatus: %x\n"
		    "\treason: %x\n"
		    "\tqualification: %lx\n"
		    "\tinst_type: %x\n"
		    "\tinst_error: %x\n",
		    vexit->u.vmx.status,
		    vexit->u.vmx.exit_reason,
		    vexit->u.vmx.exit_qualification,
		    vexit->u.vmx.inst_type,
		    vexit->u.vmx.inst_error);
		break;
	case VM_EXITCODE_SVM:
		(void) fprintf(stderr, hdr_fmt, "SVM", vexit->rip);
		break;
	case VM_EXITCODE_INST_EMUL:
		(void) fprintf(stderr, hdr_fmt, "instruction emulation",
		    vexit->rip);
		const uint_t len = vexit->u.inst_emul.num_valid > 0 ?
		    vexit->u.inst_emul.num_valid : 15;
		(void) fprintf(stderr, "\tinstruction bytes: [");
		for (uint_t i = 0; i < len; i++) {
			(void) fprintf(stderr, "%s%02x",
			    i == 0 ? "" : ", ",
			    vexit->u.inst_emul.inst[i]);
		}
		(void) fprintf(stderr, "]\n");
		break;
	case VM_EXITCODE_SUSPENDED:
		(void) fprintf(stderr, hdr_fmt, "suspend", vexit->rip);
		switch (vexit->u.suspended.how) {
		case VM_SUSPEND_RESET:
			(void) fprintf(stderr, "\thow: reset");
			break;
		case VM_SUSPEND_POWEROFF:
			(void) fprintf(stderr, "\thow: poweroff");
			break;
		case VM_SUSPEND_HALT:
			(void) fprintf(stderr, "\thow: halt");
			break;
		case VM_SUSPEND_TRIPLEFAULT:
			(void) fprintf(stderr, "\thow: triple-fault");
			break;
		default:
			(void) fprintf(stderr, "\thow: unknown - %d",
			    vexit->u.suspended.how);
			break;
		}
		break;
	default:
		(void) fprintf(stderr, "Unexpected code %d exit:\n"
		    "\t%%rip: %lx\n", vexit->exitcode, vexit->rip);
		break;
	}
	fail_finish();
}

void
test_pass(void)
{
	assert(test_name != NULL);
	(void) printf("PASS %s\n", test_name);
	test_cleanup(false);
	exit(EXIT_SUCCESS);
}

const char *
test_msg_get(struct vmctx *ctx)
{
	/* Disregard if the message address is still NULL */
	const uint64_t msg_addr = test_msg_addr;
	if (msg_addr == 0) {
		return (NULL);
	}

	/*
	 * We want to try to map up to one page after the specified message
	 * address, keeping in mind the end of lowmem. (The payload, and
	 * thus message, is assumed to be in lowmem at this time.)
	 */
	const uint64_t lowmem_end = vm_get_lowmem_size(ctx);
	const uint64_t msg_map_end = MIN(msg_addr + PAGE_SIZE, lowmem_end);

	if (msg_map_end >= lowmem_end || msg_map_end <= msg_addr) {
		return (NULL);
	}
	const uint64_t max_msg_len = msg_map_end - msg_addr;

	/*
	 * Get the mapping to that guest memory.  This assumes that the payload
	 * has provided a guest-physical address to us.
	 */
	const char *result = vm_map_gpa(ctx, msg_addr, max_msg_len);
	if (result == NULL) {
		return (NULL);
	}

	/* Demand a NUL-terminated string shorter than the map limit */
	if (strnlen(result, max_msg_len) >= max_msg_len) {
		return (NULL);
	}

	return (result);
}

void
test_msg_print(struct vmctx *ctx)
{
	const char *payload_msg = test_msg_get(ctx);

	if (payload_msg != NULL) {
		(void) fprintf(stderr, "MSG: %s\n", payload_msg);
	}
}

static int
load_payload(struct vmctx *ctx)
{
	extern uint8_t payload_data;
	extern uint32_t payload_size;

	const uint32_t len = payload_size;
	const uint32_t cap = (MEM_TOTAL_SZ - MEM_LOC_PAYLOAD);

	if (len > cap) {
		test_fail_msg("Payload size %u > capacity %u\n", len, cap);
	}

	const size_t map_len = P2ROUNDUP(len, PAGE_SIZE);
	void *outp = vm_map_gpa(ctx, MEM_LOC_PAYLOAD, map_len);
	bcopy(&payload_data, outp, len);

	return (0);
}

static struct vmctx *
test_initialize_opts(const char *tname, uint64_t create_flags, bool is_plain)
{
	char vm_name[VM_MAX_NAMELEN];
	int err;
	struct vmctx *ctx;

	assert(test_vmctx == NULL);
	assert(test_name == NULL);

	test_name = strdup(tname);
	(void) snprintf(vm_name, sizeof (vm_name), "bhyve-test-%s-%d",
	    test_name, getpid());

	err = vm_create(vm_name, create_flags);
	if (err != 0) {
		test_fail_errno(err, "Could not create VM");
	}

	ctx = vm_open(vm_name);
	if (ctx == NULL) {
		test_fail_errno(errno, "Could not open VM");
	}
	test_vmctx = ctx;

	/* No further setup required for a "plain" instance */
	if (is_plain) {
		return (ctx);
	}

	err = vm_setup_memory(ctx, MEM_TOTAL_SZ, VM_MMAP_ALL);
	if (err != 0) {
		test_fail_errno(err, "Could not set up VM memory");
	}

	err = setup_rom(ctx);
	if (err != 0) {
		test_fail_errno(err, "Could not set up VM ROM segment");
	}

	populate_identity_table(ctx);
	populate_desc_tables(ctx);

	err = load_payload(ctx);
	if (err != 0) {
		test_fail_errno(err, "Could not load payload");
	}

	return (ctx);
}

struct vmctx *
test_initialize(const char *tname)
{
	return (test_initialize_opts(tname, 0, false));
}

struct vmctx *
test_initialize_plain(const char *tname)
{
	return (test_initialize_opts(tname, 0, true));
}

struct vmctx *
test_initialize_flags(const char *tname, uint64_t create_flags)
{
	return (test_initialize_opts(tname, create_flags, false));
}

void
test_reinitialize(struct vmctx *ctx, uint64_t flags)
{
	int err;

	if ((err = vm_reinit(ctx, flags)) != 0) {
		test_fail_errno(err, "Could not reinit VM");
	}

	/* Reload tables and payload in case they were altered */

	populate_identity_table(ctx);
	populate_desc_tables(ctx);

	err = load_payload(ctx);
	if (err != 0) {
		test_fail_errno(err, "Could not load payload");
	}
}

int
test_setup_vcpu(struct vcpu *vcpu, uint64_t rip, uint64_t rsp)
{
	int err;

	err = vm_activate_cpu(vcpu);
	if (err != 0 && err != EBUSY) {
		return (err);
	}

	/*
	 * Granularity bit important here for VMX validity:
	 * "If any bit in the limit field in the range 31:20 is 1, G must be 1"
	 */
	err = vm_set_desc(vcpu, VM_REG_GUEST_CS, 0, UINT32_MAX,
	    SDT_MEMERA | SEG_ACCESS_P | SEG_ACCESS_L | SEG_ACCESS_G);
	if (err != 0) {
		return (err);
	}

	err = vm_set_desc(vcpu, VM_REG_GUEST_SS, 0, UINT32_MAX,
	    SDT_MEMRWA | SEG_ACCESS_P | SEG_ACCESS_L |
	    SEG_ACCESS_D | SEG_ACCESS_G);
	if (err != 0) {
		return (err);
	}

	err = vm_set_desc(vcpu, VM_REG_GUEST_DS, 0, UINT32_MAX,
	    SDT_MEMRWA | SEG_ACCESS_P | SEG_ACCESS_D | SEG_ACCESS_G);
	if (err != 0) {
		return (err);
	}

	/*
	 * While SVM will happilly run with an otherwise unusable TR, VMX
	 * includes it among its entry checks.
	 */
	err = vm_set_desc(vcpu, VM_REG_GUEST_TR, MEM_LOC_TSS, 0xff,
	    SDT_SYSTSSBSY | SEG_ACCESS_P);
	if (err != 0) {
		return (err);
	}
	err = vm_set_desc(vcpu, VM_REG_GUEST_GDTR, MEM_LOC_GDT, 0x1ff, 0);
	if (err != 0) {
		return (err);
	}
	err = vm_set_desc(vcpu, VM_REG_GUEST_IDTR, MEM_LOC_IDT, 0xfff, 0);
	if (err != 0) {
		return (err);
	}

	/* Mark unused segments as explicitly unusable (for VMX) */
	const int unsable_segs[] = {
		VM_REG_GUEST_ES,
		VM_REG_GUEST_FS,
		VM_REG_GUEST_GS,
		VM_REG_GUEST_LDTR,
	};
	for (uint_t i = 0; i < ARRAY_SIZE(unsable_segs); i++) {
		err = vm_set_desc(vcpu, unsable_segs[i], 0, 0,
		    SEG_ACCESS_UNUSABLE);
		if (err != 0) {
			return (err);
		}
	}

	/* Place CPU directly in long mode */
	const int regnums[] = {
		VM_REG_GUEST_CR0,
		VM_REG_GUEST_CR3,
		VM_REG_GUEST_CR4,
		VM_REG_GUEST_EFER,
		VM_REG_GUEST_RFLAGS,
		VM_REG_GUEST_RIP,
		VM_REG_GUEST_RSP,
		VM_REG_GUEST_CS,
		VM_REG_GUEST_SS,
		VM_REG_GUEST_DS,
		VM_REG_GUEST_TR,
	};
	uint64_t regvals[] = {
		CR0_PG | CR0_AM | CR0_WP | CR0_NE | CR0_ET | CR0_TS |
		    CR0_MP | CR0_PE,
		MEM_LOC_PAGE_TABLE_512G,
		CR4_DE | CR4_PSE | CR4_PAE | CR4_MCE | CR4_PGE | CR4_FSGSBASE,
		AMD_EFER_SCE | AMD_EFER_LME | AMD_EFER_LMA | AMD_EFER_NXE,
		/* start with interrupts disabled */
		PS_MB1,
		rip,
		rsp,
		(GDT_KCODE << 3),
		(GDT_KDATA << 3),
		(GDT_KDATA << 3),
		(GDT_KTSS << 3),
	};
	assert(ARRAY_SIZE(regnums) == ARRAY_SIZE(regvals));

	err = vm_set_register_set(vcpu, ARRAY_SIZE(regnums), regnums,
	    regvals);
	if (err != 0) {
		return (err);
	}

	err = vm_set_run_state(vcpu, VRS_RUN, 0);
	if (err != 0) {
		return (err);
	}

	return (0);
}

static enum vm_exit_kind
which_exit_kind(struct vm_entry *ventry, const struct vm_exit *vexit)
{
	const struct vm_inout *inout = &vexit->u.inout;

	switch (vexit->exitcode) {
	case VM_EXITCODE_BOGUS:
		bzero(ventry, sizeof (ventry));
		return (VEK_REENTR);
	case VM_EXITCODE_INOUT:
		if (inout->port == IOP_TEST_RESULT &&
		    (inout->flags & INOUT_IN) == 0) {
			if (inout->eax == TEST_RESULT_PASS) {
				return (VEK_TEST_PASS);
			} else {
				return (VEK_TEST_FAIL);
			}
		}
		if (inout->port == IOP_TEST_MSG &&
		    (inout->flags & INOUT_IN) == 0 &&
		    inout->bytes == 4) {
			test_msg_addr = inout->eax;
			ventry_fulfill_inout(vexit, ventry, 0);
			return (VEK_TEST_MSG);
		}
		break;
	default:
		break;
	}
	return (VEK_UNHANDLED);
}

enum vm_exit_kind
test_run_vcpu(struct vcpu *vcpu, struct vm_entry *ventry, struct vm_exit *vexit)
{
	int err;

	err = vm_run(vcpu, ventry, vexit);
	if (err != 0) {
		test_fail_errno(err, "Failure during vcpu entry");
	}

	return (which_exit_kind(ventry, vexit));
}

void
ventry_fulfill_inout(const struct vm_exit *vexit, struct vm_entry *ventry,
    uint32_t data)
{
	VERIFY3U(vexit->exitcode, ==, VM_EXITCODE_INOUT);

	ventry->cmd = VEC_FULFILL_INOUT;
	bcopy(&vexit->u.inout, &ventry->u.inout, sizeof (struct vm_inout));
	if ((ventry->u.inout.flags & INOUT_IN) != 0) {
		ventry->u.inout.eax = data;
	}
}

void
ventry_fulfill_mmio(const struct vm_exit *vexit, struct vm_entry *ventry,
    uint64_t data)
{
	VERIFY3U(vexit->exitcode, ==, VM_EXITCODE_MMIO);

	ventry->cmd = VEC_FULFILL_MMIO;
	bcopy(&vexit->u.mmio, &ventry->u.mmio, sizeof (struct vm_mmio));
	if (ventry->u.mmio.read != 0) {
		ventry->u.mmio.data = data;
	}
}

bool
vexit_match_inout(const struct vm_exit *vexit, bool is_read, uint16_t port,
    uint_t len, uint32_t *valp)
{
	if (vexit->exitcode != VM_EXITCODE_INOUT) {
		return (false);
	}

	const uint_t flag = is_read ? INOUT_IN : 0;
	if (vexit->u.inout.port != port ||
	    vexit->u.inout.bytes != len ||
	    (vexit->u.inout.flags & INOUT_IN) != flag) {
		return (false);
	}

	if (!is_read && valp != NULL) {
		*valp = vexit->u.inout.eax;
	}
	return (true);
}

bool
vexit_match_mmio(const struct vm_exit *vexit, bool is_read, uint64_t addr,
    uint_t len, uint64_t *valp)
{
	if (vexit->exitcode != VM_EXITCODE_MMIO) {
		return (false);
	}

	if (vexit->u.mmio.gpa != addr ||
	    vexit->u.mmio.bytes != len ||
	    (vexit->u.mmio.read != 0) != is_read) {
		return (false);
	}

	if (!is_read && valp != NULL) {
		*valp = vexit->u.mmio.data;
	}
	return (true);
}
