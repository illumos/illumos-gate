#ifndef _COMPAT_FREEBSD_VM_VM_PARAM_H_
#define	_COMPAT_FREEBSD_VM_VM_PARAM_H_

#include <machine/vmparam.h>

#define	KERN_SUCCESS		0

/*
 * The VM_MAXUSER_ADDRESS is used to determine the upper limit size limit of a
 * vmspace, their 'struct as' equivalent.  The compat value is sized well below
 * our native userlimit, even halving the available space below the VA hole.
 * This is to avoid Intel EPT limits and leave room available in the usabe VA
 * range for other mmap tricks.
 */
#define	VM_MAXUSER_ADDRESS	0x00003ffffffffffful


#endif	/* _COMPAT_FREEBSD_VM_VM_PARAM_H_ */
