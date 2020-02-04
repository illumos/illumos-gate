#include "check_debug.h"

unsigned long arch_local_irq_save();
void arch_local_irq_restore(unsigned long flags);
int spin_trylock();
void frob();

void func(int *y)
{
	int lock;
	unsigned long flags;

	if (({
		int __ret;
		flags = arch_local_irq_save();
		__ret = spin_trylock(&lock);
		if (!__ret)
			arch_local_irq_restore(flags);
		__ret;
	    }))
		return;
	frob();
}

/*
 * check-name: smatch locking #7
 * check-command: smatch -p=kernel -I.. sm_locking7.c
 *
 * check-output-start
sm_locking7.c:22 func() warn: inconsistent returns 'flags'.
  Locked on  : 21
  Unlocked on: 22
sm_locking7.c:22 func() warn: inconsistent returns 'lock'.
  Locked on  : 21
  Unlocked on: 22
 * check-output-end
 */
