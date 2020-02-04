int __raw_local_irq_save();
int _spin_trylock(int x);
int raw_local_irq_restore(flags);

#define spin_trylock_irqsave(lock, flags) \
({ \
        (flags) = __raw_local_irq_save(); \
        _spin_trylock(lock) ? 1 : ({ raw_local_irq_restore(flags);  0; }); \
})

void _spin_unlock_irqrestore(int lock, int flags);

int zzz;

void func (void)
{
	int lock = 1;
	int flags = 1;

	if (!spin_trylock_irqsave(lock, flags))
		return;
	_spin_unlock_irqrestore(lock, flags);
	if (zzz)
		return;
	if (spin_trylock_irqsave(lock, flags))
		return;
	return;
}
/*
 * check-name: Smatch locking #6
 * check-command: smatch -p=kernel sm_locking6.c
 *
 * check-output-start
sm_locking6.c:27 func() warn: inconsistent returns 'flags'.
  Locked on  : 26
  Unlocked on: 21,24,27
sm_locking6.c:27 func() warn: inconsistent returns 'lock'.
  Locked on  : 26
  Unlocked on: 21,24,27
 * check-output-end
 */
