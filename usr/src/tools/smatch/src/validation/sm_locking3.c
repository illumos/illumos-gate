int _spin_trylock(int name);
void _spin_lock(int name);
void _spin_unlock(int name);

int func (void)
{
	int mylock = 1;

	if (!({frob(); frob(); _spin_trylock(mylock);})) 
		return;

	frob();
	_spin_unlock(mylock);

	if (((_spin_trylock(mylock)?1:0)?1:0))
		return;
	frob_somemore();
	_spin_unlock(mylock);

	return;
}
/*
 * check-name: Smatch locking #3
 * check-command: smatch --project=kernel sm_locking3.c
 *
 * check-output-start
sm_locking3.c:18 func() error: double unlocked 'mylock' (orig line 15)
sm_locking3.c:20 func() warn: inconsistent returns 'mylock'.
  Locked on  : 16
  Unlocked on: 10,20
 * check-output-end
 */
