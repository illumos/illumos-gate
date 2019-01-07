void _spin_lock(int name);
void _spin_unlock(int name);

void frob(void){}
int a;
int b;
void func (void)
{
	int mylock = 1;
	int mylock2 = 2;

	if (1)
	      	_spin_unlock(mylock);
	frob();
	if (a)
		return;
	if (!0)
	      	_spin_lock(mylock);
	if (0)
	      	_spin_unlock(mylock);
	if (b)
		return;
	if (!1)
	      	_spin_lock(mylock);
}
/*
 * check-name: Smatch locking #4
 * check-command: smatch --project=kernel sm_locking4.c
 *
 * check-output-start
sm_locking4.c:23 func() warn: inconsistent returns 'spin_lock:mylock'.
  Locked on:   line 22
               line 23
  Unlocked on: line 16
 * check-output-end
 */
