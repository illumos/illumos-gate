void _spin_lock(int name);
void _spin_unlock(int name);
int _spin_trylock(int name);

int a;
int b;
int func (void)
{
	int mylock = 1;
	int mylock2 = 1;
	int mylock3 = 1;

	if (!_spin_trylock(mylock)) {
		return;
	}

	_spin_unlock(mylock);
	_spin_unlock(mylock2);

	if (a)
		_spin_unlock(mylock);
	_spin_lock(mylock2);

	if (!_spin_trylock(mylock3))
		return;
	return;
}
/*
 * check-name: Smatch locking #2
 * check-command: smatch --project=kernel sm_locking2.c
 *
 * check-output-start
sm_locking2.c:21 func() error: double unlock 'spin_lock:mylock'
sm_locking2.c:26 func() warn: inconsistent returns 'spin_lock:mylock3'.
  Locked on:   line 26
  Unlocked on: line 14
               line 25
 * check-output-end
 */
