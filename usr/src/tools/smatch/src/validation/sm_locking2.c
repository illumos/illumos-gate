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
sm_locking2.c:21 func() error: double unlocked 'mylock' (orig line 17)
sm_locking2.c:26 func() warn: inconsistent returns 'mylock3'.
  Locked on  : 26
  Unlocked on: 25
 * check-output-end
 */
