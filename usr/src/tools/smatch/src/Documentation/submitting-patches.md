Submitting patches: the sparse version
======================================

Sparse uses a patch submit process similar to the Linux Kernel
[Submitting Patches](https://www.kernel.org/doc/html/v4.12/process/submitting-patches.html)

This document mostly focuses on the parts that might be different from the Linux
Kernel submitting process.

1. Git clone a sparse repository:

        git clone git://git.kernel.org/pub/scm/devel/sparse/sparse.git

2. [Coding Style](https://www.kernel.org/doc/html/v4.12/process/coding-style.html) remains the same.

3. Sign off the patch.

   The usage of the Signed-off-by tag is the same as [Linux Kernel Sign your work](https://www.kernel.org/doc/html/v4.12/process/submitting-patches.html#sign-your-work-the-developer-s-certificate-of-origin).

   Notice that sparse uses the MIT License.

4. Smatch is built on top of Sparse but it is licensed under the GPLv2+ the
   git repostories are:

	https://github.com/error27/smatch
	https://repo.or.cz/w/smatch.git

   They are identical mirrors so it doesn't matter which you use.

   Send patches for to Smatch to <smatch@vger.kernel.org>.  If the code is
   shared with both Sparse and Smatch then please send it to the Sparse
   mailing list instead <linux-sparse@vger.kernel.org> and I will pick it up
   from there.

