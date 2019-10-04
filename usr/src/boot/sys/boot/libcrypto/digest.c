
#include <sys/cdefs.h>
#include <stand.h>
#include <sys/sha1.h>

#include <bootstrap.h>

void
sha1(void *data, size_t size, uint8_t *result)
{
	SHA1_CTX sha1_ctx;

	SHA1Init(&sha1_ctx);
	SHA1Update(&sha1_ctx, data, size);
	SHA1Final(result, &sha1_ctx);
}

static int
command_sha1(int argc, char **argv)
{
	void *ptr;
	size_t size, i;
	uint8_t resultbuf[SHA1_DIGEST_LENGTH];

	/*
	 * usage: address size
	 */
	if (argc != 3) {
		command_errmsg = "usage: address size";
		return (CMD_ERROR);
	}

	ptr = (void *)(uintptr_t)strtol(argv[1], NULL, 0);
	size = strtol(argv[2], NULL, 0);
	sha1(ptr, size, resultbuf);

	for (i = 0; i < SHA1_DIGEST_LENGTH; i++)
		printf("%02x", resultbuf[i]);
	printf("\n");
	return (CMD_OK);
}

COMMAND_SET(sha1, "sha1", "print the sha1 checksum", command_sha1);
