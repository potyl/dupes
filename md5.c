#include <stdio.h>
#include <stdlib.h>
#include <openssl/md5.h>

static
char* compute_digest (const char *filename);


int main (int argc, char *argv[]) {
	char *digest;

	digest = compute_digest("md5.c");

	printf("%s\n", digest);

	return 0;
}


static
char* compute_digest (const char *filename) {
	MD5_CTX md5_ctx = {0, };
	char md5_hex[(MD5_DIGEST_LENGTH * 2) + 1];
	char *buffer;
	unsigned char *digest;
	size_t i;

	printf("%s\n", filename);

	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, "1", 1);
	digest = malloc(sizeof(unsigned char) * (MD5_DIGEST_LENGTH + 1));
	MD5_Final(digest, &md5_ctx);

	buffer = md5_hex;
	for (i = 0; i < MD5_DIGEST_LENGTH; ++i) {
		printf("%2d) %02x\n", i, digest[i]);
		sprintf(buffer, "%02x", digest[i]);
		buffer += 2;
	}

	return buffer;
}
