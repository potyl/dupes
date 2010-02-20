#include <stdio.h>
#include <stdlib.h>
#include <openssl/md5.h>

static
char* compute_digest (const char *filename);


int main (int argc, char *argv[]) {
	char *digest;

	digest = compute_digest("md5.c");

	printf("%s\n", digest);
	if (digest) {free(digest);}

	return 0;
}


static
char* compute_digest (const char *filename) {
	MD5_CTX md5_ctx;
	unsigned char digest[MD5_DIGEST_LENGTH];
	char *digest_hex;
	char *buffer;
	size_t i;

	/* Compute the digest */
	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, "1", 1);
	MD5_Final(digest, &md5_ctx);

	/* Transform the binary digest into a human readable string */
	digest_hex = (char *) malloc(sizeof(char) * (sizeof(digest) * 2 + 1));
	buffer = digest_hex;
	for (i = 0; i < MD5_DIGEST_LENGTH; ++i) {
		sprintf(buffer, "%02x", digest[i]);
		buffer += 2;
	}

	return digest_hex;
}
