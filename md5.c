#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

#include <openssl/md5.h>

static
char* compute_digest (const char *filename, size_t buffer_size);


int main (int argc, char *argv[]) {	char *digest;
	size_t i;

	if (argc < 2) {
		printf("Usage: file\n");
		return 1;
	}

	for (i = 1; i < argc; ++i) {
		char *digest;
		struct stat64 stat_data;
		char *filename = argv[i];
		int result;

		/* Check what's the file's prefered I/O size */
		stat64(filename, &stat_data);
		result = stat64(filename, &stat_data);
		if (result == -1) {
			printf("Failed to get stat information for %s\n", filename);
			continue;
		}
		else if (! S_ISREG(stat_data.st_mode)) {
			printf("Entry %s is not a file\n", filename);
			continue;
		}

		digest = compute_digest(filename, stat_data.st_blksize);
		if (digest) {
			printf("%MD% (%s) = %s\n", filename, digest);
			free(digest);
		}
	}

	return 0;
}


static
char* compute_digest (const char *filename, size_t buffer_size) {
	MD5_CTX digest_ctx;
	unsigned char digest[MD5_DIGEST_LENGTH];
	char *digest_hex;
	char *digest_ptr;
	char *buffer;
	size_t i;
	ssize_t count;
	int fd;

	/* Compute the digest of the file */
	MD5_Init(&digest_ctx);

	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		printf("Failed to open %s\n", filename);
		return NULL;
	}

	buffer = malloc(buffer_size);
	while ( (count = read(fd, buffer, buffer_size)) > 0 ) {
		MD5_Update(&digest_ctx, buffer, count);
	}
	close(fd);
	free(buffer);

	MD5_Final(digest, &digest_ctx);

	/* Transform the binary digest into a human readable string */
	digest_hex = (char *) malloc(sizeof(digest) * 2 + 1);
	digest_ptr = digest_hex;
	for (i = 0; i < MD5_DIGEST_LENGTH; ++i) {
		sprintf(digest_ptr, "%02x", digest[i]);
		digest_ptr += 2;
	}

	return digest_hex;
}
