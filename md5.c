#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

#include <sys/dir.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <openssl/md5.h>


/* Prototypes */
static
void dupes_walk_folder (const char *dirname);

static
char* dupes_compute_digest (const char *filename);


int main (int argc, char *argv[]) {	char *digest;
	size_t i;

	if (argc < 2) {
		printf("Usage: file\n");
		return 1;
	}

	for (i = 1; i < argc; ++i) {
		char *path = argv[i];
		struct stat64 stat_data;
		int result;

		/* Check what type of file entry is being processed */
		result = stat64(path, &stat_data);
		if (result == -1) {
			printf("Failed to get stat information for %s\n", path);
			continue;
		}
		else if (S_ISDIR(stat_data.st_mode)) {
			dupes_walk_folder(path);
		}
		else if (S_ISREG(stat_data.st_mode)) {
			char *digest = dupes_compute_digest(path);
			if (digest) {
				printf("MD5 (%s) = %s\n", path, digest);
				free(digest);
			}
		}
	}

	return 0;
}


static
void dupes_walk_folder (const char *dirname) {
	DIR *handle;
	struct dirent *entry;
	char path[MAXPATHLEN];
	char *path_ptr = path;
	size_t offset = 0;

	handle = opendir(dirname);
	if (handle == NULL) {
		return;
	}

	offset += strlcpy(path_ptr, dirname, sizeof(path) - offset);
	path_ptr = &path[offset];

	if (path[offset - 1] != '/') {
		offset += strlcpy(path_ptr, "/", sizeof(path) - offset);
		path_ptr = &path[offset];
	}

	while ( (entry = readdir(handle)) != NULL ) {

		/* Ignore "." and ".." */
		if (entry->d_namlen == 1 && entry->d_name[0] == '.') {
			continue;
		}
		else if (entry->d_namlen == 2 && entry->d_name[0] == '.' && entry->d_name[1] == '.') {
			continue;
		}

		strlcpy(path_ptr, entry->d_name, sizeof(path) - offset);

		switch (entry->d_type) {
			case DT_DIR:
				dupes_walk_folder(path);
			break;

			case DT_REG: {
				char *digest = dupes_compute_digest(path);
				if (digest) {
					printf("MD5 (%s) = %s\n", path, digest);
					free(digest);
				}
			}
			break;

			default:
				printf("Skipping entry %s of file type id: %d\n", path, entry->d_type);
			break;
		}

	}
	closedir(handle);
}


static
char* dupes_compute_digest (const char *filename) {
	MD5_CTX digest_ctx;
	unsigned char digest[MD5_DIGEST_LENGTH];
	char *digest_hex;
	char *digest_ptr;
	char *buffer;
	size_t i;
	ssize_t count;
	int fd;
	struct stat64 stat_data;
	int result;


	/* Check what's the file's prefered I/O size */
	result = stat64(filename, &stat_data);
	if (result == -1) {
		printf("Failed to get stat information for %s\n", filename);
		return NULL;
	}
	else if (! S_ISREG(stat_data.st_mode)) {
		printf("Entry %s is not a file\n", filename);
		return NULL;
	}


	/* Compute the digest of the file */
	MD5_Init(&digest_ctx);

	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		printf("Failed to open %s\n", filename);
		return NULL;
	}

	buffer = malloc(stat_data.st_blksize);
	while ( (count = read(fd, buffer, stat_data.st_blksize)) > 0 ) {
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
