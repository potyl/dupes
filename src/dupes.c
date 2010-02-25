#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <getopt.h>

#include <sys/dir.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <openssl/md5.h>
#include <sqlite3.h>

#include "config.h"

#define DB_FILE PACKAGE_NAME ".db"
#define IS_SQL_ERROR(error) ((error) == SQLITE_ERROR)

struct _DupesCtx {
	sqlite3 *db;
	sqlite3_stmt *stmt_insert;
};

typedef struct _DupesCtx DupesCtx;


/* Prototypes */
static
int dupes_ctx_init (DupesCtx *ctx);

static
void dupes_ctx_finalize (DupesCtx *ctx);

static
void dupes_walk_folder (DupesCtx *ctx, const char *dirname);

static
char* dupes_compute_digest (const char *filename, size_t buffer_size);

static
void dupes_insert_digest (DupesCtx *ctx, const char *filename);

static
int dupes_usage (void);


int main (int argc, char *argv[]) {	char *digest;
	size_t i;
	DupesCtx ctx = {0, };
	int rc;
	struct option longopts[] = {
		{ "help",       no_argument,       NULL, 'h' },
		{ "version",    no_argument,       NULL, 'v' },
		{ NULL, 0, NULL, 0 },
	};

	while ( (rc = getopt_long(argc, argv, "hv", longopts, NULL)) != -1 ) {
		switch (rc) {
			case 'h':
				return dupes_usage();
			break;

			case 'v':
				printf("%s version %s\n", PACKAGE_NAME, PACKAGE_VERSION);
				return 0;
			break;
		}
	}
	argc -= optind;
	argv += optind;


	if (argc == 0) {
		return dupes_usage();
	}


	rc = dupes_ctx_init(&ctx);
	if (rc) {
		goto quit;
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
			dupes_walk_folder(&ctx, path);
		}
		else if (S_ISREG(stat_data.st_mode)) {
			dupes_insert_digest(&ctx, path);
		}
	}

quit:
	dupes_ctx_finalize(&ctx);

	return 0;
}



static
int dupes_ctx_init (DupesCtx *ctx) {
	int error;
	char *sql;
	char *error_str;


	error = sqlite3_open_v2(DB_FILE, &ctx->db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
	if (IS_SQL_ERROR(error)) {
		printf("Can't open database: %s\n", DB_FILE);
		return 1;
	}


	sql = "PRAGMA synchronous=OFF; PRAGMA count_changes=OFF;";
	sqlite3_exec(ctx->db, sql, NULL, NULL, &error_str);
	if (error_str != NULL) {
		printf("Failed to create the dubes table; error: %s", error_str);
		sqlite3_free(error_str);
		return 1;
	}


	sql = "CREATE TABLE IF NOT EXISTS dupes ("
		"  id     INTEGER PRIMARY KEY NOT NULL, "
		"  path   TEXT NOT NULL UNIQUE,"
		"  digest TEXT NOT NULL,"
		"  size   UNSIGNED INTEGER NOT NULL"
		");";
	sqlite3_exec(ctx->db, sql, NULL, NULL, &error_str);
	if (error_str != NULL) {
		printf("Failed to create the dupes table; error code: %s", error_str);
		sqlite3_free(error_str);
		return 1;
	}


	sql = "REPLACE INTO dupes (path, digest, size) VALUES (?, ?, ?)";
	error = sqlite3_prepare_v2(ctx->db, sql, -1, &ctx->stmt_insert, NULL);
	if (IS_SQL_ERROR(error)) {
		printf("Can't prepare statement: %s; error code: %d %s", sql, error, sqlite3_errmsg(ctx->db));
		return 1;
	}


	return 0;
}



static
void dupes_ctx_finalize (DupesCtx *ctx) {
	if (ctx->stmt_insert != NULL) {
		sqlite3_finalize(ctx->stmt_insert);
		ctx->stmt_insert = NULL;
	}

	if (ctx->db != NULL) {
		sqlite3_close(ctx->db);
		ctx->db = NULL;
	}
}


static
void dupes_walk_folder (DupesCtx *ctx, const char *dirname) {
	DIR *handle;
	struct dirent *entry;
	char path[MAXPATHLEN];
	char *path_ptr = path;
	size_t offset = 0;

	handle = opendir(dirname);
	if (handle == NULL) {
		return;
	}

	strncpy(path_ptr, dirname, sizeof(path) - offset);
	offset += strlen(path_ptr);
	path_ptr = &path[offset];

	if (path[offset - 1] != '/') {
		strncpy(path_ptr, "/", sizeof(path) - offset);
		offset += strlen(path_ptr);
		path_ptr = &path[offset];
	}

	while ( (entry = readdir(handle)) != NULL ) {
		/* Ignore "." and ".." */
		if (strcmp(entry->d_name, ".") == 0 || (strcmp(entry->d_name, "..") == 0)) {
			continue;
		}

		strncpy(path_ptr, entry->d_name, sizeof(path) - offset);

		switch (entry->d_type) {
			case DT_DIR:
				dupes_walk_folder(ctx, path);
			break;

			case DT_REG:
				dupes_insert_digest(ctx, path);
			break;

			default:
				printf("Skipping entry %s of file type id: %d\n", path, entry->d_type);
			break;
		}

	}
	closedir(handle);
}



static
void dupes_insert_digest (DupesCtx *ctx, const char *filename) {
	char *digest = NULL;
	int rc;
	struct stat64 stat_data;
	int result;


	/* Check what's the file's prefered I/O size */
	result = stat64(filename, &stat_data);
	if (result == -1) {
		printf("Failed to get stat information for %s\n", filename);
		return;
	}
	else if (! S_ISREG(stat_data.st_mode)) {
		printf("Entry %s is not a file\n", filename);
		return;
	}

	/* Compute the digest */
	digest = dupes_compute_digest(filename, stat_data.st_blksize);
	if (digest == NULL) {return;}


	sqlite3_reset(ctx->stmt_insert);


	/* Parameter binding */
	rc = sqlite3_bind_text(ctx->stmt_insert, 1, filename, -1, SQLITE_STATIC);
	if (IS_SQL_ERROR(rc)) {
		printf("Failed to bind parameter path: %s; error: %d, %s\n", filename, rc, sqlite3_errmsg(ctx->db));
		goto quit;
	}

	rc = sqlite3_bind_text(ctx->stmt_insert, 2, digest, -1, SQLITE_STATIC);
	if (IS_SQL_ERROR(rc)) {
		printf("Failed to bind parameter digest: %s; error: %d, %s\n", digest, rc, sqlite3_errmsg(ctx->db));
		goto quit;
	}

	rc = sqlite3_bind_int(ctx->stmt_insert, 3, stat_data.st_size);
	if (IS_SQL_ERROR(rc)) {
		printf("Failed to bind parameter size: %s; error: %d, %s\n", filename, rc, sqlite3_errmsg(ctx->db));
		goto quit;
	}


	printf("MD5 (%s) = %s\n", filename, digest);

	/* Query execution */
	rc = sqlite3_step(ctx->stmt_insert);
	if (rc != SQLITE_DONE) {
		printf("Failed to insert digest: %s, path: %s; error: %d, %s\n", digest, filename, rc, sqlite3_errmsg(ctx->db));
		goto quit;
	}


quit:
	if (digest) {free(digest);}
}


static
char* dupes_compute_digest (const char *filename, size_t buffer_size) {
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


static
int dupes_usage() {
	printf(
		"Usage: " PACKAGE_NAME " [OPTION]... SSID\n"
		"Where OPTION is one of:\n"
		"   --version,      -v     show the program's version\n"
		"   --help,         -h     print this help message\n"
	);
	return 1;
}