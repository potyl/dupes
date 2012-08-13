/* dupes.c - Find duplicate files by comparing their digest.
 *
 * Copyright (C) 2010 Emmanuel Rodriguez <emmanuel.rodriguez@gmail.com>.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <getopt.h>

#include <sys/dir.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/uio.h>

#ifdef __MAC_OS_X_VERSION_MIN_REQUIRED
	#define _DARWIN_USE_64_BIT_INODE 1
	#include <sys/stat.h>
	#define stat64 stat
#else
	#include <sys/stat.h>
#endif

#include <openssl/md5.h>
#include <openssl/sha.h>
#include <sqlite3.h>

#include "config.h"

#ifdef HAVE_STRUCT_STAT_ST_MTIMESPEC_TV_SEC
	#ifndef st_mtime
		#define st_mtime st_mtimespec.tv_sec
	#endif
#endif


#define DB_FILE PACKAGE_NAME ".db"
#define IS_SQL_ERROR(error) ((error) == SQLITE_ERROR)


typedef enum _DupesSortBy {
	DUPES_SORT_BY_SIZE = 1,
	DUPES_SORT_BY_COUNT,
} DupesSortBy;


typedef struct _DupesCtx DupesCtx;
struct _DupesCtx {
	const char *db_file;
	sqlite3 *db;
	sqlite3_stmt *stmt_insert;
	sqlite3_stmt *stmt_select;
	int replace;
	int show;
	int keep_zero_size;
	int (*compute_digest_func)(unsigned char *, int fd, char *, size_t);
	const char    *digest_name;
	size_t         digest_bin_len;
	unsigned char *digest_bin;
	char          *digest_hex;
	size_t        file_buffer_size;
	char          *file_buffer;
	unsigned int  total_added;
	DupesSortBy   sort_by;
};


/* Prototypes */
static
int dupes_ctx_init (DupesCtx *ctx);

static
void dupes_ctx_finalize (DupesCtx *ctx);

static
void dupes_walk_folder (DupesCtx *ctx, const char *dirname);

static
int dupes_compute_md5 (unsigned char *, int fd, char *buffer, size_t buffer_size);

static
int dupes_compute_sha1 (unsigned char *, int fd, char *buffer, size_t buffer_size);

static
void dupes_insert_digest (DupesCtx *ctx, const char *filename);

static
void dupes_show (DupesCtx *ctx);

static
int dupes_usage (void);

static
char *dupes_size_human_readable (size_t bytes);

int main (int argc, char *argv[]) {
	size_t i;
	DupesCtx ctx = {0, };
	int rc;
	struct option longopts [] = {
		{ "db",         required_argument, NULL, 'd' },
		{ "md5",        no_argument,       NULL, 'm' },
		{ "sha1",       no_argument,       NULL, 's' },
		{ "zero",       no_argument,       NULL, 'z' },
		{ "list",       no_argument,       NULL, 'l' },
		{ "sort-size",  no_argument,       NULL, 'S' },
		{ "sort-count", no_argument,       NULL, 'C' },
		{ "replace",    no_argument,       NULL, 'r' },
		{ "help",       no_argument,       NULL, 'h' },
		{ "version",    no_argument,       NULL, 'v' },
		{ NULL, 0, NULL, 0 },
	};

	ctx.compute_digest_func = NULL;
	ctx.db_file = DB_FILE;
	while ( (rc = getopt_long(argc, argv, "d:mszlSCrhv", longopts, NULL)) != -1 ) {
		switch (rc) {
			case 'd':
				ctx.db_file = optarg;
			break;

			case 'S':
				ctx.sort_by = DUPES_SORT_BY_SIZE;
			break;

			case 'C':
				ctx.sort_by = DUPES_SORT_BY_COUNT;
			break;

			case 'm':
				/* Will be defined later on */
				ctx.compute_digest_func = NULL;
			break;

			case 's':
				ctx.compute_digest_func = dupes_compute_sha1;
				ctx.digest_name = "SHA1";
				ctx.digest_bin_len = SHA_DIGEST_LENGTH;
			break;

			case 'z':
				ctx.keep_zero_size = 1;
			break;

			case 'l':
				ctx.show = 1;
			break;

			case 'r':
				ctx.replace = 1;
			break;

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

	if (ctx.sort_by) ctx.show = 1;
	if (argc == 0 && ! ctx.show) {
		return dupes_usage();
	}

	if (ctx.compute_digest_func == NULL) {
		ctx.digest_name = "MD5";
		ctx.compute_digest_func = dupes_compute_md5;
		ctx.digest_bin_len = MD5_DIGEST_LENGTH;
	}
	ctx.digest_bin = malloc(ctx.digest_bin_len + 1);
	if (ctx.digest_bin == NULL) goto QUIT;
	ctx.digest_hex = malloc(ctx.digest_bin_len * 2 + 1);
	if (ctx.digest_hex == NULL) goto QUIT;

	ctx.file_buffer_size = 1024;
	ctx.file_buffer = malloc(ctx.file_buffer_size);
	if (ctx.file_buffer == NULL) goto QUIT;

	rc = dupes_ctx_init(&ctx);
	if (rc) goto QUIT;

	if (ctx.show) {
		dupes_show(&ctx);
		goto QUIT;
	}


	for (i = 0; i < argc; ++i) {
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
	printf("Indexed %u files\n", ctx.total_added);

QUIT:
	dupes_ctx_finalize(&ctx);

	return 0;
}



static
int dupes_ctx_init (DupesCtx *ctx) {
	int error;
	char *sql;
	char *error_str;


	error = sqlite3_open_v2(ctx->db_file, &ctx->db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
	if (IS_SQL_ERROR(error)) {
		printf("Can't open database: %s\n", DB_FILE);
		return 1;
	}


	sql = "PRAGMA synchronous=OFF; PRAGMA count_changes=OFF;";
	sqlite3_exec(ctx->db, sql, NULL, NULL, &error_str);
	if (error_str != NULL) {
		printf("Failed to set db pragmas; error: %s\n", error_str);
		sqlite3_free(error_str);
		return 1;
	}


	sql = "CREATE TABLE IF NOT EXISTS dupes (\n"
		"  id            INTEGER PRIMARY KEY NOT NULL,\n"
		"  path          TEXT NOT NULL UNIQUE,\n"
		"  digest        TEXT NOT NULL,\n"
		"  size          UNSIGNED INTEGER NOT NULL,\n"
		"  last_modified TEXT NOT NULL\n"
		");";
	sqlite3_exec(ctx->db, sql, NULL, NULL, &error_str);
	if (error_str != NULL) {
		printf("Failed to create the dupes table; error code: %s\n", error_str);
		sqlite3_free(error_str);
		return 1;
	}

	if (ctx->show) {
		char *sql_sort_by;
		char *sql_fmt =
			"SELECT "
			"   total.total, "
			"   dupes.digest, dupes.path, last_modified, dupes.size "
			"FROM dupes "
			"INNER JOIN ( "
			"  SELECT digest, count(*) AS total FROM dupes GROUP BY digest HAVING total > 1"
			") AS total USING (digest) "
			"ORDER BY %s, digest, last_modified, path"
		;
		switch (ctx->sort_by) {
			case DUPES_SORT_BY_SIZE:
				sql_sort_by = "size DESC, total DESC";
			break;

			case DUPES_SORT_BY_COUNT:
				sql_sort_by = "total DESC, size DESC";
			break;

			default:
				printf("Unknown sort type: %d\n", ctx->sort_by);
				return 1;
			break;
		}
		asprintf(&sql, sql_fmt, sql_sort_by);
		if (sql == NULL) {
			printf("Can't allocate memory for search query\n");
			return 1;
		}
		error = sqlite3_prepare_v2(ctx->db, sql, -1, &ctx->stmt_select, NULL);
		free(sql);
		if (IS_SQL_ERROR(error)) {
			printf("Can't prepare statement: %s; error code: %d %s\n", sql, error, sqlite3_errmsg(ctx->db));
			return 1;
		}

		return 0;
	}


	if (ctx->replace) {
		sql = "INSERT OR REPLACE INTO dupes (path, digest, size, last_modified) VALUES (?, ?, ?, ?)";
		error = sqlite3_prepare_v2(ctx->db, sql, -1, &ctx->stmt_insert, NULL);
		if (IS_SQL_ERROR(error)) {
			printf("Can't prepare statement: %s; error code: %d %s\n", sql, error, sqlite3_errmsg(ctx->db));
			return 1;
		}
	}
	else {
		sql = "INSERT OR IGNORE INTO dupes (path, digest, size, last_modified) VALUES (?, ?, ?, ?)";
		error = sqlite3_prepare_v2(ctx->db, sql, -1, &ctx->stmt_insert, NULL);
		if (IS_SQL_ERROR(error)) {
			printf("Can't prepare statement: %s; error code: %d %s\n", sql, error, sqlite3_errmsg(ctx->db));
			return 1;
		}

		sql = "SELECT 1 FROM dupes WHERE path = ? LIMIT 1";
		error = sqlite3_prepare_v2(ctx->db, sql, -1, &ctx->stmt_select, NULL);
		if (IS_SQL_ERROR(error)) {
			printf("Can't prepare statement: %s; error code: %d %s\n", sql, error, sqlite3_errmsg(ctx->db));
			return 1;
		}
	}

	return 0;
}



static
void dupes_ctx_finalize (DupesCtx *ctx) {
	if (ctx->stmt_insert != NULL) {
		sqlite3_finalize(ctx->stmt_insert);
		ctx->stmt_insert = NULL;
	}

	if (ctx->stmt_select != NULL) {
		sqlite3_finalize(ctx->stmt_select);
		ctx->stmt_select = NULL;
	}

	if (ctx->db != NULL) {
		sqlite3_close(ctx->db);
		ctx->db = NULL;
	}

	if (ctx->digest_bin != NULL) {
		free(ctx->digest_bin);
		ctx->digest_bin = NULL;
	}

	if (ctx->digest_hex != NULL) {
		free(ctx->digest_hex);
		ctx->digest_hex = NULL;
	}

	if (ctx->file_buffer != NULL) {
		free(ctx->file_buffer);
		ctx->file_buffer = NULL;
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
	struct tm time_tm;
	char last_modified[20];
	size_t i;
	int fd;
	size_t buffer_size;

	/** If we don't replace existing values then we can avoid to compute the
	    digest if we have it already in the DB */
	if (! ctx->replace) {
		sqlite3_reset(ctx->stmt_select);
		rc = sqlite3_bind_text(ctx->stmt_select, 1, filename, -1, SQLITE_STATIC);
		if (IS_SQL_ERROR(rc)) {
			printf("Failed to bind parameter path: %s; error: %d, %s\n", filename, rc, sqlite3_errmsg(ctx->db));
			return;
		}

		rc = sqlite3_step(ctx->stmt_select);
		switch (rc) {
			case SQLITE_ROW:
				/* Record found */
				return;
			break;

			case SQLITE_DONE:
        		/* Record not found (empty result set); we continue in the function */
			break;

			default:
				printf("Failed to lookup record for file %s; error: %d, %s", filename, rc, sqlite3_errmsg(ctx->db));
				return;
			break;
		}
	}


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
	else if (!ctx->keep_zero_size && stat_data.st_size == 0) {
		/* Zero size file */
		return;
	}

	gmtime_r(&stat_data.st_mtime, &time_tm);
	strftime(last_modified, sizeof(last_modified), "%Y-%m-%d %H:%M:%S", &time_tm);


	/*
	   Always prefer to use the buffer size reported by stat(). If we can't
	   allocate a buffer big enough then we default to the current allocated
	   buffer size.
	 */
	buffer_size = stat_data.st_blksize;
	if (ctx->file_buffer_size < stat_data.st_blksize) {
		void *ptr;
		ptr = realloc(ctx->file_buffer, stat_data.st_blksize);
		if (ptr != NULL) {
			ctx->file_buffer = (char *) ptr;
			ctx->file_buffer_size = buffer_size = stat_data.st_blksize;
		}
	}

	/* Compute the digest */
	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		printf("Failed to open %s\n", filename);
		return;
	}
	rc = ctx->compute_digest_func(ctx->digest_bin, fd, ctx->file_buffer, buffer_size);
	close(fd);
	if (rc) {return;}

	/* Transform the digest into HEX */
    digest = ctx->digest_hex;
    for (i = 0; i < ctx->digest_bin_len; ++i) {
        sprintf(digest, "%02x", ctx->digest_bin[i]);
        digest += 2;
    }
    digest = ctx->digest_hex;


	sqlite3_reset(ctx->stmt_insert);


	/* Parameter binding */
	rc = sqlite3_bind_text(ctx->stmt_insert, 1, filename, -1, SQLITE_STATIC);
	if (IS_SQL_ERROR(rc)) {
		printf("Failed to bind parameter path: %s; error: %d, %s\n", filename, rc, sqlite3_errmsg(ctx->db));
		return;
	}

	rc = sqlite3_bind_text(ctx->stmt_insert, 2, digest, -1, SQLITE_STATIC);
	if (IS_SQL_ERROR(rc)) {
		printf("Failed to bind parameter digest: %s; error: %d, %s\n", digest, rc, sqlite3_errmsg(ctx->db));
		return;
	}

	rc = sqlite3_bind_int(ctx->stmt_insert, 3, stat_data.st_size);
	if (IS_SQL_ERROR(rc)) {
		printf("Failed to bind parameter size: %s; error: %d, %s\n", filename, rc, sqlite3_errmsg(ctx->db));
		return;
	}

	rc = sqlite3_bind_text(ctx->stmt_insert, 4, last_modified, -1, SQLITE_STATIC);
	if (IS_SQL_ERROR(rc)) {
		printf("Failed to bind parameter last_modified: %s; error: %d, %s\n", last_modified, rc, sqlite3_errmsg(ctx->db));
		return;
	}


	printf("%s (%s) = %s\n", ctx->digest_name, filename, digest);

	/* Query execution */
	rc = sqlite3_step(ctx->stmt_insert);
	if (rc != SQLITE_DONE) {
		printf("Failed to insert digest: %s, path: %s; error: %d, %s\n", digest, filename, rc, sqlite3_errmsg(ctx->db));
		return;
	}

	++ctx->total_added;
}


static
int dupes_compute_md5 (unsigned char *digest_bin, int fd, char *buffer, size_t buffer_size) {
	MD5_CTX digest_ctx;
	ssize_t count;

	/* Compute the digest of the file */
	MD5_Init(&digest_ctx);

	while ( (count = read(fd, buffer, buffer_size)) > 0 ) {
		MD5_Update(&digest_ctx, buffer, count);
	}

	MD5_Final(digest_bin, &digest_ctx);
	return 0;
}


static
int dupes_compute_sha1 (unsigned char *digest_bin, int fd, char *buffer, size_t buffer_size) {
	SHA_CTX digest_ctx;
	ssize_t count;

	/* Compute the digest of the file */
	SHA1_Init(&digest_ctx);

	while ( (count = read(fd, buffer, buffer_size)) > 0 ) {
		SHA1_Update(&digest_ctx, buffer, count);
	}

	SHA1_Final(digest_bin, &digest_ctx);
	return 0;
}


static
void dupes_show (DupesCtx *ctx) {
	int done = 0;
	int rows = 0;
	int total = 0;

	sqlite3_reset(ctx->stmt_select);
	while (! done) {
		int rc;
		const unsigned char* path;
		const unsigned char* last_modified;
		int size;
		char *size_human;

		rc = sqlite3_step(ctx->stmt_select);
		switch (rc) {
			case SQLITE_ROW:
				/* Record found */
				if (total == 0) {
					const unsigned char* digest;
					total = sqlite3_column_int(ctx->stmt_select, 0);
					digest = sqlite3_column_text(ctx->stmt_select, 1);

					printf("%s (dupes: %d)\n", digest, total);
				}

				--total;
				path = sqlite3_column_text(ctx->stmt_select, 2);
				last_modified = sqlite3_column_text(ctx->stmt_select, 3);
				size = sqlite3_column_int(ctx->stmt_select, 4);
				size_human = dupes_size_human_readable(size);
				if (size_human != NULL) {
					printf("%s %s %s %s\n", total ? "|-" : "`-", path, size_human, last_modified);
					free(size_human);
				}
				else {
					printf("%s %s %d %s\n", total ? "|-" : "`-", path, size, last_modified);
				}
				++rows;
			break;

			case SQLITE_DONE:
				/* No more records */
				if (rows == 0) {
					printf("No duplicates found\n");
				}
				done = 1;
			break;

			default:
				printf("Failed to execute SQL query for showing duplicates; error: %d, %s", rc, sqlite3_errmsg(ctx->db));
				done = 1;
			break;
		}
	}
}

static
char *dupes_size_human_readable (size_t bytes) {
	const char* units [] = {
		"B",
		"KB",
		"MB",
		"GB",
		"TB",
	};
	const char *unit;
	double size = (double) bytes;
	char *buffer = NULL;
	int count = 0;

	unit = units[count++];
	while (size > 1024) {
		size /= 1024.0;
		unit = units[count++];
	}

	if (count == 1) {
		asprintf(&buffer, "%zu%s", bytes, unit);
	}
	else {
		asprintf(&buffer, "%.1f%s", size, unit);
	}

	return buffer;
}


static
int dupes_usage() {
	printf(
		"Usage: " PACKAGE_NAME " [OPTION]... FOLDER... FILE...\n"
		"Where OPTION is one of:\n"
		"   --db=DB,        -d DB  which database to use\n"
		"   --md5,          -m     use MD5 as the digest\n"
		"   --sha1,         -s     use SHA1 as the digest\n"
		"   --list,         -l     list duplicate files\n"
		"   --sort-size     -S     sort results by file size\n"
		"   --sort-count    -C     sort results by number of dupes\n"
		"   --replace,      -r     replace existing digest\n"
		"   --zero,         -z     process empty files\n"
		"   --version,      -v     show the program's version\n"
		"   --help,         -h     print this help message\n"
	);
	return 1;
}
