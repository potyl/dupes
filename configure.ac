dnl Process this file with autoconf to produce a configure script.

AC_INIT(dupes, 0.0.5, http://github.com/potyl/dupes)
AM_INIT_AUTOMAKE([foreign subdir-objects])

AC_CONFIG_SRCDIR([src])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AM_MAINTAINER_MODE
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Libraries
PKG_CHECK_MODULES(OPENSSL, [openssl >= 0.9.8])
PKG_CHECK_MODULES(SQLITE3, [sqlite3 >= 3.6.16])


# Make sure we keep ACLOCAL_FLAGS around for maintainer builds to work
AC_SUBST(ACLOCAL_AMFLAGS, "$ACLOCAL_FLAGS -I m4")

AC_CONFIG_FILES([Makefile src/Makefile])

AC_OUTPUT
