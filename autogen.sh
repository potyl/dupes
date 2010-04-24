#!/bin/sh

aclocal -I /opt/local/share/aclocal
autoheader
automake
autoconf
