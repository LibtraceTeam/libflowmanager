#!/bin/bash

set -x -e -o pipefail

export QA_RPATHS=$[ 0x0001 ]
SOURCENAME=`echo ${GITHUB_REF##*/} | cut -d '-' -f 1`

./bootstrap.sh && ./configure && make dist
cp libtrace-*.tar.gz ~/rpmbuild/SOURCES/${SOURCENAME}.tar.gz
cp rpm/libtrace4.spec ~/rpmbuild/SPECS/
#cp rpm/libtrace4-dag.spec ~/rpmbuild/SPECS/

cd ~/rpmbuild && rpmbuild -bb --define "debug_package %{nil}" SPECS/libtrace4.spec

#if [[ "$1" =~ centos* ]]; then
#       cd ~/rpmbuild && rpmbuild -bb --define "debug_package %{nil}" SPECS/libtrace4-dag.spec
#fi

