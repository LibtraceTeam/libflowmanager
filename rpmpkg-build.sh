#!/bin/bash

set -x -e -o pipefail

export QA_RPATHS=$[ 0x0001 ]
SOURCENAME=`echo ${GITHUB_REF##*/} | cut -d '-' -f 1`

./bootstrap.sh && ./configure && make dist
cp libflowmanager-*.tar.gz ~/rpmbuild/SOURCES/${SOURCENAME}.tar.gz
cp rpm/libflowmanager.spec ~/rpmbuild/SPECS/

cd ~/rpmbuild && rpmbuild -bb --define "debug_package %{nil}" SPECS/libflowmanager.spec


