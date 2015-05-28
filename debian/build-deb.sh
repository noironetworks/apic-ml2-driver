#!/bin/bash
# Should be run from the root of the source tree
# Set env var DEB_REVISION to append to the 'revision' field in version string

BUILD_DIR=${BUILD_DIR:-`pwd`/debbuild}
mkdir -p $BUILD_DIR
rm -rf $BUILD_DIR/*
NAME=`python setup.py --name`
VERSION=`python setup.py --version`
python setup.py sdist --dist-dir $BUILD_DIR
SOURCE_FILE=${NAME}-${VERSION}.tar.gz
tar -C $BUILD_DIR -xf $BUILD_DIR/$SOURCE_FILE
# strip out stuff after '.dev' from version to make debuild happy
VERSION2=${VERSION/.dev*/.dev}
mv $BUILD_DIR/$SOURCE_FILE $BUILD_DIR/${NAME}_${VERSION2}.orig.tar.gz
pushd $BUILD_DIR/${NAME}-${VERSION}
debuild -d -us -uc
popd
