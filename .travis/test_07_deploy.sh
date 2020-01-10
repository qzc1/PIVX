#!/usr/bin/env bash

export LC_ALL=C.UTF-8

OUTDIR=$TRAVIS_BUILD_DIR/out/$TRAVIS_PULL_REQUEST/$TRAVIS_JOB_NUMBER-$HOST
mkdir -p $OUTDIR/bin

ARCHIVE_CMD="zip"

if [[ $HOST = "x86_64-w64-mingw32" ]]; then
    ARCHIVE_NAME+="windows.zip"
elif [[ $HOST = "x86_64-unknown-linux-gnu" ]]; then
    ARCHIVE_NAME+="linux_" + "$DOCKER_NAME_TAG" + ".tar.gz"
    ARCHIVE_CMD="tar -czf"
elif [[ $HOST = "x86_64-pc-linux-gnu" ]]; then
    ARCHIVE_NAME+="linux_18.04.tar.gz"
    ARCHIVE_CMD="tar -czf"
elif [[ $HOST = "x86_64-apple-darwin16" ]]; then
    ARCHIVE_NAME+="osx.zip"
fi
cp $TRAVIS_BUILD_DIR/build/pivx-$HOST/src/qt/pivx-qt $OUTDIR/bin/ || cp $TRAVIS_BUILD_DIR/build/pivx-$HOST/src/qt/pivx-qt.exe $OUTDIR/bin/ || echo "no QT Wallet"
cp $TRAVIS_BUILD_DIR/build/pivx-$HOST/src/pivxd $OUTDIR/bin/ || cp $TRAVIS_BUILD_DIR/build/pivx-$HOST/src/pivxd.exe $OUTDIR/bin/ || echo "no Daemon"
cp $TRAVIS_BUILD_DIR/build/pivx-$HOST/src/pivx-cli $OUTDIR/bin/ || cp $TRAVIS_BUILD_DIR/build/pivx-$HOST/src/pivx-cli.exe $OUTDIR/bin/ || echo "no Cli"
cp $TRAVIS_BUILD_DIR/build/pivx-$HOST/src/pivx-tx $OUTDIR/bin/ || cp $TRAVIS_BUILD_DIR/build/pivx-$HOST/src/pivx-tx.exe $OUTDIR/bin/ || echo "no TX"
strip "$OUTDIR/bin"/*
ls -lah $OUTDIR/bin

cd $OUTDIR/bin || return
ARCHIVE_CMD="$ARCHIVE_CMD $ARCHIVE_NAME *"
eval $ARCHIVE_CMD

mkdir -p $OUTDIR/zip
mv $ARCHIVE_NAME $OUTDIR/zip

sleep $(( ( RANDOM % 6 ) + 1 ))s
