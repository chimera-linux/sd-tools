#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

SYSUSERS=$1

SOURCE=${2}/test-sysusers

[ -d "$SOURCE" ] || exit 69

# for now
NOLOGIN=/usr/bin/nologin
system_guid_max=999

TESTDIR=$(mktemp -d)
# shellcheck disable=SC2064
trap "rm -rf '$TESTDIR'" EXIT INT QUIT PIPE

prepare_testdir() {
    mkdir -p "$TESTDIR/etc/sysusers.d/"
    mkdir -p "$TESTDIR/usr/lib/sysusers.d/"
    rm -f "$TESTDIR"/etc/*passwd
    rm -f "$TESTDIR"/etc/*group
    rm -f "$TESTDIR"/etc/*shadow
    for i in $1.initial-passwd $1.initial-group $1.initial-shadow; do
        test -f "$i" && cp "$i" "$TESTDIR/etc/${i#*.initial-}"
    done
    return 0
}

preprocess() {
    m=${2:-$system_guid_max}

    # shellcheck disable=SC2140
    sed -e "s/SYSTEM_UGID_MAX/$m/g;
            s#NOLOGIN#${NOLOGIN}#g" "$1"
}

compare() {
    TMPF=$(mktemp)
    preprocess "$1.expected-passwd" "$3" > $TMPF
    if ! diff -u "$TESTDIR/etc/passwd" "$TMPF"; then
        echo "**** Unexpected output for $f $2"
        rm -f "$TMPF"
        exit 1
    fi

    preprocess "$1.expected-group" "$3" > $TMPF
    if ! diff -u "$TESTDIR/etc/group" "$TMPF"; then
        echo "**** Unexpected output for $f $2"
        rm -f "$TMPF"
        exit 1
    fi

    rm -f "$TMPF"
}

rm -f "$TESTDIR"/etc/sysusers.d/* "$TESTDIR"/usr/lib/sysusers.d/*

# happy tests
for f in $(find "$SOURCE"/test-*.input | sort -V); do
    echo "*** Running $f"
    prepare_testdir "${f%.input}"
    cp "$f" "$TESTDIR/usr/lib/sysusers.d/test.conf"
    $SYSUSERS --root="$TESTDIR"

    compare "${f%.*}" ""
done

for f in $(find "$SOURCE"/test-*.input | sort -V); do
    echo "*** Running $f on stdin"
    prepare_testdir "${f%.input}"
    touch "$TESTDIR/etc/sysusers.d/test.conf"
    $SYSUSERS --root="$TESTDIR" - <"$f"

    compare "${f%.*}" "on stdin"
done

for f in $(find "$SOURCE"/test-*.input | sort -V); do
    echo "*** Running $f on stdin with --replace"
    prepare_testdir "${f%.input}"
    touch "$TESTDIR/etc/sysusers.d/test.conf"
    # this overrides test.conf which is masked on disk
    $SYSUSERS --root="$TESTDIR" --replace=/etc/sysusers.d/test.conf - <"$f"
    # this should be ignored
    $SYSUSERS --root="$TESTDIR" --replace=/usr/lib/sysusers.d/test.conf - <"$SOURCE/test-1.input"

    compare "${f%.*}" "on stdin with --replace"
done

# test --inline
echo "*** Testing --inline"
prepare_testdir "$SOURCE/inline"
# copy a random file to make sure it is ignored
cp "$f" "$TESTDIR/etc/sysusers.d/confuse.conf"
$SYSUSERS --root="$TESTDIR" --inline \
          "u     u1   222 -     - /bin/zsh" \
          "g     g1   111"

compare "$SOURCE/inline" "(--inline)"

# test --replace
echo "*** Testing --inline with --replace"
prepare_testdir "$SOURCE/inline"
# copy a random file to make sure it is ignored
cp "$f" "$TESTDIR/etc/sysusers.d/confuse.conf"
$SYSUSERS --root="$TESTDIR" \
          --inline \
          --replace=/etc/sysusers.d/confuse.conf \
          "u     u1   222 -     - /bin/zsh" \
          "g     g1   111"

compare "$SOURCE/inline" "(--inline --replace=…)"

echo "*** Testing --inline with no /etc"
rm -rf "${TESTDIR:?}/etc"
$SYSUSERS --root="$TESTDIR" --inline \
          "u     u1   222 -     - /bin/zsh" \
          "g     g1   111"

compare "$SOURCE/inline" "(--inline)"

rm -f "$TESTDIR"/etc/sysusers.d/* "$TESTDIR"/usr/lib/sysusers.d/*

cat >"$TESTDIR/etc/login.defs" <<EOF
SYS_UID_MIN abcd
SYS_UID_MAX abcd
SYS_GID_MIN abcd
SYS_GID_MAX abcd
SYS_UID_MIN 401
SYS_UID_MAX 555
SYS_GID_MIN 405
SYS_GID_MAX 666
SYS_UID_MIN abcd
SYS_UID_MAX abcd
SYS_GID_MIN abcd
SYS_GID_MAX abcd
SYS_UID_MIN999
SYS_UID_MAX999
SYS_GID_MIN999
SYS_GID_MAX999
EOF

for f in $(find "$SOURCE"/test-*.input | sort -V); do
    echo "*** Running $f (with login.defs)"
    prepare_testdir "${f%.input}"
    cp "$f" "$TESTDIR/usr/lib/sysusers.d/test.conf"
    $SYSUSERS --root="$TESTDIR"

    # shellcheck disable=SC2050
    bound=$system_guid_max
    compare "${f%.*}" "(with login.defs)" "$bound"
done

rm -f "$TESTDIR"/etc/sysusers.d/* "$TESTDIR"/usr/lib/sysusers.d/*

mv "$TESTDIR/etc/login.defs" "$TESTDIR/etc/login.defs.moved"
ln -s ../../../../../etc/login.defs.moved "$TESTDIR/etc/login.defs"

for f in $(find "$SOURCE"/test-*.input | sort -V); do
    echo "*** Running $f (with login.defs symlinked)"
    prepare_testdir "${f%.input}"
    cp "$f" "$TESTDIR/usr/lib/sysusers.d/test.conf"
    $SYSUSERS --root="$TESTDIR"

    # shellcheck disable=SC2050
    bound=$system_guid_max
    compare "${f%.*}" "(with login.defs symlinked)" "$bound"
done

rm -f "$TESTDIR"/etc/sysusers.d/* "$TESTDIR"/usr/lib/sysusers.d/*

# tests for error conditions
for f in $(find "$SOURCE"/unhappy-*.input | sort -V); do
    echo "*** Running test $f"
    prepare_testdir "${f%.input}"
    cp "$f" "$TESTDIR/usr/lib/sysusers.d/test.conf"
    $SYSUSERS --root="$TESTDIR" 2>&1 | tail -n1 | sed -r 's/^[^:]+:[^:]+://' >"$TESTDIR/err"
    if ! diff -u "$TESTDIR/err"  "${f%.*}.expected-err"; then
        echo "**** Unexpected error output for $f"
        cat "$TESTDIR/err"
        exit 1
    fi
done
