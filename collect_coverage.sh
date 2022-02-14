#!/bin/bash
# Run this at the root of a Duo Unix directory that has been compiled with coverage
# reporting turned on

if ! [ -x "$(command -v gcovr)" ]; then
    echo "Missing gcovr. Please pip install"
    exit 1
fi

mkdir -p coverage

# This section is necessary because otherwise coverage files are created with a
# file mode of 0100 (due to an issue with linking to compat) which causes
# errors. To "get ahead of this" we are creating the coverage files and setting
# their file mode to 700 this allows us to have full coverage and avoid errors.

mkdir -p tests/.libs
GCDA_FILES=(
    "/vagrant/pam_duo/.libs/pam_duo_private.gcda"
    "/vagrant/pam_duo/.libs/pam_duo.gcda"
    "/vagrant/tests/testpam.gcda"
    "/vagrant/tests/.libs/testpam_preload.gcda"
    "/vagrant/pam_duo/.libs/pam_duo_private.gcda"
    "/vagrant/pam_duo/.libs/pam_duo.gcda"
    "/vagrant/tests/testpam.gcda"
    "/vagrant/tests/.libs/testpam_preload.gcda"
    "/vagrant/lib/.libs/http_parser.gcda"
    "/vagrant/lib/.libs/urlenc.gcda"
    "/vagrant/lib/.libs/ini.gcda"
    "/vagrant/lib/.libs/https.gcda"
    "/vagrant/lib/.libs/duo.gcda"
)

for i in "${GCDA_FILES[@]}"; do
   rm -f "$i"; touch "$i"; chmod 700 "$i"
done

# end weird permission hacking

make check
gcovr --xml-pretty --exclude-unreachable-branches --print-summary -o coverage/coverage.xml --root .

if [ -f pam_duo/pam_duo.gcno ]; then
    (
        cd pam_duo || return
        gcov pam_duo.c -o .libs
        gcovr --txt
        gcovr --html-details pam_duo.html
        rm -f .libs/*.gcda
    )
    mv pam_duo/*.{css,html} coverage
else
    echo "No coverage information found for pam_duo.c"
fi
if [ -f login_duo/login_duo.gcno ]; then
    (
        cd login_duo || return
        gcov login_duo.c
        gcovr --txt
        gcovr --html-details login_duo.html
        gcovr --xml-pretty --exclude-unreachable-branches --print-summary -o login_duo.xml --root ${CI_PROJECT_DIR}
        rm -f *.gcda
    )
mv login_duo/*.{css,html} coverage
else
    echo "No coverage information found for login_duo.c"
fi
if [ -f lib/duo.gcno ]; then
    (
        cd lib || return
        gcov duo.c -o .libs
        gcovr --txt
        gcovr --html-details duo.html
        rm -f .libs/*.gcda
    )
    mv lib/*.{css,html} coverage
else
    echo "No coverage information found for duo.c"
fi
