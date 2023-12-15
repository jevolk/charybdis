#!/bin/bash

BTOOLSET=$1              # The platform toolchain name (gcc, clang, mingw, ...)
BLIBS=$2                 # A comma-separated list of which boost libs to build
BVARIANT=$3              # release optimization or debug symbols etc
BLINK=$4                 # whether to build with shared or static linkage (we like shared)
BTHREADING=$5            # whether to build with thread-safety (we benefit from SINGLE THREADED)
BVER=$6                  # boost version
BCXXFLAGS=$7
TOPDIR=$8                # This should be an absolute path to the repo root


if [ -z $TOPDIR ]; then
	TOPDIR=$PWD
fi


if [ -z $BLIBS ]; then
	BLIBS="system"
fi


case "$BTOOLSET" in
g\+\+*|gcc*)
	BSFLAGS="--with-toolset=gcc";;

clang\+\+*|clang*)
	BSFLAGS="--with-toolset=clang";;

mingw\+\+*|mingw*)
	BSFLAGS="";;

*)
	BTOOLSET="";;
esac


if [ -z $BVARIANT ]; then
	BVARIANT="release"
fi


if [ -z $BLINK ]; then
	BLINK="shared"
fi


if [ -z $BTHREADING ]; then
	BTHREADING="single"
fi


if [ -z $BCXXFLAGS ]; then
	BCXXFLAGS=""
	_BCXXFLAGS=""
else
	_BCXXFLAGS="cxxflags=$BCXXFLAGS"
fi


run ()
{
	COMMAND=$1
	# check for empty commands
	if test -z "$COMMAND" ; then
		echo -e "\033[1;5;31mERROR\033[0m No command specified!"
		return 1
	fi

	shift;
	OPTIONS="$@"
	# print a message
	if test -n "$OPTIONS" ; then
		echo -ne "\033[1m$COMMAND $OPTIONS\033[0m ... "
	else
		echo -ne "\033[1m$COMMAND\033[0m ... "
	fi

	# run or die
	$COMMAND $OPTIONS ; RESULT=$?
	if test $RESULT -ne 0 ; then
		echo -e "\033[1;5;31mERROR\033[0m $COMMAND failed. (exit code = $RESULT)"
		exit 1
	fi

	echo -e "\033[0;32myes\033[0m"
	return 0
}

# Determine if boost is already sufficiently built to bail early rather than
# redundantly rebuilding every time ./configure is reinvoked.
# - Shared library at the desired version has to be built.
# - Submodule has to be checked out at desired version for matching headers.
CHKPATH="deps/boost/lib/libboost_system.so.${BVER}"
echo -ne "checking for boost built @ ${BVER}... "
find $CHKPATH > /dev/null 2>&1 ; CHKRES=$?
desc=`git -C deps/boost describe --tags`
if test $CHKRES == 0 && test "$desc" == "boost-${BVER}" ; then
	echo -e "\033[0;32myes\033[0m"
	exit 0
else
	echo -e "\033[0;33mno\033[0m."
fi

echo "*** synchronizing and building boost..."

# Save current dir and return to it later
USERDIR=$PWD

### Populate the boost submodule directory.
run cd $TOPDIR
run git submodule --quiet update --init deps/boost
run cd deps/boost
run git fetch --tags
run git checkout --quiet "boost-${BVER}"

SUBMOD_UPDATE_ARGS="--init --recursive --checkout"
SUBMOD_UPDATE="git submodule --quiet update $SUBMOD_UPDATE_ARGS"

### Build toolsy
run $SUBMOD_UPDATE tools/build
run $SUBMOD_UPDATE tools/inspect
run $SUBMOD_UPDATE tools/boost_install

### These are the libraries we need. Most of them are header-only. If not header-only,
### add to the list --with-libraries in the ./bootstrap command below
run $SUBMOD_UPDATE libs/predef
run $SUBMOD_UPDATE libs/assert
run $SUBMOD_UPDATE libs/static_assert
run $SUBMOD_UPDATE libs/type_traits
run $SUBMOD_UPDATE libs/config
run $SUBMOD_UPDATE libs/core
run $SUBMOD_UPDATE libs/detail
run $SUBMOD_UPDATE libs/headers

run $SUBMOD_UPDATE libs/asio
run $SUBMOD_UPDATE libs/system
run $SUBMOD_UPDATE libs/regex

run $SUBMOD_UPDATE libs/serialization
run $SUBMOD_UPDATE libs/lexical_cast
run $SUBMOD_UPDATE libs/range
run $SUBMOD_UPDATE libs/concept_check
run $SUBMOD_UPDATE libs/utility
run $SUBMOD_UPDATE libs/throw_exception
run $SUBMOD_UPDATE libs/numeric
run $SUBMOD_UPDATE libs/integer
run $SUBMOD_UPDATE libs/array
run $SUBMOD_UPDATE libs/functional
run $SUBMOD_UPDATE libs/describe
run $SUBMOD_UPDATE libs/container_hash
run $SUBMOD_UPDATE libs/container
run $SUBMOD_UPDATE libs/move
run $SUBMOD_UPDATE libs/math
run $SUBMOD_UPDATE libs/mp11

run $SUBMOD_UPDATE libs/tokenizer
run $SUBMOD_UPDATE libs/iterator
run $SUBMOD_UPDATE libs/mpl
run $SUBMOD_UPDATE libs/preprocessor
run $SUBMOD_UPDATE libs/date_time
run $SUBMOD_UPDATE libs/smart_ptr
run $SUBMOD_UPDATE libs/bind

run $SUBMOD_UPDATE libs/filesystem
run $SUBMOD_UPDATE libs/io

run $SUBMOD_UPDATE libs/dll
run $SUBMOD_UPDATE libs/align
run $SUBMOD_UPDATE libs/winapi

run $SUBMOD_UPDATE libs/spirit
run $SUBMOD_UPDATE libs/phoenix
run $SUBMOD_UPDATE libs/proto
run $SUBMOD_UPDATE libs/fusion
run $SUBMOD_UPDATE libs/typeof
run $SUBMOD_UPDATE libs/variant
run $SUBMOD_UPDATE libs/type_index
run $SUBMOD_UPDATE libs/foreach
run $SUBMOD_UPDATE libs/optional
run $SUBMOD_UPDATE libs/function
run $SUBMOD_UPDATE libs/function_types
run $SUBMOD_UPDATE libs/iostreams

run $SUBMOD_UPDATE libs/coroutine
#run $SUBMOD_UPDATE libs/coroutine2
## ASIO does not need coroutine2 at this time, but there is
## some issue with segmented stack support requiring inclusion
## of libs/context...
run $SUBMOD_UPDATE libs/context
run $SUBMOD_UPDATE libs/thread
run $SUBMOD_UPDATE libs/process
run $SUBMOD_UPDATE libs/chrono
run $SUBMOD_UPDATE libs/atomic
run $SUBMOD_UPDATE libs/ratio
run $SUBMOD_UPDATE libs/intrusive
run $SUBMOD_UPDATE libs/tuple
run $SUBMOD_UPDATE libs/exception
run $SUBMOD_UPDATE libs/algorithm
run $SUBMOD_UPDATE libs/endian

run $SUBMOD_UPDATE libs/locale

B2FLAGS="threading=$BTHREADING"
B2FLAGS+=" variant=$BVARIANT"
B2FLAGS+=" link=$BLINK"
B2FLAGS+=" runtime-link=shared"
B2FLAGS+=" address-model=64"
B2FLAGS+=" warnings=all"
B2FLAGS+=" $_BCXXFLAGS"

### Install should go right into this local submodule repository
run ./bootstrap.sh --prefix=$PWD --libdir=$PWD/lib --with-libraries=$BLIBS $BSFLAGS

BJAM="./bjam"
BJAM_OPTS="--clean"
if test -f "$BJAM"; then
	run $BJAM $BJAM_OPTS $B2FLAGS
fi

run ./b2 -d0 headers $B2FLAGS
run ./b2 -d0 install $B2FLAGS

### TODO: this shouldn't be necessary.
### XXX: required when boost submodules are fetched and built la carte, but not required
### XXX: when all submodules are fetched and built. we're missing a step.
for lib in `ls -d libs/*/include`; do
	run cp -r ${lib}/* include/
done
run cp -r libs/numeric/conversion/include/* include/

# Return to user's original directory
run cd $USERDIR
