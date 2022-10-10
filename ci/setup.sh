# This file must be used with "source setup.sh" *from bash*
# you cannot run it directly
# Usage :
#  $ source setup.sh

# 
# Source lock
#

# if [ "${BASH_SOURCE-}" = "$0" ]; then
#     echo "You must source this script: \$ source $0" >&2
#     exit 33
# fi
# 
# if [ ! -z ${__DEV_ENTER+x} ]; then
#     echo "Already launched $__DEV_ENTER"
#     return 1
# fi
# 

export PROJECT_DIR=`pwd`
__DEV_ENV_NAME="$(basename `pwd`)-env"

#
# Utils
#

echo_action(){
    echo "\e[94m[$__DEV_ENV_NAME]\e[39m >>> $@"
}

echo_succes(){
    echo "\e[92m[$__DEV_ENV_NAME]\e[39m >>> $@"
}

runci(){
    echo_action "$@ BEGIN"
    $@
    echo_succes "$@ SUCCESS"
}

#
# setup variables
# 
# export ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
export ROOT=$(realpath .)
echo_action "use ROOT=$ROOT"
export RISCV=$ROOT/tmp/riscv-install
export PATH=$RISCV/bin:/bin:$PATH
export LIBRARY_PATH=$RISCV/lib
export LD_LIBRARY_PATH=$RISCV/lib
export C_INCLUDE_PATH=$RISCV/include
export CPLUS_INCLUDE_PATH=$RISCV/include

#
# setup scripts
# 

runci ci/make-tmp.sh
runci ci/install-riscv64.sh
runci ci/install-fesvr.sh
runci ci/build-riscv-tests.sh
runci ci/install-spike.sh
#
# Misc
#

PS1="[$__DEV_ENV_NAME] ${PS1-}"
__DEV_ENTER=`date`
