#!/bin/bash

CURRENT_PATH="$(dirname $(readlink -f $0))"
cd $CURRENT_PATH/..
PROJECT_PATH=`pwd`

find $PROJECT_PATH/src -name "*.cpp" -o -name "*.h" -o -name "*.hpp" -o -name "*.c" -o -name "*.cc" \
    | xargs python $PROJECT_PATH/cfg/cpplint.py --filter=-build/include,-build/include_order,-whitespace --extensions=c,cc,cpp,cxx,h,hpp,hxx --counting=detailed 2>&1 \
    | python $PROJECT_PATH/cfg/cpplint_to_cppcheckxml.py

cd -
