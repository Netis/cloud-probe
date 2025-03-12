wget https://github.com/DPDK/dpdk/archive/refs/tags/v22.11.tar.gz
tar xzf v22.11.tar.gz
cd dpdk-22.11
./build.sh

```bash
install_dir="/root/cpagent_libs_sdk"
build_dir="tmp_bld_dir"
cores=`lscpu | grep "^CPU(s)" | awk '{print $2}'`
cores=$((cores-1))

[ -d /opt/rh/devtoolset-11/ ] && source scl_source enable devtoolset-11
export CC=`which gcc`
export CXX=`which g++`

if [ -d $build_dir ] ; then
    reconf="--reconfigure"
fi
meson $reconf --prefix=$install_dir -Ddefault_library=static -Dbuildtype=release -Dcpu_instruction_set=skylake \
    -Dc_args=-DRTE_LIBRTE_ICE_16BYTE_RX_DESC  $build_dir
cd $build_dir
ninja -j$cores install
```