## linux

```bash
wget https://github.com/DPDK/dpdk/archive/refs/tags/v22.11.tar.gz
tar xzf v22.11.tar.gz
cd dpdk-22.11
meson \
    --prefix=$CLOUD_PROBE_CXX_LIBS_SDK/linux-amd64 \
    -Ddefault_library=static \
    -Dbuildtype=release \
    -Dcpu_instruction_set=native \
    -Dc_args=-DRTE_LIBRTE_ICE_16BYTE_RX_DESC \
    build
cd build
ninja -j4 install
```