# Raspberry Pi Setup and Deployment

## Kernel Setup

### 1. Initialize Raspberry Pi with stock OS

### 2. Re-build kernel with EBPF enabled

```
git clone https://github.com/raspberrypi/linux -b rpi-6.18.y  # For Pi 5 Trixie (rpi-6.12.y for Bookworm)
```

Update arch/arm64/configs/bcm2712_defconfig (or bcm2711_defconfig for Pi 4) to enable the following kernel configs (some may already be enabled/disabled, make sure there is only one configuration set for each):

```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_KPROBES=y
CONFIG_KPROBE_EVENTS=y
CONFIG_TRACEPOINTS=y
CONFIG_FTRACE=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_CGROUPS=y
CONFIG_PROC_FS=y
CONFIG_BPF_MAP_TYPE_RINGBUF=y
CONFIG_CGROUP_BPF=y
CONFIG_PSI=y
```

---

#### Cross-compiling from x86 host

**Dependencies**

```
sudo apt install gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu \
               make bc bison flex libssl-dev libelf-dev dwarves
```

- `gcc-aarch64-linux-gnu` — the cross-compiler (aarch64-linux-gnu-gcc)
- `dwarves` — provides pahole ≥ v1.16, required for CONFIG_DEBUG_INFO_BTF
- `libelf-dev` — required for BTF generation
- `bison`, `flex` — for building Kconfig tools

**Steps**

```bash
# 1. Configure
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- O=../build bcm2712_defconfig

# 2. Build
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- O=../build -j8

# 3. Install modules to a staging dir
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- O=../build \
   INSTALL_MOD_PATH=/tmp/pi5-modules modules_install
```

Output: `../build/arch/arm64/boot/Image`

---

#### Compiling natively on the Pi 5

**Dependencies**

```
sudo apt install gcc make bc bison flex libssl-dev libelf-dev dwarves
```

Same packages minus the cross-compiler — use the native gcc.

**Steps**

```bash
# 1. Configure
make O=../build bcm2712_defconfig

# 2. Build
make O=../build -j4   # Pi 5 has 4 cores

# 3. Install modules directly (no staging dir needed)
sudo make O=../build modules_install

# 4. Install kernel
sudo cp ../build/arch/arm64/boot/Image /boot/firmware/kernel_2712.img
```

### 3. Deploy Kernel

#### Deploying from cross-compile (x86 host)

```bash
BUILD=/path/to/build
PI=<pi-username>@<pi-ip>

# Back up existing kernel
ssh -t $PI "sudo cp /boot/firmware/kernel_2712.img /boot/firmware/kernel_2712_orig.img"

# Copy kernel image
scp $BUILD/arch/arm64/boot/Image /tmp/kernel_2712.img
scp /tmp/kernel_2712.img $PI:/tmp/
ssh -t $PI "sudo mv /tmp/kernel_2712.img /boot/firmware/kernel_2712.img"

# Install modules to staging dir, rsync to Pi
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- O=$BUILD \
     INSTALL_MOD_PATH=/tmp/pi5-modules modules_install
rsync -av --rsync-path="sudo rsync" /tmp/pi5-modules/lib/modules/ $PI:/lib/modules/

# Copy DTBs
for dtb in $BUILD/arch/arm64/boot/dts/broadcom/bcm2712*.dtb; do
    scp $dtb $PI:/tmp/
    ssh -t $PI "sudo mv /tmp/$(basename $dtb) /boot/firmware/"
done

ssh -t $PI "sudo reboot"
```

#### Deploying from native compile (on the Pi itself)

```bash
BUILD=/path/to/build

# Back up existing kernel
sudo cp /boot/firmware/kernel_2712.img /boot/firmware/kernel_2712_orig.img

# Install modules
sudo make O=$BUILD modules_install

# Copy kernel and DTBs
sudo cp $BUILD/arch/arm64/boot/Image /boot/firmware/kernel_2712.img
sudo cp $BUILD/arch/arm64/boot/dts/broadcom/bcm2712*.dtb /boot/firmware/

sudo reboot
```

## Build and Deploy agl-health

This exercise uses [emb_cli](https://github.com/toyota-connected/emb_cli) to cross-compile and deploy the agl-health components to the target.

```
emb cross {path-to}/agl-health/agl-health-daemon --target rpi5-trixie --build --deb --deploy pi-username@pi-ip-address
emb cross {path-to}/agl-health/agl-health-native/native --target rpi5-trixie --build --deb --deploy pi-username@pi-ip-address
emb cross {path-to}/ivi-homescreen --target rpi5-bookworm --build --backend wayland-egl --app {path-to}/agl-health/flutter_task_manager --mode release --deploy-dir flutter_task_manager --deploy
```

## 5. Run agl-health

On target:

```
sudo RUST_LOG=info agl-health-daemon &
cd flutter_task_manager && ./homescreen -b .
```
