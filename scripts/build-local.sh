#!/usr/bin/env bash
# AgileNet 本地一键构建：setup.exe + apk + anet-svc musl 静态链，产物统一归集 .build/（gitignored）
#
#   scripts/build-local.sh            # 三产物全建（默认）
#   scripts/build-local.sh --gui      # 仅 setup.exe（本机 cargo tauri build）
#   scripts/build-local.sh --apk      # 仅 apk（首跑自动在 .build/android-sdk 引导便携 SDK/NDK，不污染系统）
#   scripts/build-local.sh --musl     # 仅 anet-svc-linux-x64-musl（Docker，无需本机 Linux 工具链）
#
# 环境变量：BUILD_APK_ABIS="aarch64"（空格分隔，默认仅 aarch64；全量四 ABI 用 "aarch64 armv7 x86 x86_64"）
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/.build"
DESKTOP="$ROOT/apps/desktop"
mkdir -p "$OUT"

WANT_GUI=0; WANT_APK=0; WANT_MUSL=0
if [ $# -eq 0 ]; then
  WANT_GUI=1; WANT_APK=1; WANT_MUSL=1
else
  for a in "$@"; do
    case "$a" in
      --gui) WANT_GUI=1 ;;
      --apk) WANT_APK=1 ;;
      --musl) WANT_MUSL=1 ;;
      *) echo "未知参数: $a（可用：--gui / --apk / --musl）" >&2; exit 2 ;;
    esac
  done
fi

VER=$(grep -o '"version": *"[^"]*"' "$DESKTOP/tauri.conf.json" | head -1 | cut -d'"' -f4)
log() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
sha() { (cd "$OUT" && sha256sum "$1" > "$1.sha256"); }

# ==================== setup.exe（本机原生） ====================
if [ "$WANT_GUI" = 1 ]; then
  log "[gui] anet-gui setup.exe（cargo tauri build，release 全量编译，热缓存快、冷构建慢）"
  command -v cargo-tauri >/dev/null 2>&1 || command -v cargo >/dev/null 2>&1 || { echo "缺少 cargo/tauri-cli" >&2; exit 1; }
  (cd "$DESKTOP" && cargo tauri build)
  PRODUCT=$(grep -o '"productName": *"[^"]*"' "$DESKTOP/tauri.conf.json" | head -1 | cut -d'"' -f4)
  SETUP="$DESKTOP/target/release/bundle/nsis/${PRODUCT}_${VER}_x64-setup.exe"
  # 兜底取最新（productName 变更后目录里可能并存新旧两份，防误拷陈旧产物）
  [ -f "$SETUP" ] || SETUP=$(ls -t "$DESKTOP"/target/release/bundle/nsis/*-setup.exe | head -1)
  cp "$SETUP" "$OUT"/
  sha "$(basename "$SETUP")"
  log "[gui] 完成 → $OUT/$(basename "$SETUP")"
fi

# ==================== anet-svc musl 静态链（Docker） ====================
if [ "$WANT_MUSL" = 1 ]; then
  log "[musl] anet-svc-linux-x64-musl（Docker 构建，镜像含 musl-tools + 依赖层缓存）"
  command -v docker >/dev/null 2>&1 || { echo "缺少 docker（musl 静态链走容器构建）" >&2; exit 1; }
  docker build -f "$ROOT/.docker/Dockerfile.build" --target export \
    --output "type=local,dest=$(cygpath -m "$OUT" 2>/dev/null || echo "$OUT")" "$ROOT"
  sha anet-svc-linux-x64-musl
  log "[musl] 完成 → $OUT/anet-svc-linux-x64-musl"
fi

# ==================== apk（原生优先；无 symlink 特权自动转 Docker） ====================
# Windows 上 cargo-mobile2 强制 symlink jniLibs，需开发者模式/管理员特权；探测失败即走
# .docker/Dockerfile.android 容器构建（零系统改动）。开启开发者模式后原生路径自动生效（更快）。
apk_native_capable() {
  case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) ;; *) return 0 ;; esac
  local d="$OUT/.lnprobe" ok=1
  rm -rf "$d"; mkdir -p "$d"; echo x > "$d/t"
  if cmd //c "mklink \"$(cygpath -w "$d/l")\" \"$(cygpath -w "$d/t")\"" >/dev/null 2>&1; then ok=0; fi
  rm -rf "$d"
  return $ok
}

if [ "$WANT_APK" = 1 ]; then
  APK_SRC=""
  if apk_native_capable; then
    log "[apk] 本机原生构建（便携 SDK：.build/android-sdk；Gradle 缓存：.build/gradle）"
    command -v java >/dev/null 2>&1 || { echo "缺少 JDK（17+，当前 shell 找不到 java）" >&2; exit 1; }
    SDK="$OUT/android-sdk"
    export ANDROID_HOME="$SDK" GRADLE_USER_HOME="$OUT/gradle"
    SDKMANAGER="$SDK/cmdline-tools/latest/bin/sdkmanager.bat"

    # 1) 便携 SDK 骨架（tauri init 硬性要求 ANDROID_HOME 已存在，先放命令行工具）
    if [ ! -f "$SDKMANAGER" ]; then
      log "[apk] 首次构建：下载 Android 命令行工具（约 130MB，进 .build/android-sdk）"
      mkdir -p "$SDK/cmdline-tools"
      ZIP="$OUT/cmdline-tools.zip"
      curl -fL --retry 3 -o "$ZIP" "https://dl.google.com/android/repository/commandlinetools-win-11076708_latest.zip"
      rm -rf "$SDK/cmdline-tools/latest"
      unzip -q "$ZIP" -d "$SDK/cmdline-tools"
      mv "$SDK/cmdline-tools/cmdline-tools" "$SDK/cmdline-tools/latest"
      rm -f "$ZIP"
    fi

    # 2) NDK（tauri init 硬性要求 SDK+NDK 就位）
    NDK_VER="27.0.12077973"
    if [ ! -d "$SDK/ndk/$NDK_VER" ]; then
      log "[apk] 安装 NDK（首跑约 2GB）"
      yes | "$SDKMANAGER" --licenses >/dev/null 2>&1 || true
      "$SDKMANAGER" "platform-tools" "ndk;$NDK_VER"
    fi
    export NDK_HOME="$SDK/ndk/$NDK_VER" ANDROID_NDK_HOME="$SDK/ndk/$NDK_VER"

    # 3) 脚手架 + 按模板 compileSdk 精确安装 platform/build-tools
    [ -d "$DESKTOP/gen/android" ] || (cd "$DESKTOP" && cargo tauri android init)
    # Gradle wrapper 默认源 services.gradle.org 不可达时改写腾讯镜像（幂等）
    sed -i 's#services.gradle.org/distributions#mirrors.cloud.tencent.com/gradle#' \
      "$DESKTOP/gen/android/gradle/wrapper/gradle-wrapper.properties" 2>/dev/null || true
    COMPILE_SDK=$(grep -oE 'compileSdk *= *[0-9]+' "$DESKTOP/gen/android/app/build.gradle.kts" | grep -oE '[0-9]+' | head -1)
    COMPILE_SDK=${COMPILE_SDK:-36}
    if [ ! -d "$SDK/platforms/android-$COMPILE_SDK" ]; then
      log "[apk] 安装 platforms;android-$COMPILE_SDK + build-tools;$COMPILE_SDK.0.0"
      "$SDKMANAGER" "platforms;android-$COMPILE_SDK" "build-tools;$COMPILE_SDK.0.0"
    fi

    # 4) 交叉编译 + 打包
    ABIS=${BUILD_APK_ABIS:-aarch64}
    for abi in $ABIS; do
      case "$abi" in
        aarch64) triple=aarch64-linux-android ;;
        armv7|arm) triple=armv7-linux-androideabi ;;
        x86) triple=i686-linux-android ;;
        x86_64) triple=x86_64-linux-android ;;
        *) echo "未知 ABI: $abi" >&2; exit 2 ;;
      esac
      rustup target add "$triple" >/dev/null
    done
    TARGS=(); for abi in $ABIS; do TARGS+=(--target "$abi"); done
    (cd "$DESKTOP" && cargo tauri android build --apk --debug "${TARGS[@]}")
    APK_SRC="$DESKTOP/gen/android/app/build/outputs/apk"
  else
    log "[apk] 本机无 symlink 特权（Windows 开发者模式未开）→ Docker 容器构建（零系统改动）"
    command -v docker >/dev/null 2>&1 || { echo "缺少 docker；或开启 Windows 开发者模式后重试" >&2; exit 1; }
    docker build -f "$ROOT/.docker/Dockerfile.android" --target export       --output "type=local,dest=$(cygpath -m "$OUT" 2>/dev/null || echo "$OUT")/apk-out" "$ROOT"
    APK_SRC="$OUT/apk-out/apk"
  fi

  found=0
  while IFS= read -r apk; do
    # abi 目录形如 arm64_v8a / armeabi_v7a / universal；名归一为 arm64 等短名
    abi_dir=$(basename "$(dirname "$(dirname "$apk")")")
    short=${abi_dir%%_v8a}; short=${short%%_v7a}
    dest="$OUT/anet-gui_${VER}_android-${short}.apk"
    cp "$apk" "$dest"; sha "$(basename "$dest")"; found=1
    log "[apk] 完成 → $dest"
  done < <(find "$APK_SRC" -name '*.apk' 2>/dev/null)
  rm -rf "$OUT/apk-out"  # docker 中转目录（同一份 apk 已归集上方）
  [ "$found" = 1 ] || { echo "未找到 apk 产物（构建失败？）" >&2; exit 1; }
fi

log "全部选定产物就绪：$OUT"
ls -la "$OUT"
