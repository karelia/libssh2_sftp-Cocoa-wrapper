# Original script by Felix Shulze https://github.com/x2on/libssh2-for-iOS

# Break out if the libraries already exist.
if [ -e "${TARGET_TEMP_DIR}/libcrypto.a" ] && [ -e "${TARGET_TEMP_DIR}/libssl.a" ]
then
exit 0
fi

# Include default paths for MacPorts & HomeBrew.
export PATH=${PATH}:/opt/local/bin:/usr/local/bin

ARCH_WORKING_DIR_PREFIX="${TARGET_TEMP_DIR}/${TARGET_NAME}/${TARGET_NAME}"
LIBCRYPTO_LIPO_ARGS=()
LIBSSL_LIPO_ARGS=()

for ARCH in ${ARCHS}
do

# Copy source to a new location to build.
ARCH_WORKING_DIR="${ARCH_WORKING_DIR_PREFIX}-${ARCH}"
cd "${SRCROOT}"
mkdir -p "${ARCH_WORKING_DIR}"
cp -af openssl/ "${ARCH_WORKING_DIR}"
cd "${ARCH_WORKING_DIR}"

# Configure and build.
if [ ! "${ARCH}" == "i386" ]
then
sed -ie "s!static volatile sig_atomic_t intr_signal;!static volatile intr_signal;!" "crypto/ui/ui_openssl.c"
fi

export CC="clang -arch ${ARCH} -g -w"
export CROSS_TOP="${PLATFORM_DIR}/Developer"
export CROSS_SDK=`basename ${SDKROOT}`

./Configure iphoneos-cross
make build_libs

# Copy libraries to have arch in name.
cp -f libcrypto.a libcrypto-${ARCH}.a
cp -f libssl.a libssl-${ARCH}.a

# Add to the lipo args.
LIBCRYPTO_LIPO_ARGS=("${LIBCRYPTO_LIPO_ARGS[@]}" "-arch" "${ARCH}" "${ARCH_WORKING_DIR}/libcrypto-${ARCH}.a")
LIBSSL_LIPO_ARGS=("${LIBSSL_LIPO_ARGS[@]}" "-arch" "${ARCH}" "${ARCH_WORKING_DIR}/libssl-${ARCH}.a")

done

# Create final libraries.
cd "${TARGET_TEMP_DIR}"
lipo -create "${LIBCRYPTO_LIPO_ARGS[@]}" -output libcrypto.a
lipo -create "${LIBSSL_LIPO_ARGS[@]}" -output libssl.a

# Strip libraries.
strip -x libcrypto-iOS.a
strip -x libssl-iOS.a

# Copy headers.
mkdir -p include
cp -fRL "${ARCH_WORKING_DIR}/include/" include
