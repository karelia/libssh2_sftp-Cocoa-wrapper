# Break out if the dylibs already exist.
if [ -e "${TARGET_TEMP_DIR}/libcrypto.dylib" ] && [ -e "${TARGET_TEMP_DIR}/libssl.dylib" ]
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

# Configure & build
if [ "${ARCH}" == "i386" ]
then
ARCH_TRIPLE="darwin-i386-cc"
else
ARCH_TRIPLE="darwin64-x86_64-cc"
fi
export CC="clang -isysroot ${SDKROOT} -g -w -mmacosx-version-min=10.6"
./Configure --prefix="@loader_path/../Frameworks" threads shared zlib-dynamic no-krb5 no-jpake no-store "${ARCH_TRIPLE}"
make build_libs

# Correct the load commands of the dylibs.
# Get the full filenames of the dylibs from the symlinks.
# E.g.: dylib:"libcrypto.1.0.0.dylib" symlink:"libcrypto.dylib"
LONG_CRYPTO_DYLIB=`readlink -n libcrypto.dylib`
LONG_SSL_DYLIB=`readlink -n libssl.dylib`
# For libcrypto, fix ID.
install_name_tool -id @rpath/libcrypto.dylib ${LONG_CRYPTO_DYLIB}
# For libssl, fix ID, correct load path of libcrypto, add rpath.
install_name_tool -id @rpath/libssl.dylib ${LONG_SSL_DYLIB}
install_name_tool -change @loader_path/../Frameworks/lib/${LONG_CRYPTO_DYLIB} @rpath/libcrypto.dylib ${LONG_SSL_DYLIB}
install_name_tool -add_rpath @loader_path/../Frameworks ${LONG_SSL_DYLIB}

# Copy dylibs to have arch in name.
cp -f ${LONG_CRYPTO_DYLIB} libcrypto-${ARCH}.dylib
cp -f ${LONG_SSL_DYLIB} libssl-${ARCH}.dylib

# Add to the lipo command.
LIBCRYPTO_LIPO_ARGS=("${LIBCRYPTO_LIPO_ARGS[@]}" "-arch" "${ARCH}" "${ARCH_WORKING_DIR}/libcrypto-${ARCH}.dylib")
LIBSSL_LIPO_ARGS=("${LIBSSL_LIPO_ARGS[@]}" "-arch" "${ARCH}" "${ARCH_WORKING_DIR}/libssl-${ARCH}.dylib")

# Preserve .a files name & location. They are needed by dsymutil later.
# libcrypto.a, libssl.a

done


# Create final dylib.
cd "${TARGET_TEMP_DIR}"
lipo -create "${LIBCRYPTO_LIPO_ARGS[@]}" -output libcrypto.dylib
lipo -create "${LIBSSL_LIPO_ARGS[@]}" -output libssl.dylib


# Create dSYM.
# NOTE: dsymutil depends on the static libraries being in the same place and having the same name (see previous note).
dsymutil libcrypto.dylib
dsymutil libssl.dylib

# Strip dylib.
strip -x libcrypto.dylib
strip -x libssl.dylib

# Copy headers.
mkdir -p include
cp -fRL "${ARCH_WORKING_DIR}/include/" include
