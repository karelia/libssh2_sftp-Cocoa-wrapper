# Break out if the lib already exists.
if [ -e "${CONFIGURATION_TEMP_DIR}/libcrypto.dylib" ] && [ -e "${CONFIGURATION_TEMP_DIR}/libssl.dylib" ]
then
exit 0
fi

# Include default paths for MacPorts & HomeBrew.
export PATH=${PATH}:/opt/local/bin:/usr/local/bin
# Force building for both archs so we don't have to worry about Xcode magic.
ARCHS="i386 x86_64"
ARCH_WORKING_DIR_PREFIX="${TARGET_TEMP_DIR}/${TARGET_NAME}/${TARGET_NAME}"

for ARCH in ${ARCHS}
do

ARCH_WORKING_DIR="${ARCH_WORKING_DIR_PREFIX}-${ARCH}"
if [ "${ARCH}" == "i386" ];
then
ARCH_TRIPLE="darwin-i386-cc"
else
ARCH_TRIPLE="darwin64-x86_64-cc"
fi


# Copy source to a new location to build.
cd "${SRCROOT}"
mkdir -p "${ARCH_WORKING_DIR}"
cp -af openssl/ "${ARCH_WORKING_DIR}"
cd "${ARCH_WORKING_DIR}"

# Configure & build
export CC="clang -isysroot ${SDKROOT} -g -w -mmacosx-version-min=10.6    "
./Configure --prefix="@loader_path/../Frameworks"  threads shared zlib-dynamic  no-krb5 no-jpake no-store  "${ARCH_TRIPLE}"
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

# Preserve .a files name & location. They are needed by dsymutil later.
# libcrypto.a, libssl.a

done


# Create final dylib.

cd "${CONFIGURATION_TEMP_DIR}"
lipo -create -arch i386 "${ARCH_WORKING_DIR_PREFIX}-i386/libcrypto-i386.dylib" -arch x86_64 "${ARCH_WORKING_DIR_PREFIX}-x86_64/libcrypto-x86_64.dylib" -output libcrypto.dylib
lipo -create -arch i386 "${ARCH_WORKING_DIR_PREFIX}-i386/libssl-i386.dylib"    -arch x86_64 "${ARCH_WORKING_DIR_PREFIX}-x86_64/libssl-x86_64.dylib"    -output libssl.dylib


# Create dSYM
# NOTE: dsymutil depends on the static libraries being in the same place and having the same name (see previous note)
dsymutil libcrypto.dylib
dsymutil libssl.dylib

# Strip dylib
strip -x libcrypto.dylib
strip -x libssl.dylib

# Copy headers
mkdir -p include
cp -fRL "${ARCH_WORKING_DIR}/include/" include
