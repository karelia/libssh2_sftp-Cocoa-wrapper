# Include default paths for MacPorts & HomeBrew.
export PATH=${PATH}:/opt/local/bin:/usr/local/bin
# Force building for both archs so we don't have to worry about Xcode magic.
ARCHS="i386 x86_64"

for ARCH in ${ARCHS}
do

# Copy source to a new location to build.
cd "${SRCROOT}"
mkdir -p "{OBJROOT}/${TARGET_NAME}/${TARGET_NAME}-${ARCH}"
cp -af openssl/ "${OBJROOT}/${TARGET_NAME}/${TARGET_NAME}-${ARCH}"
cd "${OBJROOT}/${TARGET_NAME}/${TARGET_NAME}-${ARCH}"

# Configure & build
export CC="clang -isysroot ${SDKROOT} -g -w -mmacosx-version-min=10.6    "
./Configure --prefix="@loader_path/../Frameworks"  threads shared zlib-dynamic  no-krb5 no-jpake no-store  darwin-i386-cc
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
cd "${OBJROOT}/${TARGET_NAME}"
lipo -create -arch i386 "${TARGET_NAME}-i386/libcrypto-i386.dylib" -arch x86_64 "${TARGET_NAME}-x86_64/libcrypto-x86_64.dylib" -output libcrypto.dylib
lipo -create -arch i386 "${TARGET_NAME}-i386/libssl-i386.dylib"    -arch x86_64 "${TARGET_NAME}-x86_64/libssl-x86_64.dylib"    -output libssl.dylib


# Create dSYM
# NOTE: dsymutil depends on the static libraries being in the same place and having the same name (see previous note)
dsymutil libcrypto.dylib
dsymutil libssl.dylib

# Strip dylib
strip -x libcrypto.dylib
strip -x libssl.dylib

# Copy x86_64 headers
mkdir -p include
cp -fRL openssl-x86_64/include/ include
