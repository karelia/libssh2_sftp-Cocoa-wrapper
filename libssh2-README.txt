OpenSSL is not a git submodule because openssl.org is a little behind the times.
They still use CVS.

So, the way to update the version of openssl we compile is:
1. Download a new version of the source distribution and corresponding MD5 file. 
    http://www.openssl.org/source/
2. Verify the MD5.
3. Unpack the tgz. You should get a folder named something like "openssl-1.0.1c".
4. Replace the entire contents of the "openssl" folder in this folder with the contents of the unpacked distribution.
5. Make a new git commit, etc.

You can check the version of the OpenSSL source by looking in the README file.

How to build openssl for Sandvox:
1. Update the source to a new version if desired.
2. Select the target "openssl" in the Scheme popup.
3. Build. Just a regular Cmd-B build. No archiving or anything.
    Because the builds are controlled by scripts, not Xcode, they always build for "release" with -O3, but also with debug info (such as it is with -O3).
    Note also that the build outputs are:
        libcrypto.dylib & libcrypto.dylib.dSYM
        libssl.dylib & libssl.dylib.dSYM
    All we're interested in is the libraries, not the app, etc.
4. Make a new git commit if needed.
