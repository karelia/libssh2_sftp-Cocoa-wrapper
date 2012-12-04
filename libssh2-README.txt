libssh2 is a git submodule - be sure to update it via git

How to build libssh2:
1. Update the source to a new version if desired.
2. Select the target "libssh2" in the Scheme popup (32- or 64-bit doesn't matter).
3. Build. Just a regular Cmd-B build. No archiving or anything.
    Because the builds are controlled by scripts, not Xcode, they always build for "release", but also with debug info.
    Note also that the build outputs are:
    	libssh2.dylib  &  libssh2.dylib.dSYM
4. Make a new git commit if needed. Git is tracking the built dylib & dSYM as well as the source.

After updating/rebuilding libssh2, you should update/rebuild any libraries, frameworks, or apps that depend on it, such as libcurl & SFTP.
