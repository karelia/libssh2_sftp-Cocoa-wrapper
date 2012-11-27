OpenSSL is not a git submodule because openssl.org is a little behind the times.
They still use CVS.

So, the way to update the version of openssl we compile is:
1. Download a new version of the source distribution and corresponding MD5 file. 
    http://www.openssl.org/source/
2. Verify the MD5.
3. Unpack the tgz. You should get a folder named something like "openssl-1.0.1c".
4. Replace the contents of the "openssl" folder in this folder with the contents of the unpacked distribution.
5. Make a new git commit, etc.

You can check the version of the OpenSSL source by looking in the README file.
