This code provides a Cocoa-friendly wrapper around libssh2's SFTP functionality, including:

- `NSFileManager`-esque methods for common operations, including recursive directory creation
- `NSFileHandle` subclass for convenient handling of file contents
- Encapsulation of errors using `NSError`
- Create of socket etc. needed for connecting, all from a simple `NSURL`
- `NSURLConnection`-style authentication handling, including support for public key auth, and checking against known hosts file
- Transcript output for your logging/diagnostic purposes

##Supported Platforms
- Mac OS X 10.5+
- iOS 6.0+

##Usage

Clone the repository and initialize it's submodules.
Add libssh2.xcodeproj and OpenSSL.xcodeproj to your project or workspace.
If you are building an executable, add libssh2, libcrypto and libssl to your linking phase.
If you are building a library, add libssh2, libcrypto and libssl to your target dependencies.

Add these files to your project:

- Sources/CK2SFTPSession.*

For file writing or reading, you are likely to also want these two files:

- Sources/CK2SFTPFileHandle.*

And to authenticate using a public key, add these two files:

- Sources/CK2SSHCredential.*

###Connecting to an SFTP server

1. Create a `CK2SFTPSession` instance, supplying the server's URL, and your delegate
2. The delegate is called once connected so you can asynchronously (e.g. ask the user first) supply a credential to authenticate with. If auth fails, you have as many shots at it as the server allows
3. Internally, an SFTP channel is opened up and the delegate is informed, ready for it to start issuing commands

If at any point the connection fails, the delegate is notified.

###Multi-threading

`CK2SFTPSession` presently uses libssh2's blocking API, so you should generally use it on a background thread. Fortunately `NSOperationQueue` makes this nice and easy. We use the same threading model as libssh2, so session instances (and their file handles) are free to be used on any thread, but only one at a time.

##Dependencies

Building libssh2 requires automake, autoconf and GNU libtool. You can install them using [brew](http://brew.sh) or your favorite package manager.

##Known bugs

The build scripts for libssh2 and openssl exit immediately if the libraries already exist, regardless of whether the binaries are up-to-date, so if you update the submodules you have to clean out the targets to force the build.

##Credits & Contributors

Written by Mike Abdullah of Karelia Software.

Thanks also to Ira Cooke for fleshing out some functionality.

##Support

The code lives at https://github.com/karelia/libssh2_sftp-Cocoa-wrapper
Feel free to file Issues there, but no response is guaranteed.

##License

Standard BSD. You know the drill.
