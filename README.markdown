This code provides a Cocoa-friendly wrapper around libssh2's SFTP functionality, including:

- `NSFileManager`-esque methods for common operations, including recursive directory creation
- `NSFileHandle` subclass for convenient handling of file contents
- Encapsulation of errors using `NSError`
- Create of socket etc. needed for connecting, all from a simple `NSURL`
- `NSURLConnection`-style authentication handling, including support for public key auth, and checking against known hosts file
- Transcript output for your logging/diagnostic purposes

##Supported Platforms
- Mac OS X 10.5+
- In theory, iOS, but not tested at all yet

##Usage

Add these three files to your project:

- CK2SFTPSession.*
- libssh2.dylib

For file writing or reading, you are likely to also want these two files:

- CK2SFTPFileHandle.*

And to authenticate using a public key, add these two files:

- CK2SSHCredential.*

###Connecting to an SFTP server

1. Create a `CK2SFTPSession` instance, supplying the server's URL, and your delegate
2. The delegate is called once connected so you can asynchronously (e.g. ask the user first) supply a credential to authenticate with. If auth fails, you have as many shots at it as the server allows
3. Internally, an SFTP channel is opened up and the delegate is informed, ready for it to start issuing commands

If at any point the connection fails, the delegate is notified.

###Multi-threading

`CK2SFTPSession` presently uses libssh2's blocking API, so you should generally use it on a background thread. Fortunately `NSOperationQueue` makes this nice and easy. We use the same threading model as libssh2, so session instances (and their file handles) are free to be used on any thread, but only one at a time.

##Dependencies

Requires libssh2 1.2.8 or later. A pre-built `libssh2.dylib` is supplied, plus an Xcode project for building your own copy if needed.

##Credits & Contributors

Written by Mike Abdullah of Karelia Software.

Thanks also to Ira Cooke for fleshing out some functionality.

##Support

The code lives at https://github.com/karelia/libssh2_sftp-Cocoa-wrapper
Feel free to file Issues there, but no response is guaranteed.

##License

Copyright © 2011 Karelia Software

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
