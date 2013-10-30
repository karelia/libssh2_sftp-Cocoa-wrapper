//
//  CK2SSHCredential.h
//  Sandvox
//
//  Created by Mike Abdullah on 02/09/2011.
//  Copyright © 2011 Karelia Software
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
//

#import <Foundation/Foundation.h>


@interface NSURLCredential (CK2SSHCredential)

// Indicates that authentication should be public key, with the help of ssh-agent
// SANDBOXING: SSH-Agent isn't available to sandboxed apps, so this will fail. Apple consider SSH keys to be something user should explicitly grant access to. https://devforums.apple.com/thread/144342?tstart=0
+ (NSURLCredential *)ck2_SSHAgentCredentialWithUser:(NSString *)user;

// Authenticate using particular public & private key files
// On OS X, libssh2 generally uses the OpenSSL encryption library, so public key URL may be nil
+ (NSURLCredential *)ck2_credentialWithUser:(NSString *)user
                               publicKeyURL:(NSURL *)publicKey
                              privateKeyURL:(NSURL *)privateKey;

// For general use, creates a credential backed by a keychain item
// When first requested, -password is cached. It's backing store is carefully managed to use keychain's cleanup routines when no longer in use
// Returns nil if username/account can't be retrieved from the keychain item
+ (NSURLCredential *)ck2_credentialWithKeychainItem:(SecKeychainItemRef)item;

- (BOOL)ck2_isPublicKeyCredential;

// These will be nil when using ssh-agent
- (NSURL *)ck2_publicKeyURL;
- (NSURL *)ck2_privateKeyURL;

// Use to derive a new credential, such as when providing a password for public key auth
- (NSURLCredential *)ck2_credentialWithPassword:(NSString *)password persistence:(NSURLCredentialPersistence)persistence;

// Support method for easy error construction
// opDescription - supply to give user some context about what it is you were trying to do. The keychain system's own error message will be appended to this
+ (NSError *)ck2_keychainErrorWithCode:(OSStatus)code localizedOperationDescription:(NSString *)opDescription;


@end


#pragma mark -


@interface NSURLCredentialStorage (CK2SSHCredential)

// Looks up a keychain entry for the private key's passphrase. Nil if none is stored
- (NSURLCredential *)ck2_credentialForPrivateKeyAtURL:(NSURL *)privateKey user:(NSString *)user;
- (BOOL)ck2_setPrivateKeyCredential:(NSURLCredential *)credential;

@end


#pragma mark -


// NSURLProtectionSpace doesn't handle SSH properly, so we need a specialist subclass that hardcodes it
// When this space is initialized, we patch NSURLCredentialStorage to support it
@interface CK2SSHProtectionSpace : NSURLProtectionSpace
@end
