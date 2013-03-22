//
//  CK2SSHCredential.h
//  Sandvox
//
//  Created by Mike on 02/09/2011.
//  iOS support provided by Nicola Peduzzi
//  Copyright 2011 Karelia Software. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface NSURLCredential (CK2SSHCredential)

#if !TARGET_OS_IPHONE
// Indicates that authentication should be public key, with the help of ssh-agent
// SANDBOXING: SSH-Agent isn't available to sandboxed apps, so this will fail. Apple consider SSH keys to be something user should explicitly grant access to. https://devforums.apple.com/thread/144342?tstart=0
+ (NSURLCredential *)ck2_SSHAgentCredentialWithUser:(NSString *)user;
#endif

// Authenticate using particular public & private key files
// On OS X, libssh2 generally uses the OpenSSL encryption library, so public key URL may be nil
+ (NSURLCredential *)ck2_credentialWithUser:(NSString *)user
                               publicKeyURL:(NSURL *)publicKey
                              privateKeyURL:(NSURL *)privateKey;

#if !TARGET_OS_IPHONE
// For general use, creates a credential backed by a keychain item
// When first requested, -password is cached. It's backing store is carefully managed to use keychain's cleanup routines when no longer in use
// Returns nil if username/account can't be retrieved from the keychain item
+ (NSURLCredential *)ck2_credentialWithKeychainItem:(SecKeychainItemRef)item;
#else
+ (NSURLCredential *)ck2_credentialWithKeychainQuery:(NSDictionary *)query;
#endif

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
