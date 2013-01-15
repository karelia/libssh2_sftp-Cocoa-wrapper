//
//  CK2SSHCredential.h
//  Sandvox
//
//  Created by Mike on 02/09/2011.
//  iOS support provided by Nicola Peduzzi
//  Copyright 2011 Karelia Software. All rights reserved.
//

#import <Foundation/Foundation.h>

#if TARGET_OS_IPHONE

// Substituting keychain definition for iOS
#define SecKeychainItemRef CFTypeRef
#define SecItemAttr CFTypeRef
#define SecProtocolType CFTypeRef

#define kSecAccountItemAttr kSecAttrAccount
#define kSecLabelItemAttr kSecAttrLabel
#define kSecServiceItemAttr kSecAttrService
#define kSecServerItemAttr kSecAttrServer
#define kSecPathItemAttr kSecAttrPath

#define kSecProtocolTypeFTP kSecAttrProtocolFTP
#define kSecProtocolTypeFTPAccount kSecAttrProtocolFTPAccount
#define kSecProtocolTypeHTTP kSecAttrProtocolHTTP
#define kSecProtocolTypeIRC kSecAttrProtocolIRC
#define kSecProtocolTypeNNTP kSecAttrProtocolNNTP
#define kSecProtocolTypePOP3 kSecAttrProtocolPOP3
#define kSecProtocolTypeSMTP kSecAttrProtocolSMTP
#define kSecProtocolTypeSOCKS kSecAttrProtocolSOCKS
#define kSecProtocolTypeIMAP kSecAttrProtocolIMAP
#define kSecProtocolTypeLDAP kSecAttrProtocolLDAP
#define kSecProtocolTypeAppleTalk kSecAttrProtocolAppleTalk
#define kSecProtocolTypeAFP kSecAttrProtocolAFP
#define kSecProtocolTypeTelnet kSecAttrProtocolTelnet
#define kSecProtocolTypeSSH kSecAttrProtocolSSH
#define kSecProtocolTypeFTPS kSecAttrProtocolFTPS
#define kSecProtocolTypeHTTPS kSecAttrProtocolHTTPS
#define kSecProtocolTypeHTTPProxy kSecAttrProtocolHTTPProxy
#define kSecProtocolTypeHTTPSProxy kSecAttrProtocolHTTPSProxy
#define kSecProtocolTypeFTPProxy kSecAttrProtocolFTPProxy
#define kSecProtocolTypeSMB kSecAttrProtocolSMB
#define kSecProtocolTypeRTSP kSecAttrProtocolRTSP
#define kSecProtocolTypeRTSPProxy kSecAttrProtocolRTSPProxy
#define kSecProtocolTypeDAAP kSecAttrProtocolDAAP
#define kSecProtocolTypeEPPC kSecAttrProtocolEPPC
#define kSecProtocolTypeIPP kSecAttrProtocolIPP
#define kSecProtocolTypeNNTPS kSecAttrProtocolNNTPS
#define kSecProtocolTypeLDAPS kSecAttrProtocolLDAPS
#define kSecProtocolTypeTelnetS kSecAttrProtocolTelnetS
#define kSecProtocolTypeIMAPS kSecAttrProtocolIMAPS
#define kSecProtocolTypeIRCS kSecAttrProtocolIRCS
#define kSecProtocolTypePOP3S kSecAttrProtocolPOP3S

#endif


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
+ (NSURLCredential *)ck2_credentialWithUser:(NSString *)user keychainItem:(SecKeychainItemRef)item;
#endif

- (BOOL)ck2_isPublicKeyCredential;

// These will be nil when using ssh-agent
- (NSURL *)ck2_publicKeyURL;
- (NSURL *)ck2_privateKeyURL;

// Use to derive a new credential, such as when providing a password for public key auth
- (NSURLCredential *)ck2_credentialWithPassword:(NSString *)password persistence:(NSURLCredentialPersistence)persistence;


@end


#pragma mark -


@interface NSURLCredentialStorage (CK2SSHCredential)

// NSURLCredentialStorage can only handle HTTP and FTP credentials by default
- (BOOL)ck2_setCredential:(NSURLCredential *)credential forSSHHost:(NSString *)host port:(NSInteger)port error:(NSError **)error;

// Looks up a keychain entry for the private key's passphrase. Nil if none is stored
- (NSURLCredential *)ck2_credentialForPrivateKeyAtURL:(NSURL *)privateKey user:(NSString *)user;
- (BOOL)ck2_setPrivateKeyCredential:(NSURLCredential *)credential;

// Support method for easy error construction
// opDescription - supply to give user some context about what it is you were trying to do. The keychain system's own error message will be appended to this
+ (NSError *)ck2_keychainErrorWithCode:(OSStatus)code localizedOperationDescription:(NSString *)opDescription;

@end
