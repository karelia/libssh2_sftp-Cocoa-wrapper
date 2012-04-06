//
//  CK2SFTPSession.h
//  Sandvox
//
//  Created by Mike on 03/07/2011.
//  Copyright 2011 Karelia Software. All rights reserved.
//

//
//  Like the underlying libssh2 library, a CK2SFTPSession is safe to use from any thread, as long as only one at a time is accessing it.


#import <Cocoa/Cocoa.h>

#import "CK2SFTPFileHandle.h"

#include <libssh2_sftp.h>


extern NSString *const CK2SSHDisconnectErrorDomain; // For disconnect reason codes as described in rfc4250. libssh2 defines constants for them
extern NSString *const CK2LibSSH2ErrorDomain;
extern NSString *const CK2LibSSH2SFTPErrorDomain;

extern NSString *const CK2SSHAuthenticationSchemePublicKey;
extern NSString *const CK2SSHAuthenticationSchemeKeyboardInteractive;
extern NSString *const CK2SSHAuthenticationSchemePassword;


#define CK2SFTPPreferredChunkSize 30000


@protocol CK2SFTPSessionDelegate;


@interface CK2SFTPSession : NSObject <NSURLAuthenticationChallengeSender>
{
  @private
    NSURL               *_URL;
    LIBSSH2_SFTP        *_sftp;
    LIBSSH2_SESSION     *_session;
    CFSocketRef         _socket;
    
    id <CK2SFTPSessionDelegate>     _delegate;
    NSURLAuthenticationChallenge    *_challenge;
    NSURLCredential                 *_keyboardInteractiveCredential;    // weak
}

- (id)initWithURL:(NSURL *)URL delegate:(id <CK2SFTPSessionDelegate>)delegate;
- (id)initWithURL:(NSURL *)URL delegate:(id <CK2SFTPSessionDelegate>)delegate startImmediately:(BOOL)startImmediately;

- (void)start;  // Causes the receiver to begin session, if it has not already
- (void)cancel; // after cancelling, you'll stop receiving delegate messages

- (CK2SFTPFileHandle *)openHandleAtPath:(NSString *)path flags:(unsigned long)flags mode:(long)mode error:(NSError **)error;
- (BOOL)setPermissions:(long)permissions forItemAtPath:(NSString *)path error:(NSError **)error;

- (BOOL)removeFileAtPath:(NSString *)path error:(NSError **)error;
- (BOOL)removeDirectoryAtPath:(NSString *)path error:(NSError **)error;
- (BOOL)moveItemAtPath:(NSString *)oldPath toPath:(NSString *)newPath error:(NSError **)error;


#pragma mark Creating Symbolic and Hard Links
- (NSString *)destinationOfSymbolicLinkAtPath:(NSString *)path error:(NSError **)error;


#pragma mark Managing the Current Directory
- (NSString *)currentDirectoryPath:(NSError **)error;


#pragma mark Directories

// Like NSFileManager
- (NSArray *)contentsOfDirectoryAtPath:(NSString *)path error:(NSError **)error;

// Returns an array of dictionaries, one per directory item, with the same keys as NSFileManager uses, but with the addition of cxFilenameKey
- (NSArray *)attributesOfContentsOfDirectoryAtPath:(NSString *)path error:(NSError **)error;

- (BOOL)createDirectoryAtPath:(NSString *)path mode:(long)mode error:(NSError **)error;
- (BOOL)createDirectoryAtPath:(NSString *)path withIntermediateDirectories:(BOOL)createIntermediates mode:(long)mode error:(NSError **)error;


#pragma mark Host Fingerprint

// Returns one of LIBSSH2_KNOWNHOST_CHECK_* values. error pointer is filled in for LIBSSH2_KNOWNHOST_CHECK_FAILURE
+ (int)checkKnownHostsForFingerprintFromSession:(CK2SFTPSession *)session error:(NSError **)error;

// Adds this connection's fingerprint to the standard known_hosts file. Call after accepting a new host, or accepting a change in fingerprint
- (BOOL)addToKnownHosts:(NSError **)error;

- (NSData *)hostkeyHashForType:(int)hash_type;  // LIBSSH2_HOSTKEY_HASH_SHA1 or LIBSSH2_HOSTKEY_HASH_MD5


#pragma mark Auth Support
// Returns an array of CK2SSHAuthenticationSchemePassword etc. nil in the event of failure, or the server supports unauthenticated usage
- (NSArray *)supportedAuthenticationSchemesForUser:(NSString *)user;    


#pragma mark Error Handling
// The last error produced by the system. If a method provides an error directly (or via the delegate), you should use that instead, as it has more contextual information available than -sessionError.
- (NSError *)sessionError;


#pragma mark libssh2
@property(nonatomic, readonly) LIBSSH2_SFTP *libssh2_sftp;
@property(nonatomic, readonly) LIBSSH2_SESSION *libssh2_session;


@end



@protocol CK2SFTPSessionDelegate

- (void)SFTPSessionDidInitialize:(CK2SFTPSession *)session; // session is now ready to read/write files etc.
- (void)SFTPSession:(CK2SFTPSession *)session didFailWithError:(NSError *)error;

// Generally handy for your debugging, the session gives a moderately detailed description of what it's up to. The received argument distinguishes between messages sent to the server, versus those received
- (void)SFTPSession:(CK2SFTPSession *)session appendStringToTranscript:(NSString *)string received:(BOOL)received;

// Upon the initial challenge, the first thing to do is check the hostkey's fingerprint against known hosts. Your app may have it hard coded, may go to a file, may present it to the user, that's your call. -checkHostFingerprint: is probably a good bet
// Note that NSURLCredentialStorage doesn't yet support SSH, so you will probably have to fetch the credential yourself from the keychain
- (void)SFTPSession:(CK2SFTPSession *)session didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge;
- (void)SFTPSession:(CK2SFTPSession *)session didCancelAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge;


@end

