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


extern NSString *const CK2LibSSH2ErrorDomain;
extern NSString *const CK2LibSSH2SFTPErrorDomain;


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
}

- (id)initWithURL:(NSURL *)URL delegate:(id <CK2SFTPSessionDelegate>)delegate;
- (id)initWithURL:(NSURL *)URL delegate:(id <CK2SFTPSessionDelegate>)delegate startImmediately:(BOOL)startImmediately;

- (void)start;  // Causes the receiver to begin session, if it has not already
- (void)cancel; // after cancelling, you'll stop receiving delegate messages

- (CK2SFTPFileHandle *)openHandleAtPath:(NSString *)path flags:(unsigned long)flags mode:(long)mode error:(NSError **)error;

- (BOOL)removeFileAtPath:(NSString *)path error:(NSError **)error;

- (BOOL)createDirectoryAtPath:(NSString *)path mode:(long)mode error:(NSError **)error;
- (BOOL)createDirectoryAtPath:(NSString *)path withIntermediateDirectories:(BOOL)createIntermediates mode:(long)mode error:(NSError **)error;

- (NSData *)hostkeyHashForType:(int)hash_type; // LIBSSH2_HOSTKEY_HASH_SHA1 or LIBSSH2_HOSTKEY_HASH_MD5

// The last error produced by the system. If a method provides an error directly (or via the delegate), you should use that instead, as it has more contextual information available than -sessionError.
- (NSError *)sessionError;

@property(nonatomic, readonly) LIBSSH2_SFTP *libssh2_sftp;

@end



@protocol CK2SFTPSessionDelegate

- (void)SFTPSessionDidInitialize:(CK2SFTPSession *)session; // session is now ready to read/write files etc.
- (void)SFTPSession:(CK2SFTPSession *)session didFailWithError:(NSError *)error;
- (void)SFTPSession:(CK2SFTPSession *)session appendStringToTranscript:(NSString *)string;

// Upon the initial challenge, the first thing to do is check the hostkey's fingerprint against known hosts. Your app may have it hard coded, may go to a file, may present it to the user, that's your call
- (void)SFTPSession:(CK2SFTPSession *)session didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge;

@end

