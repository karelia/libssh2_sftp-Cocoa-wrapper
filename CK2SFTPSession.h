//
//  CK2SFTPSession.h
//  Sandvox
//
//  Created by Mike on 03/07/2011.
//  Copyright 2011 Karelia Software. All rights reserved.
//

#import <Cocoa/Cocoa.h>

#include <libssh2_sftp.h>


extern NSString *const CK2LibSSH2ErrorDomain;
extern NSString *const CK2LibSSH2SFTPErrorDomain;


#define CK2SFTPPreferredChunkSize 30000


@class CK2SFTPFileHandle;
@protocol CK2SFTPSessionDelegate;


@interface CK2SFTPSession : NSObject <NSURLAuthenticationChallengeSender>
{
  @private
    LIBSSH2_SFTP        *_sftp;
    LIBSSH2_SESSION     *_session;
    CFSocketRef         _socket;
    
    id <CK2SFTPSessionDelegate>     _delegate;
    NSURLAuthenticationChallenge    *_challenge;
}

- (id)initWithURL:(NSURL *)URL delegate:(id <CK2SFTPSessionDelegate>)delegate;
- (void)close;

- (NSFileHandle *)openHandleAtPath:(NSString *)path flags:(unsigned long)flags mode:(long)mode error:(NSError **)error;

- (BOOL)removeFileAtPath:(NSString *)path error:(NSError **)error;

- (BOOL)createDirectoryAtPath:(NSString *)path mode:(long)mode error:(NSError **)error;
- (BOOL)createDirectoryAtPath:(NSString *)path withIntermediateDirectories:(BOOL)createIntermediates mode:(long)mode error:(NSError **)error;

// The last error produced by the system. If a method provides an error directly (or via the delegate), you should use that instead, as it has more contextual information available than -sessionError.
- (NSError *)sessionError;

@property(nonatomic, readonly) LIBSSH2_SFTP *libssh2_sftp;

@end



@protocol CK2SFTPSessionDelegate
- (void)SFTPSession:(CK2SFTPSession *)session didFailWithError:(NSError *)error;

- (void)SFTPSessionDidInitialize:(CK2SFTPSession *)session; // session is now ready to read/write files etc.
- (void)SFTPSession:(CK2SFTPSession *)session didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge;
@end
