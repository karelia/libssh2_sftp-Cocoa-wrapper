//
//  CK2SFTPSession.h
//  Sandvox
//
//  Created by Mike on 03/07/2011.
//  Copyright 2011 Karelia Software. All rights reserved.
//

#import <Cocoa/Cocoa.h>

#include <libssh2_sftp.h>


@protocol CK2SFTPSessionDelegate;


@interface CK2SFTPSession : NSObject <NSURLAuthenticationChallengeSender>
{
  @private
    LIBSSH2_SFTP        *_sftp_session;
    LIBSSH2_SESSION     *_session;
    CFSocketRef         _socket;
    
    id <CK2SFTPSessionDelegate> _delegate;
    
    LIBSSH2_SFTP_HANDLE *_sftp_handle;
}

- (id)initWithURL:(NSURL *)URL delegate:(id <CK2SFTPSessionDelegate>)delegate;
- (void)close;

- (LIBSSH2_SFTP_HANDLE *)openHandleAtPath:(NSString *)path flags:(unsigned long)flags mode:(long)mode;
- (NSInteger)write:(const uint8_t *)buffer maxLength:(NSUInteger)length handle:(LIBSSH2_SFTP_HANDLE *)handle;

@end



@protocol CK2SFTPSessionDelegate
- (void)SFTPSession:(CK2SFTPSession *)session didFailWithError:(NSError *)error;

- (void)SFTPSessionDidInitialize:(CK2SFTPSession *)session; // session is now ready to read/write files etc.
- (void)SFTPSession:(CK2SFTPSession *)session didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge;
@end
