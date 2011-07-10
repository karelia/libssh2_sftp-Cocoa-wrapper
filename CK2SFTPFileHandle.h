//
//  CK2SFTPFileHandle.h
//  Sandvox
//
//  Created by Mike on 03/07/2011.
//  Copyright 2011 Karelia Software. All rights reserved.
//

#import <Cocoa/Cocoa.h>

#include <libssh2_sftp.h>


@class CK2SFTPSession;


@interface CK2SFTPFileHandle : NSFileHandle
{
  @private
    LIBSSH2_SFTP_HANDLE *_handle;
    CK2SFTPSession      *_session;
    NSString            *_path;
}

// Session reference & path are not compulsary, but without you won't get decent error information
- (id)initWithSFTPHandle:(LIBSSH2_SFTP_HANDLE *)handle session:(CK2SFTPSession *)session path:(NSString *)path;

- (BOOL)closeFile:(NSError **)error;

- (BOOL)writeData:(NSData *)data error:(NSError **)error;
- (NSInteger)write:(const uint8_t *)buffer maxLength:(NSUInteger)length error:(NSError **)error;
- (NSInteger)write:(const uint8_t *)buffer maxLength:(NSUInteger)length;

@end
