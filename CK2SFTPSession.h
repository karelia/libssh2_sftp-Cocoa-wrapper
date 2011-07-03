//
//  CK2SFTPSession.h
//  Sandvox
//
//  Created by Mike on 03/07/2011.
//  Copyright 2011 Karelia Software. All rights reserved.
//

#import <Cocoa/Cocoa.h>

#include <libssh2_sftp.h>


@interface CK2SFTPSession : NSObject
{
  @private
    LIBSSH2_SFTP        *_sftp_session;
    LIBSSH2_SESSION     *_session;
    CFSocketRef         _socket;
    
    LIBSSH2_SFTP_HANDLE *_sftp_handle;
}

- (id)initWithURL:(NSURL *)URL;

@end
