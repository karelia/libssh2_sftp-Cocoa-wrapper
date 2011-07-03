//
//  CK2SFTPHandle.h
//  Sandvox
//
//  Created by Mike on 03/07/2011.
//  Copyright 2011 Karelia Software. All rights reserved.
//

#import <Cocoa/Cocoa.h>

#include <libssh2_sftp.h>


@interface CK2SFTPHandle : NSObject
{
  @private
    LIBSSH2_SFTP_HANDLE *_sftp_handle;
}

- (id)initWithURL:(NSURL *)URL;

@end
