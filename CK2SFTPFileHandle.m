//
//  CK2SFTPFileHandle.m
//  Sandvox
//
//  Created by Mike on 03/07/2011.
//  Copyright 2011 Karelia Software. All rights reserved.
//

#import "CK2SFTPFileHandle.h"


@implementation CK2SFTPFileHandle

- (id)initWithSFTPHandle:(LIBSSH2_SFTP_HANDLE *)handle;
{
    if (self = [self init])
    {
        _handle = handle;
    }
    
    return self;
}

- (void)closeFile;
{
    [super closeFile];
    
    libssh2_sftp_close(_handle);
}

- (void)writeData:(NSData *)data;
{
    /* write data in a loop until we block */
    NSInteger result = libssh2_sftp_write(_handle, [data bytes], [data length]);
    OBASSERT(result == [data length]);
}

@end
