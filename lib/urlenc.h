/*
  urlenc.h

  SPDX-License-Identifier: LicenseRef-URLEnc-MIT

  Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
  Copyright (c) 1996 - 2010, Daniel Stenberg, <daniel@haxx.se>.
  All rights reserved.
*/

#ifndef URLENC_H
#define URLENC_H

char *urlenc_encode(const char *string);
char *urlenc_decode(const char *string, size_t *olen);

#endif /* URLENC_H */
