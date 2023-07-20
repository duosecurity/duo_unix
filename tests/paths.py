#
# SPDX-License-Identifier: GPL-2.0-with-classpath-exception
#
# Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
# All rights reserved.
#
# paths.py
#

import os

if os.environ.get('BUILDDIR'):
    build = '%s/tests' % os.environ['BUILDDIR']
else:
    build = os.path.dirname(__file__) or '.'
    
topbuilddir = os.path.realpath(build + '/..')

login_duo = os.path.realpath(topbuilddir + '/login_duo/login_duo')


