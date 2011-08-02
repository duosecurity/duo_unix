
import os

if os.environ.get('BUILDDIR'):
    build = '%s/tests' % os.environ['BUILDDIR']
else:
    build = os.path.dirname(__file__) or '.'
    
topbuilddir = os.path.realpath(build + '/..')

login_duo = os.path.realpath(topbuilddir + '/login_duo/login_duo')


