Duo Unix
===
[![Build Status](https://travis-ci.org/duosecurity/duo_unix.svg?branch=master)](https://travis-ci.org/duosecurity/duo_unix)
[![Issues](https://img.shields.io/github/issues/duosecurity/duo_unix)](https://github.com/duosecurity/duo_unix/issues)
[![Forks](https://img.shields.io/github/forks/duosecurity/duo_unix)](https://github.com/duosecurity/duo_unix/network/members)
[![Stars](https://img.shields.io/github/stars/duosecurity/duo_unix)](https://github.com/duosecurity/duo_unix/stargazers)
[![License](https://img.shields.io/badge/License-View%20License-orange)](https://github.com/duosecurity/duo_unix/blob/master/LICENSE)

Duo two-factor authentication for Unix systems.

Duo Unix includes a PAM module or alternatively a stand alone executable that can be used to protect programs such as SSH or Sudo.

This repository is meant to be used for development or cutting edge versions of Duo Unix.
For production deployments Duo recommends using our stable release tarballs or packages. Instructions can be found on our documentation page [Duo Unix Docs](https://duo.com/docs/duounix)


## Getting Started

These instructions are geared towards getting you up and running on your local machine for development and testing purposes.
See the deployment section for notes on how to deploy Duo Unix in production.

### Prerequisites

You will likely want to have some kind of virtual machine when developing Duo Unix. If Duo Unix is configured incorrectly it has the potential to lock you out of a system. It's better to have that happen on a virtual machine instead of your computer.

We recommend something like [Vagrant](https://www.vagrantup.com/) or [Docker](https://www.docker.com/)

### Installing

Install the necessary third party libraries.

- Debian based Systems
```
$ sudo apt-get install autoconf libtool libpam-dev libssl-dev make
```

- RHEL based systems
```
$ sudo yum install autoconf libtool pam-devel openssl-devel
```

- RHEL 7 and CentOS 7 systems with SELinux enabled
```
$ sudo yum install selinux-policy-devel bzip2
```

Clone the Duo Unix project down and enter the directory
```
$ git clone <paste the url here>
$ cd duo_unix/
```

Run bootstrap to generate the configure script.
```
$ ./bootstrap
```

Run configure to generate your makefiles.
```
$ ./configure --with-pam --prefix=/usr
```

Build the project locally
```
$ make
```

Install the project. The install location will be the same as the prefix you specified in the configure step.
```
$ sudo make install
```

After installation add your integration keys to the config files
- Visit the Duo Admin Panel and create a "Unix" integration if you don't have one already
- Copy your ikey, skey, and api_host into the proper fields of the config files
```
$ vim /etc/duo/login_duo.conf
$ vim /etc/duo/pam_duo.conf
```

Finally, test an auth!
```
$ sudo login_duo -f myusername 'echo "Hello World"'
```
You should only see "Hello World" if the authentication succeeds.

## Running the tests

The additional prereq for running the tests is python
```
#  RHEL Based
$ sudo yum install python
#  Debian Based
$ sudo apt-get install python
```

To run all the automated tests simply run
```
$ sudo make check
```
To run an individual test file
```
$ cd tests/
$ python test_login_duo.py
```
To run an individual test suite
```
$ cd tests/
$ python test_login_duo.py TestLoginDuoConfig
```
To run an individual test case
```
$ cd tests/
$ python test_login_duo.py TestLoginDuoConfig.test_empty_args
```

### Python Tests

For Duo Unix we use the python `unittest` library to do our testing. Each suite
typically starts by creating a mock duo service. After we create that service
we perform a series of tests to verify that this software is working as
expected. Although we use the `unittest` library these are not truely "unit tests"
as manage subprocesses and generally employ blackbox testing. The true "unit tests"
for Duo Unix are the unity tests.

### Testing with coverage
To generate coverate reports you'll need to compile Duo Unix with the `--with-coverage` options.
Please note that in order to view HTML version of the coverage reports you'll also need to
install the python package `gcovr`.

To see the testing coverage of the Duo PAM for example you would run the following at the
repository root.
```
$ ./configure --with-coverage --with-pam
$ ./collect_coverage.sh
$ $BROWSER coverage/pam_duo.html
```
Note that configuring Duo Unix --with-coverage disables any compiler optimizations
to allow the profiler to better match executed instructions with lines of code.

### Other testing tips

Each test creates the mockduo server for you, but if you need to run it manually to test things you can.
Below is an example of running a mockduo server in one session and authenticating against it in another.
```
$ cd tests/
$ python mockduo.py certs/mockduo.pem
Now in a separate terminal window
$ ../login_duo/login_duo -d -c confs/mockduo.conf -f my_username echo "Success"
```
This mock server can be a bit brittle so you may have to restart it if you start seeing very weird behavior.

## Static analysis

Install [cppcheck](http://cppcheck.sourceforge.net/)

```
$ cppcheck --quiet --force -i tests --suppressions-list=.false_positive.txt --error-exitcode=1 .
```

## Deployment

For production deployments Duo recommends using our stable release tarballs or packages. Instructions can be found on our documentation page [Duo Unix Docs](https://duo.com/docs/duounix)

### TLS 1.2 and 1.3 Support

Duo Unix uses the system's OpenSSL library for TLS operations.  It will use the highest TLS version available when making API calls to Duo.  TLS 1.2 support requires OpenSSL 1.0.1 or higher; TLS 1.3 support requires OpenSSL 1.1.1 or higher.

## Contributing

Please read [CODEOFCONDUCT.md](CODEOFCONDUCT.md) and [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests to us.

## Versioning

We use [SemVer](http://semver.org/) for versioning.

## License

This project is licensed under the GPLv2 License - see the [LICENSE](LICENSES/GPL-2.0-with-classpath-exception.txt) file for details

## Support

Report any bugs, feature requests, etc. to support@duo.com
