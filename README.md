Duo Unix
===
[![Build Status](https://travis-ci.org/duosecurity/duo_unix.svg?branch=master)](https://travis-ci.org/duosecurity/duo_unix)

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
$ sudo apt-get install autoconf libtool libpam-dev libssl-dev
```

- RHEL based systems
```
$ sudo yum install autoconf libtool pam-devel openssl-devel
```

- RHEL 7 and CentOS 7 systems with SELinux enabled
```
$ sudo yum install selinux-policy-devel
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
$ make check
```

To run an individual test
```
$ cd tests/
$ python cram.py login_duo-1.t
```

### Cram Tests

For Duo Unix we use [Cram](https://bitheap.org/cram/) to do our testing. Each test file typically starts by creating a mock duo service. After we create that service we list commands followed by the expected output of that command.
If the output matches, then the cram test passes. If not, it fails.

Example passing test
```
$ echo "Hello World"
Hello World
```
Example failing test
```
$ echo "Hello World"
Goodbye World
```

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

## Deployment

For production deployments Duo recommends using our stable release tarballs or packages. Instructions can be found on our documentation page [Duo Unix Docs](https://duo.com/docs/duounix)

## Contributing

Please read [CODEOFCONDUCT.md](CODEOFCONDUCT.md) and [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests to us.

## Versioning

We use [SemVer](http://semver.org/) for versioning.

## License

This project is licensed under the GPLv2 License - see the [LICENSE](LICENSE) file for details

## Support

Report any bugs, feature requests, etc. to support@duo.com
