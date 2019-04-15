# Contributing
Thanks for your interest in contributing to Duo Unix!

We welcome pull requests as well issues you may have.

## Opening Issues
Before opening an issue on the Github project see if your issue falls into the following categories. If it does please direct your issue to those locations instead.

##### My issue is related to a security vulnerability in Duo Unix
Thank you for reporting this! In order to keep our customers safe we ask that you do NOT open an issue on the public Github page but instead contact us directly using our [Security Response Guide](https://duo.com/labs/security-response).

##### My issue is related to my PAM stack or other configuration problems
Due to the sensitive nature of your configuration we ask that you don't post any config files, log files, etc. on the Github project. In scenarios where the issue is related to your specific configuration we ask that you reach out to our [Duo Support Team](https://duo.com/support).

If you are simply using the latest tarball and having an issue with the documentation we also ask that you reach out to [Duo Support](https://duo.com/support).

##### My issue doesn't fit into the above categories
Great! Please open an issue with us and fill out the template.

## Creating a pull request
Before creating a pull request we encourage you to also open an issue. This will give us an opportunity to let you know if your change is something we'd be interested in pulling in or not before you put in all the work.


Once you are ready to make a pull request

1. Check your style matches our [style guidelines](#style-guidelines).
2. Make sure you have included tests to cover your change. Check out our[README.md](README.md) for information about our tests.
3. Follow the instructions in the pull request template.
4. Make sure that your diff passes the TravisCI tests.

## Style Guidelines
Our C programming style guidelines are a work in progress right now.

- For the most part we just ask that you look at the code around your change and attempt to match it's style.
- Use 4 space indentation
- Do not include whitespaces on blank lines
- Do not use single line if statements without {}
- Use `/* This is a comment */` over `//This is a comment`
