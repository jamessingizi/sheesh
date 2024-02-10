# sheesh

Sheesh is a collection of useful IT tools in the commandline.

### How to install sheesh

```shell
pip install sheesh
```

This will install sheesh on your system

### How to use sheesh

Using the app is easy, just type `sheesh` followed by a command that describes what you want to do eg:

```shell
sheesh uuid
```

This command will generate a valid UUID.

Most `sheesh` commands have options that make it easy to customise each command to your liking. As an example the `uuid`
command can take a version option to specify the version of UUID to generate. It can also take a count param to specify
how many uuids you want to generate. Passing in all the options and params, the uuid command can look like:

```shell
sheesh uuid --version=4 --count=10
```

Most commands follow this simple convention. To view the help for any command just type:

```shell
sheesh <command-name> --help
```

and this will show you all the available options and params for the command.

To view all available sheesh commands, just type:

```shell
sheesh --help
```

### Available Utilities

Crypto
---
- bcrypt
- bip39
- decrypt
- encrypt
- hash
- HMAC
- password
- slugify
- token
- ulid
- uuid
- rsa (RSA key pair generator)
- Password strength analyser


#### Coming soon
- PDF Signature checker
---

The goal is to add as many tools as possible and make them as simple a possible
