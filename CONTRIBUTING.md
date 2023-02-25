# Contributing to ACMEd


## Testing and bug report

The first way to help is to actually use the software and [report any bug you encounter](https://github.com/breard-r/acmed/issues). Do not hesitate to test the limits.


## Improving the language

Since the author is not a native English speaker, some of the texts used in this project should be fixed. This is especially true on the man pages as well as the [wiki](https://github.com/breard-r/acmed-wiki).


## Package it for your favorite system

A great way to contribute to the project is to package it. You can check the packages status on [Repology](https://repology.org/project/acmed/versions).


## Work on dependencies

### botan and botan-sys

Although Botan isn't a dependency, it is considered as an alternative to OpenSSL. But before this can be done, the Botan crate need to support a few features:

- Access to a certificate's expiration time (via `botan_sys::botan_x509_cert_get_time_expires`).
- Access to a certificate's subject's alt names.
- Self-signed certificate generation (via `botan_sys::botan_x509_cert_gen_selfsigned`).
- CSR (requires to add bindings to [create_cert_req](https://botan.randombit.net/handbook/api_ref/x509.html#creating-pkcs-10-requests)) with DER export.
- Implement `Clone` for `botan::Privkey`.


## Improving the code

As a one-man project, it has several goals already set but not explicitly written in an issue or any other follow-up file. It will not be the case before version 1.0 is released since everything may change at any moment. Therefore, it is recommended to request change instead of implementing them, this way we can discuss how things should be made. That said, there might be a few [good first issues](https://github.com/breard-r/acmed/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) you might want to look into.

If you want to submit a pull request, please :

- document your changes in the man pages and the `CHANGELOG.md` file
- write as much tests as you can
- run `cargo test` and be sure every test pass
- format your code using [rustfmt](https://github.com/rust-lang/rustfmt)
- be sure not to have any warning when compiling
- run [clippy](https://github.com/rust-lang/rust-clippy) and fix any issue
- refrain from including a new dependency
- beware of potential repercussions on the default hooks: those should remain usable

Notice: man pages are written using the mdoc syntax, documentation is available in [`man 7 mdoc`](https://man.freebsd.org/cgi/man.cgi?query=mdoc&sektion=7&apropos=0&manpath=FreeBSD+13.1-RELEASE).


## Author vs. contributor

Some people have troubles seeing the difference between an author and a contributor. Here is how it is seen withing this project.

A contributor is a person who helps the project in various ways whenever she or he wants. As such, a contributor does not have any obligation other than being respectful and open-minded. People who wrote code that have been accepted are automatically listed in the [contributors page](https://github.com/breard-r/acmed/graphs/contributors). The creation of a file with the names of people contributing outside of the code base will be studied upon request from such people.

An author is a person who has some responsibilities on the project. Authors are expected to contribute on a regular basis, decide architectural choices, enforce copyright issues and so on. One does not grant himself the author status, it is given by the others authors after having discussed the request.
