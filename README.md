# Squid external acl ldap helper

This is the GO version of squid external acl ldap helper. This helper allows you to determine whether a user is a member of an OU or a domain group. In case of a positive result, the helper also adds a tag with the name OU or group to the answer. This allows Squid to perform additional filtering of requests based on the tag. The helper can work both in synchronous and asynchronous mode (concurrency option in squid.conf).

The helper can use more than one LDAP server. In the process, is controlled by the availability of LDAP servers. Requests are distributed according to the Round Robin scheme.

To use the mechanism of LDAP server availability control, as well as the RR distribution of requests, I have modified the [https://github.com/fatih/pool](https://github.com/fatih/pool) package.

## Getting Started

You must install a version of the helper that matches your platform. After that, you need to make changes to the Squid settings.

To filter based on domain groups, use the helper **ext-acl-ldap-group**.

To filter based on OU, use the helper **ext-acl-ldap-ou**.

All possible options can be found in the output of the helper using the help option.

### Installing

You can [download the binary](https://github.com/verdel/go-ext-acl-ldap-helper/releases/latest) from the releases page.

Or you can prepare your own binary files using the command

```bash
go get -u github.com/verdel/go-ext-acl-ldap-helper/cmd/ext-acl-ldap-ou
go get -u github.com/verdel/go-ext-acl-ldap-helper/cmd/ext-acl-ldap-ou
go install github.com/verdel/go-ext-acl-ldap-helper/cmd/ext-acl-ldap-ou
go install github.com/verdel/go-ext-acl-ldap-helper/cmd/ext-acl-ldap-group
```

### Using example

``` bash
/usr/sbin/ext-acl-ldap-ou --server 10.0.0.1 --server 10.0.0.2 --port 636 --binduser squid@domain.local --pwdfile "/etc/squid/squid_pass" --basedn "ou=%ou,dc=domain,dc=local" --filter "sAMAccountName=%u" --strip-realm --strip-domain --tls --log /var/log/squid/ext_acl.log
```

## Authors

* [**Vadim Aleksandrov**](https://about.me/verdel)

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

## Acknowledgments

* Some ideas were taken from the code of [squid-urlrewrite](https://github.com/rchunping/squid-urlrewrite)
* Thank [Fatih Arslan](https://github.com/fatih) for the package [https://github.com/fatih/pool](https://github.com/fatih/pool)
