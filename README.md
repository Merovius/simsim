# simsim - Trust on first use SSH server

**Do not expose this to the internet (or probably at all). If you do, you are
donating your CPU to a random Bitcoin mining pool**

simsim is a minimal SSH server that allows anyone to create an account on the
machine it's running on. If a client tries to login as a user that does not
exist yet, that user is automatically created and the clients public key is
added to their `~/.ssh/authorized_keys` file. This has the effect that the
first client that tries to login as a given user "claims" that username.

The obvious implication is, that anyone who can connect to your machine, also
gains access to it. Hence above warning - obviously this is horrificly insecure
and you shouldn't use it on a machine you care about (at all).

The intended usecase is for a friendly programming competition - participants
can upload their solutions by logging into a shared machine, which contains
binaries that run a prepared test suite against them. Because it's just in good
fun, we don't care about what horrible, horrible things people might do to that
machine with arbitrary code execution.

# Limitations

* I wrote this in approximately six hours so it's horrificly buggy. I assume
  that it will break on first contact with the enemy (=user).
* It intentionally only supports public key authentication and for now only
  ed25519 (though I plan on changing that).
* It so far only supports executing a shell. No port forwarding, no X11, not
  even running a specific command. As this is not supposed to be
  production-grade software, that probably won't change.
* It's not very debuggable. Error messages are unhelpful and there are no
  tests.

# Acknowledgements

simsim relies heavily on the [Go x/crypto packages](https://github.com/golang/crypto),
written and maintained by the Go team, as well as Keith Rarick's [pty package](https://github.com/kr/pty).

# License

```
Copyright 2018 Axel Wagner

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
