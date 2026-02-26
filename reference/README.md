# Sentry-Zig References

This folder is for local, disposable upstream reference checkouts used during
development of Sentry-Zig SDK.
It is ignored by git (except this file and `fetch-sources.sh`).

## Included Source

- sentry-native

## Refresh

```sh
./reference/fetch-sources.sh
```

By default, refresh skips repositories with local modifications.
To force-update and discard local changes in all reference clones:

```sh
./reference/fetch-sources.sh --hard
```
