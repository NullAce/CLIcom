# CLIcom

A python based CLI server host chat

## Releases

All releases are in the releases folder
- The `releases/archive` stores all old versions of the chat.
- The `releases/beta` holds the newest updates, but will be the most unstable.
- The `releases/latest` holds the newest tested and stable version.

## How to use

- Use argument `--mode` to specify whether device is the client or the server, defaults to `client.`
- Use argument `--key` to specify the connection key, this does not encrypt traffic, it only makes the connection refuse if the key is wrong.
- Use arguemnt `--host` for the client only, use the local ip address of the server, defaults to `127.0.0.1`.
