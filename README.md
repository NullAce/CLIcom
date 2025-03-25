# CLIcom

A python based CLI server host chat

## Releases

All releases are in the `releases` folder
- The `archive` stores all old versions of the chat.
- The `beta` holds the newest updates, but may be unstable.
- The `latest` holds the newest tested and stable version.

## How to use

- Prompts for `key`, connection only occurs if key is the same, there is no encryption.
- Prompts for `server || client`, defaults to client.
- Prompts for `host` address, defaults to `127.0.0.1`


### How to use (Before v0.1.2)

- Use argument `--key` to specify the connection key, this does not encrypt traffic, it only makes the connection refuse if the key is wrong.
- Use argument `--mode` to specify whether device is the client or the server, defaults to `client.`
- Use arguemnt `--host` for the client only, use the local ip address of the server, defaults to `127.0.0.1`.

## Future plans

1. First and formost is to add encryption. Preferiable a `Diffie Hellman` key exchange.
2. Styling interface more.
3. Adding option to have more than `1` client.
