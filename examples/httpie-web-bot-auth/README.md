# HTTPie plugin for web bot auth

![GitHub License](https://img.shields.io/github/license/cloudflare/web-bot-auth)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A plugin to use web bot auth in [HTTPie](https://httpie.io) HTTP client.

Read the [story behind Web Bot Auth](https://blog.cloudflare.com/web-bot-auth/), or find out more about how to
[Identify Bots with HTTP Message Signatures](https://http-message-signatures-example.research.cloudflare.com/).

## Installation

Install `httpie` via [`uv`](https://docs.astral.sh/uv/getting-started/installation/)

```shell
uv venv

source ./venv/bin/activate

uv pip install httpie
```

```shell
httpie cli plugins install httpie-web-bot-auth
```

## Usage

You should have a local key in a JSON-encoded JWK file.

Set `HTTPIE_WBA_KEY` to a path to this file.

Then make your request with `http+wba://`, or `https+wba://`.

Example

```shell
HTTPIE_WBA_KEY="/path/to/jwk.json" http 'http+wba://example.com'
```

## Development

### Requirements

- [Python 3.13](https://www.python.org/downloads/)
- [uv](https://docs.astral.sh/uv/getting-started/installation/) - Python package manager

### Build

To build bot-auth package

```shell
uv sync

uv build
```

### Lint

This codebase uses [ruff](https://docs.astral.sh/ruff/) and [Black](https://black.readthedocs.io/en/stable/index.html) for linting.

To run a check, use

```shell
uv run ruff check .
uv run black --check .
```

To format the codebase

```shell
uv run ruff format .
uv run black .
```

## Security Considerations

This software has not been audited. Please use at your sole discretion.

## License

This project is under the Apache 2.0 license.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall
be Apache 2.0 licensed as above, without any additional terms or conditions.
