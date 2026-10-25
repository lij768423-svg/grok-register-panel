#!/usr/bin/env python3
import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import static_asset_cache as cache


@dataclass
class FakeRequest:
    url: str
    resource_type: str = "script"
    method: str = "GET"


class FakeResponse:
    status = 200
    headers = {"Content-Type": "text/javascript", "Content-Length": "3"}

    def body(self):
        return b"abc"


class FakeRoute:
    def __init__(self, request):
        self.request = request
        self.fetch_count = 0
        self.fulfilled = None
        self.continued = False

    def fetch(self):
        self.fetch_count += 1
        return FakeResponse()

    def fulfill(self, **kwargs):
        self.fulfilled = kwargs

    def continue_(self):
        self.continued = True


class FakeContext:
    def __init__(self):
        self.handlers = []

    def route(self, pattern, handler):
        assert pattern in cache.static_route_globs()
        assert not pattern.endswith("*.js")
        self.handlers.append((pattern, handler))


def main():
    old_enabled = os.environ.get("GROK_STATIC_ASSET_CACHE")
    old_dir = os.environ.get("GROK_STATIC_CACHE_DIR")
    try:
        with tempfile.TemporaryDirectory(prefix="grok-static-cache-test-") as root:
            os.environ["GROK_STATIC_ASSET_CACHE"] = "1"
            os.environ["GROK_STATIC_CACHE_DIR"] = root
            asset = "https://assets.example.test/_next/static/app.css?v=2#fragment"
            script = "https://assets.example.test/_next/static/app.js?v=2#fragment"
            challenge = "https://challenges.cloudflare.com/turnstile/v0/api.js"
            assert cache.cache_enabled()
            assert not cache.is_static_request(script, "script", "GET")
            assert cache.is_static_request(asset, "stylesheet", "GET")
            assert not cache.is_static_request(challenge, "script", "GET")
            assert not cache.is_static_request(asset, "stylesheet", "POST")
            assert not cache.is_static_request(
                "https://api.example.test/account/avatar", "image", "GET"
            )
            key = cache.cache_key(asset)
            cache._write_entry(
                key,
                url=asset,
                status=200,
                headers={"Content-Type": "text/javascript"},
                body=b"abc",
            )
            stored = cache._read_entry(key)
            assert stored and stored["body"] == b"abc"
            assert stored["headers"] == {"content-type": "text/javascript"}

            private_asset = "https://assets.example.test/private.js"
            private_key = cache.cache_key(private_asset)
            cache._write_entry(
                private_key,
                url=private_asset,
                status=200,
                headers={"Cache-Control": "private, max-age=3600"},
                body=b"private",
            )
            assert cache._read_entry(private_key) is None
            assert cache._cache_ttl({"Cache-Control": "max-age=9999999"}) == 604800
            assert cache._cache_ttl({"Set-Cookie": "session=value"}) == 0

            cache.reset_stats()
            context = FakeContext()
            assert cache.attach_static_cache(context)
            assert cache.attach_static_cache(context)
            assert len(context.handlers) == len(cache.static_route_globs())
            handler = context.handlers[0][1]

            skipped = FakeRoute(FakeRequest("https://cdn.example.test/app-v3.js", "script"))
            handler(skipped)
            assert skipped.fetch_count == 0
            assert skipped.fulfilled is None
            assert skipped.continued is True

            first = FakeRoute(FakeRequest("https://cdn.example.test/app-v3.css", "stylesheet"))
            handler(first)
            assert first.fetch_count == 1
            assert first.fulfilled["headers"]["x-grok-static-cache"] == "MISS"

            second = FakeRoute(FakeRequest("https://cdn.example.test/app-v3.css", "stylesheet"))
            handler(second)
            assert second.fetch_count == 0
            assert second.fulfilled["headers"]["x-grok-static-cache"] == "HIT"
            assert cache.get_stats()["hits"] == 1
        print("OK static asset cache")
    finally:
        if old_enabled is None:
            os.environ.pop("GROK_STATIC_ASSET_CACHE", None)
        else:
            os.environ["GROK_STATIC_ASSET_CACHE"] = old_enabled
        if old_dir is None:
            os.environ.pop("GROK_STATIC_CACHE_DIR", None)
        else:
            os.environ["GROK_STATIC_CACHE_DIR"] = old_dir


if __name__ == "__main__":
    main()
