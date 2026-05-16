"""Tests for caching system."""

import json
import pytest
import tempfile
import time
from pathlib import Path

from awslabs.aws_security_posture_advisor.core.common.cache import (
    CacheEntry,
    MemoryCache,
    PersistentCache,
    CacheManager,
)


class TestCacheEntry:
    """Tests for CacheEntry class."""

    def test_not_expired(self):
        entry = CacheEntry(data="test", ttl_seconds=3600)
        assert entry.is_expired is False

    def test_expired(self):
        entry = CacheEntry(data="test", ttl_seconds=0)
        time.sleep(0.01)
        assert entry.is_expired is True

    def test_age_seconds(self):
        entry = CacheEntry(data="test", ttl_seconds=3600)
        time.sleep(0.01)
        assert entry.age_seconds >= 0.01


class TestMemoryCache:
    """Tests for in-memory cache."""

    def test_set_and_get(self):
        cache = MemoryCache(default_ttl=60)
        cache.set("key1", {"data": "value"})
        assert cache.get("key1") == {"data": "value"}

    def test_get_missing_key(self):
        cache = MemoryCache()
        assert cache.get("nonexistent") is None

    def test_expired_entry_returns_none(self):
        cache = MemoryCache(default_ttl=0)
        cache.set("key1", "value")
        time.sleep(0.01)
        assert cache.get("key1") is None

    def test_custom_ttl(self):
        cache = MemoryCache(default_ttl=3600)
        cache.set("key1", "value", ttl_seconds=0)
        time.sleep(0.01)
        assert cache.get("key1") is None

    def test_delete(self):
        cache = MemoryCache()
        cache.set("key1", "value")
        assert cache.delete("key1") is True
        assert cache.get("key1") is None

    def test_delete_nonexistent(self):
        cache = MemoryCache()
        assert cache.delete("nonexistent") is False

    def test_clear(self):
        cache = MemoryCache()
        cache.set("k1", "v1")
        cache.set("k2", "v2")
        cache.clear()
        assert cache.get("k1") is None
        assert cache.get("k2") is None

    def test_max_size_eviction(self):
        cache = MemoryCache(default_ttl=3600, max_size=2)
        cache.set("k1", "v1")
        cache.set("k2", "v2")
        cache.set("k3", "v3")
        # One of k1/k2 should be evicted
        remaining = [cache.get("k1"), cache.get("k2"), cache.get("k3")]
        assert remaining.count(None) >= 1
        assert "v3" in remaining

    def test_cleanup_expired(self):
        cache = MemoryCache(default_ttl=0)
        cache.set("k1", "v1")
        cache.set("k2", "v2")
        time.sleep(0.01)
        removed = cache.cleanup_expired()
        assert removed == 2


class TestPersistentCache:
    """Tests for JSON-based persistent cache."""

    def test_set_and_get(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = PersistentCache(tmpdir, default_ttl=60)
            cache.set("key1", {"data": [1, 2, 3]})
            result = cache.get("key1")
            assert result == {"data": [1, 2, 3]}

    def test_expired_entry(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = PersistentCache(tmpdir, default_ttl=0)
            cache.set("key1", "value")
            time.sleep(0.01)
            assert cache.get("key1") is None

    def test_get_missing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = PersistentCache(tmpdir)
            assert cache.get("nonexistent") is None

    def test_delete(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = PersistentCache(tmpdir)
            cache.set("key1", "value")
            assert cache.delete("key1") is True
            assert cache.get("key1") is None

    def test_clear(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = PersistentCache(tmpdir)
            cache.set("k1", "v1")
            cache.set("k2", "v2")
            cache.clear()
            assert cache.get("k1") is None
            assert cache.get("k2") is None

    def test_stores_as_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = PersistentCache(tmpdir)
            cache.set("key1", {"hello": "world"})
            # Verify the file is valid JSON
            json_files = list(Path(tmpdir).glob("*.json"))
            assert len(json_files) == 1
            with open(json_files[0], 'r') as f:
                content = json.load(f)
            assert content["data"] == {"hello": "world"}
            assert "timestamp" in content
            assert "ttl_seconds" in content

    def test_corrupted_file_handled(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = PersistentCache(tmpdir)
            cache.set("key1", "value")
            # Corrupt the file
            json_files = list(Path(tmpdir).glob("*.json"))
            with open(json_files[0], 'w') as f:
                f.write("not valid json{{{")
            # Should return None and clean up
            assert cache.get("key1") is None

    def test_cleanup_expired(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = PersistentCache(tmpdir, default_ttl=0)
            cache.set("k1", "v1")
            cache.set("k2", "v2")
            time.sleep(0.01)
            removed = cache.cleanup_expired()
            assert removed == 2


class TestCacheManager:
    """Tests for the CacheManager combining memory and persistent caches."""

    def test_memory_only(self):
        mgr = CacheManager(cache_dir=None, memory_ttl=60)
        mgr.set("key1", "value")
        assert mgr.get("key1") == "value"

    def test_with_persistent(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = CacheManager(cache_dir=tmpdir, memory_ttl=60, persistent_ttl=120)
            mgr.set("key1", {"nested": True})
            # Clear memory to test persistent fallback
            mgr.memory_cache.clear()
            result = mgr.get("key1")
            assert result == {"nested": True}

    def test_delete_from_both(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = CacheManager(cache_dir=tmpdir)
            mgr.set("key1", "value")
            assert mgr.delete("key1") is True
            assert mgr.get("key1") is None
