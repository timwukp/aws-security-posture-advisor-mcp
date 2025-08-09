"""Caching and fallback mechanisms for AWS Security Posture Advisor.

This module provides caching capabilities and fallback mechanisms to improve
resilience and performance when AWS services are unavailable or slow.
"""

import asyncio
import json
import pickle
import time
from pathlib import Path
from typing import Any, Dict, Optional, Union, Callable, TypeVar
from functools import wraps
from loguru import logger

T = TypeVar('T')


class CacheEntry:
    """Represents a cached data entry with metadata."""
    
    def __init__(self, data: Any, ttl_seconds: int = 3600):
        """Initialize cache entry.
        
        Args:
            data: Data to cache
            ttl_seconds: Time to live in seconds
        """
        self.data = data
        self.timestamp = time.time()
        self.ttl_seconds = ttl_seconds
    
    @property
    def is_expired(self) -> bool:
        """Check if cache entry is expired."""
        return time.time() - self.timestamp > self.ttl_seconds
    
    @property
    def age_seconds(self) -> float:
        """Get age of cache entry in seconds."""
        return time.time() - self.timestamp


class MemoryCache:
    """In-memory cache with TTL support."""
    
    def __init__(self, default_ttl: int = 3600, max_size: int = 1000):
        """Initialize memory cache.
        
        Args:
            default_ttl: Default time to live in seconds
            max_size: Maximum number of entries to keep
        """
        self.default_ttl = default_ttl
        self.max_size = max_size
        self._cache: Dict[str, CacheEntry] = {}
    
    def get(self, key: str) -> Optional[Any]:
        """Get cached data by key.
        
        Args:
            key: Cache key
            
        Returns:
            Optional[Any]: Cached data if available and not expired
        """
        if key not in self._cache:
            return None
        
        entry = self._cache[key]
        if entry.is_expired:
            logger.debug(f"Cache entry expired for key: {key}")
            del self._cache[key]
            return None
        
        logger.debug(f"Cache hit for key: {key} (age: {entry.age_seconds:.1f}s)")
        return entry.data
    
    def set(self, key: str, data: Any, ttl_seconds: Optional[int] = None) -> None:
        """Set cached data.
        
        Args:
            key: Cache key
            data: Data to cache
            ttl_seconds: Time to live in seconds (uses default if None)
        """
        if ttl_seconds is None:
            ttl_seconds = self.default_ttl
        
        # Evict oldest entries if cache is full
        if len(self._cache) >= self.max_size:
            self._evict_oldest()
        
        self._cache[key] = CacheEntry(data, ttl_seconds)
        logger.debug(f"Cached data for key: {key} (TTL: {ttl_seconds}s)")
    
    def delete(self, key: str) -> bool:
        """Delete cached data.
        
        Args:
            key: Cache key
            
        Returns:
            bool: True if key was deleted, False if not found
        """
        if key in self._cache:
            del self._cache[key]
            logger.debug(f"Deleted cache entry for key: {key}")
            return True
        return False
    
    def clear(self) -> None:
        """Clear all cached data."""
        self._cache.clear()
        logger.debug("Cleared all cache entries")
    
    def _evict_oldest(self) -> None:
        """Evict the oldest cache entry."""
        if not self._cache:
            return
        
        oldest_key = min(self._cache.keys(), key=lambda k: self._cache[k].timestamp)
        del self._cache[oldest_key]
        logger.debug(f"Evicted oldest cache entry: {oldest_key}")
    
    def cleanup_expired(self) -> int:
        """Remove all expired entries.
        
        Returns:
            int: Number of entries removed
        """
        expired_keys = [key for key, entry in self._cache.items() if entry.is_expired]
        for key in expired_keys:
            del self._cache[key]
        
        if expired_keys:
            logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")
        
        return len(expired_keys)


class PersistentCache:
    """Persistent cache using file system storage."""
    
    def __init__(self, cache_dir: Union[str, Path], default_ttl: int = 3600):
        """Initialize persistent cache.
        
        Args:
            cache_dir: Directory to store cache files
            default_ttl: Default time to live in seconds
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.default_ttl = default_ttl
    
    def _get_cache_file(self, key: str) -> Path:
        """Get cache file path for key."""
        # Use hash to avoid filesystem issues with special characters
        import hashlib
        key_hash = hashlib.md5(key.encode()).hexdigest()
        return self.cache_dir / f"{key_hash}.cache"
    
    def get(self, key: str) -> Optional[Any]:
        """Get cached data by key.
        
        Args:
            key: Cache key
            
        Returns:
            Optional[Any]: Cached data if available and not expired
        """
        cache_file = self._get_cache_file(key)
        
        if not cache_file.exists():
            return None
        
        try:
            with open(cache_file, 'rb') as f:
                entry = pickle.load(f)
            
            if entry.is_expired:
                logger.debug(f"Persistent cache entry expired for key: {key}")
                cache_file.unlink(missing_ok=True)
                return None
            
            logger.debug(f"Persistent cache hit for key: {key} (age: {entry.age_seconds:.1f}s)")
            return entry.data
            
        except Exception as e:
            logger.warning(f"Failed to read persistent cache for key {key}: {e}")
            cache_file.unlink(missing_ok=True)
            return None
    
    def set(self, key: str, data: Any, ttl_seconds: Optional[int] = None) -> None:
        """Set cached data.
        
        Args:
            key: Cache key
            data: Data to cache
            ttl_seconds: Time to live in seconds (uses default if None)
        """
        if ttl_seconds is None:
            ttl_seconds = self.default_ttl
        
        cache_file = self._get_cache_file(key)
        entry = CacheEntry(data, ttl_seconds)
        
        try:
            with open(cache_file, 'wb') as f:
                pickle.dump(entry, f)
            
            logger.debug(f"Persistently cached data for key: {key} (TTL: {ttl_seconds}s)")
            
        except Exception as e:
            logger.warning(f"Failed to write persistent cache for key {key}: {e}")
    
    def delete(self, key: str) -> bool:
        """Delete cached data.
        
        Args:
            key: Cache key
            
        Returns:
            bool: True if key was deleted, False if not found
        """
        cache_file = self._get_cache_file(key)
        if cache_file.exists():
            cache_file.unlink()
            logger.debug(f"Deleted persistent cache entry for key: {key}")
            return True
        return False
    
    def clear(self) -> None:
        """Clear all cached data."""
        for cache_file in self.cache_dir.glob("*.cache"):
            cache_file.unlink()
        logger.debug("Cleared all persistent cache entries")
    
    def cleanup_expired(self) -> int:
        """Remove all expired cache files.
        
        Returns:
            int: Number of files removed
        """
        removed_count = 0
        
        for cache_file in self.cache_dir.glob("*.cache"):
            try:
                with open(cache_file, 'rb') as f:
                    entry = pickle.load(f)
                
                if entry.is_expired:
                    cache_file.unlink()
                    removed_count += 1
                    
            except Exception as e:
                logger.warning(f"Failed to check cache file {cache_file}: {e}")
                cache_file.unlink()
                removed_count += 1
        
        if removed_count > 0:
            logger.debug(f"Cleaned up {removed_count} expired persistent cache entries")
        
        return removed_count


class CacheManager:
    """Manages both memory and persistent caches."""
    
    def __init__(
        self,
        cache_dir: Optional[Union[str, Path]] = None,
        memory_ttl: int = 300,  # 5 minutes
        persistent_ttl: int = 3600,  # 1 hour
        max_memory_size: int = 1000
    ):
        """Initialize cache manager.
        
        Args:
            cache_dir: Directory for persistent cache (None to disable)
            memory_ttl: Default TTL for memory cache
            persistent_ttl: Default TTL for persistent cache
            max_memory_size: Maximum memory cache size
        """
        self.memory_cache = MemoryCache(default_ttl=memory_ttl, max_size=max_memory_size)
        
        if cache_dir:
            self.persistent_cache = PersistentCache(cache_dir, default_ttl=persistent_ttl)
        else:
            self.persistent_cache = None
    
    def get(self, key: str, use_persistent: bool = True) -> Optional[Any]:
        """Get cached data, checking memory first, then persistent.
        
        Args:
            key: Cache key
            use_persistent: Whether to check persistent cache
            
        Returns:
            Optional[Any]: Cached data if available
        """
        # Check memory cache first
        data = self.memory_cache.get(key)
        if data is not None:
            return data
        
        # Check persistent cache if enabled
        if use_persistent and self.persistent_cache:
            data = self.persistent_cache.get(key)
            if data is not None:
                # Promote to memory cache
                self.memory_cache.set(key, data)
                return data
        
        return None
    
    def set(
        self,
        key: str,
        data: Any,
        memory_ttl: Optional[int] = None,
        persistent_ttl: Optional[int] = None,
        use_persistent: bool = True
    ) -> None:
        """Set cached data in both memory and persistent caches.
        
        Args:
            key: Cache key
            data: Data to cache
            memory_ttl: TTL for memory cache
            persistent_ttl: TTL for persistent cache
            use_persistent: Whether to use persistent cache
        """
        # Always cache in memory
        self.memory_cache.set(key, data, memory_ttl)
        
        # Cache persistently if enabled
        if use_persistent and self.persistent_cache:
            self.persistent_cache.set(key, data, persistent_ttl)
    
    def delete(self, key: str) -> bool:
        """Delete cached data from both caches.
        
        Args:
            key: Cache key
            
        Returns:
            bool: True if key was deleted from at least one cache
        """
        memory_deleted = self.memory_cache.delete(key)
        persistent_deleted = False
        
        if self.persistent_cache:
            persistent_deleted = self.persistent_cache.delete(key)
        
        return memory_deleted or persistent_deleted
    
    def clear(self) -> None:
        """Clear all cached data."""
        self.memory_cache.clear()
        if self.persistent_cache:
            self.persistent_cache.clear()
    
    def cleanup_expired(self) -> Dict[str, int]:
        """Remove expired entries from both caches.
        
        Returns:
            Dict[str, int]: Count of removed entries by cache type
        """
        result = {
            'memory': self.memory_cache.cleanup_expired(),
            'persistent': 0
        }
        
        if self.persistent_cache:
            result['persistent'] = self.persistent_cache.cleanup_expired()
        
        return result


def cached(
    key_func: Optional[Callable[..., str]] = None,
    ttl_seconds: int = 300,
    use_persistent: bool = False,
    cache_manager: Optional[CacheManager] = None
):
    """Decorator for caching function results.
    
    Args:
        key_func: Function to generate cache key from arguments
        ttl_seconds: Time to live in seconds
        use_persistent: Whether to use persistent cache
        cache_manager: Cache manager instance (uses global if None)
    
    Returns:
        Decorator function
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        async def async_wrapper(*args, **kwargs) -> T:
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                # Default key generation
                cache_key = f"{func.__module__}.{func.__name__}:{hash((args, tuple(sorted(kwargs.items()))))}"
            
            # Get cache manager
            mgr = cache_manager or _global_cache_manager
            if not mgr:
                # No caching available, execute function directly
                if asyncio.iscoroutinefunction(func):
                    return await func(*args, **kwargs)
                else:
                    return func(*args, **kwargs)
            
            # Check cache
            cached_result = mgr.get(cache_key, use_persistent=use_persistent)
            if cached_result is not None:
                logger.debug(f"Cache hit for function {func.__name__}")
                return cached_result
            
            # Execute function and cache result
            try:
                if asyncio.iscoroutinefunction(func):
                    result = await func(*args, **kwargs)
                else:
                    result = func(*args, **kwargs)
                
                mgr.set(
                    cache_key,
                    result,
                    memory_ttl=ttl_seconds,
                    persistent_ttl=ttl_seconds * 2 if use_persistent else None,
                    use_persistent=use_persistent
                )
                
                logger.debug(f"Cached result for function {func.__name__}")
                return result
                
            except Exception as e:
                logger.debug(f"Function {func.__name__} failed, not caching: {e}")
                raise
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs) -> T:
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                # Default key generation
                cache_key = f"{func.__module__}.{func.__name__}:{hash((args, tuple(sorted(kwargs.items()))))}"
            
            # Get cache manager
            mgr = cache_manager or _global_cache_manager
            if not mgr:
                # No caching available, execute function directly
                return func(*args, **kwargs)
            
            # Check cache
            cached_result = mgr.get(cache_key, use_persistent=use_persistent)
            if cached_result is not None:
                logger.debug(f"Cache hit for function {func.__name__}")
                return cached_result
            
            # Execute function and cache result
            try:
                result = func(*args, **kwargs)
                
                mgr.set(
                    cache_key,
                    result,
                    memory_ttl=ttl_seconds,
                    persistent_ttl=ttl_seconds * 2 if use_persistent else None,
                    use_persistent=use_persistent
                )
                
                logger.debug(f"Cached result for function {func.__name__}")
                return result
                
            except Exception as e:
                logger.debug(f"Function {func.__name__} failed, not caching: {e}")
                raise
        
        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


# Global cache manager instance
_global_cache_manager: Optional[CacheManager] = None


def initialize_cache_manager(
    cache_dir: Optional[Union[str, Path]] = None,
    memory_ttl: int = 300,
    persistent_ttl: int = 3600,
    max_memory_size: int = 1000
) -> CacheManager:
    """Initialize global cache manager.
    
    Args:
        cache_dir: Directory for persistent cache
        memory_ttl: Default TTL for memory cache
        persistent_ttl: Default TTL for persistent cache
        max_memory_size: Maximum memory cache size
        
    Returns:
        CacheManager: Initialized cache manager
    """
    global _global_cache_manager
    _global_cache_manager = CacheManager(
        cache_dir=cache_dir,
        memory_ttl=memory_ttl,
        persistent_ttl=persistent_ttl,
        max_memory_size=max_memory_size
    )
    return _global_cache_manager


def get_cache_manager() -> Optional[CacheManager]:
    """Get global cache manager instance.
    
    Returns:
        Optional[CacheManager]: Cache manager if initialized
    """
    return _global_cache_manager