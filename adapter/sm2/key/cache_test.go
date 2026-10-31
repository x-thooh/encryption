package key

import (
	"sync"
	"testing"
)

func TestCacheLimit(t *testing.T) {
	gen := NewSM2()
	pub1, _, err := gen.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	pub2, _, err := gen.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	p := NewSM2(WithCacheLimit(1))
	if _, err := p.ParsePublicKey(pub1); err != nil {
		t.Fatalf("parse pub1: %v", err)
	}
	if _, err := p.ParsePublicKey(pub2); err != nil {
		t.Fatalf("parse pub2: %v", err)
	}
	if got := p.pubCache.len(); got != 1 {
		t.Fatalf("cache len = %d, want 1", got)
	}

	// pub2 是最新写入的条目，必须留在缓存里（旧实现会丢弃它）。
	if _, ok := p.pubCache.Load(pub2); !ok {
		t.Fatal("newest key was dropped from cache")
	}
	// pub1 应被 FIFO 淘汰，但仍可重新解析。
	if _, ok := p.pubCache.Load(pub1); ok {
		t.Fatal("oldest key should have been evicted")
	}
	if _, err := p.ParsePublicKey(pub1); err != nil {
		t.Fatalf("re-parse pub1: %v", err)
	}
	if got := p.pubCache.len(); got != 1 {
		t.Fatalf("cache len after re-parse = %d, want 1", got)
	}
}

// TestCacheEvictsOldest 达到上限后仍接受新条目，淘汰最早写入的条目。
func TestCacheEvictsOldest(t *testing.T) {
	c := newKeyCache(2)
	c.Store("a", 1)
	c.Store("b", 2)
	c.Store("c", 3)

	if got := c.len(); got != 2 {
		t.Fatalf("cache len = %d, want 2", got)
	}
	if _, ok := c.Load("a"); ok {
		t.Fatal("a should have been evicted")
	}
	for _, k := range []string{"b", "c"} {
		if _, ok := c.Load(k); !ok {
			t.Fatalf("%s missing from cache", k)
		}
	}
}

// TestCacheUnlimited limit <= 0 表示不限制容量。
func TestCacheUnlimited(t *testing.T) {
	c := newKeyCache(0)
	for _, k := range []string{"a", "b", "c", "d"} {
		c.Store(k, k)
	}
	if got := c.len(); got != 4 {
		t.Fatalf("cache len = %d, want 4", got)
	}
}

// TestCacheOverwrite 重复写入同一 key 不增加条目数。
func TestCacheOverwrite(t *testing.T) {
	c := newKeyCache(4)
	c.Store("a", 1)
	c.Store("a", 2)
	if got := c.len(); got != 1 {
		t.Fatalf("cache len = %d, want 1", got)
	}
	v, ok := c.Load("a")
	if !ok || v.(int) != 2 {
		t.Fatalf("cache value = %v, want 2", v)
	}
}

func cacheStoreAndLoadAsync(wg *sync.WaitGroup, c *keyCache, i int) {
	defer wg.Done()
	key := string(rune('a' + i%26))
	c.Store(key, i)
	c.Load(key)
	c.len()
}

// TestCacheConcurrent 并发读写不应触发数据竞争。
func TestCacheConcurrent(t *testing.T) {
	c := newKeyCache(8)

	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go cacheStoreAndLoadAsync(&wg, c, i)
	}
	wg.Wait()

	if got := c.len(); got > 8 {
		t.Fatalf("cache len = %d, want <= 8", got)
	}
}
