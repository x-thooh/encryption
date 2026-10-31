package key

import "sync"

// keyCache 是按原始密钥字符串缓存解析结果的并发安全 FIFO 缓存。
//
// limit <= 0 表示不限制容量；limit > 0 时达到上限后淘汰最早写入的条目，
// 而不是丢弃新条目（旧实现会让缓存被一批畸形密钥永久占满）。
type keyCache struct {
	mu    sync.Mutex
	items map[string]any
	order []string // 环形 FIFO，记录可淘汰 key 的写入顺序
	next  int
	limit int
}

func newKeyCache(limit int) *keyCache {
	return &keyCache{
		items: make(map[string]any),
		limit: limit,
	}
}

func (c *keyCache) Load(key string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.items[key]
	return v, ok
}

func (c *keyCache) Store(key string, value any) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.items[key]; ok {
		c.items[key] = value
		return
	}

	if c.limit > 0 {
		if len(c.order) < c.limit {
			c.order = append(c.order, key)
		} else {
			// 环形 FIFO：淘汰最早写入的条目，并复用它的槽位。
			victim := c.order[c.next]
			delete(c.items, victim)
			c.order[c.next] = key
			c.next = (c.next + 1) % c.limit
		}
	}
	c.items[key] = value
}

func (c *keyCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}
