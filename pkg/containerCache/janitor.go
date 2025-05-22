package containercache

import "time"

type Janitor struct{
  Interval time.Duration
  stop chan bool
}

func (j *Janitor) Run(c *Cache) {
	ticker := time.NewTicker(j.Interval)
	for {
		select {
		case <-ticker.C:
			c.evictExpired()
		case <-j.stop:
			ticker.Stop()
			return
		}
	}
}

func runJanitor(c *Cache, ci time.Duration) {
	j := &Janitor{
		Interval: ci,
		stop:     make(chan bool),
	}
	c.janitor = j
	go j.Run(c)
}

func stopJanitor(c *Cache) {
	c.janitor.stop <- true
}
