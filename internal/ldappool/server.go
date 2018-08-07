package ldappool

import (
	"errors"
	"net"
	"time"
)

type poolStrategy int

const (
	FIRST poolStrategy = iota
	RR
)

type server struct {
	address      string
	alive        bool
	checkTimeout time.Duration
	lastCheck    time.Time
}

func (s *server) checkAvailability() bool {
	conn, err := net.DialTimeout("tcp", s.address, s.checkTimeout)
	if err == nil {
		defer conn.Close()
		return true
	} else {
		return false
	}
}

type serverPool struct {
	servers           []server
	lastUsed          int
	strategy          poolStrategy
	checkRetryTimeout time.Duration
}

func (c *serverPool) Get() (string, error) {
	if len(c.servers) != 0 {
		var serverIndex int
		var err error

		if c.strategy == RR {
			serverIndex, err = c.findActiveServer(c.lastUsed + 1)
		} else {
			serverIndex, err = c.findActiveServer(0)
		}
		if err != nil {
			return "", err
		}
		c.lastUsed = serverIndex

		return c.servers[serverIndex].address, nil
	} else {
		return "", errors.New("ldap server pool is empty")
	}
}

func (c *serverPool) findActiveServer(starting int) (int, error) {
	var offset int
	if starting >= len(c.servers) {
		starting = 0
	}
	counter := 3
	pool_size := len(c.servers)
	for i := 0; i < counter; i++ {
		index := -1
		for index < (pool_size - 1) {
			index += 1
			if (index + starting) < pool_size {
				offset = (index + starting)
			} else {
				offset = (index + starting - pool_size)
			}

			if !c.servers[offset].alive {
				if time.Now().Sub(c.servers[offset].lastCheck) < c.checkRetryTimeout {
					continue
				}
			}
			c.servers[offset].lastCheck = time.Now()
			if c.servers[offset].checkAvailability() {
				c.servers[offset].alive = true
				return offset, nil
			} else {
				c.servers[offset].alive = false
			}
		}
	}
	return 0, errors.New("no active ldap server found")
}

func NewServerPool(servers *[]string, checkRetryTimeout, serverCheckTimeout int, roundrobin bool) (*serverPool, error) {
	var pool_server server
	var c *serverPool
	var strategy poolStrategy

	if roundrobin {
		strategy = RR
	} else {
		strategy = FIRST
	}

	if len(*servers) == 0 {
		return nil, errors.New("incoming ldap server list is empty")
	}

	c = &serverPool{strategy: strategy, lastUsed: -1, checkRetryTimeout: time.Duration(checkRetryTimeout) * time.Millisecond}
	for _, address := range *servers {
		pool_server.address = address
		pool_server.alive = true
		pool_server.lastCheck = time.Now()
		pool_server.checkTimeout = time.Duration(serverCheckTimeout) * time.Millisecond
		c.servers = append(c.servers, pool_server)
	}
	return c, nil
}
