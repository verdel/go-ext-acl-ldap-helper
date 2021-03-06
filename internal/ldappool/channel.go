package ldappool

import (
	"crypto/tls"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/verdel/go-ext-acl-ldap-helper/internal/ldap.v2"
)

// channelPool implements the Pool interface based on buffered channels.
type channelPool struct {
	// storage for our net.Conn connections
	mu         sync.RWMutex
	conns      chan ldap.Client
	name       string
	serverPool *serverPool
	useTLS     bool
	closeAt    []uint8
}

// PoolFactory is a function to create new connections.
// type ChannelPoolFactory func(string) (ldap.Client, error)

// NewChannelPool returns a new pool based on buffered channels with an initial
// capacity and maximum capacity. Factory is used when initial capacity is
// greater than zero to fill the pool. A zero initialCap doesn't fill the Pool
// until a new Get() is called. During a Get(), If there is no new connection
// available in the pool, a new connection will be created via the Factory()
// method.
//
// closeAt will automagically mark the connection as unusable if the return code
// of the call is one of those passed, most likely you want to set this to something
// like
//   []uint8{ldap.LDAPResultTimeLimitExceeded, ldap.ErrorNetwork}
func NewChannelPool(initialCap, maxCap int, servers *serverPool, useTLS bool, closeAt []uint8) (Pool, error) {
	if initialCap < 0 || maxCap <= 0 || initialCap > maxCap {
		return nil, errors.New("invalid capacity settings")
	}

	c := &channelPool{
		conns:      make(chan ldap.Client, maxCap),
		serverPool: servers,
		useTLS:     useTLS,
		closeAt:    closeAt,
	}

	// create initial connections, if something goes wrong,
	// just close the pool error out.
	for i := 0; i < initialCap; i++ {
		conn, err := c.NewConn(useTLS)
		if err != nil {
			c.Close()
			return nil, errors.New("factory is not able to fill the pool: " + err.Error())
		}
		c.conns <- conn
	}

	return c, nil
}

func (c *channelPool) getConns() chan ldap.Client {
	c.mu.RLock()
	conns := c.conns
	c.mu.RUnlock()
	return conns
}

// Get implements the Pool interfaces Get() method. If there is no new
// connection available in the pool, a new connection will be created via the
// Factory() method.
func (c *channelPool) Get() (*PoolConn, error) {
	conns := c.getConns()
	if conns == nil {
		return nil, ErrClosed
	}

	// wrap our connections with our ldap.Client implementation (wrapConn
	// method) that puts the connection back to the pool if it's closed.
	select {
	case conn := <-conns:
		if conn == nil {
			return nil, ErrClosed
		}
		if isAlive(conn) {
			return c.wrapConn(conn, c.closeAt), nil
		}
		conn.Close()
		return c.NewConn(c.useTLS)
	default:
		return c.NewConn(c.useTLS)
	}
}

func isAlive(conn ldap.Client) bool {
	_, err := conn.Search(&ldap.SearchRequest{BaseDN: "", Scope: ldap.ScopeBaseObject, Filter: "(&)", Attributes: []string{"1.1"}})
	return err == nil
}

func (c *channelPool) NewConn(useTLS bool) (*PoolConn, error) {
	var conn *ldap.Conn

	server, err := c.serverPool.Get()
	if err != nil {
		return nil, err
	}

	if useTLS {
		conn, err = ldap.DialTLS("tcp", server, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = ldap.Dial("tcp", server)
	}

	if err != nil {
		return nil, err
	}
	conn.SetTimeout(time.Duration(300) * time.Millisecond)
	return c.wrapConn(conn, c.closeAt), nil
}

// put puts the connection back to the pool. If the pool is full or closed,
// conn is simply closed. A nil conn will be rejected.
func (c *channelPool) put(conn ldap.Client) {
	if conn == nil {
		log.Printf("connection is nil. rejecting")
		return
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.conns == nil {
		// pool is closed, close passed connection
		conn.Close()
		return
	}

	// put the resource back into the pool. If the pool is full, this will
	// block and the default case will be executed.
	select {
	case c.conns <- conn:
		return
	default:
		// pool is full, close passed connection
		conn.Close()
		return
	}
}

func (c *channelPool) Close() {
	c.mu.RLock()
	conns := c.conns
	c.conns = nil
	c.mu.RUnlock()

	if conns == nil {
		return
	}

	close(conns)
	for conn := range conns {
		conn.Close()
	}
	return
}

func (c *channelPool) Len() int { return len(c.getConns()) }

func (c *channelPool) wrapConn(conn ldap.Client, closeAt []uint8) *PoolConn {
	p := &PoolConn{c: c, closeAt: closeAt}
	p.Conn = conn
	return p
}
