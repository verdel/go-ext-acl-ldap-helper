package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jessevdk/go-flags"
	cache "github.com/patrickmn/go-cache"
	"github.com/verdel/go-ext-acl-ldap-helper/internal/ldap.v2"
	"github.com/verdel/go-ext-acl-ldap-helper/internal/ldappool"
)

const (
	version = "0.0.5"
)

var (
	rewriterExitChan    chan int       = make(chan int, 1)
	responseChan        chan string    = make(chan string, 1024*10)
	signalHupChan       chan os.Signal = make(chan os.Signal, 1)
	signalInterruptChan chan os.Signal = make(chan os.Signal, 1)
	stdinLineChan       chan string    = make(chan string, 100)
	lastUsedIndex       int
	ldapConnPool        ldappool.Pool
	c                   = cache.New(300*time.Second, 30*time.Second)
)

var opts struct {
	ServerSlice     []string `short:"s" long:"server" description:"Domain controller server address (required)" required:"true"`
	ServerPort      int      `short:"p" long:"port" description:"Domain controller LDAP service port (default: 389)" default:"389"`
	UseTLS          bool     `long:"tls" description:"Using LDAP over TLS"`
	BindUsername    string   `short:"u" long:"binduser" description:"Username for LDAP Bind operation (required)" required:"true"`
	BindPassword    string   `short:"w" long:"bindpassword" description:"Password for LDAP Bind operation"`
	PwdFile         string   `short:"f" long:"pwdfile" description:"File with password for Bind operation"`
	BaseDN          string   `short:"b" long:"basedn" description:"BaseDN for user search process. %ou = OU (required)" required:"true"`
	UserFilter      string   `long:"user-filter" description:"User search filter pattern. %u = login (required)" required:"true"`
	GroupFilter     string   `long:"group-filter" description:"Group search filter pattern. %u = user DN, %g = user group name (required)" required:"true"`
	StripRealm      bool     `long:"strip-realm" description:"Strip Kerberos Realm from usernames"`
	StripDomain     bool     `long:"strip-domain" description:"Strip NT domain from usernames"`
	CacheExpiration int      `long:"cache" description:"Use in-memory cache. Set entry expiration time in seconds"`
	LogFile         string   `long:"log" description:"Path to log file (default: /var/log/squid-ext-acl-ldap.log)" default:"/var/log/squid-ext-acl-ldap.log"`
}

func isInt(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

func addResponse(s string) {
	responseChan <- s
}

func writerResponseLines() {
	out := bufio.NewWriter(os.Stdout)
	for {
		line := <-responseChan
		out.WriteString(line)
		out.WriteString("\n")
		out.Flush()
	}
}

func startChecker() {
	var (
		line    string
		err     error
		servers []string
	)

	for _, server := range opts.ServerSlice {
		servers = append(servers, fmt.Sprintf("%s:%d", server, opts.ServerPort))
	}

	serverpool, err := ldappool.NewServerPool(&servers, 10000, 200, true)
	if err != nil {
		log.Fatalf("[ERROR] Cannot create LDAP server pool. Error - %s", err.Error())
		os.Exit(1)
	}

	ldapConnPool, err = ldappool.NewChannelPool(0, 100*len(opts.ServerSlice), serverpool, opts.UseTLS, []uint8{ldap.LDAPResultTimeLimitExceeded, ldap.ErrorNetwork, ldap.LDAPResultInvalidCredentials})
	if err != nil {
		log.Fatalf("[ERROR] Cannot create LDAP connection pool. Message - %s", err.Error())
		os.Exit(1)
	}
	defer ldapConnPool.Close()

scanloop:
	for {

		select {
		case line = <-stdinLineChan:

		case <-signalHupChan:
			log.Print("[INFO] Got SIGHUP to reload configuration")
			break scanloop

		case <-signalInterruptChan:
			log.Print("[INFO] Got signal to exit squid LDAP external acl helper")
			os.Exit(0)
		}

		line = strings.TrimSpace(line)

		id := ""
		username := ""
		searchEntity := ""

		fs := strings.Fields(line)

		concurrency := false
		if len(fs) >= 3 && isInt(fs[0]) {
			concurrency = true
			id = fs[0]
			username = fs[1]
			searchEntity = fs[2]
		} else if len(fs) >= 2 {
			username = fs[0]
			searchEntity = fs[1]
		}

		if concurrency {
			go doRequest(id, username, searchEntity)
		} else {
			doRequest(id, username, searchEntity)
		}
	}

	log.Print("[INFO] Stop squid LDAP external acl helper")
	rewriterExitChan <- 1
}

func printPositiveResult(id, searchEntity string) {
	if id == "" {
		addResponse(fmt.Sprintf("OK tag=%s", searchEntity))
	} else {
		addResponse(fmt.Sprintf("%s OK tag=%s", id, searchEntity))
	}
}

func printNegativeResult(id string) {
	if id == "" {
		addResponse(fmt.Sprintf("ERR"))
	} else {
		addResponse(fmt.Sprintf("%s ERR", id))
	}
}

func doRequest(id, username string, searchEntity string) {
	if opts.StripRealm {
		username = strings.Split(username, "@")[0]
	}
	if opts.StripDomain && strings.Contains(username, "\\") {
		username = strings.Split(username, "\\")[1]
	}

	if opts.CacheExpiration != 0 {
		searchResult, cacheFound := c.Get(fmt.Sprintf("%s:%s", username, searchEntity))
		if cacheFound {
			if searchResult == 1 {
				printPositiveResult(id, searchEntity)
			} else {
				printNegativeResult(id)
			}
			return
		}
	}

	conn, err := ldapConnPool.Get()
	if err != nil {
		log.Fatal("[ERROR] Cannot get active LDAP connection")
		printNegativeResult(id)
	}

	err = conn.Bind(opts.BindUsername, opts.BindPassword)

	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			log.Fatal("[ERROR] LDAP binding operation error. Invalid Credentials")
		} else {
			log.Printf("[WARN] LDAP binding operation error. Message - %s", err.Error())
		}
		printNegativeResult(id)
		return
	}
	defer conn.Close()

	searchRequest := ldap.NewSearchRequest(
		opts.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(%s))", strings.Replace(opts.UserFilter, "%u", username, -1)),
		[]string{"sAMAccountName"},
		nil,
	)
	sr, err := conn.Search(searchRequest)
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			log.Printf("[WARN] Exception during execution of the LDAP query. User '%s' is not found in domain. Using LDAP path - %s", username, opts.BaseDN)
		} else {
			log.Printf("[WARN] Exception during execution of the LDAP query. Message - %s", err.Error())
		}
		printNegativeResult(id)
		return
	} else {
		if len(sr.Entries) == 1 {
			r := strings.NewReplacer("%u", sr.Entries[0].DN,
				"%g", searchEntity)

			searchRequest := ldap.NewSearchRequest(
				opts.BaseDN,
				ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
				r.Replace(opts.GroupFilter),
				[]string{"sAMAccountName"},
				nil,
			)

			sr, err = conn.Search(searchRequest)
			if err != nil {
				if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
					log.Printf("[WARN] Exception during execution of the LDAP query. User '%s' is not found in domain. Using LDAP path - %s", username, opts.BaseDN)
				} else {
					log.Printf("[WARN] Exception during execution of the LDAP query. Message - %s", err.Error())
				}

				printNegativeResult(id)
				return
			} else {
				if len(sr.Entries) > 0 {
					if opts.CacheExpiration != 0 {
						c.Set(fmt.Sprintf("%s:%s", username, searchEntity), 1, time.Duration(opts.CacheExpiration)*time.Second)
					}

					printPositiveResult(id, searchEntity)
					return
				} else {
					if opts.CacheExpiration != 0 {
						c.Set(fmt.Sprintf("%s:%s", username, searchEntity), 0, time.Duration(opts.CacheExpiration)*time.Second)
					}

					printNegativeResult(id)
					return
				}
			}
		} else {
			log.Printf("[WARN] Exception during execution of the LDAP query. User '%s' is not found in domain. Using LDAP path - %s", username, opts.BaseDN)
			printNegativeResult(id)
			return
		}
	}
}

func main() {
	parser := flags.NewParser(&opts, flags.Default)
	parser.Usage = fmt.Sprintf("\n\nVersion: %s", version)

	if len(os.Args) == 1 {
		parser.WriteHelp(os.Stderr)
		os.Exit(0)
	}
	_, err := parser.Parse()

	if err != nil {
		os.Exit(1)
	}

	f, err := os.OpenFile(opts.LogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("[ERROR] Error opening log file: %v", err.Error())
	}
	defer f.Close()
	log.SetOutput(f)

	if opts.BindPassword == "" {
		fmt.Printf("%s", opts.BindPassword)
		if &opts.PwdFile != nil {
			if _, err := os.Stat(opts.PwdFile); !os.IsNotExist(err) {
				file, err := os.Open(opts.PwdFile)
				if err != nil {
					log.Fatalf("[ERROR] Cannot open file with password for LDAP connection. Message - %s", err.Error())
				}
				reader := bufio.NewReader(file)
				line, _ := reader.ReadString('\n')
				line = strings.TrimSuffix(line, "\n")
				opts.BindPassword = line
				file.Close()
			} else {
				log.Fatal("[ERROR] File with password for LDAP connection is not exist")
			}
		} else {
			log.Fatal("[ERROR] Password for LDAP connection is not set")
		}
	}
	signal.Notify(signalHupChan, syscall.SIGHUP)
	signal.Notify(signalInterruptChan, os.Interrupt, syscall.SIGTERM)

	go writerResponseLines()

	inscanner := bufio.NewScanner(os.Stdin)
	go func() {
		for inscanner.Scan() {
			stdinLineChan <- inscanner.Text()
		}
		err := inscanner.Err()
		if err != nil {
			log.Printf("[WARN] Stdin error. Message - %s", err.Error())
			os.Exit(1)
		}
		log.Print("[INFO] Stop squid LDAP external acl helper")
		os.Exit(0)
	}()

	rewriterExitChan <- 1
	for {
		<-rewriterExitChan
		log.Print("[INFO] Start squid LDAP external acl helper")
		go startChecker()
	}
}
