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

	"github.com/jessevdk/go-flags"
	"github.com/verdel/go-ext-acl-ldap-helper/internal/ldappool"
	"gopkg.in/ldap.v2"
)

const (
	version = "0.0.1"
)

var (
	rewriterExitChan    chan int       = make(chan int, 1)
	responseChan        chan string    = make(chan string, 1024*10)
	signalHupChan       chan os.Signal = make(chan os.Signal, 1)
	signalInterruptChan chan os.Signal = make(chan os.Signal, 1)
	stdinLineChan       chan string    = make(chan string, 100)
	lastUsedIndex       int
	ldapConnPool        ldappool.Pool
)

var opts struct {
	ServerSlice  []string `short:"s" long:"server" description:"Domain controller server address (required)" required:"true"`
	ServerPort   int      `short:"p" long:"port" description:"Domain controller LDAP service port (default: 389)" default:"389"`
	UseTLS       bool     `long:"tls" description:"Using LDAP over TLS"`
	BindUsername string   `short:"u" long:"binduser" description:"Username for LDAP Bind operation (required)" required:"true"`
	BindPassword string   `short:"w" long:"bindpassword" description:"Password for LDAP Bind operation"`
	PwdFile      string   `short:"f" long:"pwdfile" description:"File with password for Bind operation"`
	BaseDN       string   `short:"b" long:"basedn" description:"BaseDN for user search process. %ou = OU (required)" required:"true"`
	Filter       string   `long:"filter" description:"User search filter pattern. %u = login (required)" required:"true"`
	StripRealm   bool     `long:"strip-realm" description:"Strip Kerberos Realm from usernames"`
	StripDomain  bool     `long:"strip-domain" description:"Strip NT domain from usernames"`
	LogFile      string   `long:"log" description:"Path to log file (default: /var/log/squid-ext-acl-ldap.log)" default:"/var/log/squid-ext-acl-ldap.log"`
}

func isInt(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

func addResponse(s string) {
	responseChan <- s
}

func writerResponseLine() {
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
		log.Fatalf("[ERROR] Cannot create LDAP server pool. Message - %s", err.Error())
		os.Exit(1)
	}

	ldapConnPool, err = ldappool.NewChannelPool(0, len(opts.ServerSlice), serverpool, opts.UseTLS, []uint8{ldap.LDAPResultTimeLimitExceeded, ldap.ErrorNetwork, ldap.LDAPResultInvalidCredentials})
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

func doRequest(id, username string, searchEntity string) {

	conn, err := ldapConnPool.Get()
	if err != nil {
		log.Fatalln("[ERROR] Cannot get active LDAP connection")
		return
	}

	err = conn.Bind(opts.BindUsername, opts.BindPassword)

	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			log.Fatal("[ERROR] LDAP binding operation error. Invalid Credentials")
		} else {
			log.Printf("[WARN] LDAP binding operation error. Error - %s", err.Error())
		}
		return
	}
	defer conn.Close()

	if opts.StripRealm {
		username = strings.Split(username, "@")[0]
	}
	if opts.StripDomain && strings.Contains(username, "\\") {
		username = strings.Split(username, "\\")[1]
	}

	searchRequest := ldap.NewSearchRequest(
		strings.Replace(opts.BaseDN, "%ou", searchEntity, -1),
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(%s))", strings.Replace(opts.Filter, "%u", username, -1)),
		[]string{"sAMAccountName"},
		nil,
	)
	sr, err := conn.Search(searchRequest)
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			log.Printf("[WARN] Exception during execution of the LDAP query. OU '%s' is not found in domain. Using LDAP path - %s", searchEntity, strings.Replace(opts.BaseDN, "%ou", searchEntity, -1))
		} else {
			log.Printf("[WARN] Exception during execution of the LDAP query. Message - %s", err.Error())
		}
	}

	if len(sr.Entries) > 0 {
		if id == "" {
			addResponse(fmt.Sprintf("OK tag=%s", searchEntity))
		} else {
			addResponse(fmt.Sprintf("%s OK tag=%s", id, searchEntity))
		}

	} else {
		if id == "" {
			addResponse(fmt.Sprintf("ERR"))
		} else {
			addResponse(fmt.Sprintf("%s ERR", id))
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
		log.Fatalf("[ERROR] Error opening log file. Message - %s", err.Error())
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

	go writerResponseLine()

	inscanner := bufio.NewScanner(os.Stdin)
	go func() {
		for inscanner.Scan() {
			stdinLineChan <- inscanner.Text()
		}
		err := inscanner.Err()
		if err != nil {
			log.Printf("[WARN] Stdin error: %s", err.Error())
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
