package main

// Imports
import (
	"os" // For quiting
	"fmt" // For printing of results/errors
	"net" // For talking to the who-is server
	"time" // For timeouts
	"regexp" // For matching whois results
	"io/ioutil" // For reading whois results
	"strings" // For cleaning up strings before printing
)

// Checks if a domain is actually a legal domain name
func validDomain(domain string) bool {

	// We have to have a tld, if not, bail
	if !strings.Contains(domain, ".") {
		return false
	}

	// Loop each character in the domain
	for _, c := range domain {

		// Check the character
		switch c {
			// Valid chars
			case 'a', 'b', 'c', 'd', 'e', 'f':
			case 'g', 'h', 'i', 'j', 'k', 'l':
			case 'm', 'n', 'o', 'p', 'q', 'r':
			case 's', 't', 'u', 'v', 'w', 'x':
			case 'y', 'z', '0', '1', '2', '3':
			case '4', '5', '6', '7', '8', '9':
			case '-', '.':
				continue
			// Invalid chars
			default:
				return false
		}

	}

	// Must be
	return true

}

// Global cache of domains to nameservers
var cache map[string][]string

// Checks the validity of a domain and prints the nameservers if possible
func lookupDomain(domain string) *[]string {

	// Split the domain by dots
	splitDomain := strings.Split(domain, ".")
	rootDomain := strings.Join(splitDomain[len(splitDomain)-2:], ".")

	// Check the cache for a existing lookup first
	result, exists := cache[rootDomain]
	if exists {
		return &result
	}

	// Connect to [tld].whois-server.net on port 43
	conn, err := net.DialTimeout(
		"tcp", 
		net.JoinHostPort(splitDomain[len(splitDomain)-1] + ".whois-servers.net", "43"), 
		time.Second * 10,
	)
	if err != nil {
		return nil
	}

	// Send a query for the root domain
	conn.Write([]byte("domain " + rootDomain + "\r\n"))
	var buffer []byte
	buffer, err = ioutil.ReadAll(conn)
	if err != nil {
		panic(err)
	}

	// Cleanup
	conn.Close()

	// Save the result in cache
	response := string(buffer[:])

	// Look for a "Status:" line
	statusRe := regexp.MustCompile(`Status:(.*)\n`)
	status := statusRe.FindStringSubmatch(response)

	// If no match, or status is "free", probably not registered
	if status == nil || strings.TrimSpace(status[1]) == "free" {
		return nil
	}

	// Else, grab the name servers
	nsRe := regexp.MustCompile(`(Name Server|Nserver|Nameserver):(.*)\n`)
	ns := nsRe.FindAllStringSubmatch(response, -1)

	// Extract the actual nameserver values
	servers := make([]string, len(ns))
	for i, server := range ns {

		// Cleanup the name and add it to the list
		servers[i] = strings.ToLower(strings.TrimSpace(server[2]))

	}
	
	// Save it in the cache for later
	cache[rootDomain] = servers

	// Return the list
	return &servers

}

// Entry point
func main() {

	// Verify we have the correct number of args
	if len(os.Args) != 2 { 
		
		// Print usage and bail
		fmt.Fprintln(os.Stderr, "Usage: " + os.Args[0] + " [domain]")
		os.Exit(1)

	}

	// Grab the domain from args
	domain := os.Args[1]

	// Setup the worst-case size cache of nameservers for a given domain
	cache = make(map[string][]string, len(domain)*6)

	// Loop over each character in domain
	for i, c := range domain {

		// Loop each bit in character
		for j := 0; j < 8; j++ {

			// First bit it always 0 in ASCII and third bit is case which is irrelevant in DNS, skip them
			if j == 7 || j == 5 {
				continue
			}

			// Toggle the bit value
			c ^= 1 << uint(j);

			// Rebuild the flipped name for the domain from slices
			flipped := domain[:i] + string(c) + domain[i+1:]

			// If it's a valid domain
			if validDomain(flipped) {

				// Print the domain
				fmt.Print(flipped + "\t")

				// Lookup the nameservers for it
				servers := lookupDomain(flipped)

				// If we found some
				if servers == nil {
					fmt.Println("*")
				} else {
					fmt.Println(strings.Join(*servers, ","))
				}

			}

			// Toggle the bit value back before trying the next one
			c ^= 1 << uint(j);

		}

	}
	
}
