package cmd

import (
	"fmt"
	"net"
	"os"
	"time"

	"dns-guardian/internal/ca"
	
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

// NewStatusCmd creates the status command
func NewStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Check DNS Guardian agent status",
		Long:  `Display the current status of the DNS Guardian agent service.`,
		RunE:  runStatus,
	}
}

func runStatus(cmd *cobra.Command, args []string) error {
	fmt.Println("🔍 DNS Guardian Status Check")
	fmt.Println("============================")
	
	// Check if running as root
	if os.Geteuid() == 0 {
		fmt.Println("✅ Running with root privileges")
	} else {
		fmt.Println("⚠️  Not running as root (required for service)")
	}
	
	// Check CA certificate
	fmt.Println("\n📜 CA Certificate:")
	caPath := ca.GetCAPath()
	if _, err := os.Stat(caPath); err == nil {
		fmt.Printf("✅ CA directory exists: %s\n", caPath)
		
		// Try to load CA
		if caManager, err := ca.LoadOrCreateCA(); err == nil {
			cert := caManager.GetCert()
			fmt.Printf("✅ CA Subject: %s\n", cert.Subject)
			fmt.Printf("✅ Valid until: %s\n", cert.NotAfter.Format("2006-01-02"))
		}
	} else {
		fmt.Println("❌ CA not found (run 'install-ca' first)")
	}
	
	// Check DNS server
	fmt.Println("\n🌐 DNS Server:")
	if checkPort(53) {
		fmt.Println("✅ DNS server is running on port 53")
		
		// Try a test query
		if testDNS() {
			fmt.Println("✅ DNS queries are working")
		} else {
			fmt.Println("⚠️  DNS server is not responding to queries")
		}
	} else {
		fmt.Println("❌ DNS server is not running")
	}
	
	// Check HTTP server
	fmt.Println("\n🌐 HTTP Server:")
	if checkPort(80) {
		fmt.Println("✅ HTTP server is running on port 80")
	} else {
		fmt.Println("❌ HTTP server is not running")
	}
	
	// Check HTTPS server
	fmt.Println("\n🔒 HTTPS Server:")
	if checkPort(443) {
		fmt.Println("✅ HTTPS server is running on port 443")
	} else {
		fmt.Println("❌ HTTPS server is not running")
	}
	
	// Overall status
	fmt.Println("\n📊 Overall Status:")
	if checkPort(53) && checkPort(80) && checkPort(443) {
		fmt.Println("✅ All services are running")
		fmt.Println("\n💡 Next steps:")
		fmt.Println("1. Set your DNS to 127.0.0.1")
		fmt.Println("2. Test by visiting a blocked domain")
	} else {
		fmt.Println("❌ Some services are not running")
		fmt.Println("\n💡 To start the agent:")
		fmt.Println("sudo ./dns-guardian run")
	}
	
	return nil
}

func checkPort(port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 1*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func testDNS() bool {
	c := new(dns.Client)
	c.Timeout = 2 * time.Second
	
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	
	_, _, err := c.Exchange(m, "127.0.0.1:53")
	return err == nil
}