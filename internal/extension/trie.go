package extension

import (
	"strings"
	"sync"
)

// TrieNode represents a node in the domain trie
type TrieNode struct {
	Children map[string]*TrieNode
	IsEnd    bool
	Blocked  bool
}

// DomainTrie implements an efficient trie structure for domain matching
// It stores domains in reverse order for efficient subdomain matching
type DomainTrie struct {
	root *TrieNode
	mu   sync.RWMutex
}

// NewDomainTrie creates a new domain trie
func NewDomainTrie() *DomainTrie {
	return &DomainTrie{
		root: &TrieNode{Children: make(map[string]*TrieNode)},
	}
}

// Insert adds a domain to the trie
func (dt *DomainTrie) Insert(domain string) {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	// Normalize and split domain
	parts := strings.Split(strings.ToLower(domain), ".")
	
	// Reverse domain parts for efficient subdomain matching
	// example.com becomes [com, example]
	for i := len(parts)/2 - 1; i >= 0; i-- {
		opp := len(parts) - 1 - i
		parts[i], parts[opp] = parts[opp], parts[i]
	}

	current := dt.root
	for _, part := range parts {
		if current.Children[part] == nil {
			current.Children[part] = &TrieNode{Children: make(map[string]*TrieNode)}
		}
		current = current.Children[part]
	}
	current.IsEnd = true
	current.Blocked = true
}

// IsBlocked checks if a domain is blocked
// It also matches subdomains - if example.com is blocked, sub.example.com is also blocked
func (dt *DomainTrie) IsBlocked(domain string) bool {
	dt.mu.RLock()
	defer dt.mu.RUnlock()

	// Normalize and split domain
	parts := strings.Split(strings.ToLower(domain), ".")
	
	// Reverse domain parts
	for i := len(parts)/2 - 1; i >= 0; i-- {
		opp := len(parts) - 1 - i
		parts[i], parts[opp] = parts[opp], parts[i]
	}

	current := dt.root
	for _, part := range parts {
		if current.Children[part] == nil {
			return false
		}
		current = current.Children[part]
		// If we find a blocked domain that's a parent, block this subdomain too
		if current.IsEnd && current.Blocked {
			return true
		}
	}
	return false
}

// Clear removes all domains from the trie
func (dt *DomainTrie) Clear() {
	dt.mu.Lock()
	defer dt.mu.Unlock()
	dt.root = &TrieNode{Children: make(map[string]*TrieNode)}
}

// GetDomainList returns all blocked domains in the trie
func (dt *DomainTrie) GetDomainList() []string {
	dt.mu.RLock()
	defer dt.mu.RUnlock()

	var domains []string
	dt.collectDomains(dt.root, []string{}, &domains)
	return domains
}

// collectDomains recursively collects all domains from the trie
func (dt *DomainTrie) collectDomains(node *TrieNode, path []string, domains *[]string) {
	if node.IsEnd && node.Blocked {
		// Reverse path back to normal domain format
		domain := make([]string, len(path))
		for i := 0; i < len(path); i++ {
			domain[len(path)-1-i] = path[i]
		}
		*domains = append(*domains, strings.Join(domain, "."))
	}

	for part, child := range node.Children {
		newPath := append(append([]string{}, path...), part)
		dt.collectDomains(child, newPath, domains)
	}
}

// Size returns the number of blocked domains
func (dt *DomainTrie) Size() int {
	dt.mu.RLock()
	defer dt.mu.RUnlock()
	return dt.countDomains(dt.root)
}

// countDomains recursively counts domains in the trie
func (dt *DomainTrie) countDomains(node *TrieNode) int {
	count := 0
	if node.IsEnd && node.Blocked {
		count = 1
	}
	for _, child := range node.Children {
		count += dt.countDomains(child)
	}
	return count
}

// LoadDomains bulk loads domains into the trie
func (dt *DomainTrie) LoadDomains(domains []string) {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	// Clear existing domains
	dt.root = &TrieNode{Children: make(map[string]*TrieNode)}

	// Insert all domains
	for _, domain := range domains {
		if domain == "" {
			continue
		}
		
		// Use internal insert without locking
		parts := strings.Split(strings.ToLower(domain), ".")
		
		// Reverse domain parts
		for i := len(parts)/2 - 1; i >= 0; i-- {
			opp := len(parts) - 1 - i
			parts[i], parts[opp] = parts[opp], parts[i]
		}

		current := dt.root
		for _, part := range parts {
			if current.Children[part] == nil {
				current.Children[part] = &TrieNode{Children: make(map[string]*TrieNode)}
			}
			current = current.Children[part]
		}
		current.IsEnd = true
		current.Blocked = true
	}
}