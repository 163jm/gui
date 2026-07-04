package node

import (
	"encoding/json"
	"os"
	"sync"
)

type Store struct {
	mu    sync.RWMutex
	nodes []Node
	path  string
}

func NewStore(path string) *Store {
	return &Store{path: path}
}

func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			s.nodes = []Node{}
			return nil
		}
		return err
	}
	return json.Unmarshal(data, &s.nodes)
}

func (s *Store) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := json.MarshalIndent(s.nodes, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0644)
}

func (s *Store) GetAll() []Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Node, len(s.nodes))
	copy(result, s.nodes)
	return result
}

func (s *Store) Get(id string) *Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.nodes {
		if s.nodes[i].ID == id {
			n := s.nodes[i]
			return &n
		}
	}
	return nil
}

func (s *Store) AddMany(nodes []Node) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodes = append(s.nodes, nodes...)
}

func (s *Store) Update(n Node) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.nodes {
		if s.nodes[i].ID == n.ID {
			s.nodes[i] = n
			return
		}
	}
}

func (s *Store) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	newNodes := s.nodes[:0]
	for _, n := range s.nodes {
		if n.ID != id {
			newNodes = append(newNodes, n)
		}
	}
	s.nodes = newNodes
}

func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodes = []Node{}
}

func (s *Store) RemoveBySubscription(subURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	newNodes := s.nodes[:0]
	for _, n := range s.nodes {
		if n.SubURL != subURL {
			newNodes = append(newNodes, n)
		}
	}
	s.nodes = newNodes
}
