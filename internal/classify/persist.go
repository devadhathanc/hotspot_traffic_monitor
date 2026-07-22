package classify

import (
	"encoding/json"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

const bucketName = "dns_cache"

// Persister provides BoltDB-backed persistence for the classify cache.
//
// Design choice: BoltDB (bbolt) is used over SQLite because:
// - Zero-cgo dependency, pure Go — no cross-compilation issues.
// - Simple key-value model is ideal for IP→AppInfo lookups.
// - Single-file embedded database with ACID transactions.
// - Excellent concurrent read performance with B+ tree storage.
type Persister struct {
	db *bolt.DB
}

// NewPersister opens (or creates) a BoltDB database at the given path.
func NewPersister(dbPath string) (*Persister, error) {
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{
		Timeout: 0, // Wait indefinitely for the lock.
	})
	if err != nil {
		return nil, fmt.Errorf("opening bolt db at %s: %w", dbPath, err)
	}

	// Ensure the bucket exists.
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		return err
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("creating bucket %s: %w", bucketName, err)
	}

	return &Persister{db: db}, nil
}

// Put writes an IP→AppInfo entry to disk (write-through).
func (p *Persister) Put(ip string, info AppInfo) error {
	data, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("marshaling AppInfo for %s: %w", ip, err)
	}

	return p.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		return b.Put([]byte(ip), data)
	})
}

// Delete removes an entry from the persistence layer.
func (p *Persister) Delete(ip string) error {
	return p.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		return b.Delete([]byte(ip))
	})
}

// LoadAll reads all entries from the persistence layer.
// Callers are responsible for filtering expired entries.
func (p *Persister) LoadAll() (map[string]AppInfo, error) {
	result := make(map[string]AppInfo)

	err := p.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var info AppInfo
			if err := json.Unmarshal(v, &info); err != nil {
				// Skip corrupt entries rather than failing entirely.
				return nil
			}
			result[string(k)] = info
			return nil
		})
	})

	return result, err
}

// Close closes the underlying BoltDB database.
func (p *Persister) Close() error {
	if p.db != nil {
		return p.db.Close()
	}
	return nil
}
