package cuckoo

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/dgryski/go-wyhash"
)

// maxCuckooKickouts is the maximum number of times reinsert
// is attempted.
const maxCuckooKickouts = 500

// Filter is a probabilistic counter.
type Filter struct {
	buckets []bucket
	count   uint
	// Bit mask set to len(buckets) - 1. As len(buckets) is always a power of 2,
	// applying this mask mimics the operation x % len(buckets).
	bucketIndexMask uint
	// rng is a simple pseudo-random number generator that we store locally
	// so that we don't have to spend time locking the global RNG.
	rng *wyhash.Rng
}

// NewFilter returns a new cuckoofilter suitable for the given number of elements.
// When inserting more elements, insertion speed will drop significantly and insertions might fail altogether.
// A capacity of 1000000 is a normal default, which allocates
// about ~2MB on 64-bit machines.
func NewFilter(numElements uint) *Filter {
	numBuckets := getNextPow2(uint64(numElements / bucketSize))
	if float64(numElements)/float64(numBuckets*bucketSize) > 0.96 {
		numBuckets <<= 1
	}
	if numBuckets == 0 {
		numBuckets = 1
	}
	buckets := make([]bucket, numBuckets)
	rng := wyhash.Rng(time.Now().UnixNano())
	return &Filter{
		buckets:         buckets,
		count:           0,
		bucketIndexMask: uint(len(buckets) - 1),
		rng:             &rng,
	}
}

// Lookup returns true if data is in the filter.
func (cf *Filter) Lookup(data []byte) bool {
	i1, fp := getIndexAndFingerprint(data, cf.bucketIndexMask)
	if b := cf.buckets[i1]; b.contains(fp) {
		return true
	}
	i2 := getAltIndex(fp, i1, cf.bucketIndexMask)
	b := cf.buckets[i2]
	return b.contains(fp)
}

// Reset removes all items from the filter, setting count to 0.
func (cf *Filter) Reset() {
	for i := range cf.buckets {
		cf.buckets[i].reset()
	}
	cf.count = 0
}

// Insert data into the filter. Returns false if insertion failed. In the resulting state, the filter
// * Might return false negatives
// * Deletes are not guaranteed to work
// To increase success rate of inserts, create a larger filter.
func (cf *Filter) Insert(data []byte) bool {
	i1, fp := getIndexAndFingerprint(data, cf.bucketIndexMask)
	if cf.insert(fp, i1) {
		return true
	}
	i2 := getAltIndex(fp, i1, cf.bucketIndexMask)
	if cf.insert(fp, i2) {
		return true
	}
	return cf.reinsert(fp, cf.Coinflip(i1, i2))
}

// this isn't perfectly uniform, but it's good enough for our purposes since
// n is on the order of 10^6 and our rng is 63 bits (10^19); this means the
// bias is on the order of 10^-13. For our use case, that's well below the
// noise floor.
func (cf *Filter) Intn(n int) int {
	// we need to make sure it's strictly positive, so mask off the sign bit
	return int(cf.rng.Next()&0x7FFF_FFFF_FFFF_FFFF) % n
}

// Coinflip returns either i1 or i2 randomly.
func (cf Filter) Coinflip(i1, i2 uint) uint {
	if cf.rng.Next()&0x1 == 0 {
		return i1
	}
	return i2
}

func (cf *Filter) insert(fp fingerprint, i uint) bool {
	if cf.buckets[i].insert(fp) {
		cf.count++
		return true
	}
	return false
}

func (cf *Filter) reinsert(fp fingerprint, i uint) bool {
	for k := 0; k < maxCuckooKickouts; k++ {
		j := cf.Intn(bucketSize)
		// Swap fingerprint with bucket entry.
		cf.buckets[i][j], fp = fp, cf.buckets[i][j]

		// Move kicked out fingerprint to alternate location.
		i = getAltIndex(fp, i, cf.bucketIndexMask)
		if cf.insert(fp, i) {
			return true
		}
	}
	return false
}

// Delete data from the filter. Returns true if the data was found and deleted.
func (cf *Filter) Delete(data []byte) bool {
	i1, fp := getIndexAndFingerprint(data, cf.bucketIndexMask)
	i2 := getAltIndex(fp, i1, cf.bucketIndexMask)
	return cf.delete(fp, i1) || cf.delete(fp, i2)
}

func (cf *Filter) delete(fp fingerprint, i uint) bool {
	if cf.buckets[i].delete(fp) {
		cf.count--
		return true
	}
	return false
}

// Count returns the number of items in the filter.
func (cf *Filter) Count() uint {
	return cf.count
}

// LoadFactor returns the fraction slots that are occupied.
func (cf *Filter) LoadFactor() float64 {
	return float64(cf.count) / float64(len(cf.buckets)*bucketSize)
}

const bytesPerBucket = bucketSize * fingerprintSizeBits / 8

// Encode returns a byte slice representing a Cuckoofilter.
func (cf *Filter) Encode() []byte {
	res := new(bytes.Buffer)
	res.Grow(len(cf.buckets) * bytesPerBucket)

	for _, b := range cf.buckets {
		for _, fp := range b {
			binary.Write(res, binary.LittleEndian, fp)
		}
	}
	return res.Bytes()
}

// Decode returns a Cuckoofilter from a byte slice created using Encode.
func Decode(data []byte) (*Filter, error) {
	if len(data)%bucketSize != 0 {
		return nil, fmt.Errorf("bytes must to be multiple of %d, got %d", bucketSize, len(data))
	}
	numBuckets := len(data) / bytesPerBucket
	if numBuckets < 1 {
		return nil, fmt.Errorf("bytes can not be smaller than %d, size in bytes is %d", bytesPerBucket, len(data))
	}
	if getNextPow2(uint64(numBuckets)) != uint(numBuckets) {
		return nil, fmt.Errorf("numBuckets must to be a power of 2, got %d", numBuckets)
	}
	var count uint
	buckets := make([]bucket, numBuckets)
	reader := bytes.NewReader(data)

	for i, b := range buckets {
		for j := range b {
			binary.Read(reader, binary.LittleEndian, &buckets[i][j])
			if buckets[i][j] != nullFp {
				count++
			}
		}
	}
	return &Filter{
		buckets:         buckets,
		count:           count,
		bucketIndexMask: uint(len(buckets) - 1),
	}, nil
}
