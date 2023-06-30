package cuckoo

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestInsertion(t *testing.T) {
	cf := NewFilter(1000000)
	fd, err := os.Open("/usr/share/dict/words")
	if err != nil {
		t.Skipf("failed reading words: %v", err)
	}
	scanner := bufio.NewScanner(fd)

	var values [][]byte
	var lineCount uint
	for scanner.Scan() {
		s := []byte(scanner.Text())
		if cf.Insert(s) {
			lineCount++
		}
		values = append(values, s)
	}

	if got, want := cf.Count(), lineCount; got != want {
		t.Errorf("After inserting: Count() = %d, want %d", got, want)
	}
	if got, want := cf.LoadFactor(), float64(0.95); got >= want {
		t.Errorf("After inserting: LoadFactor() = %f, want less than %f.", got, want)
	}

	for _, v := range values {
		cf.Delete(v)
	}

	if got, want := cf.Count(), uint(0); got != want {
		t.Errorf("After deleting: Count() = %d, want %d", got, want)
	}
	if got, want := cf.LoadFactor(), float64(0); got != want {
		t.Errorf("After deleting: LoadFactor() = %f, want %f", got, want)
	}
}

func TestLookup(t *testing.T) {
	cf := NewFilter(4)
	cf.Insert([]byte("one"))
	cf.Insert([]byte("two"))
	cf.Insert([]byte("three"))

	testCases := []struct {
		word string
		want bool
	}{
		{"one", true},
		{"two", true},
		{"three", true},
		{"four", false},
		{"five", false},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(fmt.Sprintf("cf.Lookup(%q)", tc.word), func(t *testing.T) {
			t.Parallel()
			if got := cf.Lookup([]byte(tc.word)); got != tc.want {
				t.Errorf("cf.Lookup(%q) got %v, want %v", tc.word, got, tc.want)
			}
		})
	}
}

func TestFilter_LookupLarge(t *testing.T) {
	const size = 10000
	insertFail := 0
	cf := NewFilter(size)
	for i := 0; i < size; i++ {
		if !cf.Insert([]byte{byte(i)}) {
			insertFail++
		}
	}
	fn := 0
	for i := 0; i < size; i++ {
		if !cf.Lookup([]byte{byte(i)}) {
			fn++
		}
	}

	if fn != 0 {
		t.Errorf("cf.Lookup() with %d items. False negatives = %d, want 0. Insert failed %d times", size, fn, insertFail)
	}
}

func TestFilter_Insert(t *testing.T) {
	filter := NewFilter(10000)
	rng := rand.New(rand.NewSource(int64(42)))

	hash := make([]byte, 32)
	for i := 0; i < 100; i++ {
		rng.Read(hash)
		filter.Insert(hash)
	}

	if got, want := filter.Count(), uint(100); got != want {
		t.Errorf("inserting 100 items, Count() = %d, want %d", got, want)
	}
}

func BenchmarkFilter_Reset(b *testing.B) {
	const cap = 10000
	filter := NewFilter(cap)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		filter.Reset()
	}
}

// benchmarkKeys returns a slice of keys for benchmarking with length `size`.
func benchmarkKeys(b *testing.B, size int) [][]byte {
	b.Helper()
	keys := make([][]byte, size)
	rng := rand.New(rand.NewSource(int64(size)))
	for i := range keys {
		keys[i] = make([]byte, 32)
		if _, err := rng.Read(keys[i]); err != nil {
			b.Error(err)
		}
	}
	return keys
}

func BenchmarkFilter_Insert(b *testing.B) {
	const size = 10000
	keys := benchmarkKeys(b, int(float64(size)*0.8))
	b.ResetTimer()

	for i := 0; i < b.N; {
		b.StopTimer()
		filter := NewFilter(size)
		b.StartTimer()
		for _, k := range keys {
			filter.Insert(k)
			i++
		}
	}
}

func BenchmarkFilter_Lookup(b *testing.B) {
	f := NewFilter(10000)
	keys := benchmarkKeys(b, 10000)
	for _, k := range keys {
		f.Insert(k)
	}
	// One half is likely missing, other half is present.
	lookupKeys := append(benchmarkKeys(b, 1000), keys[0:1000]...)
	rand.New(rand.NewSource(42)).Shuffle(2000, func(i, j int) {
		lookupKeys[i] = lookupKeys[j]
	})

	b.ResetTimer()
	for i := 0; i < b.N; {
		for _, k := range lookupKeys {
			f.Lookup(k)
			i++
		}
	}
}

func TestDelete(t *testing.T) {
	cf := NewFilter(8)
	cf.Insert([]byte("one"))
	cf.Insert([]byte("two"))
	cf.Insert([]byte("three"))

	testCases := []struct {
		word string
		want bool
	}{
		{"four", false},
		{"five", false},
		{"one", true},
		{"two", true},
		{"three", true},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("cf.Delete(%q)", tc.word), func(t *testing.T) {
			if got := cf.Delete([]byte(tc.word)); got != tc.want {
				t.Errorf("cf.Delete(%q) got %v, want %v", tc.word, got, tc.want)
			}
		})
	}
}

func TestDeleteMultipleSame(t *testing.T) {
	cf := NewFilter(4)
	for i := 0; i < 5; i++ {
		if !cf.Insert([]byte("some_item")) {
			t.Error("Failed insert during setup.")
		}
	}

	testCases := []struct {
		word      string
		want      bool
		wantCount uint
	}{
		{"missing", false, 5},
		{"missing2", false, 5},
		{"some_item", true, 4},
		{"some_item", true, 3},
		{"some_item", true, 2},
		{"some_item", true, 1},
		{"some_item", true, 0},
		{"some_item", false, 0},
	}
	t.Logf("Filter state full: %v", cf)
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("cf.Delete(%q)", tc.word), func(t *testing.T) {
			if got, gotCount := cf.Delete([]byte(tc.word)), cf.Count(); got != tc.want || gotCount != tc.wantCount {
				t.Errorf("cf.Delete(%q) = %v, count = %d; want %v, count = %d", tc.word, got, gotCount, tc.want, tc.wantCount)
			}
		})
	}
}

func TestEncodeDecode(t *testing.T) {
	cf := NewFilter(10)
	cf.Insert([]byte{1})
	cf.Insert([]byte{2})
	cf.Insert([]byte{3})
	cf.Insert([]byte{4})
	cf.Insert([]byte{5})
	cf.Insert([]byte{6})
	cf.Insert([]byte{7})
	cf.Insert([]byte{8})
	cf.Insert([]byte{9})
	encoded := cf.Encode()
	got, err := Decode(encoded)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if !cmp.Equal(cf, got, cmp.AllowUnexported(Filter{})) {
		t.Errorf("Decode = %v, want %v, encoded = %v", got, cf, encoded)
	}
}

func TestFilter_randi(t *testing.T) {
	cf := NewFilter(8)
	yes := 0
	for i := 0; i < 1000000; i++ {
		if cf.Coinflip(0, 1) == 1 {
			yes++
		}
	}
	if yes < 499000 || yes > 501000 {
		t.Errorf("yes: %d, expected 500000", yes)
	}
}

func TestFilter_Intn(t *testing.T) {
	const tries = 1_000_000
	for _, n := range []int{10, 100, 1000} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			cf := NewFilter(8)
			yes := 0
			buckets := make([]int, n)
			for i := 0; i < tries; i++ {
				x := cf.Intn(n)
				buckets[x]++
				if x == 0 {
					yes++
				}
			}
			// this is a rectangular distribution, so the expected value is
			// tries / n. We expect the actual value to be within 10% of that.
			// This means that the test will randomly fail occasionally, but it
			// should be rare.
			expected := tries / n
			if yes < (expected*90)/100 || yes > (expected*110)/100 {
				t.Errorf("yes: %d, expected between %d and %d", yes, (expected*95)/100, (expected*105)/100)
				t.Log(buckets)
			}
		})
	}
}
