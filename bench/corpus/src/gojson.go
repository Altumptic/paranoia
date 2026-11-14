// Benchmark corpus sample: a small, deterministic Go program that uses a
// realistic slice of the standard library (encoding/json, sort, strings,
// strconv, time, os) so the build links a good number of std functions.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type record struct {
	Name  string            `json:"name"`
	Score float64           `json:"score"`
	Tags  []string          `json:"tags,omitempty"`
	Meta  map[string]string `json:"meta,omitempty"`
}

type summary struct {
	Total  int               `json:"total"`
	ByName map[string]record `json:"by_name"`
	Top    []string          `json:"top"`
}

func parseRecord(line string) (record, error) {
	var r record
	if err := json.Unmarshal([]byte(line), &r); err != nil {
		return r, fmt.Errorf("parse %q: %w", line, err)
	}
	r.Name = strings.ToLower(strings.TrimSpace(r.Name))
	return r, nil
}

func rank(rs []record) summary {
	s := summary{Total: len(rs), ByName: map[string]record{}}
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].Score == rs[j].Score {
			return rs[i].Name < rs[j].Name
		}
		return rs[i].Score > rs[j].Score
	})
	for i, r := range rs {
		s.ByName[r.Name] = r
		if i < 5 {
			s.Top = append(s.Top, r.Name)
		}
	}
	return s
}

func main() {
	sc := bufio.NewScanner(os.Stdin)
	var rs []record
	now := time.Now().Unix()
	for sc.Scan() {
		r, err := parseRecord(sc.Text())
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		if r.Score == 0 {
			r.Score = float64(len(r.Name)) / float64(len(r.Tags)+1)
		}
		r.Meta = map[string]string{"epoch": strconv.FormatInt(now, 10)}
		rs = append(rs, r)
	}
	out := rank(rs)
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(b))
}
