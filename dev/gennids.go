// Copyright (C) 2017. See AUTHORS.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var nidRegex = regexp.MustCompile(`^#\s*define\s+([\w]+)\s+(\d+)\s*$`)

const header = `// Copyright (C) 2017. See AUTHORS.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openssl

type NID int

const (
`

const footer = ")"

type NID struct {
	Name  string
	Value int
}

// ByValue implements sort.Interface for []NID based on the Value field.
type ByValue []NID

func (v ByValue) Len() int {
	return len(v)
}
func (v ByValue) Swap(i, j int) {
	v[i], v[j] = v[j], v[i]
}
func (v ByValue) Less(i, j int) bool {
	return v[i].Value < v[j].Value
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Generates a nids.go file from openssl/obj_mac.h\n\n")
		flag.PrintDefaults()
	}

	headerPath := flag.String(
		"header",
		"/usr/include/openssl/obj_mac.h",
		"path to openssl/obj_mac.h",
	)
	outputPath := flag.String(
		"output",
		"-",
		"path to output file, or - for stdout",
	)
	flag.Parse()

	var err error

	headerFile, err := os.Open(*headerPath)
	if err != nil {
		log.Fatalf("failed to open file '%s' for reading: %v", *headerPath, err)
	}
	defer headerFile.Close()
	headerScanner := bufio.NewScanner(headerFile)

	var outputFile = os.Stdout
	if *outputPath != "-" {
		outputFile, err = os.Create(*outputPath)
		if err != nil {
			log.Fatalf("failed to open file '%s' for writing: %v", *outputPath, err)
		}
		defer outputFile.Close()
	}

	var nids []NID
	var maxNameLen int

	for headerScanner.Scan() {
		line := headerScanner.Text()
		matches := nidRegex.FindStringSubmatch(line)
		if matches == nil {
			continue
		}
		name := matches[1]
		value, err := strconv.Atoi(matches[2])
		if err != nil {
			log.Fatalf("failed to convert value in '%s' to integer: %v'", matches[0], err)
		}
		nids = append(nids, NID{
			Name:  name,
			Value: value,
		})

		if len(name) > maxNameLen {
			maxNameLen = len(name)
		}
	}

	sort.Sort(ByValue(nids))

	_, err = outputFile.WriteString(header)
	if err != nil {
		log.Fatalf("failed to write header to output: %v", err)
	}
	for _, nid := range nids {
		padLen := maxNameLen - len(nid.Name)
		padding := strings.Repeat(" ", padLen)
		_, err = fmt.Fprintf(
			outputFile,
			"    %s%s NID = %d\n",
			nid.Name,
			padding,
			nid.Value,
		)
		if err != nil {
			log.Fatalf("failed writing NID '%s' = '%d': %v", nid.Name, nid.Value, err)
		}
	}
	_, err = outputFile.WriteString(footer)
	if err != nil {
		log.Fatalf("failed to write footer to output: %v", err)
	}
}
