// patch-sensitive-value-schema patches CRD YAML files to add oneOf schema
// validation for SensitiveValue fields. These fields accept either a plain
// string or an object with value/valueFrom properties.
//
// controller-gen emits SensitiveValue fields without a type constraint (due to
// the +kubebuilder:validation:Type="" marker). This script finds those fields
// and adds: oneOf: [{type: string}, {type: object}]
//
// Usage: go run hack/patch-sensitive-value-schema.go <crd-file> [<crd-file>...]
package main

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <crd-file> [<crd-file>...]\n", os.Args[0])
		os.Exit(1)
	}

	for _, path := range os.Args[1:] {
		if err := patchFile(path); err != nil {
			fmt.Fprintf(os.Stderr, "error patching %s: %v\n", path, err)
			os.Exit(1)
		}
	}
}

// isSensitiveValueBlock checks whether a YAML block at the given indentation
// looks like a SensitiveValue: it has "properties:" with "value:" and
// "valueFrom:" children, but no "type:" at the field level.
//
// We detect the pattern by scanning forward from a field definition line
// (the line with "description:") to see if it has the right shape.
func patchFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	var out []string

	// We look for blocks that match this pattern (at any indent level):
	//   <fieldname>:
	//     description: ...
	//     properties:
	//       value:
	//         ...
	//       valueFrom:
	//         ...
	//
	// WITHOUT a "type:" line at the same indent as "description:".
	// When found, we insert "oneOf:" right before "properties:".

	// Pattern: a line with only spaces + a yaml key + colon (field name line)
	// followed by description, then properties with value+valueFrom children.

	i := 0
	for i < len(lines) {
		line := lines[i]

		// Detect the start of a SensitiveValue field:
		// Look for a "properties:" line, peek backward for no "type:" and
		// peek forward for "value:" and "valueFrom:" children.
		if isSensitiveValueProperties(lines, i) {
			indent := leadingSpaces(line)
			// Insert oneOf before properties
			oneOf := fmt.Sprintf("%soneOf:\n%s- type: string\n%s- type: object", indent, indent, indent)
			out = append(out, oneOf)
		}

		out = append(out, line)
		i++
	}

	result := strings.Join(out, "\n")
	if !bytes.Equal(data, []byte(result)) {
		return os.WriteFile(path, []byte(result), 0644)
	}
	return nil
}

// leadingSpaces returns the leading whitespace of a line.
func leadingSpaces(line string) string {
	return line[:len(line)-len(strings.TrimLeft(line, " "))]
}

// indentLevel returns the number of leading spaces.
func indentLevel(line string) int {
	return len(line) - len(strings.TrimLeft(line, " "))
}

var propertiesRe = regexp.MustCompile(`^(\s+)properties:\s*$`)

// isSensitiveValueProperties checks if lines[i] is a "properties:" line that
// belongs to a SensitiveValue schema block.
func isSensitiveValueProperties(lines []string, i int) bool {
	m := propertiesRe.FindStringSubmatch(lines[i])
	if m == nil {
		return false
	}
	propIndent := indentLevel(lines[i])

	// Check that immediately preceding lines at propIndent have "description:"
	// but NOT "type:". We scan backward to find the parent block.
	hasDescription := false
	hasType := false
	for j := i - 1; j >= 0; j-- {
		jIndent := indentLevel(lines[j])
		if strings.TrimSpace(lines[j]) == "" {
			continue
		}
		if jIndent < propIndent {
			break // went above our block
		}
		if jIndent == propIndent {
			trimmed := strings.TrimSpace(lines[j])
			if strings.HasPrefix(trimmed, "description:") {
				hasDescription = true
			}
			if strings.HasPrefix(trimmed, "type:") {
				hasType = true
			}
		}
	}

	if !hasDescription || hasType {
		return false
	}

	// Check that the direct children of "properties:" are exactly "value:" and "valueFrom:"
	// (no other keys like "name:" which would indicate a corev1.EnvVar)
	childIndent := propIndent + 2
	hasValue := false
	hasValueFrom := false
	childCount := 0
	for j := i + 1; j < len(lines); j++ {
		if strings.TrimSpace(lines[j]) == "" {
			continue
		}
		jIndent := indentLevel(lines[j])
		if jIndent <= propIndent {
			break // left the properties block
		}
		if jIndent == childIndent {
			childCount++
			trimmed := strings.TrimSpace(lines[j])
			if trimmed == "value:" {
				hasValue = true
			}
			if trimmed == "valueFrom:" {
				hasValueFrom = true
			}
		}
	}

	return hasValue && hasValueFrom && childCount == 2
}
