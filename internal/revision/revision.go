// Package revision validates Git object IDs against a protected repository profile.
package revision

// Size returns the exact hexadecimal width, or zero for an unsupported profile.
func Size(objectFormat string) int {
	switch objectFormat {
	case "sha1":
		return 40
	case "sha256":
		return 64
	default:
		return 0
	}
}

// Valid never selects an algorithm from the supplied ID's length or spelling.
func Valid(objectFormat, id string) bool {
	size := Size(objectFormat)
	if size == 0 || len(id) != size {
		return false
	}
	for i := 0; i < len(id); i++ {
		if !(id[i] >= '0' && id[i] <= '9' || id[i] >= 'a' && id[i] <= 'f') {
			return false
		}
	}
	return true
}
