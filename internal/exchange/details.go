package exchange

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
)

var ErrDetails = errors.New("invalid_authorization_details")

const maxDetailsBytes = 8 << 10

// Details preserves the JSON values of both standard and type-specific members.
type Details []map[string]json.RawMessage

func ParseDetails(raw string) (Details, error) {
	var details Details
	if err := json.Unmarshal([]byte(raw), &details); err != nil {
		return nil, ErrDetails
	}
	return details, nil
}

func (d *Details) UnmarshalJSON(raw []byte) error {
	if len(raw) > maxDetailsBytes {
		return ErrDetails
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := readDetailJSON(decoder, 0)
	if err != nil {
		return ErrDetails
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrDetails
	}
	items, ok := value.([]any)
	if !ok || len(items) == 0 {
		return ErrDetails
	}
	parsed := make(Details, 0, len(items))
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			return ErrDetails
		}
		kind, ok := object["type"].(string)
		if !ok || kind == "" || strings.TrimSpace(kind) != kind {
			return ErrDetails
		}
		detail := make(map[string]json.RawMessage, len(object))
		for key, field := range object {
			if detailSetField(key) {
				values, ok := field.([]any)
				if !ok || len(values) == 0 {
					return ErrDetails
				}
				for _, value := range values {
					if text, ok := value.(string); !ok || strings.TrimSpace(text) == "" {
						return ErrDetails
					}
				}
			}
			if key == "identifier" {
				if text, ok := field.(string); !ok || strings.TrimSpace(text) == "" {
					return ErrDetails
				}
			}
			encoded, err := json.Marshal(field)
			if err != nil {
				return ErrDetails
			}
			detail[key] = encoded
		}
		parsed = append(parsed, detail)
	}
	// Bound the canonical form as well, since JSON escaping can increase its size.
	encoded, err := json.Marshal(parsed)
	if err != nil || len(encoded) > maxDetailsBytes {
		return ErrDetails
	}
	*d = parsed
	return nil
}

func readDetailJSON(decoder *json.Decoder, depth int) (any, error) {
	if depth > 16 {
		return nil, ErrDetails
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch token {
	case json.Delim('{'):
		object := make(map[string]any)
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			name, ok := key.(string)
			if _, duplicate := object[name]; !ok || duplicate {
				return nil, ErrDetails
			}
			object[name], err = readDetailJSON(decoder, depth+1)
			if err != nil {
				return nil, err
			}
		}
		_, err = decoder.Token()
		return object, err
	case json.Delim('['):
		items := []any{}
		for decoder.More() {
			item, err := readDetailJSON(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			items = append(items, item)
		}
		_, err = decoder.Token()
		return items, err
	default:
		return token, nil
	}
}

func detailSetField(key string) bool {
	return key == "actions" || key == "locations" || key == "datatypes" || key == "privileges"
}

// permitsDetails requires one complete grant per requested object. Unknown
// fields retain their exact values because their type defines their semantics.
func permitsDetails(granted, requested Details) bool {
	for _, candidate := range requested {
		if !slices.ContainsFunc(granted, func(parent map[string]json.RawMessage) bool {
			if len(parent) != len(candidate) {
				return false
			}
			for key, child := range candidate {
				original, ok := parent[key]
				if !ok {
					return false
				}
				if bytes.Equal(original, child) {
					continue
				}
				if !detailSetField(key) {
					return false
				}
				var ceiling, subset []string
				if json.Unmarshal(original, &ceiling) != nil || json.Unmarshal(child, &subset) != nil || len(subset) == 0 {
					return false
				}
				for _, value := range subset {
					if !slices.Contains(ceiling, value) {
						return false
					}
				}
			}
			return true
		}) {
			return false
		}
	}
	return true
}
