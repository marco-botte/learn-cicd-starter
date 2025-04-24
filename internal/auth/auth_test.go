package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		header  http.Header
		wantKey string
		wantErr error
	}{
		{
			name:    "No header",
			header:  http.Header{},
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed header - missing ApiKey prefix",
			header: http.Header{
				"Authorization": []string{"Bearer abc123"},
			},
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name: "Malformed header - only one part",
			header: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name: "Valid header",
			header: http.Header{
				"Authorization": []string{"ApiKey abc123"},
			},
			wantKey: "abc123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.header)
			if tt.wantErr == nil {
				if err == nil || err.Error() != tt.wantErr.Error() {
					t.Fatalf("expected error '%v', got '%v'", tt.wantErr, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if gotKey != tt.wantKey {
					t.Fatalf("expected key '%s', got '%s'", tt.wantKey, gotKey)
				}
			}
		})
	}
}
