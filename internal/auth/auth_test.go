package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {

	malferr := errors.New("malformed authorization header")

	tests := map[string]struct {
		input http.Header
		want  string
		err   error
	}{
		"simple": {
			input: http.Header{
				"Authorization": []string{"ApiKey 1234"},
			},
			want: "1234",
			err:  nil,
		},
		"blank": {
			input: http.Header{
				"Authorization": []string{""},
			},
			want: "",
			err:  ErrNoAuthHeaderIncluded,
		},
		"malformed type": {
			input: http.Header{
				"Authorization": []string{"Bearer 1234"},
			},
			want: "",
			err:  malferr,
		},
		"malformed split": {
			input: http.Header{
				"Authorization": []string{"ApiKey1234"},
			},
			want: "",
			err:  malferr,
		},
		"missing": {
			input: http.Header{
				"NotAuthorization": []string{"foobar"},
			},
			want: "",
			err:  ErrNoAuthHeaderIncluded,
		},
		"nil": {
			input: nil,
			want:  "",
			err:   ErrNoAuthHeaderIncluded,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, terr := GetAPIKey(tc.input)
			if tc.err != terr && tc.err.Error() != terr.Error() {
				t.Fatalf("expected: %v, got: %v", tc.err, terr)
			}
			if got != tc.want {
				t.Fatalf("expected: %v, got: %v", tc.want, got)
			}
		})
	}

}
