package handler

import "testing"

func TestDocumentImportType(t *testing.T) {
	for _, tc := range []struct {
		kind   string
		config bool
		want   string
	}{
		{"", false, ""}, {"normal", true, ""}, {"structured", true, "SECURITY_PROCESSING_UNSUPPORTED_FOR_IMPORT_TYPE"},
		{"structured", false, "STRUCTURED_IMPORT_UNSUPPORTED"}, {"unknown", true, "INVALID_IMPORT_TYPE"},
	} {
		t.Run(tc.kind+tc.want, func(t *testing.T) {
			err := validateDocumentImportType(tc.kind, tc.config)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || err.Error() != tc.want {
				t.Fatalf("got %v want %s", err, tc.want)
			}
		})
	}
}
