package file

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/proxify/pkg/types"
)

func TestSaveRejectsNameOutsideFolder(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "cwd", "proxify_logs")
	client, err := New(&Options{OutputFolder: logs})
	if err != nil {
		t.Fatal(err)
	}
	err = client.Save(types.HTTPTransaction{Name: "../../outside-1fde6388dae4f50d", RawData: []byte("data")})
	if err == nil {
		t.Fatal("expected an error for a name that leaves the log folder")
	}
	if _, statErr := os.Stat(filepath.Join(root, "outside-1fde6388dae4f50d.txt")); !os.IsNotExist(statErr) {
		t.Fatalf("file written outside the log folder: %v", statErr)
	}
	if err := client.Save(types.HTTPTransaction{Name: "example.com:8443-1fde6388dae4f50d", RawData: []byte("data")}); err != nil {
		t.Fatal(err)
	}
}
