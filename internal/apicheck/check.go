// Package apicheck checks the public identifier inventory, including aliases.
// It is used only by tests; it is not a dependency of the format library.
package apicheck

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/importer"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
)

// Check inspects compiled exports, so aliased types' fields and methods are
// guarded too. api.txt is a review artifact, never updated by this test.
// This is an identifier gate, not proof that semantics or signatures are unchanged.
func Check(t *testing.T) {
	t.Helper()
	command := exec.Command("go", "list", "-export", "-deps", "-json", ".")
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		t.Fatalf("inspect exports: %v: %s", err, stderr.String())
	}
	paths := map[string]string{}
	target := ""
	decoder := json.NewDecoder(bytes.NewReader(output))
	for {
		var item struct {
			ImportPath, Export string
			DepOnly            bool
		}
		err := decoder.Decode(&item)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		paths[item.ImportPath] = item.Export
		if !item.DepOnly {
			target = item.ImportPath
		}
	}
	load := importer.ForCompiler(token.NewFileSet(), "gc", func(path string) (io.ReadCloser, error) {
		name := paths[path]
		if name == "" {
			return nil, fmt.Errorf("missing exports for %s", path)
		}
		return os.Open(name)
	})
	pkg, err := load.Import(target)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, name := range pkg.Scope().Names() {
		if !token.IsExported(name) {
			continue
		}
		object := pkg.Scope().Lookup(name)
		switch object := object.(type) {
		case *types.Const:
			names = append(names, "const "+name)
		case *types.Var:
			names = append(names, "var "+name)
		case *types.Func:
			names = append(names, "func "+name)
		case *types.TypeName:
			names = append(names, "type "+name)
			typ := types.Unalias(object.Type())
			if structure, ok := typ.Underlying().(*types.Struct); ok {
				for i := 0; i < structure.NumFields(); i++ {
					field := structure.Field(i)
					if field.Exported() {
						names = append(names, "field "+name+"."+field.Name())
					}
				}
			}
			methods := types.NewMethodSet(types.NewPointer(typ))
			if _, ok := typ.Underlying().(*types.Interface); ok {
				methods = types.NewMethodSet(typ)
			}
			for i := 0; i < methods.Len(); i++ {
				method := methods.At(i).Obj()
				if method.Exported() {
					names = append(names, "method "+name+"."+method.Name())
				}
			}
		}
	}
	sort.Strings(names)
	got := strings.Join(names, "\n") + "\n"
	want, err := os.ReadFile("api.txt")
	if err != nil {
		t.Fatalf("read reviewed API inventory: %v\nactual API:\n%s", err, got)
	}
	if string(want) != got {
		t.Fatalf("public API differs from api.txt; review the change and update the inventory explicitly\nactual API:\n%s", got)
	}
}
