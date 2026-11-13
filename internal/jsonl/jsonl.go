package jsonl

import (
	"encoding/json"
	"os"
)

// AppendJSONL appends v to path as one JSON line, creating the file if needed.
// JSONL ledgers in the workdir (evidence manifest, planner graph, canary ledger,
// watch drift, OAST interactions) all persist through this one writer.
func AppendJSONL(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// JSONUnmarshalLine decodes one JSON line into v, reporting success.
func JSONUnmarshalLine(line string, v any) bool { return json.Unmarshal([]byte(line), v) == nil }
