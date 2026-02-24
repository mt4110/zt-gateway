package main

import (
	"encoding/json"
	"os"
)

func emitDoctorJSON(v doctorResult) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
