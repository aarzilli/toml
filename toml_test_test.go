package toml

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type testCase struct {
	name    string
	in, tgt string
}

func slurp(t *testing.T, path string) string {
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatalf("error reading file %s: %v", path, err)
	}
	return string(buf)
}

func readTestDirectory(t *testing.T, path string, inext, tgtext string) []testCase {
	fh, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	fis, err := fh.Readdir(-1)
	if err != nil {
		t.Fatal(err)
	}
	r := []testCase{}
	for _, fi := range fis {
		if filepath.Ext(fi.Name()) != inext {
			continue
		}
		cleanname := strings.Replace(fi.Name(), inext, "", -1)
		tc := testCase{
			name: cleanname,
			in:   slurp(t, filepath.Join(path, fi.Name())),
		}
		if tgtext != "" {
			tgtname := strings.Replace(fi.Name(), inext, tgtext, -1)
			_, err := os.Stat(filepath.Join(path, tgtname))
			if err != nil && tgtext == ".toml2" {
				tc.tgt = tc.in
			} else {
				tc.tgt = slurp(t, filepath.Join(path, tgtname))
			}
		}
		r = append(r, tc)
	}
	return r
}

func TestDecoderValid(t *testing.T) {
	for _, testCase := range readTestDirectory(t, "_tests/valid", ".toml", ".json") {
		t.Run(testCase.name, func(t *testing.T) {
			testDecoder(t, testCase, true)
		})
	}
}

func TestDecoderInvalid(t *testing.T) {
	for _, testCase := range readTestDirectory(t, "_tests/invalid", ".toml", "") {
		t.Run(testCase.name, func(t *testing.T) {
			testDecoder(t, testCase, false)
		})
	}
}

func TestEncoderValid(t *testing.T) {
	testCases := readTestDirectory(t, "_tests/valid", ".toml", ".toml2")
	for i, testCase := range testCases {
		stop := false
		t.Run(testCase.name, func(t *testing.T) {
			testEncoder(t, testCase)
			if t.Failed() {
				stop = true
			}
		})
		if stop {
			t.Logf("executed %d/%d", i, len(testCases))
			break
		}
	}
}

func TestEncoderInvalid(t *testing.T) {
	t.Skip("these tests don't work") // XXX fix this
	for _, testCase := range readTestDirectory(t, "_tests/invalid-encoder", ".json", "") {
		t.Run(testCase.name, func(t *testing.T) {
			testEncoderJSON(t, testCase, false)
		})
	}
}

func testDecoder(t *testing.T, testCase testCase, valid bool) {
	var tmp interface{}
	_, err := Decode(testCase.in, &tmp)
	if valid {
		if err != nil {
			t.Errorf("error: %v", err)
			return
		}
	} else {
		if err == nil {
			t.Errorf("expected error, got no errors")
		} else {
			t.Logf("error: %v", err)
		}
		return
	}
	typedTmp := translateDecode(tmp)

	var tgtv interface{}
	err = json.NewDecoder(strings.NewReader(testCase.tgt)).Decode(&tgtv)
	if err != nil {
		t.Fatal(err)
	}

	r := result{valid: true}
	r = r.cmpJson(tgtv, typedTmp)
	if r.failed() {
		t.Fatal(r.String())
	}
}

func translateDecode(tomlData interface{}) interface{} {
	switch orig := tomlData.(type) {
	case map[string]interface{}:
		typed := make(map[string]interface{}, len(orig))
		for k, v := range orig {
			typed[k] = translateDecode(v)
		}
		return typed
	case []map[string]interface{}:
		typed := make([]map[string]interface{}, len(orig))
		for i, v := range orig {
			typed[i] = translateDecode(v).(map[string]interface{})
		}
		return typed
	case []interface{}:
		typed := make([]interface{}, len(orig))
		for i, v := range orig {
			typed[i] = translateDecode(v)
		}

		// We don't really need to tag arrays, but let's be future proof.
		// (If TOML ever supports tuples, we'll need this.)
		return tag("array", typed)
	case time.Time:
		return tag("datetime", orig.Format(time.RFC3339Nano))
	case bool:
		return tag("bool", fmt.Sprintf("%v", orig))
	case int64:
		return tag("integer", fmt.Sprintf("%d", orig))
	case float64:
		return tag("float", fmt.Sprintf("%v", orig))
	case string:
		return tag("string", orig)
	}

	panic(fmt.Sprintf("Unknown type: %T", tomlData))
}

func tag(typeName string, data interface{}) map[string]interface{} {
	return map[string]interface{}{
		"type":  typeName,
		"value": data,
	}
}

func testEncoderJSON(t *testing.T, testCase testCase, valid bool) {
	defer func() {
		ierr := recover()
		if ierr == nil {
			return
		}
		t.Errorf("encoder error: %v", ierr)
	}()
	var tmp interface{}
	if err := json.NewDecoder(strings.NewReader(testCase.in)).Decode(&tmp); err != nil {
		t.Fatal(err)
	}

	tomlData := translateEncode(tmp)
	var buf bytes.Buffer
	err := NewEncoder(&buf).Encode(tomlData)
	if valid {
		if err != nil {
			t.Error(err)
			return
		}
	} else {
		if err == nil {
			t.Errorf("expected an error, got nothing")
		} else {
			t.Logf("expected encode error: %v", err)
		}
		return
	}

	if out := buf.String(); out != testCase.tgt {
		t.Errorf("output mismatch\noutput:\t%q\ntarget\t%q", out, testCase.tgt)
	}
}

func testEncoder(t *testing.T, testCase testCase) {
	defer func() {
		ierr := recover()
		if ierr == nil {
			return
		}
		t.Errorf("encoder error: %v", ierr)
	}()

	var tmp interface{}
	md, err := Decode(testCase.in, &tmp)
	if err != nil {
		t.Errorf("error: %v", err)
		return
	}

	var buf bytes.Buffer
	err = NewEncoder(&buf).EncodeWithMetadata(&md, tmp)
	if err != nil {
		t.Error(err)
	}

	if out := buf.String(); out != testCase.tgt {
		diff := doDiff(out, testCase.tgt)
		t.Errorf("output mismatch\n===== OUTPUT =====\n%s\n===== TARGET =====\n%s\n==== DIFF ====\n%s", out, testCase.tgt, diff)

	}
}

type result struct {
	testName string
	err      error
	valid    bool
	failure  string
	key      string
}

func (r result) failed() bool {
	return r.err != nil || len(r.failure) > 0
}

func (r result) errorf(format string, v ...interface{}) result {
	r.err = fmt.Errorf(format, v...)
	return r
}

func (r result) failedf(format string, v ...interface{}) result {
	r.failure = fmt.Sprintf(format, v...)
	return r
}

func (r result) mismatch(expected string, got interface{}) result {
	return r.failedf("Type mismatch for key '%s'. Expected %s but got %T.",
		r.key, expected, got)
}

func (r result) valMismatch(expected string, got string) result {
	return r.failedf("Type mismatch for key '%s'. Expected %s but got %s.",
		r.key, expected, got)
}

func (r result) kjoin(key string) result {
	if len(r.key) == 0 {
		r.key = key
	} else {
		r.key += "." + key
	}
	return r
}

func (r result) String() string {
	buf := new(bytes.Buffer)
	p := func(s string, v ...interface{}) { fmt.Fprintf(buf, s, v...) }

	validStr := "invalid"
	if r.valid {
		validStr = "valid"
	}
	p("Test: %s (%s)\n\n", r.testName, validStr)

	if r.err != nil {
		p("Error running test: %s", r.err)
		return buf.String()
	}
	if len(r.failure) > 0 {
		p(r.failure)
		return buf.String()
	}

	p("PASSED.")
	return buf.String()
}

// compareJson consumes the recursive structure of both `expected` and `test`
// simultaneously. If anything is unequal, the result has failed and
// comparison stops.
//
// N.B. `reflect.DeepEqual` could work here, but it won't tell us how the
// two structures are different.
func (r result) cmpJson(expected, test interface{}) result {
	switch e := expected.(type) {
	case map[string]interface{}:
		return r.cmpJsonMaps(e, test)
	case []interface{}:
		return r.cmpJsonArrays(e, test)
	default:
		return r.failedf("Key '%s' in expected output should be a map or a "+
			"list of maps, but it's a %T.", r.key, expected)
	}
	panic("unreachable")
}

func (r result) cmpJsonMaps(e map[string]interface{}, test interface{}) result {

	t, ok := test.(map[string]interface{})
	if !ok {
		return r.mismatch("table", t)
	}

	// Check to make sure both or neither are values.
	if isValue(e) && !isValue(t) {
		return r.failedf("Key '%s' is supposed to be a value, but the "+
			"parser reports it as a table.", r.key)
	}
	if !isValue(e) && isValue(t) {
		return r.failedf("Key '%s' is supposed to be a table, but the "+
			"parser reports it as a value.", r.key)
	}
	if isValue(e) && isValue(t) {
		return r.cmpJsonValues(e, t)
	}

	// Check that the keys of each map are equivalent.
	for k, _ := range e {
		if _, ok := t[k]; !ok {
			bunk := r.kjoin(k)
			return bunk.failedf("Could not find key '%s' in parser output.",
				bunk.key)
		}
	}
	for k, _ := range t {
		if _, ok := e[k]; !ok {
			bunk := r.kjoin(k)
			return bunk.failedf("Could not find key '%s' in expected output.",
				bunk.key)
		}
	}

	// Okay, now make sure that each value is equivalent.
	for k, _ := range e {
		if sub := r.kjoin(k).cmpJson(e[k], t[k]); sub.failed() {
			return sub
		}
	}
	return r
}

func (r result) cmpJsonArrays(e, t interface{}) result {
	ea, ok := e.([]interface{})
	if !ok {
		return r.failedf("BUG in test case. 'value' should be a JSON array "+
			"when 'type' indicates 'array', but it is a %T.", e)
	}

	var ta []interface{}

	switch ta2 := t.(type) {
	case []interface{}:
		ta = ta2
	case []map[string]interface{}:
		ta = make([]interface{}, len(ta2))
		for i := range ta2 {
			ta[i] = ta2[i]
		}
	case map[string]interface{}:
		// tagged array?
		if typ, _ := ta2["type"].(string); typ != "array" {
			return r.failedf("Malformed parser output. 'value' should be a JSON array when 'type' indicates 'array', but it is a %T.", t)
		}

		ta = ta2["value"].([]interface{})
	default:
		return r.failedf("Malformed parser output. 'value' should be a JSON array when 'type' indicates 'array', but it is a %T.", t)
	}

	if len(ea) != len(ta) {
		return r.failedf("Array lengths differ for key '%s'. Expected a length of %d but got %d.", r.key, len(ea), len(ta))
	}
	for i := 0; i < len(ea); i++ {
		if sub := r.cmpJson(ea[i], ta[i]); sub.failed() {
			return sub
		}
	}
	return r
}

func (r result) cmpJsonValues(e, t map[string]interface{}) result {
	etype, ok := e["type"].(string)
	if !ok {
		return r.failedf("BUG in test case. 'type' should be a string, "+
			"but it is a %T.", e["type"])
	}

	ttype, ok := t["type"].(string)
	if !ok {
		return r.failedf("Malformed parser output. 'type' should be a "+
			"string, but it is a %T.", t["type"])
	}

	if etype != ttype {
		return r.valMismatch(etype, ttype)
	}

	// If this is an array, then we've got to do some work to check
	// equality.
	if etype == "array" {
		return r.cmpJsonArrays(e["value"], t["value"])
	} else {
		// Atomic values are always strings
		evalue, ok := e["value"].(string)
		if !ok {
			return r.failedf("BUG in test case. 'value' "+
				"should be a string, but it is a %T.",
				e["value"])
		}
		tvalue, ok := t["value"].(string)
		if !ok {
			return r.failedf("Malformed parser output. 'value' "+
				"should be a string but it is a %T.",
				t["value"])
		}

		// Excepting floats and datetimes, other values can be
		// compared as strings.
		switch etype {
		case "float":
			return r.cmpFloats(evalue, tvalue)
		case "datetime":
			return r.cmpAsDatetimes(evalue, tvalue)
		default:
			return r.cmpAsStrings(evalue, tvalue)
		}
	}
}

func (r result) cmpAsStrings(e, t string) result {
	if e != t {
		return r.failedf("Values for key '%s' don't match. Expected a "+
			"value of '%s' but got '%s'.", r.key, e, t)
	}
	return r
}

func (r result) cmpFloats(e, t string) result {
	ef, err := strconv.ParseFloat(e, 64)
	if err != nil {
		return r.failedf("BUG in test case. Could not read '%s' as a "+
			"float value for key '%s'.", e, r.key)
	}

	tf, err := strconv.ParseFloat(t, 64)
	if err != nil {
		return r.failedf("Malformed parser output. Could not read '%s' "+
			"as a float value for key '%s'.", t, r.key)
	}
	if math.IsNaN(ef) && math.IsNaN(tf) {
		return r
	}
	if ef != tf {
		return r.failedf("Values for key '%s' don't match. Expected a "+
			"value of '%v' but got '%v'.", r.key, ef, tf)
	}
	return r
}

func timeParse(e string) (time.Time, bool) {
	for _, fmt := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999", "2006-01-02"} {
		t, err := time.ParseInLocation(fmt, e, time.Local)
		if err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func (r result) cmpAsDatetimes(e, t string) result {
	ef, ok := timeParse(e)
	if !ok {
		return r.failedf("BUG in test case. Could not read '%s' as a datetime value for key '%s'.", e, r.key)
	}

	tf, ok := timeParse(t)
	if !ok {
		return r.failedf("Malformed parser output. Could not read '%s' as datetime value for key '%s'.", t, r.key)
	}
	if !ef.Equal(tf) {
		return r.failedf("Values for key '%s' don't match. Expected a value of '%v' but got '%v'.", r.key, ef, tf)
	}
	return r
}

func isValue(m map[string]interface{}) bool {
	if len(m) != 2 {
		return false
	}
	if _, ok := m["type"]; !ok {
		return false
	}
	if _, ok := m["value"]; !ok {
		return false
	}
	return true
}

func translateEncode(typedJson interface{}) interface{} {
	switch v := typedJson.(type) {
	case map[string]interface{}:
		if len(v) == 2 && in("type", v) && in("value", v) {
			return untag(v)
		}
		m := make(map[string]interface{}, len(v))
		for k, v2 := range v {
			m[k] = translateEncode(v2)
		}
		return m
	case []interface{}:
		tabArray := make([]map[string]interface{}, len(v))
		for i := range v {
			if m, ok := translateEncode(v[i]).(map[string]interface{}); ok {
				tabArray[i] = m
			} else {
				panic(fmt.Errorf("JSON arrays may only contain objects. This " +
					"corresponds to only tables being allowed in " +
					"TOML table arrays."))
			}
		}
		return tabArray
	}
	panic(fmt.Errorf("Unrecognized JSON format '%T'.", typedJson))
}

func untag(typed map[string]interface{}) interface{} {
	t := typed["type"].(string)
	v := typed["value"]
	switch t {
	case "string":
		return v.(string)
	case "integer":
		v := v.(string)
		n, err := strconv.Atoi(v)
		if err != nil {
			panic(fmt.Errorf("Could not parse '%s' as integer: %s", v, err))
		}
		return n
	case "float":
		v := v.(string)
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			panic(fmt.Errorf("Could not parse '%s' as float64: %s", v, err))
		}
		return f
	case "datetime":
		v := v.(string)
		t, err := time.Parse("2006-01-02T15:04:05Z", v)
		if err != nil {
			panic(fmt.Errorf("Could not parse '%s' as a datetime: %s", v, err))
		}
		return t
	case "bool":
		v := v.(string)
		switch v {
		case "true":
			return true
		case "false":
			return false
		}
		panic(fmt.Errorf("Could not parse '%s' as a boolean.", v))
	case "array":
		v := v.([]interface{})
		array := make([]interface{}, len(v))
		for i := range v {
			if m, ok := v[i].(map[string]interface{}); ok {
				array[i] = untag(m)
			} else {
				panic(fmt.Errorf("Arrays may only contain other arrays or "+
					"primitive values, but found a '%T'.", m))
			}
		}
		return array
	}
	panic(fmt.Errorf("Unrecognized tag type '%s'.", t))
	panic("unreachable")
}

func in(key string, m map[string]interface{}) bool {
	_, ok := m[key]
	return ok
}

func writetmp(a string) string {
	f1, err := ioutil.TempFile("", "toml_test_test_diff")
	if err != nil {
		panic(err)
	}
	name := f1.Name()
	if _, err := f1.Write([]byte(a)); err != nil {
		panic(err)
	}
	if err := f1.Close(); err != nil {
		panic(err)
	}
	return name
}

func doDiff(a, b string) string {
	name1 := writetmp(a)
	defer os.Remove(name1)

	name2 := writetmp(b)
	defer os.Remove(name2)

	cmd := exec.Command("/usr/bin/diff", name1, name2)
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		panic(err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Sprintf("could not diff: %v", err)
	}

	var buf bytes.Buffer
	io.Copy(&buf, out)
	cmd.Wait()

	return buf.String()
}
