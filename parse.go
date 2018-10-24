package toml

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type parser struct {
	mapping table
	lx      *lexer

	// A list of keys in the order that they appear in the TOML data.
	ordered []Key

	// the full key for the current hash in scope
	context Key

	// the base key name for everything except hashes
	currentKey string

	// rough approximation of line number
	approxLine int
}

type parseError string

func (pe parseError) Error() string {
	return string(pe)
}

func parse(data string) (p *parser, err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			if err, ok = r.(parseError); ok {
				return
			}
			panic(r)
		}
	}()

	p = &parser{
		lx:      lex(data),
		ordered: make([]Key, 0),
	}
	for {
		item := p.next()
		if item.typ == itemEOF {
			break
		}
		p.topLevel(item)
	}

	return p, nil
}

func (p *parser) panicf(format string, v ...interface{}) {
	msg := fmt.Sprintf("Near line %d (last key parsed '%s'): %s",
		p.approxLine, p.current(), fmt.Sprintf(format, v...))
	panic(parseError(msg))
}

// returns the next non-comment item
func (p *parser) next() item {
	for {
		it := p.lx.nextItem()
		switch it.typ {
		case itemError:
			p.panicf("%s", it.val)
		case itemComment:
			// skip
		default:
			return it
		}
	}

}

func (p *parser) bug(format string, v ...interface{}) {
	panic(fmt.Sprintf("BUG: "+format+"\n\n", v...))
}

func (p *parser) expect(typ itemType) item {
	it := p.next()
	p.assertEqual(typ, it.typ)
	return it
}

func (p *parser) assertEqual(expected, got itemType) {
	if expected != got {
		p.bug("Expected '%s' but got '%s'.", expected, got)
	}
}

func (p *parser) topLevel(item item) {
	switch item.typ {
	case itemTableStart:
		kg := p.next()
		p.approxLine = kg.line

		var key Key
		for ; kg.typ != itemTableEnd && kg.typ != itemEOF; kg = p.next() {
			key = append(key, p.keyString(kg))
		}
		p.assertEqual(itemTableEnd, kg.typ)

		p.establishContext(key, false)
		p.ordered = append(p.ordered, key)
	case itemArrayTableStart:
		kg := p.next()
		p.approxLine = kg.line

		var key Key
		for ; kg.typ != itemArrayTableEnd && kg.typ != itemEOF; kg = p.next() {
			key = append(key, p.keyString(kg))
		}
		p.assertEqual(itemArrayTableEnd, kg.typ)

		p.establishContext(key, true)
		p.ordered = append(p.ordered, key)
	case itemKeyStart:
		kname := p.next()
		p.approxLine = kname.line
		p.currentKey = p.keyString(kname)

		val := p.value(p.next())
		p.addEntry(p.currentKey, val)
		p.ordered = append(p.ordered, p.context.add(p.currentKey))
	default:
		p.bug("Unexpected type at top level: %s", item.typ)
	}
}

// Gets a string for a key (or part of a key in a table name).
func (p *parser) keyString(it item) string {
	switch it.typ {
	case itemText:
		return it.val
	case itemString:
		return p.replaceEscapes(it.val)
	case itemMultilineString:
		trimmed := stripFirstNewline(stripEscapedWhitespace(it.val))
		return p.replaceEscapes(trimmed)
	case itemRawString:
		return it.val
	case itemRawMultilineString:
		return stripFirstNewline(it.val)
	default:
		p.bug("Unexpected key type: %s", it.typ)
		panic("unreachable")
	}
}

// value translates an expected value from the lexer into a Go value wrapped
// as an empty interface.
func (p *parser) value(it item) *entry {
	scalarEntry := func(scalar interface{}, typ tomlType) *entry {
		return &entry{kind: entryScalar, scalar: scalar, typ: typ}
	}
	switch it.typ {
	case itemString:
		return scalarEntry(p.replaceEscapes(it.val), p.typeOfPrimitive(it))
	case itemMultilineString:
		trimmed := stripFirstNewline(stripEscapedWhitespace(it.val))
		return scalarEntry(p.replaceEscapes(trimmed), p.typeOfPrimitive(it))
	case itemRawString:
		return scalarEntry(it.val, p.typeOfPrimitive(it))
	case itemRawMultilineString:
		return scalarEntry(stripFirstNewline(it.val), p.typeOfPrimitive(it))
	case itemBool:
		switch it.val {
		case "true":
			return scalarEntry(true, p.typeOfPrimitive(it))
		case "false":
			return scalarEntry(false, p.typeOfPrimitive(it))
		}
		p.bug("Expected boolean value, but got '%s'.", it.val)
	case itemInteger:
		if !numUnderscoresOK(it.val) {
			p.panicf("Invalid integer %q: underscores must be surrounded by digits",
				it.val)
		}
		if !leadingZeroOK(it.val) {
			p.panicf("Invalid integer %q: leading zeros are not allowed", it.val)
		}
		val := strings.Replace(it.val, "_", "", -1)
		num, err := strconv.ParseInt(val, 10, 64)
		p.manageStrconvErr(err, it)
		return scalarEntry(num, p.typeOfPrimitive(it))
	case itemIntegerWithBase:
		if len(it.val) < 3 {
			p.panicf("Invalid integer %q: too short", it.val)
		}
		if !numUnderscoresOK(it.val[2:]) {
			p.panicf("Invalid integer %q: underscores must be surrounded by digits", it.val)
		}
		val := strings.Replace(it.val[2:], "_", "", -1)
		var num int64
		var err error
		switch it.val[1] {
		case 'x':
			num, err = strconv.ParseInt(val, 16, 64)
		case 'o':
			num, err = strconv.ParseInt(val, 8, 64)
		case 'b':
			num, err = strconv.ParseInt(val, 2, 64)
		}
		p.manageStrconvErr(err, it)
		return scalarEntry(num, p.typeOfPrimitive(it))
	case itemFloat:
		parts := strings.FieldsFunc(it.val, func(r rune) bool {
			switch r {
			case '.', 'e', 'E':
				return true
			}
			return false
		})
		for _, part := range parts {
			if !numUnderscoresOK(part) {
				p.panicf("Invalid float %q: underscores must be "+
					"surrounded by digits", it.val)
			}
		}
		if len(parts) > 0 && !leadingZeroOK(parts[0]) {
			p.panicf("Invalid float %q: leading zeros are not allowed", it.val)
		}
		if !numPeriodsOK(it.val) {
			// As a special case, numbers like '123.' or '1.e2',
			// which are valid as far as Go/strconv are concerned,
			// must be rejected because TOML says that a fractional
			// part consists of '.' followed by 1+ digits.
			p.panicf("Invalid float %q: '.' must be followed "+
				"by one or more digits", it.val)
		}
		val := strings.Replace(it.val, "_", "", -1)
		switch val {
		case "+nan", "-nan":
			val = "nan"
		}
		num, err := strconv.ParseFloat(val, 64)
		if err != nil {
			if e, ok := err.(*strconv.NumError); ok &&
				e.Err == strconv.ErrRange {

				p.panicf("Float '%s' is out of the range of 64-bit "+
					"IEEE-754 floating-point numbers.", it.val)
			} else {
				p.panicf("Invalid float value: %q", it.val)
			}
		}
		return scalarEntry(num, p.typeOfPrimitive(it))
	case itemDatetime:
		var t time.Time
		var ok bool
		var err error
		for _, format := range []string{
			"2006-01-02T15:04:05Z07:00",
			"2006-01-02 15:04:05Z07:00",
			"2006-01-02T15:04:05",
			"2006-01-02 15:04:05",
			"2006-01-02",
		} {
			t, err = time.ParseInLocation(format, it.val, time.Local)
			if err == nil {
				ok = true
				break
			}
		}
		if !ok {
			p.panicf("Invalid TOML Datetime: %q.", it.val)
		}
		return scalarEntry(t, p.typeOfPrimitive(it))
	case itemTime:
		if !timeOK(it.val) {
			p.panicf("Invalid time value: %q", it.val)
		}
		return scalarEntry(it.val, p.typeOfPrimitive(it))
	case itemArray:
		array := make([]entry, 0) //TODO: change this!
		types := make([]tomlType, 0)

		for it = p.next(); it.typ != itemArrayEnd; it = p.next() {
			val := p.value(it)
			array = append(array, *val)
			types = append(types, val.typ)
		}
		return &entry{kind: entryArray, array: array, typ: p.typeOfArray(types)}
	case itemInlineTableStart:
		var (
			hash         = make([]entry, 0) //TODO: change this!
			outerContext = p.context
			outerKey     = p.currentKey
		)

		p.context = append(p.context, p.currentKey)
		p.currentKey = ""
		for it := p.next(); it.typ != itemInlineTableEnd; it = p.next() {
			if it.typ != itemKeyStart {
				p.bug("Expected key start but instead found %q, around line %d",
					it.val, p.approxLine)
			}

			// retrieve key
			k := p.next()
			p.approxLine = k.line
			kname := p.keyString(k)

			// retrieve value
			p.currentKey = kname
			val := p.value(p.next())
			val.name = kname
			p.ordered = append(p.ordered, p.context.add(p.currentKey))
			hash = append(hash, *val)
		}
		p.context = outerContext
		p.currentKey = outerKey
		return &entry{kind: entryTable, table: &table{hash}, typ: tomlHash}
	}
	p.bug("Unexpected value type: %s", it.typ)
	panic("unreachable")
}

func (p *parser) manageStrconvErr(err error, it item) {
	if err != nil {
		// Distinguish integer values. Normally, it'd be a bug if the lexer
		// provides an invalid integer, but it's possible that the number is
		// out of range of valid values (which the lexer cannot determine).
		// So mark the former as a bug but the latter as a legitimate user
		// error.
		if e, ok := err.(*strconv.NumError); ok &&
			e.Err == strconv.ErrRange {

			p.panicf("Integer '%s' is out of the range of 64-bit "+
				"signed integers.", it.val)
		} else {
			p.bug("Expected integer value, but got '%s'.", it.val)
		}
	}
}

// numUnderscoresOK checks whether each underscore in s is surrounded by
// characters that are not underscores.
func numUnderscoresOK(s string) bool {
	accept := false
	for _, r := range s {
		if r == '_' {
			if !accept {
				return false
			}
			accept = false
			continue
		}
		accept = true
	}
	return accept
}

// numPeriodsOK checks whether every period in s is followed by a digit.
func numPeriodsOK(s string) bool {
	period := false
	for _, r := range s {
		if period && !isDigit(r) {
			return false
		}
		period = r == '.'
	}
	return !period
}

// Returns true if s does not contain leading zeroes, which are disallowed by toml specification
func leadingZeroOK(s string) bool {
	if len(s) == 0 {
		// how could this be?
		return true
	}
	if (s[0] == '+') || (s[0] == '-') {
		if len(s) == 1 {
			return true
		}
		s = s[1:]
	}
	if len(s) < 2 {
		// signed zero is acceptable
		return true
	}
	return s[0] != '0'
}

// Returns true if s is a valid time string.
func timeOK(s string) bool {
	fields := strings.Split(s, ":")
	if len(fields) != 3 {
		return false
	}
	isnum := func(s string, n int) bool {
		if len(s) != n {
			return false
		}
		for j := range s {
			if !isDigit(rune(s[j])) {
				return false
			}
		}
		return true
	}
	for i := 0; i < 2; i++ {
		if !isnum(fields[i], 2) {
			return false
		}
	}
	if dot := strings.Index(fields[2], "."); dot >= 0 {
		if !isnum(fields[2][:dot], 2) || !isnum(fields[2][dot+1:], 6) {
			return false
		}
	} else {
		if !isnum(fields[2], 2) {
			return false
		}
	}
	return true
}

// establishContext sets the current context of the parser,
// where the context is either a hash or an array of hashes. Which one is
// set depends on the value of the `array` parameter.
//
// Establishing the context also makes sure that the key isn't a duplicate, and
// will create implicit hashes automatically.
func (p *parser) establishContext(key Key, array bool) {
	// Always start at the top level and drill down for our context.
	hashContext := &p.mapping
	keyContext := make(Key, 0)

	// We only need implicit hashes for key[0:-1]
	for _, k := range key[0 : len(key)-1] {
		e := hashContext.getEntry(k)
		keyContext = append(keyContext, k)

		// No key? Make an implicit hash and move on.
		if e == nil {
			e = hashContext.newEntry(k, entryTable)
			e.table = &table{}
			e.implicit = true
		}

		// If the hash context is actually an array of tables, then set
		// the hash context to the last element in that array.
		//
		// Otherwise, it better be a table, since this MUST be a key group (by
		// virtue of it not being the last element in a key).
		switch e.kind {
		case entryArray:
			e = &e.array[len(e.array)-1]
			if e.kind != entryTable {
				p.panicf("Key '%s' is not an array of tables", keyContext)
			}
			hashContext = e.table
		case entryTable:
			hashContext = e.table
		default:
			p.panicf("Key '%s' was already created as a scalar", keyContext)
		}
	}

	p.context = keyContext
	if array {
		// If this is the first element for this array, then allocate a new
		// list of tables for it.
		k := key[len(key)-1]
		e := hashContext.getEntry(k)
		if e == nil {
			e = hashContext.newEntry(k, entryArray)
			e.typ = tomlArrayHash
			e.array = make([]entry, 0, 5)
		}

		// Add a new table. But make sure the key hasn't already been used
		// for something else.
		if e.kind == entryArray && ((len(e.array) == 0) || (e.array[len(e.array)-1].kind == entryTable)) {
			e.array = append(e.array, entry{kind: entryTable, table: &table{}})
		} else {
			p.panicf("Key '%s' was already created and cannot be used as an array", keyContext)
		}
	} else {
		p.addEntry(key[len(key)-1], &entry{kind: entryTable, table: &table{}, typ: tomlHash})
	}
	p.context = append(p.context, key[len(key)-1])
}

// addEntry sets the given key to the given value in the current context.
// It will make sure that the key hasn't already been defined, account for
// implicit key groups.
func (p *parser) addEntry(key string, entry *entry) {
	hash := &p.mapping
	keyContext := make(Key, 0)
	for _, k := range p.context {
		keyContext = append(keyContext, k)
		e := hash.getEntry(k)
		if e == nil {
			p.bug("Context for key '%s' has not been established", keyContext)
		}
		switch e.kind {
		case entryArray:
			// The context is a table of hashes. Pick the most recent table
			// defined as the current hash.
			if len(e.array) == 0 || e.array[len(e.array)-1].kind != entryTable {
				p.panicf("Key '%s' is not an array of tables", keyContext)
			}
			hash = e.array[len(e.array)-1].table
		case entryTable:
			hash = e.table
		default:
			p.bug("Key '%s' is not a table or array of tables", keyContext)
		}
	}
	keyContext = append(keyContext, key)

	e := hash.getEntry(key)
	if e != nil {
		if entry.kind != entryTable {
			p.panicf("Key '%s' has already been defined as a table", keyContext)
		}
		// Typically, if the given key has already been set, then we have
		// to raise an error since duplicate keys are disallowed. However,
		// it's possible that a key was previously defined implicitly. In this
		// case, it is allowed to be redefined concretely. (See the
		// `tests/valid/implicit-and-explicit-after.toml` test in `toml-test`.)
		//
		// But we have to make sure to stop marking it as an implicit. (So that
		// another redefinition provokes an error.)
		//
		// Note that since it has already been defined (as a hash), we don't
		// want to overwrite it. So our business is done.
		if e.implicit {
			e.implicit = false
			return
		}

		// Otherwise, we have a concrete key trying to override a previous
		// key, which is *always* wrong.
		p.panicf("Key '%s' has already been defined", keyContext)
	}
	e = hash.newEntry(key, entry.kind)
	*e = *entry
	e.name = key
}

// current returns the full key name of the current context.
func (p *parser) current() string {
	if len(p.currentKey) == 0 {
		return p.context.String()
	}
	if len(p.context) == 0 {
		return p.currentKey
	}
	return fmt.Sprintf("%s.%s", p.context, p.currentKey)
}

func stripFirstNewline(s string) string {
	if len(s) == 0 || s[0] != '\n' {
		return s
	}
	return s[1:]
}

var escapedWhitespaceRegex = regexp.MustCompile(`\\[ \t]*\n`)

func stripEscapedWhitespace(s string) string {
	//TODO: this should really be part of the lexer, not hacked in here
	esc := escapedWhitespaceRegex.Split(s, -1)
	if len(esc) > 1 {
		for i := 1; i < len(esc); i++ {
			esc[i] = strings.TrimLeftFunc(esc[i], unicode.IsSpace)
		}
	}
	return strings.Join(esc, "")
}

func (p *parser) replaceEscapes(str string) string {
	var replaced []rune
	s := []byte(str)
	r := 0
	for r < len(s) {
		if s[r] != '\\' {
			c, size := utf8.DecodeRune(s[r:])
			r += size
			replaced = append(replaced, c)
			continue
		}
		r += 1
		if r >= len(s) {
			p.bug("Escape sequence at end of string.")
			return ""
		}
		switch s[r] {
		default:
			p.bug("Expected valid escape code after \\, but got %q.", s[r])
			return ""
		case 'b':
			replaced = append(replaced, rune(0x0008))
			r += 1
		case 't':
			replaced = append(replaced, rune(0x0009))
			r += 1
		case 'n':
			replaced = append(replaced, rune(0x000A))
			r += 1
		case 'f':
			replaced = append(replaced, rune(0x000C))
			r += 1
		case 'r':
			replaced = append(replaced, rune(0x000D))
			r += 1
		case '"':
			replaced = append(replaced, rune(0x0022))
			r += 1
		case '\\':
			replaced = append(replaced, rune(0x005C))
			r += 1
		case 'u':
			// At this point, we know we have a Unicode escape of the form
			// `uXXXX` at [r, r+5). (Because the lexer guarantees this
			// for us.)
			escaped := p.asciiEscapeToUnicode(s[r+1 : r+5])
			replaced = append(replaced, escaped)
			r += 5
		case 'U':
			// At this point, we know we have a Unicode escape of the form
			// `uXXXX` at [r, r+9). (Because the lexer guarantees this
			// for us.)
			escaped := p.asciiEscapeToUnicode(s[r+1 : r+9])
			replaced = append(replaced, escaped)
			r += 9
		}
	}
	return string(replaced)
}

func (p *parser) asciiEscapeToUnicode(bs []byte) rune {
	s := string(bs)
	hex, err := strconv.ParseUint(strings.ToLower(s), 16, 32)
	if err != nil {
		p.bug("Could not parse '%s' as a hexadecimal number, but the "+
			"lexer claims it's OK: %s", s, err)
	}
	if !utf8.ValidRune(rune(hex)) {
		p.panicf("Escaped character '\\u%s' is not valid UTF-8.", s)
	}
	return rune(hex)
}

func isStringType(ty itemType) bool {
	return ty == itemString || ty == itemMultilineString ||
		ty == itemRawString || ty == itemRawMultilineString
}
