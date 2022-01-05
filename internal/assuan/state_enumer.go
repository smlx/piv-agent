// Code generated by "enumer -type=State -text -transform upper"; DO NOT EDIT.

package assuan

import (
	"fmt"
	"strings"
)

const _StateName = "INVALIDSTATEREADYCONNECTEDSIGNINGKEYISSETHASHISSETDECRYPTINGKEYISSETWAITINGFORCIPHERTEXT"

var _StateIndex = [...]uint8{0, 12, 17, 26, 41, 50, 68, 88}

const _StateLowerName = "invalidstatereadyconnectedsigningkeyissethashissetdecryptingkeyissetwaitingforciphertext"

func (i State) String() string {
	if i < 0 || i >= State(len(_StateIndex)-1) {
		return fmt.Sprintf("State(%d)", i)
	}
	return _StateName[_StateIndex[i]:_StateIndex[i+1]]
}

// An "invalid array index" compiler error signifies that the constant values have changed.
// Re-run the stringer command to generate them again.
func _StateNoOp() {
	var x [1]struct{}
	_ = x[invalidState-(0)]
	_ = x[ready-(1)]
	_ = x[connected-(2)]
	_ = x[signingKeyIsSet-(3)]
	_ = x[hashIsSet-(4)]
	_ = x[decryptingKeyIsSet-(5)]
	_ = x[waitingForCiphertext-(6)]
}

var _StateValues = []State{invalidState, ready, connected, signingKeyIsSet, hashIsSet, decryptingKeyIsSet, waitingForCiphertext}

var _StateNameToValueMap = map[string]State{
	_StateName[0:12]:       invalidState,
	_StateLowerName[0:12]:  invalidState,
	_StateName[12:17]:      ready,
	_StateLowerName[12:17]: ready,
	_StateName[17:26]:      connected,
	_StateLowerName[17:26]: connected,
	_StateName[26:41]:      signingKeyIsSet,
	_StateLowerName[26:41]: signingKeyIsSet,
	_StateName[41:50]:      hashIsSet,
	_StateLowerName[41:50]: hashIsSet,
	_StateName[50:68]:      decryptingKeyIsSet,
	_StateLowerName[50:68]: decryptingKeyIsSet,
	_StateName[68:88]:      waitingForCiphertext,
	_StateLowerName[68:88]: waitingForCiphertext,
}

var _StateNames = []string{
	_StateName[0:12],
	_StateName[12:17],
	_StateName[17:26],
	_StateName[26:41],
	_StateName[41:50],
	_StateName[50:68],
	_StateName[68:88],
}

// StateString retrieves an enum value from the enum constants string name.
// Throws an error if the param is not part of the enum.
func StateString(s string) (State, error) {
	if val, ok := _StateNameToValueMap[s]; ok {
		return val, nil
	}

	if val, ok := _StateNameToValueMap[strings.ToLower(s)]; ok {
		return val, nil
	}
	return 0, fmt.Errorf("%s does not belong to State values", s)
}

// StateValues returns all values of the enum
func StateValues() []State {
	return _StateValues
}

// StateStrings returns a slice of all String values of the enum
func StateStrings() []string {
	strs := make([]string, len(_StateNames))
	copy(strs, _StateNames)
	return strs
}

// IsAState returns "true" if the value is listed in the enum definition. "false" otherwise
func (i State) IsAState() bool {
	for _, v := range _StateValues {
		if i == v {
			return true
		}
	}
	return false
}

// MarshalText implements the encoding.TextMarshaler interface for State
func (i State) MarshalText() ([]byte, error) {
	return []byte(i.String()), nil
}

// UnmarshalText implements the encoding.TextUnmarshaler interface for State
func (i *State) UnmarshalText(text []byte) error {
	var err error
	*i, err = StateString(string(text))
	return err
}