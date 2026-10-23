package ccj_test

import (
	"errors"
	"fmt"
	"github.com/relux-works/swarma-registrar/ccj"
)

// Fixed JSON fixtures demonstrate canonicalization and typed duplicate rejection.
func ExampleParse() {
	value, err := ccj.Parse([]byte(` {"z":2,"a":[true,1]} `), ccj.EnrollmentMalformed)
	if err != nil {
		panic(err)
	}
	canonical, err := ccj.Marshal(value, ccj.EnrollmentMalformed)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(canonical))
	_, err = ccj.Parse([]byte(`{"a":1,"a":2}`), ccj.EnrollmentMalformed)
	var refusal *ccj.Error
	if errors.As(err, &refusal) {
		fmt.Println(refusal.Code)
	}
	// Output:
	// {"a":[true,1],"z":2}
	// enrollment_malformed
}
