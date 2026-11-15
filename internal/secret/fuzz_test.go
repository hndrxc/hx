package secret

import (
	"bytes"
	"testing"
)

func FuzzRedactionIndependence(f *testing.F) {
	f.Add([]byte("a"))
	f.Add([]byte("R"))
	f.Add([]byte("[REDACTED]"))
	f.Add([]byte("\x00\xff"))
	f.Add(bytes.Repeat([]byte("A"), 1024))

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) == 0 || len(input) > MaxSize {
			return
		}

		// Make a copy since FromBytes zeroes its input slice.
		inputCopy := make([]byte, len(input))
		copy(inputCopy, input)

		vInput, err := FromBytes(inputCopy)
		if err != nil {
			t.Fatalf("FromBytes(input) failed: %v", err)
		}
		defer vInput.Destroy()

		refBytes := []byte("reference")
		vRef, err := FromBytes(refBytes)
		if err != nil {
			t.Fatalf("FromBytes(reference) failed: %v", err)
		}
		defer vRef.Destroy()

		containersInput := buildContainers(vInput)
		containersRef := buildContainers(vRef)
		encoders := getGeneralEncoders()

		for i := range containersInput {
			cIn := containersInput[i]
			cRef := containersRef[i]

			for _, enc := range encoders {
				outIn, errIn := enc.fn(cIn.val)
				outRef, errRef := enc.fn(cRef.val)
				if (errIn != nil) != (errRef != nil) {
					t.Fatalf("encoder %s error mismatch: input err %v, ref err %v", enc.name, errIn, errRef)
				}
				if outIn != outRef {
					t.Fatalf("encoder %s container %s output mismatch:\ninput: %q\nref:   %q", enc.name, cIn.name, outIn, outRef)
				}
			}
		}

		// xml.Marshal of struct{Token *Value} (StructPtr)
		xmlIn, errIn := encodeXML(vInput)
		xmlRef, errRef := encodeXML(vRef)
		if (errIn != nil) != (errRef != nil) {
			t.Fatalf("encodeXML error mismatch: input err %v, ref err %v", errIn, errRef)
		}
		if xmlIn != xmlRef {
			t.Fatalf("encodeXML output mismatch:\ninput: %q\nref:   %q", xmlIn, xmlRef)
		}
	})
}
