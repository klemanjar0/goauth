package failure

import (
	"fmt"
)

type Failure struct {
	Code    int
	Message string
}

func (e *Failure) Error() string {
	return fmt.Sprintf("[%04x] %s", e.Code, e.Message)
}

func (e *Failure) Get() (int, string) {
	return e.Code, e.Message
}
