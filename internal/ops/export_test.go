package ops

// PlainRefusal and Retitled let the external tests (package ops_test) run Recheck's wording on a refusal that the real
// merge adapter produced.
func PlainRefusal(r *Refusal) string { return plainRefusal(r) }

func Retitled(r *Refusal) bool { return retitled(r) }
