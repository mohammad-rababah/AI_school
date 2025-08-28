package repo

// ChanResult is a generic channel result type for passing data or error
// Data holds the result, Error holds any error (including descriptive DB errors)
type ChanResult[T any] struct {
	Data  T
	Error error
}
