package http

import (
	"encoding/json"
	"net/http"

	"github.com/loganrk/user-vault/internal/core/port"
)

// handler struct represents the handler for handling HTTP requests.
// It contains usecases (services), a logger for logging messages,
// and a token engine for JWT-related functionality.
type handler struct {
	usecases       port.SvrList // List of usecases (services) to handle business logic
	logger         port.Logger  // Logger instance for logging messages
	tokenEngineIns port.Token   // Token engine for handling JWT tokens
}

// New creates and returns a new handler instance with the provided logger, token engine, and service list.
func New(loggerIns port.Logger, tokenEngineIns port.Token, svcList port.SvrList) *handler {
	return &handler{
		usecases:       svcList,        // List of services that will handle specific business logic
		logger:         loggerIns,      // Logger for capturing logs
		tokenEngineIns: tokenEngineIns, // Token engine for managing tokens
	}
}

// response struct is used for formatting the response sent to the client.
// It includes the status code, success flag, error messages, and the response data.
type response struct {
	Status  int        `json:"status"`          // HTTP status code for the response
	Success bool       `json:"success"`         // A flag indicating if the operation was successful
	Err     []errorMsg `json:"error,omitempty"` // List of error messages (if any)
	Data    any        `json:"data,omitempty"`  // The data to be returned in the response (if any)
}

// errorMsg struct represents an individual error message with a code and description.
type errorMsg struct {
	Code string `json:"code,omitempty"` // Error code identifying the error
	Msg  string `json:"msg"`            // A human-readable error message
}

// SetError appends a new error message to the Err field in the response struct.
// It takes an error message string as input and creates an errorMsg struct to append.
func (r *response) SetError(errMsg string) {
	r.Err = append(r.Err, errorMsg{
		Msg: errMsg, // Sets the error message in the errorMsg struct
	})
}

// SetStatus sets the HTTP status code for the response.
// Takes an integer status code as input.
func (r *response) SetStatus(status int) {
	r.Status = status // Sets the status field of the response
}

// SetData sets the data to be included in the response.
// Takes any data as input and assigns it to the Data field in the response struct.
func (r *response) SetData(data any) {
	r.Data = data // Sets the data to be returned in the response
}

// Send writes the response to the HTTP writer, setting the appropriate HTTP headers.
// It handles setting the Content-Type to "application/json" and encoding the response into JSON format.
func (r *response) Send(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	if len(r.Err) > 0 {
		w.WriteHeader(r.Status) // If errors exist, write the provided status code
		r.Success = false       // Marks the operation as unsuccessful
		r.Data = struct{}{}     // Sets data as an empty struct if there are errors
	} else {
		w.WriteHeader(http.StatusOK) // Sets status code as HTTP 200 OK if no errors exist
		r.Status = http.StatusOK     // Sets status field to 200
		r.Success = true             // Marks the operation as successful
		r.Err = make([]errorMsg, 0)  // Clears any existing error messages
	}

	json.NewEncoder(w).Encode(r) // Encodes the response struct as JSON and writes it to the response writer
}
