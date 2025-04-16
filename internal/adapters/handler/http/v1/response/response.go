package response

import (
	"encoding/json"
	"net/http"
	"userVault/internal/port"
)

func New() port.Response {
	return &response{}
}

func (r *response) SetError(errMsg string) {
	r.Err = append(r.Err, errorMsg{
		Msg: errMsg,
	})
}

func (r *response) SetStatus(status int) {
	r.Status = status
}

func (r *response) SetData(data any) {
	r.Data = data
}

func (r *response) Send(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	if len(r.Err) > 0 {
		w.WriteHeader(r.Status)
		r.Success = false
		r.Data = struct{}{}
	} else {
		w.WriteHeader(http.StatusOK)
		r.Status = http.StatusOK
		r.Success = true
		r.Err = make([]errorMsg, 0)
	}

	json.NewEncoder(w).Encode(r)
}
