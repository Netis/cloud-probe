package httpmix

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/gorilla/schema"

	"github.com/Netis/cloud-probe/cpgolib/slogx"
)

var DefaultSchemaDecoder = schema.NewDecoder()

func init() {
	DefaultSchemaDecoder.SetAliasTag("json")
}

type ErrorResponse struct {
	Error ErrorInfo `json:"error"`
}

type ErrorInfo struct {
	Message string `json:"message"`
}

func NewErrorInfo(err error) ErrorInfo {
	return ErrorInfo{Message: err.Error()}
}

type Helper struct {
	W   http.ResponseWriter
	R   *http.Request
	dec *schema.Decoder
	lg  *slog.Logger
}

func NewHelper(w http.ResponseWriter, req *http.Request) *Helper {
	hp := Helper{
		W:   w,
		R:   req,
		dec: DefaultSchemaDecoder,
		lg: slog.Default().With(
			slogx.LoggerName("httpmix"),
			slog.String("path", req.URL.Path),
			slog.String("method", req.Method),
		),
	}
	return &hp
}

func (hp *Helper) Logger() *slog.Logger {
	return hp.lg
}

func (hp *Helper) BadRequest(err error) {
	hp.Fail(http.StatusBadRequest, NewErrorInfo(err))
}

func (hp *Helper) NotFound(err error) {
	hp.Fail(http.StatusNotFound, NewErrorInfo(err))
}

func (hp *Helper) Abort(err error) {
	hp.lg.Error("abort", slogx.Error(err))
	hp.Fail(http.StatusInternalServerError, NewErrorInfo(err))
}

func (hp *Helper) Fail(code int, e ErrorInfo) {
	hp.W.Header().Set("Content-Type", "application/json; charset=utf-8")

	data, err := json.Marshal(ErrorResponse{Error: e})
	if err != nil {
		panic(err)
	}

	hp.Code(code, data)
}

func (hp *Helper) JSON(code int, v any) {
	hp.W.Header().Set("Content-Type", "application/json; charset=utf-8")

	data, err := json.Marshal(v)
	if err != nil {
		hp.Abort(err)
		return
	}

	hp.Code(code, data)
}

func (hp *Helper) NoContent() {
	hp.Code(http.StatusNoContent, nil)
}

func (hp *Helper) Code(code int, v []byte) {
	hp.W.WriteHeader(code)
	_, err := hp.W.Write(v)
	if err != nil {
		hp.lg.Error("write fail", slogx.Error(err))
	}
}

func (hp *Helper) DecodeJson(v any) bool {
	err := json.NewDecoder(hp.R.Body).Decode(v)
	if err != nil {
		hp.lg.Debug("decode body", slogx.Error(err))
		hp.BadRequest(err)
		return false
	}
	return true
}

func (hp *Helper) DecodeQuery(v any) bool {
	err := hp.dec.Decode(v, hp.R.URL.Query())
	if err != nil {
		hp.lg.Debug("decode query params", slogx.Error(err))
		hp.BadRequest(err)
		return false
	}
	return true
}
