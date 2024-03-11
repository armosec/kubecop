package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"sync"
	"time"

	admissiontypes "github.com/armosec/kubecop/pkg/admission"
	"github.com/armosec/kubecop/pkg/exporters"
	log "github.com/sirupsen/logrus"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"
)

type Interface interface {
	// Runs the webhook server until the passed context is cancelled, or it
	// experiences an internal error.
	//
	// Error is always non-nil and will always be one of:
	//		deadline exceeded
	//		context cancelled
	//		or http listen error
	Run(ctx context.Context) error
}

type webhook struct {
	validator        admission.ValidationInterface
	objectInferfaces admission.ObjectInterfaces
	decoder          runtime.Decoder
	addr             string
	exporter         exporters.ExporterBus
	certFile         string
	keyFile          string
}

func New(addr string, certFile, keyFile string, exporter exporters.ExporterBus, scheme *runtime.Scheme, validator admission.ValidationInterface) Interface {
	codecs := serializer.NewCodecFactory(scheme)
	return &webhook{
		objectInferfaces: admission.NewObjectInterfacesFromScheme(scheme),
		decoder:          codecs.UniversalDeserializer(),
		validator:        validator,
		addr:             addr,
		certFile:         certFile,
		keyFile:          keyFile,
		exporter:         exporter,
	}
}

func notifyChanges(ctx context.Context, paths ...string) <-chan struct{} {
	type info struct {
		modTime time.Time
		err     string
	}
	infos := map[string]info{}
	getInfos := func() map[string]info {
		res := map[string]info{}
		for _, v := range paths {
			fileInfo, err := os.Stat(v)
			if err != nil {
				infos[v] = info{err: err.Error()}
			} else {
				infos[v] = info{modTime: fileInfo.ModTime()}
			}

		}
		return res
	}
	lastInfos := getInfos()

	res := make(chan struct{})
	go func() {
		defer close(res)

		for {
			select {
			case <-ctx.Done():
				// context cancelled, stop watching
				return

			case <-time.After(2 * time.Second):
				newInfos := getInfos()
				if reflect.DeepEqual(lastInfos, newInfos) {
					continue
				}

				lastInfos = newInfos

				// skip event if client has not read last change
				select {
				case res <- struct{}{}:
				default:
				}
			}
		}
	}()
	return res
}

func (wh *webhook) Run(ctx context.Context) error {
	var serverError error
	var wg sync.WaitGroup

	log.Info("starting webhook HTTP server")
	defer log.Info("stopped webhook HTTP server")
	defer wg.Wait()

	wg.Add(1)
	defer wg.Done()

	launchServer := func() (*http.Server, <-chan error) {
		mux := http.NewServeMux()
		mux.HandleFunc("/health", wh.handleHealth)
		mux.HandleFunc("/validate", wh.handleWebhookValidate)
		srv := &http.Server{}
		srv.Handler = mux
		srv.Addr = wh.addr

		errChan := make(chan error)

		wg.Add(1)
		go func() {
			defer wg.Done()
			defer close(errChan)

			err := srv.ListenAndServeTLS(wh.certFile, wh.keyFile)
			errChan <- err
			// ListenAndServeTLS always returns non-nil error
		}()

		return srv, errChan
	}

	watchCtx, cancelWatches := context.WithCancel(ctx)
	defer cancelWatches()

	keyWatch := notifyChanges(watchCtx, wh.certFile, wh.keyFile)

	currentServer, currentErrorChannel := launchServer()
loop:
	for {
		select {
		case <-ctx.Done():
			// If the caller closed their context, rather than the server having errored,
			// close the server. srv.Close() is safe to call on an already-closed server
			//
			// note: should we prefer to use Shutdown with a deadline for graceful close
			// rather than Close?
			if err := currentServer.Close(); err != nil {
				// Errors with gracefully shutting down connections. Not fatal. Server
				// is still closed.
				log.Errorf("error closing server: %v", err)
			}
			serverError = ctx.Err()
			break loop
		case serverError = <-currentErrorChannel:
			// Server was closed independently of being restarted
			break loop

		case _, ok := <-keyWatch:
			if !ok {
				serverError = watchCtx.Err()
				break loop
			}

			log.Info("TLS input has changed, restarting HTTP server")

			// Graceful shutdown, ignore any errors
			wg.Add(1)

			q := currentServer
			go func() {
				defer wg.Done()

				//!TOOD: add shutdown timeout, requests to a webhook should
				// not be long-lived
				shutdownCtx, shutdownCancel := context.WithTimeout(watchCtx, 5*time.Second)
				defer shutdownCancel()

				q.Shutdown(shutdownCtx)
			}()
			currentServer, currentErrorChannel = launchServer()
		}
	}
	return serverError
}

func (wh *webhook) handleHealth(w http.ResponseWriter, req *http.Request) {
	fmt.Fprint(w, "OK")
}

func (wh *webhook) handleWebhookValidate(w http.ResponseWriter, req *http.Request) {
	parsed, err := parseRequest(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Debugf(
		"review request: user=%s, resource=%s, operation=%s, uid=%s",
		parsed.Request.UserInfo.String(),
		parsed.Request.Resource.String(),
		parsed.Request.Operation,
		parsed.Request.UID,
	)

	failure := func(err error, status int) {
		http.Error(w, err.Error(), status)
		log.Errorf("review response: uid=%s, status=%d, err=%v", parsed.Request.UID, status, err)
	}

	err = nil

	var attrs admission.Attributes

	if wh.validator.Handles(admission.Operation(parsed.Request.Operation)) {
		var object runtime.Object
		var oldObject runtime.Object

		if len(parsed.Request.OldObject.Raw) > 0 {
			obj, gvk, err := wh.decoder.Decode(parsed.Request.OldObject.Raw, nil, nil)
			switch {
			case gvk == nil || *gvk != schema.GroupVersionKind(parsed.Request.Kind):
				// GVK case first. If object type is unknown it is parsed to
				// unstructured, but
				failure(fmt.Errorf("unexpected GVK %v. Expected %v", gvk, parsed.Request.Kind), http.StatusBadRequest)
				return
			case err != nil && runtime.IsNotRegisteredError(err):
				var oldUnstructured unstructured.Unstructured
				err = json.Unmarshal(parsed.Request.OldObject.Raw, &oldUnstructured)
				if err != nil {
					failure(err, http.StatusInternalServerError)
					return
				}

				oldObject = &oldUnstructured
			case err != nil:
				failure(err, http.StatusBadRequest)
				return
			default:
				oldObject = obj
			}
		}

		// Parse into native types if possible
		convertExtra := func(input map[string]authenticationv1.ExtraValue) map[string][]string {
			if input == nil {
				return nil
			}

			res := map[string][]string{}
			for k, v := range input {
				var converted []string
				for _, s := range v {
					converted = append(converted, string(s))
				}
				res[k] = converted
			}
			return res
		}

		//!TODO: Parse options as v1.CreateOptions, v1.DeleteOptions, or v1.PatchOptions

		attrs = admission.NewAttributesRecord(
			object,
			oldObject,
			schema.GroupVersionKind(parsed.Request.Kind),
			parsed.Request.Namespace,
			parsed.Request.Name,
			schema.GroupVersionResource{
				Group:    parsed.Request.Resource.Group,
				Version:  parsed.Request.Resource.Version,
				Resource: parsed.Request.Resource.Resource,
			},
			parsed.Request.SubResource,
			admission.Operation(parsed.Request.Operation),
			nil, // operation options?
			false,
			&user.DefaultInfo{
				Name:   parsed.Request.UserInfo.Username,
				UID:    parsed.Request.UserInfo.UID,
				Groups: parsed.Request.UserInfo.Groups,
				Extra:  convertExtra(parsed.Request.UserInfo.Extra),
			})

		err = wh.validator.Validate(context.TODO(), attrs, wh.objectInferfaces)
	}

	response := wh.reviewResponse(
		parsed.Request.UID,
		err,
		parsed.Request.Resource.Resource,
		parsed.Request.Name,
		parsed.Request.Namespace,
		attrs,
		&parsed.Request.UserInfo,
	)

	out, err := json.Marshal(response)
	if err != nil {
		failure(err, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
	log.Debugf("review response: uid=%s, status=%d, err=%v", parsed.Request.UID, response.Response.Result.Code, response.Response.Result.Message)
}

func (wh *webhook) reviewResponse(uid types.UID, err error, resource string, name string, namespace string, attrs admission.Attributes, requestingUser *authenticationv1.UserInfo) *admissionv1.AdmissionReview {
	var status int32 = http.StatusAccepted
	if err != nil {
		status = http.StatusForbidden
	}
	reason := metav1.StatusReasonUnknown
	message := "valid"
	if err != nil {
		message = err.Error()
	}

	var statusErr *k8serrors.StatusError
	if ok := errors.As(err, &statusErr); ok {
		reason = statusErr.ErrStatus.Reason
		message = statusErr.ErrStatus.Message
		status = statusErr.ErrStatus.Code
	}

	// If the request is denied, we want to log the request and the reason for the denial. (denied == allowed but we want to audit).
	if status != http.StatusAccepted {
		wh.exporter.SendAdmissionControlAlert(
			admissiontypes.AdmissionControlData{
				UID:             string(uid),
				User:            requestingUser.Username,
				Groups:          requestingUser.Groups,
				Operation:       string(attrs.GetOperation()),
				Kind:            attrs.GetKind().String(),
				Name:            name,
				Namespace:       namespace,
				Resource:        resource,
				Subresource:     attrs.GetSubresource(),
				ResponseMessage: message,
			})
	}

	// We don't want to deny the requests.
	return &admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			Kind:       "AdmissionReview",
			APIVersion: "admission.k8s.io/v1",
		},
		Response: &admissionv1.AdmissionResponse{
			UID:     uid,
			Allowed: true,
			Result: &metav1.Status{
				Code:    http.StatusAccepted,
				Message: message,
				Reason:  reason,
			},
		},
	}
}

// parseRequest extracts an AdmissionReview from an http.Request if possible
func parseRequest(r *http.Request) (*admissionv1.AdmissionReview, error) {
	if r.Header.Get("Content-Type") != "application/json" {
		return nil, fmt.Errorf("Content-Type: %q should be %q",
			r.Header.Get("Content-Type"), "application/json")
	}

	bodybuf := new(bytes.Buffer)
	bodybuf.ReadFrom(r.Body)
	body := bodybuf.Bytes()

	if len(body) == 0 {
		return nil, fmt.Errorf("admission request body is empty")
	}

	var admissionReview admissionv1.AdmissionReview

	if err := json.Unmarshal(body, &admissionReview); err != nil {
		return nil, fmt.Errorf("could not parse admission review request: %v", err)
	}

	if admissionReview.Request == nil {
		return nil, fmt.Errorf("admission review can't be used: Request field is nil")
	}

	return &admissionReview, nil
}
