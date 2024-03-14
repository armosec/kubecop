package admission

// Contains the data on the al
type AdmissionControlData struct {
	// The user who sent the request
	User string `json:"user"`
	// The user groups
	Groups []string `json:"groups"`
	// The user UID
	UID string `json:"uid"`
	// The namespace of the request
	Namespace string `json:"namespace"`
	// The name of the request
	Name string `json:"name"`
	// The operation of the request
	Operation string `json:"operation"`
	// The kind of the request
	Kind string `json:"kind"`
	// The request resource
	Resource string `json:"resource"`
	// The request subresource
	Subresource string `json:"subresource"`
	// The request response message
	ResponseMessage string `json:"responseMessage"`
}
