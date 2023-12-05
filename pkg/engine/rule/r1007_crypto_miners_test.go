package rule

import (
	"fmt"
	"testing"

	"github.com/kubescape/kapprofiler/pkg/tracing"
)

func TestR1007CryptoMiners(t *testing.T) {
	// Create a new rule
	r := CreateRuleR1007CryptoMiners()
	// Assert r is not nil
	if r == nil {
		t.Errorf("Expected r to not be nil")
	}

	// Create network event
	e := &tracing.NetworkEvent{
		GeneralEvent: tracing.GeneralEvent{
			ContainerID: "test",
			PodName:     "test",
			Namespace:   "test",
			Timestamp:   0,
		},
		PacketType:  "OUTGOING",
		Protocol:    "TCP",
		Port:        2222,
		DstEndpoint: "1.1.1.1",
	}

	ruleResult := r.ProcessEvent(tracing.NetworkEventType, e, nil, nil)
	if ruleResult != nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be nil since dst port is not in the commonly used crypto miners ports")
		return
	}

	// Create network event with dst port 3333
	e.Port = 3333

	ruleResult = r.ProcessEvent(tracing.NetworkEventType, e, nil, nil)
	if ruleResult == nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be Failure because of dst port is in the commonly used crypto miners ports")
		return
	}

}