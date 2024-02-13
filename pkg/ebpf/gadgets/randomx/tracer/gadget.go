package tracer

import (
	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/mount/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
)

type GadgetDesc struct{}

func (g *GadgetDesc) Name() string {
	return "randomx"
}

func (g *GadgetDesc) Category() string {
	return gadgets.CategoryTrace
}

func (g *GadgetDesc) Type() gadgets.GadgetType {
	return gadgets.TypeTrace
}

func (g *GadgetDesc) Description() string {
	return "Trace fpu deactivations to detect randomx mining"
}

func (g *GadgetDesc) ParamDescs() params.ParamDescs {
	return nil
}

func (g *GadgetDesc) Parser() parser.Parser {
	return parser.NewParser[types.Event](types.GetColumns())
}

func (g *GadgetDesc) EventPrototype() any {
	return &types.Event{}
}

func init() {
	gadgetregistry.Register(&GadgetDesc{})
}
